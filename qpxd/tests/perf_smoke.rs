#[path = "support/empty_body.rs"]
mod empty_body_support;
#[path = "support/http2_client.rs"]
mod http2_client_support;
#[path = "support/test_client.rs"]
mod test_client_support;

use anyhow::{anyhow, Context, Result};
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use bytes::Buf;
use bytes::Bytes;
use empty_body_support::empty_body;
use http_body_util::{BodyExt as _, Full};
use hyper::Method;
use hyper::Request;
use hyper::StatusCode;
#[cfg(all(feature = "http3", feature = "tls-rustls"))]
use quinn::crypto::rustls::QuicClientConfig;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

struct QpxdHandle {
    child: Child,
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
const PERF_TLS_SERVER_NAME: &str = "reverse.local";

type PerfOperation =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

#[derive(Clone, Copy)]
struct PerfThresholds {
    min_req_per_sec: f64,
    max_p95: Duration,
}

impl Drop for QpxdHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_local_response_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-perf-smoke")?;
    let cfg = dir.join("perf-smoke.yaml");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("perf-smoke.log"), |port| {
        format!(
            r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: perf
  listen: 127.0.0.1:{port}
  routes:
  - name: perf
    match:
      host:
      - perf.local
      path:
      - /perf
    local_response:
      status: 200
      body: PERF"#
        )
    })?;

    let client = test_client_support::test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/perf").parse()?;

    for _ in 0..64 {
        let response = client
            .request(
                Request::builder()
                    .method("GET")
                    .uri(uri.clone())
                    .header("host", "perf.local")
                    .body(empty_body())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let _ = response.into_body().collect().await?;
    }

    let op: PerfOperation = Arc::new(move || {
        let client = client.clone();
        let uri = uri.clone();
        Box::pin(async move {
            let response = client
                .request(
                    Request::builder()
                        .method("GET")
                        .uri(uri.clone())
                        .header("host", "perf.local")
                        .body(empty_body())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let _ = response.into_body().collect().await?;
            Ok(())
        })
    });
    measure_parallel_perf(
        "reverse_local_response",
        512,
        32,
        PerfThresholds {
            min_req_per_sec: 1000.0,
            max_p95: Duration::from_millis(100),
        },
        op,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_connect_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-forward-connect-perf")?;
    let cfg = dir.join("forward-connect-perf.yaml");
    let echo_addr = serve_tcp_echo_loop().await?;
    let authority = echo_addr.to_string();
    let client_hello = Arc::new(build_test_client_hello());

    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("forward-connect-perf.log"), |port| {
            format!(
                r#"listeners:
- name: forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules: []
  mode: forward
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#
            )
        })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let op: PerfOperation = Arc::new(move || {
        let authority = authority.clone();
        let client_hello = client_hello.clone();
        Box::pin(async move {
            let mut stream =
                timeout(Duration::from_secs(3), TcpStream::connect(proxy_addr)).await??;
            let request = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            let status = read_http1_status(&mut stream).await?;
            if status != 200 {
                return Err(anyhow!("expected CONNECT 200, got {status}"));
            }
            stream.write_all(client_hello.as_slice()).await?;
            stream.flush().await?;
            let mut echoed = vec![0u8; client_hello.len()];
            timeout(Duration::from_secs(3), stream.read_exact(&mut echoed)).await??;
            if echoed != client_hello.as_slice() {
                return Err(anyhow!("unexpected CONNECT echo payload"));
            }
            Ok(())
        })
    });
    measure_parallel_perf(
        "forward_connect",
        128,
        16,
        PerfThresholds {
            min_req_per_sec: 100.0,
            max_p95: Duration::from_millis(200),
        },
        op,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_upstream_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let backend_dir = temp_dir("qpxd-reverse-upstream-backend")?;
    let front_dir = temp_dir("qpxd-reverse-upstream-front")?;
    let backend_cfg = backend_dir.join("backend.yaml");
    let front_cfg = front_dir.join("front.yaml");

    let (backend_port, _backend) =
        spawn_qpxd_on_random_port(&backend_cfg, backend_dir.join("backend.log"), |port| {
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: backend
  listen: 127.0.0.1:{port}
  routes:
  - name: perf
    match:
      path:
      - /perf
    local_response:
      status: 200
      body: PERF"#
            )
        })?;

    let (front_port, _front) =
        spawn_qpxd_on_random_port(&front_cfg, front_dir.join("front.log"), |port| {
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: front
  listen: 127.0.0.1:{port}
  routes:
  - name: perf
    match:
      host:
      - perf.local
      path:
      - /perf
    upstreams:
    - http://127.0.0.1:{backend_port}"#
            )
        })?;

    let client = test_client_support::test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{front_port}/perf").parse()?;
    let op: PerfOperation = Arc::new(move || {
        let client = client.clone();
        let uri = uri.clone();
        Box::pin(async move {
            let response = client
                .request(
                    Request::builder()
                        .method("GET")
                        .uri(uri.clone())
                        .header("host", "perf.local")
                        .body(empty_body())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let _ = response.into_body().collect().await?;
            Ok(())
        })
    });
    measure_parallel_perf(
        "reverse_upstream_http1",
        512,
        32,
        PerfThresholds {
            min_req_per_sec: 400.0,
            max_p95: Duration::from_millis(150),
        },
        op,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_unary_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-grpc-unary-perf")?;
    let cfg = dir.join("grpc-unary-perf.yaml");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("grpc-unary-perf.log"), |port| {
        format!(
            r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: grpc
  listen: 127.0.0.1:{port}
  routes:
  - name: unary
    match:
      path:
      - /perf.Service/Unary
    local_response:
      status: 200
      body: OK
      rpc:
        protocol: grpc
        status: "0"
        message: ok"#
        )
    })?;

    let request_body = Bytes::from(frame_grpc_message(Bytes::from_static(b"ping")));
    let op: PerfOperation = Arc::new(move || {
        let request_body = request_body.clone();
        Box::pin(async move {
            let stream = timeout(
                Duration::from_secs(3),
                TcpStream::connect(("127.0.0.1", port)),
            )
            .await??;
            let (mut sender, conn) = http2_client_support::handshake_http2(stream).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let uri: hyper::Uri = format!("http://127.0.0.1:{port}/perf.Service/Unary").parse()?;
            let req = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header(http::header::TE, "trailers")
                .body(full_body(request_body.clone()))?;
            let resp = sender.send_request(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(anyhow!("expected grpc unary 200, got {}", resp.status()));
            }
            let collected = resp.into_body().collect().await?;
            let trailers = collected.trailers().cloned();
            let body = collected.to_bytes();
            if body.as_ref() != frame_grpc_message(Bytes::from_static(b"OK")).as_slice() {
                return Err(anyhow!("unexpected grpc unary response body"));
            }
            let trailers = trailers.ok_or_else(|| anyhow!("missing grpc unary trailers"))?;
            let status = trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok());
            if status != Some("0") {
                return Err(anyhow!("unexpected grpc unary status: {status:?}"));
            }
            Ok(())
        })
    });
    measure_parallel_perf(
        "grpc_unary",
        128,
        8,
        PerfThresholds {
            min_req_per_sec: 50.0,
            max_p95: Duration::from_millis(250),
        },
        op,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_streaming_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-grpc-streaming-perf")?;
    let cfg = dir.join("grpc-streaming-perf.yaml");
    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("grpc-streaming-perf.log"), |port| {
            format!(
                r#"listeners:
- name: grpc-forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  mode: forward
  rules:
  - name: client-streaming
    match:
      path:
      - /perf.Service/ClientStream
      rpc:
        protocol:
        - grpc
        streaming:
        - client
    action:
      type: respond
      local_response:
        status: 200
        body: STREAM
        rpc:
          protocol: grpc
          status: "0"
          message: streamed
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#
            )
        })?;

    let mut request_frames = frame_grpc_message(Bytes::from_static(b"one"));
    request_frames.extend_from_slice(&frame_grpc_message(Bytes::from_static(b"two")));
    let request_body = Bytes::from(request_frames);
    let op: PerfOperation = Arc::new(move || {
        let request_body = request_body.clone();
        Box::pin(async move {
            let stream = timeout(
                Duration::from_secs(3),
                TcpStream::connect(("127.0.0.1", port)),
            )
            .await??;
            let (mut sender, conn) = http2_client_support::handshake_http2(stream).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let uri: hyper::Uri =
                format!("http://127.0.0.1:{port}/perf.Service/ClientStream").parse()?;
            let req = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header(http::header::TE, "trailers")
                .body(full_body(request_body.clone()))?;
            let resp = sender.send_request(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(anyhow!(
                    "expected grpc streaming 200, got {}",
                    resp.status()
                ));
            }
            let collected = resp.into_body().collect().await?;
            let trailers = collected.trailers().cloned();
            let body = collected.to_bytes();
            if body.as_ref() != frame_grpc_message(Bytes::from_static(b"STREAM")).as_slice() {
                return Err(anyhow!("unexpected grpc streaming response body"));
            }
            let trailers = trailers.ok_or_else(|| anyhow!("missing grpc streaming trailers"))?;
            let status = trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok());
            if status != Some("0") {
                return Err(anyhow!("unexpected grpc streaming status: {status:?}"));
            }
            Ok(())
        })
    });
    measure_parallel_perf(
        "grpc_streaming",
        96,
        8,
        PerfThresholds {
            min_req_per_sec: 30.0,
            max_p95: Duration::from_millis(300),
        },
        op,
    )
    .await
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_http3_terminate_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-reverse-h3-terminate-perf")?;
    let cfg = dir.join("reverse-h3-terminate.yaml");
    let (cert_path, key_path) = write_self_signed_cert(&dir, PERF_TLS_SERVER_NAME)?;

    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("reverse-h3-terminate.log"), |port| {
            let cert_yaml = yaml_quote_path(&cert_path);
            let key_yaml = yaml_quote_path(&key_path);
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: reverse
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: {server_name}
      cert: {cert_yaml}
      key: {key_yaml}
  http3:
    enabled: true
  routes:
  - name: perf
    match:
      host:
      - {server_name}
      path:
      - /perf
    local_response:
      status: 200
      body: H3PERF"#,
                server_name = PERF_TLS_SERVER_NAME,
                cert_yaml = cert_yaml,
                key_yaml = key_yaml,
            )
        })?;

    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&cert_path)?);
    let conn = timeout(
        Duration::from_secs(3),
        endpoint.connect(
            SocketAddr::from(([127, 0, 0, 1], port)),
            PERF_TLS_SERVER_NAME,
        )?,
    )
    .await??;
    let mut builder = ::h3::client::builder();
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let started = Instant::now();
    let mut latencies = Vec::with_capacity(128);
    for _ in 0..128usize {
        let req_started = Instant::now();
        let uri = http::Uri::builder()
            .scheme("https")
            .authority(format!("{PERF_TLS_SERVER_NAME}:{port}"))
            .path_and_query("/perf")
            .build()?;
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(())?;
        let mut stream = sender.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            let mut chunk = chunk;
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        if body != b"H3PERF" {
            return Err(anyhow!("unexpected h3 terminate response body"));
        }
        latencies.push(req_started.elapsed());
    }
    driver.abort();
    let _ = driver.await;

    report_perf(
        "reverse_http3_terminate",
        128,
        started.elapsed(),
        latencies,
        PerfThresholds {
            min_req_per_sec: 50.0,
            max_p95: Duration::from_millis(200),
        },
    )
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_http3_passthrough_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let backend_dir = temp_dir("qpxd-reverse-h3-perf-backend")?;
    let front_dir = temp_dir("qpxd-reverse-h3-perf-front")?;
    let backend_cfg = backend_dir.join("backend.yaml");
    let front_cfg = front_dir.join("front.yaml");
    let (cert_path, key_path) = write_self_signed_cert(&backend_dir, PERF_TLS_SERVER_NAME)?;

    let (backend_port, _backend) =
        spawn_qpxd_on_random_port(&backend_cfg, backend_dir.join("backend.log"), |port| {
            let cert_yaml = yaml_quote_path(&cert_path);
            let key_yaml = yaml_quote_path(&key_path);
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: backend
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: {server_name}
      cert: {cert_yaml}
      key: {key_yaml}
  http3:
    enabled: true
  routes:
  - name: perf
    match:
      host:
      - {server_name}
      path:
      - /perf
    local_response:
      status: 200
      body: H3PASS"#,
                server_name = PERF_TLS_SERVER_NAME,
                cert_yaml = cert_yaml,
                key_yaml = key_yaml,
            )
        })?;

    let front_port = pick_free_tcp_port()?;
    let front_log = front_dir.join("front.log");
    let front_state_dir = front_dir.join("state");
    fs::create_dir_all(&front_state_dir)?;
    let front_state_yaml = yaml_quote_path(&front_state_dir);
    fs::write(
        &front_cfg,
        format!(
            r#"state_dir:
  {front_state_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: passthrough
  listen: 127.0.0.1:{front_port}
  http3:
    enabled: true
    listen: 127.0.0.1:{front_port}
    passthrough_upstreams:
    - 127.0.0.1:{backend_port}
  routes: []"#,
            front_state_yaml = front_state_yaml
        ),
    )?;
    let _front = spawn_qpxd_without_ready_check(&front_cfg, front_log.clone())?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&cert_path)?);
    let conn = timeout(
        Duration::from_secs(3),
        endpoint.connect(
            SocketAddr::from(([127, 0, 0, 1], front_port)),
            PERF_TLS_SERVER_NAME,
        )?,
    )
    .await??;
    let mut builder = ::h3::client::builder();
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let started = Instant::now();
    let mut latencies = Vec::with_capacity(64);
    for _ in 0..64usize {
        let req_started = Instant::now();
        let uri = http::Uri::builder()
            .scheme("https")
            .authority(format!("{PERF_TLS_SERVER_NAME}:{front_port}"))
            .path_and_query("/perf")
            .build()?;
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri(uri)
            .body(())?;
        let mut stream = sender.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            let mut chunk = chunk;
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        if body != b"H3PASS" {
            return Err(anyhow!("unexpected h3 passthrough response body"));
        }
        latencies.push(req_started.elapsed());
    }
    driver.abort();
    let _ = driver.await;

    report_perf(
        "reverse_http3_passthrough",
        64,
        started.elapsed(),
        latencies,
        PerfThresholds {
            min_req_per_sec: 25.0,
            max_p95: Duration::from_millis(300),
        },
    )
}

async fn measure_parallel_perf(
    label: &str,
    total_requests: usize,
    concurrency: usize,
    thresholds: PerfThresholds,
    op: PerfOperation,
) -> Result<()> {
    let latencies = Arc::new(Mutex::new(Vec::with_capacity(total_requests)));
    let next = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let latencies = latencies.clone();
        let next = next.clone();
        let op = op.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if idx >= total_requests {
                    break;
                }
                let req_started = Instant::now();
                (op)().await?;
                latencies.lock().await.push(req_started.elapsed());
            }
            Ok::<_, anyhow::Error>(())
        }));
    }

    for task in tasks {
        task.await.expect("join")?;
    }

    let latencies = latencies.lock().await.clone();
    report_perf(
        label,
        total_requests,
        started.elapsed(),
        latencies,
        thresholds,
    )
}

fn report_perf(
    label: &str,
    total_requests: usize,
    elapsed: Duration,
    mut latencies: Vec<Duration>,
    thresholds: PerfThresholds,
) -> Result<()> {
    if latencies.is_empty() {
        return Err(anyhow!("no perf samples recorded for {label}"));
    }
    latencies.sort_unstable();
    let p95_index = ((latencies.len() as f64) * 0.95).ceil() as usize - 1;
    let p95 = latencies[p95_index];
    let req_per_sec = total_requests as f64 / elapsed.as_secs_f64();

    eprintln!(
        "perf_smoke[{label}] total={} elapsed_ms={} req_per_sec={:.1} p95_ms={}",
        total_requests,
        elapsed.as_millis(),
        req_per_sec,
        p95.as_millis()
    );

    assert!(
        req_per_sec >= thresholds.min_req_per_sec,
        "throughput regression on {label}: req_per_sec={req_per_sec:.1} (< {})",
        thresholds.min_req_per_sec
    );
    assert!(
        p95 <= thresholds.max_p95,
        "tail-latency regression on {label}: p95={}ms (> {}ms)",
        p95.as_millis(),
        thresholds.max_p95.as_millis()
    );
    Ok(())
}

fn full_body(
    bytes: Bytes,
) -> http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible> {
    Full::new(bytes).boxed()
}

fn frame_grpc_message(bytes: Bytes) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + bytes.len());
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&bytes);
    out
}

fn temp_dir(prefix: &str) -> Result<PathBuf> {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}.{suffix}"));
    fs::create_dir_all(&dir).with_context(|| format!("create temp dir {}", dir.display()))?;
    Ok(dir)
}

fn pick_free_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).context("pick free tcp port")?;
    Ok(listener.local_addr()?.port())
}

fn spawn_qpxd(config_path: &Path, ready_port: u16, log_path: PathBuf) -> Result<QpxdHandle> {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_qpxd"));
    let log = fs::File::create(&log_path).context("create qpxd log")?;
    let log_err = log.try_clone().context("clone qpxd log")?;

    let mut cmd = Command::new(bin);
    cmd.arg("run")
        .arg("--config")
        .arg(config_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    let mut child = cmd.spawn().context("spawn qpxd")?;
    wait_for_qpxd(&mut child, ready_port, &log_path)?;
    Ok(QpxdHandle { child })
}

fn wait_for_qpxd(child: &mut Child, ready_port: u16, log_path: &Path) -> Result<()> {
    let started = Instant::now();
    let addr: SocketAddr = format!("127.0.0.1:{ready_port}").parse()?;
    while started.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait().context("qpxd wait")? {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!(
                "qpxd exited early: {status} (log: {})",
                log_path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(anyhow!(
        "timed out waiting for qpxd to listen on {} (log: {})",
        addr,
        log_path.display()
    ))
}

fn is_retryable_bind_error_text(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("address already in use")
        || message.contains("eaddrinuse")
        || message.contains("permission denied")
        || message.contains("operation not permitted")
        || message.contains("os error 1")
}

fn spawn_qpxd_on_random_port(
    config_path: &Path,
    log_path: PathBuf,
    make_config: impl Fn(u16) -> String,
) -> Result<(u16, QpxdHandle)> {
    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..256 {
        let port = pick_free_tcp_port()?;
        fs::write(config_path, make_config(port)).context("write qpxd config")?;
        match spawn_qpxd(config_path, port, log_path.clone()) {
            Ok(handle) => return Ok((port, handle)),
            Err(err) => {
                let log_retryable = fs::read_to_string(&log_path)
                    .ok()
                    .map(|value| is_retryable_bind_error_text(&value))
                    .unwrap_or(false);
                let err_retryable = is_retryable_bind_error_text(&err.to_string());
                if log_retryable || err_retryable {
                    last_err = Some(err);
                    continue;
                }
                return Err(err);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("failed to start qpxd after retrying ports")))
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn spawn_qpxd_without_ready_check(config_path: &Path, log_path: PathBuf) -> Result<QpxdHandle> {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_qpxd"));
    let log = fs::File::create(&log_path).context("create qpxd log")?;
    let log_err = log.try_clone().context("clone qpxd log")?;

    let mut cmd = Command::new(bin);
    cmd.arg("run")
        .arg("--config")
        .arg(config_path)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    let mut child = cmd.spawn().context("spawn qpxd")?;
    std::thread::sleep(Duration::from_millis(200));
    if child.try_wait()?.is_some() {
        return Err(anyhow!(
            "qpxd exited early while starting UDP/QUIC-only config (log: {})",
            log_path.display()
        ));
    }
    Ok(QpxdHandle { child })
}

async fn serve_tcp_echo_loop() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        break;
                    };
                    if n == 0 {
                        break;
                    }
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = stream.flush().await;
                }
            });
        }
    });
    Ok(addr)
}

async fn read_http1_status(stream: &mut TcpStream) -> Result<u16> {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
        if n == 0 {
            return Err(anyhow!("connection closed before HTTP/1 response head"));
        }
        head.extend_from_slice(&buf[..n]);
        if head.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if head.len() > 128 * 1024 {
            return Err(anyhow!("HTTP/1 response head exceeded 128 KiB"));
        }
    }
    let raw = String::from_utf8(head)?;
    let status = raw
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or_else(|| anyhow!("missing HTTP/1 status line"))?;
    Ok(status.parse::<u16>()?)
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn yaml_quote_path(path: &Path) -> String {
    let mut out = String::with_capacity(path.as_os_str().len() + 2);
    out.push('\'');
    for ch in path.to_string_lossy().chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn write_self_signed_cert(dir: &Path, dns_name: &str) -> Result<(PathBuf, PathBuf)> {
    let mut params = rcgen::CertificateParams::new(vec![dns_name.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_name);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_path = dir.join(format!("{dns_name}.crt.pem"));
    let key_path = dir.join(format!("{dns_name}.key.pem"));
    fs::write(&cert_path, cert.pem()).context("write cert")?;
    fs::write(&key_path, key_pair.serialize_pem()).context("write key")?;
    Ok((cert_path, key_path))
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn build_quinn_client_endpoint() -> Result<quinn::Endpoint> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    quinn::Endpoint::client(addr)
        .map_err(|err| anyhow!(err))
        .context("bind quinn client endpoint")
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
fn build_h3_test_client_config(ca_cert_pem: &Path) -> Result<quinn::ClientConfig> {
    let mut roots = quinn::rustls::RootCertStore::empty();
    let certs = qpx_core::tls::load_cert_chain(ca_cert_pem)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("no certs loaded from {}", ca_cert_pem.display()));
    }

    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure h3 client tls versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto =
        QuicClientConfig::try_from(tls).map_err(|_| anyhow!("failed to build h3 client crypto"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

fn build_test_client_hello() -> Vec<u8> {
    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u24(out: &mut Vec<u8>, value: usize) {
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
    }

    fn push_extension(out: &mut Vec<u8>, ty: u16, data: &[u8]) {
        push_u16(out, ty);
        push_u16(out, data.len() as u16);
        out.extend_from_slice(data);
    }

    let mut body = Vec::new();
    push_u16(&mut body, 0x0303);
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);

    let cipher_suites = [0x13u8, 0x01, 0x13, 0x02, 0x13, 0x03];
    push_u16(&mut body, cipher_suites.len() as u16);
    body.extend_from_slice(&cipher_suites);

    body.push(1);
    body.push(0);

    let mut extensions = Vec::new();

    let sni = b"example.com";
    let mut sni_ext = Vec::new();
    push_u16(&mut sni_ext, (sni.len() + 3) as u16);
    sni_ext.push(0);
    push_u16(&mut sni_ext, sni.len() as u16);
    sni_ext.extend_from_slice(sni);
    push_extension(&mut extensions, 0, &sni_ext);

    let groups = [0x00u8, 0x04, 0x00, 0x1d, 0x00, 0x17];
    push_extension(&mut extensions, 10, &groups);

    let ec_point_formats = [1u8, 0];
    push_extension(&mut extensions, 11, &ec_point_formats);

    let alpn = b"h2";
    let mut alpn_ext = Vec::new();
    push_u16(&mut alpn_ext, (alpn.len() + 1) as u16);
    alpn_ext.push(alpn.len() as u8);
    alpn_ext.extend_from_slice(alpn);
    push_extension(&mut extensions, 16, &alpn_ext);

    let supported_versions = [4u8, 0x03, 0x04, 0x03, 0x03];
    push_extension(&mut extensions, 43, &supported_versions);

    push_u16(&mut body, extensions.len() as u16);
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(22);
    push_u16(&mut record, 0x0301);
    push_u16(&mut record, handshake.len() as u16);
    record.extend_from_slice(&handshake);
    record
}
