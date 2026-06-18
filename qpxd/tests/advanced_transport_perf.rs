#![cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rcgen::generate_simple_self_signed;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;

pub mod common;
mod h3_client_support;
mod yaml_support;

use common::{QpxdHandle, pick_free_tcp_port, spawn_qpxd, temp_dir};
use h3_client_support::{build_h3_test_client_config, build_quinn_client_endpoint};
use yaml_support::yaml_quote_path;

type PerfOperation =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

#[derive(Clone, Copy)]
struct PerfThresholds {
    min_req_per_sec: f64,
    max_p95: Duration,
}

fn benchmark_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

const PORT_PICK_ATTEMPTS: usize = 256;

fn spawn_qpxd_on_random_tcp_udp_ports(
    config_path: &Path,
    log_path: PathBuf,
    make_config: impl Fn(u16, u16) -> String,
) -> Result<(u16, u16, QpxdHandle)> {
    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..PORT_PICK_ATTEMPTS {
        let tcp_port = pick_free_tcp_port()?;
        let udp_port = pick_free_udp_port()?;
        fs::write(config_path, make_config(tcp_port, udp_port))?;
        match spawn_qpxd(config_path, tcp_port, log_path.clone()) {
            Ok(handle) => return Ok((tcp_port, udp_port, handle)),
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
    Err(last_err.unwrap_or_else(|| {
        anyhow!(
            "failed to start qpxd after {} tcp/udp port attempts",
            PORT_PICK_ATTEMPTS
        )
    }))
}

fn pick_free_udp_port() -> Result<u16> {
    let socket = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    Ok(socket.local_addr()?.port())
}

fn is_retryable_bind_error_text(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("address already in use")
        || message.contains("eaddrinuse")
        || message.contains("permission denied")
        || message.contains("operation not permitted")
        || message.contains("os error 1")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_h3_connect_udp_transport_perf() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping advanced transport perf assertions in debug build");
        return Ok(());
    }

    let _guard = benchmark_lock().lock().await;

    let op: PerfOperation = Arc::new(|| Box::pin(run_connect_udp_round()));
    measure_isolated_perf(
        "forward_h3_connect_udp",
        4,
        PerfThresholds {
            min_req_per_sec: 0.1,
            max_p95: Duration::from_secs(8),
        },
        op,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_h3_extended_connect_transport_perf() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping advanced transport perf assertions in debug build");
        return Ok(());
    }

    let _guard = benchmark_lock().lock().await;

    let op: PerfOperation = Arc::new(|| Box::pin(run_extended_connect_round()));
    measure_isolated_perf(
        "forward_h3_extended_connect",
        4,
        PerfThresholds {
            min_req_per_sec: 0.08,
            max_p95: Duration::from_secs(10),
        },
        op,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_h3_webtransport_transport_perf() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping advanced transport perf assertions in debug build");
        return Ok(());
    }

    let _guard = benchmark_lock().lock().await;

    let op: PerfOperation = Arc::new(|| Box::pin(run_webtransport_round()));
    measure_isolated_perf(
        "forward_h3_webtransport",
        4,
        PerfThresholds {
            min_req_per_sec: 0.05,
            max_p95: Duration::from_secs(12),
        },
        op,
    )
    .await
}

async fn measure_isolated_perf(
    label: &str,
    total_requests: usize,
    thresholds: PerfThresholds,
    op: PerfOperation,
) -> Result<()> {
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(total_requests);
    for _ in 0..total_requests {
        let req_started = Instant::now();
        (op)().await?;
        latencies.push(req_started.elapsed());
    }
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
        "advanced_transport_perf[{label}] total={} elapsed_ms={} req_per_sec={:.2} p95_ms={}",
        total_requests,
        elapsed.as_millis(),
        req_per_sec,
        p95.as_millis()
    );
    write_perf_artifact(label, total_requests, elapsed, req_per_sec, p95)?;

    assert!(
        req_per_sec >= thresholds.min_req_per_sec,
        "throughput regression on {label}: req_per_sec={req_per_sec:.2} (< {})",
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

fn write_perf_artifact(
    label: &str,
    total_requests: usize,
    elapsed: Duration,
    req_per_sec: f64,
    p95: Duration,
) -> Result<()> {
    let Some(path) = std::env::var_os("QPX_PERF_SMOKE_JSON") else {
        return Ok(());
    };
    let _guard = perf_artifact_lock().lock().expect("perf artifact lock");
    let path = PathBuf::from(path);
    let record = serde_json::json!({
        "bench": canonical_perf_bench_label(label),
        "legacy_bench": label,
        "first_byte_ms": serde_json::Value::Null,
        "p95_chunk_gap_ms": serde_json::Value::Null,
        "total_ms": elapsed.as_secs_f64() * 1000.0,
        "rss_peak_mb": serde_json::Value::Null,
        "cpu_ms": serde_json::Value::Null,
        "bytes": serde_json::Value::Null,
        "commit": perf_commit(),
        "total_requests": total_requests,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "req_per_sec": req_per_sec,
        "p95_ms": p95.as_secs_f64() * 1000.0,
    });
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|err| anyhow!("create perf artifact dir {}: {err}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| anyhow!("open perf artifact {}: {err}", path.display()))?;
    use std::io::Write as _;
    writeln!(file, "{}", serde_json::to_string(&record)?)
        .map_err(|err| anyhow!("write perf artifact: {err}"))?;
    Ok(())
}

fn perf_artifact_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn canonical_perf_bench_label(label: &str) -> &str {
    match label {
        "forward_h3_connect_udp" => "connect_streaming_messages",
        "forward_h3_extended_connect" => "connect_streaming_messages",
        "forward_h3_webtransport" => "connect_streaming_messages",
        other => other,
    }
}

fn perf_commit() -> String {
    if let Ok(value) = std::env::var("GITHUB_SHA")
        && !value.trim().is_empty()
    {
        return value;
    }
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn run_connect_udp_round() -> Result<()> {
    let dir = temp_dir("qpxd-forward-connect-udp-advanced-perf")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-connect-udp.yaml");
    let target_port = pick_free_tcp_port()?;
    let (_tcp_port, udp_port, _qpxd) = spawn_qpxd_on_random_tcp_udp_ports(
        &cfg,
        dir.join("forward-connect-udp.log"),
        |tcp_port, udp_port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"edges:
- kind: forward
  name: forward-h3
  listen: 127.0.0.1:{tcp_port}
  default_action:
    type: direct
  tls_inspection:
    enabled: true
    verify_upstream: false
  rules: []
  http3:
    enabled: true
    listen: 127.0.0.1:{udp_port}
    connect_udp:
      enabled: true
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            )
        },
    )?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let ca_cert = state_dir.join("ca.crt");
    wait_for_file(&ca_cert).await?;
    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&ca_cert)?);
    let conn = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], udp_port)), "localhost")?,
    )
    .await??;
    let mut builder = ::h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let uri = http::Uri::builder()
        .scheme("https")
        .authority(format!("localhost:{udp_port}"))
        .path_and_query(format!("/.well-known/masque/udp/127.0.0.1/{target_port}/"))
        .build()?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .header("capsule-protocol", "?1")
        .body(())?;
    request
        .extensions_mut()
        .insert(::h3::ext::Protocol::CONNECT_UDP);

    let mut stream = sender.send_request(request).await?;
    stream.finish().await?;
    let response = timeout(Duration::from_secs(5), stream.recv_response()).await??;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok()),
        Some("?1")
    );
    driver.abort();
    let _ = driver.await;
    Ok(())
}

async fn run_extended_connect_round() -> Result<()> {
    let (upstream_addr, upstream_task) = start_qpx_h3_server(QpxH3ExtendedEchoHandler).await?;
    let dir = temp_dir("qpxd-forward-qpx-extended-connect-advanced-perf")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-qpx-extended-connect.yaml");
    let (_tcp_port, udp_port, _qpxd) = spawn_qpxd_on_random_tcp_udp_ports(
        &cfg,
        dir.join("forward-qpx-extended-connect.log"),
        |tcp_port, udp_port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"edges:
- kind: forward
  name: forward-h3
  listen: 127.0.0.1:{tcp_port}
  default_action:
    type: direct
  tls_inspection:
    enabled: true
    verify_upstream: false
  rules: []
  http3:
    enabled: true
    listen: 127.0.0.1:{udp_port}
    connect_udp:
      enabled: true
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            )
        },
    )?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let ca_cert = state_dir.join("ca.crt");
    wait_for_file(&ca_cert).await?;
    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&ca_cert)?);
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], udp_port)), "localhost")?,
    )
    .await??;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!(
            "https://127.0.0.1:{}/extended",
            upstream_addr.port()
        ))
        .body(())?;
    let mut stream = qpx_h3::open_extended_connect_stream(
        endpoint,
        connection,
        request,
        Some(qpx_h3::Protocol::Other("websocket".to_string())),
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        },
        Duration::from_secs(5),
    )
    .await?;
    assert_eq!(stream.response.status(), http::StatusCode::OK);

    stream
        .request_stream
        .send_data(Bytes::from_static(b"ping"))
        .await?;
    let echoed = timeout(Duration::from_secs(5), stream.request_stream.recv_data())
        .await
        .map_err(|_| anyhow!("timed out waiting for extended CONNECT echo"))??
        .ok_or_else(|| anyhow!("missing extended CONNECT echo"))?;
    assert_eq!(echoed, Bytes::from_static(b"ping"));

    tokio::time::sleep(Duration::from_millis(25)).await;
    let datagrams = stream
        .datagrams
        .as_mut()
        .ok_or_else(|| anyhow!("missing extended CONNECT datagrams"))?;
    datagrams.sender.send_unprefixed_datagram_with_scratch(
        Bytes::from_static(b"dg"),
        &mut bytes::BytesMut::new(),
    )?;
    let echoed_datagram = timeout(Duration::from_secs(5), datagrams.receiver.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for extended CONNECT datagram"))?
        .ok_or_else(|| anyhow!("missing extended CONNECT datagram"))?;
    assert_eq!(echoed_datagram, Bytes::from_static(b"dg"));

    shutdown_qpx_extended_stream(stream).await?;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

async fn run_webtransport_round() -> Result<()> {
    let (upstream_addr, upstream_task) = start_qpx_h3_server(QpxH3WebTransportEchoHandler).await?;
    let dir = temp_dir("qpxd-forward-qpx-webtransport-advanced-perf")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-qpx-webtransport.yaml");
    let (_tcp_port, udp_port, _qpxd) = spawn_qpxd_on_random_tcp_udp_ports(
        &cfg,
        dir.join("forward-qpx-webtransport.log"),
        |tcp_port, udp_port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"edges:
- kind: forward
  name: forward-h3
  listen: 127.0.0.1:{tcp_port}
  default_action:
    type: direct
  tls_inspection:
    enabled: true
    verify_upstream: false
  rules: []
  http3:
    enabled: true
    listen: 127.0.0.1:{udp_port}
    connect_udp:
      enabled: true
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            )
        },
    )?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let ca_cert = state_dir.join("ca.crt");
    wait_for_file(&ca_cert).await?;
    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&ca_cert)?);
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], udp_port)), "localhost")?,
    )
    .await??;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!(
            "https://127.0.0.1:{}/webtransport",
            upstream_addr.port()
        ))
        .body(())?;
    let mut stream = qpx_h3::open_extended_connect_stream(
        endpoint,
        connection,
        request,
        Some(qpx_h3::Protocol::WebTransport),
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 4,
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        },
        Duration::from_secs(5),
    )
    .await?;
    assert_eq!(stream.response.status(), http::StatusCode::OK);

    stream
        .request_stream
        .send_data(Bytes::from_static(b"request-stream"))
        .await?;
    let echoed = timeout(Duration::from_secs(5), stream.request_stream.recv_data())
        .await
        .map_err(|_| anyhow!("timed out waiting for WebTransport request echo"))??
        .ok_or_else(|| anyhow!("missing WebTransport request echo"))?;
    assert_eq!(echoed, Bytes::from_static(b"request-stream"));

    tokio::time::sleep(Duration::from_millis(150)).await;
    let datagrams = stream
        .datagrams
        .as_mut()
        .ok_or_else(|| anyhow!("missing WebTransport datagrams"))?;
    datagrams.sender.send_unprefixed_datagram_with_scratch(
        Bytes::from_static(b"wt-dgram"),
        &mut bytes::BytesMut::new(),
    )?;
    let echoed_datagram = timeout(Duration::from_secs(5), datagrams.receiver.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for WebTransport datagram echo"))?
        .ok_or_else(|| anyhow!("missing WebTransport datagram echo"))?;
    assert_eq!(echoed_datagram, Bytes::from_static(b"wt-dgram"));

    let session_id = stream.request_stream.id();
    let mut opener = stream
        .opener
        .take()
        .ok_or_else(|| anyhow!("missing WebTransport opener"))?;
    let mut associated_bidi = stream
        .associated_bidi
        .take()
        .ok_or_else(|| anyhow!("missing associated bidi receiver"))?;
    let mut associated_uni = stream
        .associated_uni
        .take()
        .ok_or_else(|| anyhow!("missing associated uni receiver"))?;

    let server_bidi = timeout(Duration::from_secs(5), associated_bidi.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for server-initiated bidi"))?
        .ok_or_else(|| anyhow!("missing server-initiated bidi"))?;
    assert_eq!(read_qpx_bidi_stream(server_bidi).await?, b"server-bidi");

    let client_bidi = opener.open_webtransport_bidi(session_id).await?;
    let (mut client_bidi_send, mut client_bidi_recv) = client_bidi.split();
    client_bidi_send
        .send_chunk(Bytes::from_static(b"client-bidi"))
        .await?;
    client_bidi_send.finish().await?;
    let mut echoed_bidi = Vec::new();
    while let Some(chunk) = client_bidi_recv.recv_chunk().await? {
        echoed_bidi.extend_from_slice(chunk.as_ref());
    }
    assert_eq!(echoed_bidi, b"client-bidi");

    let server_uni = timeout(Duration::from_secs(5), associated_uni.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for server-initiated uni"))?
        .ok_or_else(|| anyhow!("missing server-initiated uni"))?;
    assert_eq!(read_qpx_uni_stream(server_uni).await?, b"server-uni");

    let mut client_uni = opener.open_webtransport_uni(session_id).await?;
    client_uni
        .send_chunk(Bytes::from_static(b"client-uni"))
        .await?;
    client_uni.finish().await?;
    let echoed_uni = timeout(Duration::from_secs(5), associated_uni.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for echoed uni"))?
        .ok_or_else(|| anyhow!("missing echoed uni"))?;
    assert_eq!(read_qpx_uni_stream(echoed_uni).await?, b"client-uni");

    shutdown_qpx_extended_stream(stream).await?;
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

async fn wait_for_file(path: &Path) -> Result<()> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        if path.is_file() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!("timed out waiting for {}", path.display()))
}

#[derive(Clone, Default)]
struct QpxH3ExtendedEchoHandler;

#[async_trait]
impl qpx_h3::RequestHandler for QpxH3ExtendedEchoHandler {
    fn settings(&self) -> qpx_h3::Settings {
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: qpx_h3::Request,
        _conn: qpx_h3::ConnectionInfo,
        _stream: qpx_h3::RequestStream,
    ) -> std::result::Result<(), qpx_h3::H3Error> {
        Err(anyhow!("unexpected buffered request").into())
    }

    async fn handle_connect_stream(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: qpx_h3::RequestStream,
        _conn: qpx_h3::ConnectionInfo,
        protocol: qpx_h3::Protocol,
        mut datagrams: Option<qpx_h3::StreamDatagrams>,
    ) -> std::result::Result<(), qpx_h3::H3Error> {
        match protocol {
            qpx_h3::Protocol::Other(name) if name == "websocket" => {}
            other => return Err(anyhow!("unexpected protocol: {other:?}").into()),
        }
        req_stream
            .send_response_head(&ok_qpx_response_head(false))
            .await?;
        let chunk = timeout(Duration::from_secs(5), req_stream.recv_data())
            .await
            .map_err(|_| anyhow!("timed out waiting for extended CONNECT request data"))??
            .ok_or_else(|| anyhow!("missing extended CONNECT request data"))?;
        req_stream.send_data(chunk).await?;
        let payload = timeout(Duration::from_secs(5), async {
            datagrams
                .as_mut()
                .ok_or_else(|| anyhow!("missing downstream datagrams"))?
                .receiver
                .recv()
                .await
                .ok_or_else(|| anyhow!("missing downstream extended CONNECT datagram"))
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for extended CONNECT datagram"))??;
        datagrams
            .as_mut()
            .expect("checked above")
            .sender
            .send_unprefixed_datagram_with_scratch(payload, &mut bytes::BytesMut::new())?;
        req_stream.finish().await
    }
}

#[derive(Clone, Default)]
struct QpxH3WebTransportEchoHandler;

#[async_trait]
impl qpx_h3::RequestHandler for QpxH3WebTransportEchoHandler {
    fn settings(&self) -> qpx_h3::Settings {
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 8,
            read_timeout: Duration::from_secs(5),
            ..Default::default()
        }
    }

    async fn handle_request(
        &self,
        _request: qpx_h3::Request,
        _conn: qpx_h3::ConnectionInfo,
        _stream: qpx_h3::RequestStream,
    ) -> std::result::Result<(), qpx_h3::H3Error> {
        Err(anyhow!("unexpected buffered request").into())
    }

    async fn handle_webtransport_connect(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: qpx_h3::RequestStream,
        _conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> std::result::Result<(), qpx_h3::H3Error> {
        let qpx_h3::WebTransportSession {
            session_id,
            mut opener,
            mut datagrams,
            mut bidi_streams,
            mut uni_streams,
        } = session;

        req_stream
            .send_response_head(&ok_qpx_response_head(false))
            .await?;

        let server_bidi = opener.open_webtransport_bidi(session_id).await?;
        let (mut server_bidi_send, _) = server_bidi.split();
        server_bidi_send
            .send_chunk(Bytes::from_static(b"server-bidi"))
            .await?;
        server_bidi_send.finish().await?;

        let mut server_uni = opener.open_webtransport_uni(session_id).await?;
        server_uni
            .send_chunk(Bytes::from_static(b"server-uni"))
            .await?;
        server_uni.finish().await?;

        let chunk = timeout(Duration::from_secs(5), req_stream.recv_data())
            .await
            .map_err(|_| anyhow!("timed out waiting for WebTransport request data"))??
            .ok_or_else(|| anyhow!("missing WebTransport request data"))?;
        req_stream.send_data(chunk).await?;

        let payload = timeout(Duration::from_secs(5), async {
            datagrams
                .as_mut()
                .ok_or_else(|| anyhow!("missing WebTransport datagrams"))?
                .receiver
                .recv()
                .await
                .ok_or_else(|| anyhow!("missing WebTransport datagram"))
        })
        .await
        .map_err(|_| anyhow!("timed out waiting for WebTransport datagram"))??;
        datagrams
            .as_mut()
            .expect("checked above")
            .sender
            .send_unprefixed_datagram_with_scratch(payload, &mut bytes::BytesMut::new())?;

        let bidi = timeout(Duration::from_secs(5), bidi_streams.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for client bidi stream"))?
            .ok_or_else(|| anyhow!("missing client bidi stream"))?;
        let (mut bidi_send, mut bidi_recv) = bidi.split();
        while let Some(chunk) = bidi_recv.recv_chunk().await? {
            bidi_send.send_chunk(chunk).await?;
        }
        bidi_send.finish().await?;

        let uni = timeout(Duration::from_secs(5), uni_streams.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for client uni stream"))?
            .ok_or_else(|| anyhow!("missing client uni stream"))?;
        let echoed = read_qpx_uni_stream(uni).await?;
        let mut reply_uni = opener.open_webtransport_uni(session_id).await?;
        reply_uni.send_chunk(Bytes::from(echoed)).await?;
        reply_uni.finish().await?;

        req_stream.finish().await
    }
}

async fn start_qpx_h3_server<H: qpx_h3::RequestHandler>(
    handler: H,
) -> Result<(
    SocketAddr,
    JoinHandle<std::result::Result<(), qpx_h3::H3Error>>,
)> {
    let server_config = build_qpx_h3_server_config()?;
    let endpoint = quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        let connecting = timeout(Duration::from_secs(5), endpoint.accept())
            .await
            .map_err(|_| anyhow!("timed out waiting for inbound QUIC connection"))?
            .ok_or_else(|| anyhow!("server endpoint closed before accept"))?;
        qpx_h3::serve_connection(connecting, addr.port(), handler).await
    });
    Ok((addr, task))
}

fn build_qpx_h3_server_config() -> Result<quinn::ServerConfig> {
    let certified =
        generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let cert_der = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));

    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut tls = quinn::rustls::ServerConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure qpx-h3 perf server tls versions"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;

    let quic_crypto = QuicServerConfig::try_from(tls)
        .map_err(|_| anyhow!("failed to build qpx-h3 perf QUIC server config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow!("failed to configure qpx-h3 perf QUIC transport"))?;
    transport.max_concurrent_bidi_streams(64_u32.into());
    transport.max_concurrent_uni_streams(64_u32.into());
    server_config.migration(false);
    Ok(server_config)
}

fn ok_qpx_response_head(capsule_protocol: bool) -> http::Response<()> {
    let mut response = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .expect("static response");
    if capsule_protocol {
        response.headers_mut().insert(
            http::header::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_static("?1"),
        );
    }
    response
}

async fn read_qpx_bidi_stream(stream: qpx_h3::BidiStream) -> Result<Vec<u8>> {
    let (_, mut recv) = stream.split();
    let mut out = Vec::new();
    while let Some(chunk) = recv.recv_chunk().await? {
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

async fn read_qpx_uni_stream(mut stream: qpx_h3::UniRecvStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = stream.recv_chunk().await? {
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

async fn shutdown_qpx_extended_stream(mut stream: qpx_h3::ExtendedConnectStream) -> Result<()> {
    let _ = stream.request_stream.finish().await;
    if let Some(task) = stream.datagram_task.take() {
        task.abort();
        let _ = task.await;
    }
    stream.driver.abort();
    let _ = stream.driver.await;
    Ok(())
}
