#![cfg(all(feature = "http3", feature = "tls-rustls"))]

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicClientConfig;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, Instant, timeout};

pub mod common;
mod streaming_backend;

use common::QpxdHandle;

const H3_HOST: &str = "reverse.local";

struct H3ReadResult {
    status: http::StatusCode,
    ttfb: Duration,
    first_data_at: Option<Duration>,
    ttlb: Duration,
    body: Vec<u8>,
    trailers: Option<http::HeaderMap>,
    data_error: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn response_streaming_not_buffered() -> Result<()> {
    let chunks = (0..5)
        .map(|idx| {
            (
                Bytes::from(format!("chunk-{idx}\n")),
                Duration::from_millis(if idx == 0 { 0 } else { 100 }),
            )
        })
        .collect();
    let (backend_port, backend_task, _closed) = streaming_backend::spawn_slow_chunked_backend(
        chunks,
        vec![("content-type", "text/plain")],
        None,
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(backend_port, "")?;

    let response = request_h3(port, &cert_path, "/stream", &[], false).await?;

    assert_eq!(response.status, http::StatusCode::OK);
    assert!(
        response.ttfb < Duration::from_millis(150),
        "TTFB was {:?}",
        response.ttfb
    );
    assert!(
        response.ttlb > Duration::from_millis(350),
        "TTLB was {:?}",
        response.ttlb
    );
    assert!(
        response
            .body
            .windows(b"chunk-4".len())
            .any(|window| window == b"chunk-4")
    );
    backend_task.await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_response_bounded_memory() -> Result<()> {
    let payload = Bytes::from(vec![b'x'; 16 * 1024]);
    let chunks = (0..625)
        .map(|_| (payload.clone(), Duration::ZERO))
        .collect();
    let (backend_port, backend_task, _closed) = streaming_backend::spawn_slow_chunked_backend(
        chunks,
        vec![("content-type", "application/octet-stream")],
        None,
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(backend_port, "")?;

    let response = request_h3(port, &cert_path, "/large", &[], false).await?;

    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(response.body.len(), 625 * 16 * 1024);
    let first_data = response.first_data_at.expect("first data");
    assert!(
        first_data < response.ttlb,
        "expected DATA before response completion: first_data={first_data:?}, ttlb={:?}",
        response.ttlb
    );
    backend_task.await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_cancel_propagates_to_upstream() -> Result<()> {
    let (backend_port, backend_task, closed) = streaming_backend::spawn_infinite_stream_backend(
        Bytes::from_static(b"x"),
        Duration::from_millis(50),
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(backend_port, "")?;

    let response = request_h3(port, &cert_path, "/infinite", &[], true).await?;

    assert_eq!(response.status, http::StatusCode::OK);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if closed.load(Ordering::SeqCst) {
            let _ = timeout(Duration::from_millis(200), backend_task).await;
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!(
        "upstream did not observe client cancellation within 5s"
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_abort_resets_h3_stream() -> Result<()> {
    let (backend_port, backend_task) = streaming_backend::spawn_abort_after_partial_backend(
        "HTTP/1.1 200 OK",
        vec![("content-length", "10")],
        b"partial",
        Duration::from_millis(50),
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(backend_port, "")?;

    let response = request_h3(port, &cert_path, "/abort", &[], false).await?;

    assert_eq!(response.status, http::StatusCode::OK);
    assert!(
        response.data_error.is_some(),
        "expected stream reset on partial upstream body"
    );
    backend_task.await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_frame_split_across_chunks() -> Result<()> {
    let frame = streaming_backend::build_grpc_frame(b"grpc");
    let (backend_port, backend_task) = streaming_backend::spawn_grpc_backend(
        vec![frame.clone()],
        vec![("grpc-status", "0")],
        "application/grpc",
        vec![3, 5],
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(backend_port, "")?;

    let response = request_h3(port, &cert_path, "/grpc", &[], false).await?;

    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(response.body, frame.as_ref());
    backend_task.await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_message_exceeds_limit_aborts() -> Result<()> {
    let frame = streaming_backend::build_grpc_frame(&vec![b'x'; 2048]);
    let (backend_port, backend_task) = streaming_backend::spawn_grpc_backend(
        vec![frame],
        vec![("grpc-status", "0")],
        "application/grpc",
        vec![5],
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(
        backend_port,
        r#"    grpc:
      max_message_bytes: 1024
"#,
    )?;

    match request_h3(port, &cert_path, "/grpc-limit", &[], false).await {
        Ok(response) => {
            assert_eq!(response.status, http::StatusCode::OK);
            assert!(
                response.data_error.is_some(),
                "oversized gRPC message should reset the stream"
            );
        }
        Err(err) if err.to_string().contains("Remote reset") => {}
        Err(err) => return Err(err),
    }
    backend_task.await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_web_text_base64_boundary_split() -> Result<()> {
    let frame = streaming_backend::build_grpc_frame(b"grpc-web-text");
    let trailers = streaming_backend::build_grpc_web_trailer_frame(&[("grpc-status", "0")]);
    let mut framed = Vec::with_capacity(frame.len() + trailers.len());
    framed.extend_from_slice(frame.as_ref());
    framed.extend_from_slice(trailers.as_ref());
    let encoded = Bytes::from(BASE64.encode(framed));
    let chunks = vec![
        (encoded.slice(0..3), Duration::ZERO),
        (encoded.slice(3..7), Duration::ZERO),
        (encoded.slice(7..), Duration::ZERO),
    ];
    let (backend_port, backend_task, _closed) = streaming_backend::spawn_slow_chunked_backend(
        chunks,
        vec![("content-type", "application/grpc-web-text")],
        None,
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(backend_port, "")?;

    let response = request_h3(port, &cert_path, "/grpc-web-text", &[], false).await?;

    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(response.body, encoded.as_ref());
    assert!(
        response.data_error.is_none(),
        "grpc-web-text boundary split should not abort"
    );
    backend_task.await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trailers_preserved_through_streaming() -> Result<()> {
    let (backend_port, backend_task, _closed) = streaming_backend::spawn_slow_chunked_backend(
        vec![(Bytes::from_static(b"done"), Duration::ZERO)],
        vec![("content-type", "text/plain")],
        Some(vec![("grpc-status", "0"), ("x-trailer", "kept")]),
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(backend_port, "")?;

    let response = request_h3(port, &cert_path, "/trailers", &[], false).await?;

    assert_eq!(response.status, http::StatusCode::OK);
    let trailers = response.trailers.expect("trailers");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    assert_eq!(
        trailers
            .get("x-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );
    backend_task.await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn partial_failure_no_double_response() -> Result<()> {
    let (backend_port, backend_task) = streaming_backend::spawn_abort_after_partial_backend(
        "HTTP/1.1 200 OK",
        vec![("content-length", "10")],
        b"partial",
        Duration::from_millis(50),
    )
    .await;
    let (_qpxd, port, cert_path) = spawn_reverse_h3_proxy(backend_port, "")?;

    let response = request_h3(port, &cert_path, "/partial", &[], false).await?;

    assert_eq!(response.status, http::StatusCode::OK);
    assert_ne!(response.status, http::StatusCode::BAD_GATEWAY);
    assert!(
        response
            .body
            .windows(b"partial".len())
            .any(|window| window == b"partial")
    );
    assert!(
        response.data_error.is_some(),
        "partial response must end with stream reset"
    );
    backend_task.await?;
    Ok(())
}

fn spawn_reverse_h3_proxy(
    backend_port: u16,
    route_extra: &str,
) -> Result<(QpxdHandle, u16, PathBuf)> {
    let dir = temp_dir("qpxd-h3-streaming")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir).context("create state dir")?;
    let (cert_path, key_path) = write_self_signed_cert(&dir, H3_HOST)?;
    let cfg = dir.join("qpxd.yaml");
    let port = pick_free_tcp_port()?;
    fs::write(
        &cfg,
        format!(
            r#"upstreams:
- name: streaming
  url: http://127.0.0.1:{backend_port}
state_dir: {state_dir}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: h3-streaming
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: {H3_HOST}
      cert: {cert_path}
      key: {key_path}
  http3:
    enabled: true
  routes:
  - name: streaming
    match:
      host:
      - {H3_HOST}
      path:
      - /*
{route_extra}    target:
      type: upstream
      upstreams:
      - streaming"#,
            state_dir = yaml_quote_path(&state_dir),
            cert_path = yaml_quote_path(&cert_path),
            key_path = yaml_quote_path(&key_path),
        ),
    )
    .context("write qpxd config")?;
    let handle = spawn_qpxd_without_ready_check(&cfg, dir.join("qpxd.log"))?;
    Ok((handle, port, cert_path))
}

async fn request_h3(
    port: u16,
    ca_cert: &Path,
    path: &str,
    headers: &[(&str, &str)],
    close_after_first_data: bool,
) -> Result<H3ReadResult> {
    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(ca_cert)?);
    let started = Instant::now();
    let conn = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], port)), H3_HOST)?,
    )
    .await??;

    let mut builder = ::h3::client::builder();
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let uri = http::Uri::builder()
        .scheme("https")
        .authority(format!("{H3_HOST}:{port}"))
        .path_and_query(path)
        .build()?;
    let mut request = http::Request::builder().method(http::Method::GET).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request.body(())?;
    let mut stream = sender.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let ttfb = started.elapsed();
    let status = response.status();
    let mut body = Vec::new();
    let mut first_data_at = None;
    let mut data_error = None;

    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                first_data_at.get_or_insert_with(|| started.elapsed());
                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                if close_after_first_data {
                    conn.close(quinn::VarInt::from_u32(0), b"client cancel");
                    driver.abort();
                    let _ = driver.await;
                    return Ok(H3ReadResult {
                        status,
                        ttfb,
                        first_data_at,
                        ttlb: started.elapsed(),
                        body,
                        trailers: None,
                        data_error: None,
                    });
                }
            }
            Ok(None) => break,
            Err(err) => {
                data_error = Some(err.to_string());
                break;
            }
        }
    }

    let trailers = if data_error.is_none() {
        stream.recv_trailers().await?
    } else {
        None
    };
    driver.abort();
    let _ = driver.await;
    Ok(H3ReadResult {
        status,
        ttfb,
        first_data_at,
        ttlb: started.elapsed(),
        body,
        trailers,
        data_error,
    })
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

fn pick_free_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).context("pick free tcp port")?;
    Ok(listener.local_addr()?.port())
}

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
    std::thread::sleep(Duration::from_millis(500));
    if child.try_wait()?.is_some() {
        return Err(anyhow!(
            "qpxd exited early while starting HTTP/3 streaming config (log: {})",
            log_path.display()
        ));
    }
    Ok(QpxdHandle::new(child))
}

fn write_self_signed_cert(dir: &Path, dns_name: &str) -> Result<(PathBuf, PathBuf)> {
    let mut params = rcgen::CertificateParams::new(vec![dns_name.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns_name);
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_path = dir.join(format!("{dns_name}.crt.pem"));
    let key_path = dir.join(format!("{dns_name}.key.pem"));
    fs::write(&cert_path, cert_pem).context("write cert")?;
    fs::write(&key_path, key_pem).context("write key")?;
    Ok((cert_path, key_path))
}

fn build_quinn_client_endpoint() -> Result<quinn::Endpoint> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    quinn::Endpoint::client(addr)
        .map_err(|err| anyhow!(err))
        .context("bind quinn client endpoint")
}

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
