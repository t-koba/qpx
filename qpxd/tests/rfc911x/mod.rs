#![cfg(all(feature = "http3", feature = "tls-rustls"))]

#[path = "../collect_body_support/mod.rs"]
mod collect_body_support;
#[path = "../common/mod.rs"]
pub mod common;
#[path = "../empty_body_support/mod.rs"]
mod empty_body_support;
#[path = "../full_body_support/mod.rs"]
mod full_body_support;
#[path = "../http1_service_shutdown_support/mod.rs"]
mod http1_service_shutdown_support;
#[path = "../http2_client_support/mod.rs"]
mod http2_client_support;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::{Buf, Bytes};
use collect_body_support::collect_body;
use common::QpxdHandle;
use empty_body_support::empty_body;
use full_body_support::full_body;
use http_body_util::combinators::BoxBody;
use http1_service_shutdown_support::spawn_http1_service_with_shutdown;
use http2_client_support::handshake_http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};
use tokio::time::{Instant, timeout};

type TestBody = BoxBody<Bytes, std::convert::Infallible>;

#[derive(Deserialize)]
struct BatchGetRequest {
    keys: Vec<String>,
}

#[derive(Serialize)]
struct BatchGetResponse {
    values: Vec<Option<String>>,
}

fn ensure_rustls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

/// RFC 911x / related RFCs contract tests.
///
/// Scope: provides black-box e2e/contract tests that detect regressions in
/// qpxd's implemented RFC compliance points (see docs/rfc911x-compliance.md).
mod cache;
mod hop_via;
mod http1;
mod http2;
mod http3;
mod tunnel_websocket;
use cache::cache_contract;
use hop_via::hop_by_hop_and_via_contract;
use http1::http11_validation_cases;
use http2::{http2_h2c_contract, http2_tls_alpn_contract};
use http3::http3_reverse_terminate_smoke;
use tunnel_websocket::{connect_tunnel_contract, websocket_upgrade_contract};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rfc911x_contract() -> Result<()> {
    rfc911x_contract_inner().await
}

async fn rfc911x_contract_inner() -> Result<()> {
    ensure_rustls_provider();
    // --- Scenario 1: HTTP/1.1 forward proxy semantics (RFC 9110/9112 + 6455) ---
    {
        let dir = temp_dir("qpxd-rfc911x-forward")?;
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        let cfg_path = dir.join("qpxd-forward.yaml");
        let (forward_port, _qpxd) =
            spawn_qpxd_on_random_port(&cfg_path, dir.join("qpxd-forward.log"), |port| {
                let state_dir_yaml = yaml_quote_path(&state_dir);
                format!(
                    r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules: []
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                    state_dir_yaml = state_dir_yaml
                )
            })?;

        // RFC 9112: Host/authority validation and message framing checks (strict reject).
        http11_validation_cases(forward_port).await?;

        // RFC 9110: hop-by-hop header stripping + Via, and RFC 9110 section 11.7 proxy creds not forwarded.
        hop_by_hop_and_via_contract(forward_port).await?;

        // RFC 9110 CONNECT (authority-form) + successful CONNECT no-body framing.
        connect_tunnel_contract(forward_port).await?;

        // RFC 6455 WebSocket upgrade: preserve upgrade hop-by-hop pair and tunnel upgraded bytes.
        websocket_upgrade_contract(forward_port).await?;
    }

    // --- Scenario 2: RFC 9111 caching (forward listener, HTTP cache backend) ---
    cache_contract().await?;

    // --- Scenario 3: RFC 9113 HTTP/2 (h2c prior knowledge, reverse + transparent) ---
    http2_h2c_contract().await?;

    // --- Scenario 4: RFC 9113 HTTP/2 over TLS (ALPN h2), reverse ---
    http2_tls_alpn_contract().await?;

    // --- Scenario 5: RFC 9114 HTTP/3 terminate smoke (reverse) ---
    http3_reverse_terminate_smoke().await?;

    Ok(())
}
fn spawn_qpxd(config_path: &Path, port: u16, log_path: PathBuf) -> Result<QpxdHandle> {
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

    // Wait for TCP listener to come up (best-effort).
    let started = std::time::Instant::now();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    while started.elapsed() < Duration::from_secs(15) {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return Ok(QpxdHandle::new(child));
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
        "timed out waiting for qpxd to listen on {addr} (log: {})",
        log_path.display()
    ))
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

fn yaml_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn yaml_quote_path(path: &Path) -> String {
    yaml_single_quote(path.to_string_lossy().as_ref())
}

const PORT_PICK_ATTEMPTS: usize = 256;

fn pick_free_tcp_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).context("pick free tcp port")?;
    Ok(listener.local_addr()?.port())
}

fn is_retryable_bind_error_text(msg: &str) -> bool {
    let msg = msg.to_ascii_lowercase();
    msg.contains("address already in use")
        || msg.contains("eaddrinuse")
        || msg.contains("permission denied")
        || msg.contains("operation not permitted")
        || msg.contains("os error 1")
}

fn spawn_qpxd_on_random_port(
    config_path: &Path,
    log_path: PathBuf,
    make_config: impl Fn(u16) -> String,
) -> Result<(u16, QpxdHandle)> {
    let mut last_err: Option<anyhow::Error> = None;
    for _ in 0..PORT_PICK_ATTEMPTS {
        let port = pick_free_tcp_port()?;
        fs::write(config_path, make_config(port)).context("write qpxd config")?;
        match spawn_qpxd(config_path, port, log_path.clone()) {
            Ok(handle) => return Ok((port, handle)),
            Err(err) => {
                let log_retryable = fs::read_to_string(&log_path)
                    .ok()
                    .map(|s| is_retryable_bind_error_text(&s))
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
            "failed to start qpxd after {} port attempts",
            PORT_PICK_ATTEMPTS
        )
    }))
}

fn build_quinn_client_endpoint() -> Result<quinn::Endpoint> {
    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 0));
    quinn::Endpoint::client(addr)
        .map_err(|e| anyhow!(e))
        .context("bind quinn client endpoint")
}

async fn read_at_least(
    stream: &mut TcpStream,
    mut already: Vec<u8>,
    want_len: usize,
    timeout_dur: Duration,
) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout_dur;
    let mut tmp = [0u8; 1024];
    while already.len() < want_len && Instant::now() < deadline {
        let n = match timeout(Duration::from_millis(200), stream.read(&mut tmp)).await {
            Ok(read) => read?,
            Err(_) => continue,
        };
        if n == 0 {
            break;
        }
        already.extend_from_slice(&tmp[..n]);
    }
    if already.len() < want_len {
        return Err(anyhow!("deadline has elapsed"));
    }
    Ok(already)
}

async fn assert_status(addr: SocketAddr, req: String, expected: u16) -> Result<()> {
    let (status, _headers, _rest) = send_http1_and_read_head(addr, req.as_bytes()).await?;
    if status != expected {
        return Err(anyhow!(
            "unexpected status for request (expected={expected} got={status})\n--- request ---\n{req}\n-------------"
        ));
    }
    Ok(())
}

type Http1Head = (u16, Vec<(String, String)>, Vec<u8>);

async fn send_http1_and_read_head(addr: SocketAddr, request_bytes: &[u8]) -> Result<Http1Head> {
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .context("connect timed out")??;
    stream.write_all(request_bytes).await?;
    stream.flush().await?;
    read_http1_head(&mut stream).await
}

async fn send_http1_and_read_response(addr: SocketAddr, request_bytes: &[u8]) -> Result<Http1Head> {
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .context("connect timed out")??;
    stream.write_all(request_bytes).await?;
    stream.flush().await?;
    let (status, headers, mut body) = read_http1_head(&mut stream).await?;
    if headers.iter().any(|(name, value)| {
        name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
    }) {
        body = read_http1_chunked_body(&mut stream, body).await?;
        return Ok((status, headers, body));
    }
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    while body.len() < content_length {
        let need = content_length - body.len();
        let mut chunk = vec![0u8; need.min(2048)];
        let read = timeout(Duration::from_secs(3), stream.read(&mut chunk))
            .await
            .context("body read timed out")??;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok((status, headers, body))
}

async fn read_http1_chunked_body(stream: &mut TcpStream, mut buf: Vec<u8>) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut pos = 0usize;
    loop {
        let line_end = loop {
            if let Some(rel) = find_crlf(&buf[pos..]) {
                break pos + rel;
            }
            read_more_http1_body(stream, &mut buf).await?;
        };
        let size_line = std::str::from_utf8(&buf[pos..line_end]).context("chunk size utf8")?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).context("chunk size parse")?;
        pos = line_end + 2;
        while buf.len().saturating_sub(pos) < size + 2 {
            read_more_http1_body(stream, &mut buf).await?;
        }
        decoded.extend_from_slice(&buf[pos..pos + size]);
        pos += size;
        if buf.get(pos..pos + 2) != Some(b"\r\n") {
            return Err(anyhow!("chunk payload missing trailing CRLF"));
        }
        pos += 2;
        if size == 0 {
            return Ok(decoded);
        }
        if pos > 8192 {
            buf.drain(..pos);
            pos = 0;
        }
    }
}

async fn read_more_http1_body(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Result<()> {
    let mut chunk = [0u8; 2048];
    let read = timeout(Duration::from_secs(3), stream.read(&mut chunk))
        .await
        .context("body read timed out")??;
    if read == 0 {
        return Err(anyhow!("unexpected EOF while reading HTTP/1 body"));
    }
    buf.extend_from_slice(&chunk[..read]);
    Ok(())
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

async fn read_http1_head(stream: &mut TcpStream) -> Result<Http1Head> {
    let buf = read_until(stream, b"\r\n\r\n", 128 * 1024, Duration::from_secs(3)).await?;
    parse_http1_head(&buf)
}

async fn read_until(
    stream: &mut TcpStream,
    delim: &[u8],
    max_bytes: usize,
    timeout_dur: Duration,
) -> Result<Vec<u8>> {
    let started = Instant::now();
    let mut out = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        if out.windows(delim.len()).any(|w| w == delim) {
            break;
        }
        if out.len() > max_bytes {
            return Err(anyhow!("read_until exceeded max_bytes={max_bytes}"));
        }
        if started.elapsed() > timeout_dur {
            return Err(anyhow!("read_until timed out"));
        }
        let n = match timeout(Duration::from_millis(200), stream.read(&mut tmp)).await {
            Ok(read) => read?,
            Err(_) => continue,
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

fn parse_http1_head(buf: &[u8]) -> Result<Http1Head> {
    let s = String::from_utf8_lossy(buf);
    let Some(idx) = s.find("\r\n\r\n") else {
        return Err(anyhow!("missing header delimiter"));
    };
    let (head, rest) = buf.split_at(idx + 4);
    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("invalid status line: {status_line:?}"))?
        .parse::<u16>()
        .context("parse status code")?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    Ok((code, headers, rest.to_vec()))
}

fn assert_header_absent(headers: &[(String, String)], name: &str) {
    let name = name.to_ascii_lowercase();
    assert!(
        headers.iter().all(|(k, _)| k != &name),
        "unexpected header present: {name}\nheaders={headers:?}"
    );
}

fn assert_header_present(headers: &[(String, String)], name: &str) {
    let name = name.to_ascii_lowercase();
    assert!(
        headers.iter().any(|(k, _)| k == &name),
        "expected header missing: {name}\nheaders={headers:?}"
    );
}

fn assert_header_present_contains(headers: &[(String, String)], name: &str, needle: &str) {
    let name = name.to_ascii_lowercase();
    let needle = needle.to_ascii_lowercase();
    let values = headers
        .iter()
        .filter(|(k, _)| k == &name)
        .map(|(_, v)| v.to_ascii_lowercase())
        .collect::<Vec<_>>();
    assert!(
        values.iter().any(|v| v.contains(&needle)),
        "expected header {name} to contain {needle:?}, got {values:?}"
    );
}

async fn serve_http1_capture_once(
    response_bytes: Vec<u8>,
) -> Result<(SocketAddr, oneshot::Receiver<Vec<u8>>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("bind tcp")?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = run_http1_capture_once(listener, response_bytes, tx).await;
    });
    Ok((addr, rx))
}

async fn run_http1_capture_once(
    listener: TcpListener,
    response_bytes: Vec<u8>,
    tx: oneshot::Sender<Vec<u8>>,
) -> Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let req = read_until(&mut stream, b"\r\n\r\n", 128 * 1024, Duration::from_secs(3)).await?;
    let _ = tx.send(req);
    stream.write_all(&response_bytes).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn serve_tcp_echo_once() -> Result<(SocketAddr, oneshot::Receiver<Vec<u8>>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("bind tcp")?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = run_tcp_echo_once(listener, tx).await;
    });
    Ok((addr, rx))
}

async fn run_tcp_echo_once(listener: TcpListener, tx: oneshot::Sender<Vec<u8>>) -> Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let mut buf = [0u8; 64];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    let received = buf[..n].to_vec();
    let _ = tx.send(received.clone());
    if received == b"ping" {
        stream.write_all(b"pong").await?;
    } else {
        stream.write_all(&received).await?;
    }
    let _ = stream.shutdown().await;
    Ok(())
}

async fn serve_websocket_stub_once() -> Result<(
    SocketAddr,
    oneshot::Receiver<Vec<u8>>,
    oneshot::Receiver<Vec<u8>>,
)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .context("bind tcp")?;
    let addr = listener.local_addr()?;
    let (captured_tx, captured_rx) = oneshot::channel();
    let (upgraded_tx, upgraded_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = run_websocket_stub_once(listener, captured_tx, upgraded_tx).await;
    });
    Ok((addr, captured_rx, upgraded_rx))
}

async fn run_websocket_stub_once(
    listener: TcpListener,
    captured_tx: oneshot::Sender<Vec<u8>>,
    upgraded_tx: oneshot::Sender<Vec<u8>>,
) -> Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let req = read_until(&mut stream, b"\r\n\r\n", 128 * 1024, Duration::from_secs(3)).await?;
    let _ = captured_tx.send(req);

    let response = b"HTTP/1.1 101 Switching Protocols\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n";
    stream.write_all(response).await?;
    stream.flush().await?;

    let mut buf = [0u8; 128];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buf)).await??;
    let received = buf[..n].to_vec();
    let _ = upgraded_tx.send(received);
    stream.write_all(b"server-bytes").await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn start_origin_server(hits: Arc<AtomicUsize>) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let hits = hits.clone();
        async move { Ok::<_, std::convert::Infallible>(handle_origin(req, hits).await) }
    });
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    spawn_http1_service_with_shutdown(listener, service, shutdown_rx);
    Ok((addr, shutdown_tx))
}

async fn handle_origin(
    req: Request<hyper::body::Incoming>,
    hits: Arc<AtomicUsize>,
) -> Response<TestBody> {
    hits.fetch_add(1, Ordering::SeqCst);
    match req.uri().path() {
        "/cacheable" => Response::builder()
            .status(StatusCode::OK)
            .header("cache-control", "public, max-age=60")
            .body(full_body("CACHEABLE"))
            .unwrap(),
        "/cookie" => Response::builder()
            .status(StatusCode::OK)
            .header("cache-control", "public, max-age=60")
            .header("vary", "cookie")
            .header("set-cookie", "sid=abc; Path=/; HttpOnly")
            .body(full_body("COOKIE"))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(full_body("not found"))
            .unwrap(),
    }
}

type TestCacheStore = Arc<Mutex<HashMap<String, Vec<u8>>>>;

async fn start_http_cache_backend() -> Result<(SocketAddr, oneshot::Sender<()>, TestCacheStore)> {
    let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let service_store = store.clone();
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        let store = service_store.clone();
        async move { Ok::<_, std::convert::Infallible>(handle_cache_backend(req, store).await) }
    });
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    spawn_http1_service_with_shutdown(listener, service, shutdown_rx);
    Ok((addr, shutdown_tx, store))
}

async fn wait_for_cache_store_entries(store: TestCacheStore, min_entries: usize) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if store.lock().await.len() >= min_entries {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("timed out waiting for cache writeback"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn handle_cache_backend(
    req: Request<hyper::body::Incoming>,
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
) -> Response<TestBody> {
    let path = req.uri().path().to_string();
    let key = path.strip_prefix("/v1/cache/").unwrap_or("").to_string();
    match *req.method() {
        Method::POST if key.ends_with("/_batch_get") => {
            let namespace = key.trim_end_matches("/_batch_get");
            let bytes = collect_body(req.into_body()).await.unwrap_or_default();
            let batch: BatchGetRequest = serde_json::from_slice(bytes.as_ref()).unwrap();
            let map = store.lock().await;
            let values = batch
                .keys
                .iter()
                .map(|key| {
                    map.get(format!("{namespace}/{key}").as_str())
                        .map(|value| BASE64.encode(value))
                })
                .collect();
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(full_body(
                    serde_json::to_vec(&BatchGetResponse { values }).unwrap(),
                ))
                .unwrap()
        }
        Method::GET => {
            let map = store.lock().await;
            match map.get(&key) {
                Some(v) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/octet-stream")
                    .body(full_body(v.clone()))
                    .unwrap(),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(empty_body())
                    .unwrap(),
            }
        }
        Method::PUT => {
            let bytes = collect_body(req.into_body()).await.unwrap_or_default();
            let mut map = store.lock().await;
            map.insert(key, bytes.to_vec());
            Response::builder()
                .status(StatusCode::CREATED)
                .body(empty_body())
                .unwrap()
        }
        Method::DELETE => {
            let mut map = store.lock().await;
            map.remove(&key);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(empty_body())
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(empty_body())
            .unwrap(),
    }
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

async fn connect_tls_with_alpn_h2(
    addr: impl tokio::net::ToSocketAddrs,
    ca_cert_pem: &Path,
    server_name: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let certs = qpx_core::tls::load_cert_chain(ca_cert_pem)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("no certs loaded from {}", ca_cert_pem.display()));
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = timeout(Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .context("tcp connect timed out")??;
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow!("invalid server name"))?;
    Ok(timeout(Duration::from_secs(3), connector.connect(name, stream)).await??)
}

fn build_h3_test_client_config(ca_cert_pem: &Path) -> Result<quinn::ClientConfig> {
    use quinn::crypto::rustls::QuicClientConfig;
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
