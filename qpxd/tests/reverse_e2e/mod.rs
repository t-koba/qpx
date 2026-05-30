#[path = "../collect_body_support/mod.rs"]
mod collect_body_support;
#[path = "../empty_body_support/mod.rs"]
mod empty_body_support;
#[path = "../full_body_support/mod.rs"]
mod full_body_support;
#[path = "../http1_service_support/mod.rs"]
mod http1_service_support;
#[path = "../reverse_support.rs"]
mod reverse_support;
#[path = "../test_client_support/mod.rs"]
mod test_client_support;

mod resilience;
mod response;
mod routing;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use collect_body_support::collect_body;
use empty_body_support::empty_body;
use full_body_support::full_body;
use http_body_util::combinators::BoxBody;
use http1_service_support::spawn_http1_service;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reverse_support::{spawn_qpxd_on_random_port, temp_dir, yaml_quote_path};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};
use test_client_support::test_client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;

type TestBody = BoxBody<Bytes, Infallible>;

#[derive(Deserialize)]
struct BatchGetRequest {
    keys: Vec<String>,
}

#[derive(Serialize)]
struct BatchGetResponse {
    values: Vec<Option<String>>,
}

async fn wait_for_counter(counter: &Arc<AtomicUsize>, expected: usize) -> Result<()> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if counter.load(Ordering::Relaxed) >= expected {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow::anyhow!(
        "counter did not reach {expected}, current={}",
        counter.load(Ordering::Relaxed)
    ))
}

fn start_text_backend(
    body: &'static str,
    extra_headers: Vec<(http::header::HeaderName, http::HeaderValue)>,
) -> Result<(SocketAddr, Arc<AtomicUsize>)> {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = StdTcpListener::bind(("127.0.0.1", 0)).context("bind backend")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let body = body.to_string();
    let make_hits = hits.clone();
    let service = service_fn(move |_req| {
        let hits = make_hits.clone();
        let body = body.clone();
        let headers = extra_headers.clone();
        async move {
            hits.fetch_add(1, Ordering::Relaxed);
            let mut response = Response::builder().status(StatusCode::OK);
            for (name, value) in &headers {
                response = response.header(name, value);
            }
            Ok::<_, Infallible>(response.body(full_body(body.clone())).unwrap())
        }
    });
    spawn_http1_service(listener, service);
    Ok((addr, hits))
}

fn start_http_cache_backend(
    state: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ops: Arc<AtomicUsize>,
) -> Result<SocketAddr> {
    let listener = StdTcpListener::bind(("127.0.0.1", 0)).context("bind cache backend")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let service = service_fn(move |req| {
        let state = state.clone();
        let ops = ops.clone();
        async move { handle_cache_backend(req, state, ops).await }
    });
    spawn_http1_service(listener, service);
    Ok(addr)
}

async fn handle_cache_backend(
    req: Request<hyper::body::Incoming>,
    state: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ops: Arc<AtomicUsize>,
) -> Result<Response<TestBody>, Infallible> {
    ops.fetch_add(1, Ordering::Relaxed);
    let key = req.uri().path().to_string();
    let response = match *req.method() {
        hyper::Method::POST if key.ends_with("/_batch_get") => {
            let body = collect_body(req.into_body()).await.expect("batch body");
            let batch: BatchGetRequest = serde_json::from_slice(body.as_ref()).expect("batch json");
            let state = state.lock().await;
            let values = batch
                .keys
                .iter()
                .map(|key| {
                    state
                        .get(format!("/v1/cache/reverse-cache/{key}").as_str())
                        .map(|value| BASE64.encode(value))
                })
                .collect();
            Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(full_body(
                    serde_json::to_vec(&BatchGetResponse { values }).unwrap(),
                ))
                .unwrap()
        }
        hyper::Method::GET => {
            let state = state.lock().await;
            match state.get(&key) {
                Some(value) => Response::builder()
                    .status(StatusCode::OK)
                    .body(full_body(value.clone()))
                    .unwrap(),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(empty_body())
                    .unwrap(),
            }
        }
        hyper::Method::PUT => {
            let body = collect_body(req.into_body()).await.expect("cache body");
            state.lock().await.insert(key, body.to_vec());
            Response::builder()
                .status(StatusCode::CREATED)
                .body(empty_body())
                .unwrap()
        }
        hyper::Method::DELETE => {
            state.lock().await.remove(&key);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(empty_body())
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(empty_body())
            .unwrap(),
    };
    Ok(response)
}

async fn start_raw_backend(response: Vec<u8>) -> Result<SocketAddr> {
    let listener = StdTcpListener::bind(("127.0.0.1", 0)).context("bind raw backend")?;
    let addr = listener.local_addr()?;
    std::thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().expect("accept raw backend");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = std::io::Read::read(&mut stream, &mut buf).expect("read raw backend");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            std::io::Write::write_all(&mut stream, &response).expect("write raw backend");
            std::io::Write::flush(&mut stream).expect("flush raw backend");
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    Ok(addr)
}

async fn serve_websocket_stub_once() -> Result<(
    SocketAddr,
    oneshot::Receiver<Vec<u8>>,
    oneshot::Receiver<Vec<u8>>,
)> {
    let listener =
        StdTcpListener::bind(("127.0.0.1", 0)).context("bind websocket stub listener")?;
    let addr = listener.local_addr()?;
    let (captured_tx, captured_rx) = oneshot::channel();
    let (upgraded_tx, upgraded_rx) = oneshot::channel();
    std::thread::spawn(move || {
        let _ = run_websocket_stub_once(listener, captured_tx, upgraded_tx);
    });
    Ok((addr, captured_rx, upgraded_rx))
}

fn run_websocket_stub_once(
    listener: StdTcpListener,
    captured_tx: oneshot::Sender<Vec<u8>>,
    upgraded_tx: oneshot::Sender<Vec<u8>>,
) -> Result<()> {
    loop {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let req = read_until_blocking(&mut stream, b"\r\n\r\n", 128 * 1024)?;
        if req.is_empty() {
            continue;
        }
        let _ = captured_tx.send(req);

        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Accept: dummy\r\n\
\r\n";
        std::io::Write::write_all(&mut stream, response)?;
        std::io::Write::flush(&mut stream)?;

        let mut buf = [0u8; 64];
        let n = std::io::Read::read(&mut stream, &mut buf)?;
        let _ = upgraded_tx.send(buf[..n].to_vec());
        std::io::Write::write_all(&mut stream, b"server-bytes")?;
        std::io::Write::flush(&mut stream)?;
        let _ = stream.shutdown(std::net::Shutdown::Both);
        return Ok(());
    }
}

fn read_until_blocking(
    stream: &mut std::net::TcpStream,
    delim: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        if out.windows(delim.len()).any(|window| window == delim) {
            break;
        }
        if out.len() > max_bytes {
            anyhow::bail!("read_until_blocking exceeded max_bytes={max_bytes}");
        }
        let n = std::io::Read::read(stream, &mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

async fn read_until(
    stream: &mut TcpStream,
    delim: &[u8],
    max_bytes: usize,
    timeout_dur: Duration,
) -> Result<Vec<u8>> {
    let started = tokio::time::Instant::now();
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        if out.windows(delim.len()).any(|window| window == delim) {
            break;
        }
        if out.len() > max_bytes {
            anyhow::bail!("read_until exceeded max_bytes={max_bytes}");
        }
        if started.elapsed() > timeout_dur {
            anyhow::bail!("read_until timed out");
        }
        let n = match timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
            Ok(read) => read?,
            Err(_) => continue,
        };
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}
