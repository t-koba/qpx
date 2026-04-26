#[path = "support/collect_body.rs"]
mod collect_body_support;
#[path = "support/empty_body.rs"]
mod empty_body_support;
#[path = "support/full_body.rs"]
mod full_body_support;
#[path = "support/http1_service.rs"]
mod http1_service_support;
mod reverse_support;
#[path = "support/test_client.rs"]
mod test_client_support;

use anyhow::{Context, Result};
use bytes::Bytes;
use collect_body_support::collect_body;
use empty_body_support::empty_body;
use full_body_support::full_body;
use http1_service_support::spawn_http1_service;
use http_body_util::combinators::BoxBody;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use reverse_support::{spawn_qpxd_on_random_port, temp_dir, yaml_quote_path};
use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

type TestBody = BoxBody<Bytes, Infallible>;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_route_retries_and_mirrors() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-route-e2e")?;
    let cfg = dir.join("reverse-route.yaml");
    let (live_addr, live_hits) = start_text_backend("LIVE", vec![])?;
    let dead_port = reverse_support::pick_free_tcp_port()?;
    let (mirror_addr, mirror_hits) = start_text_backend("MIRROR", vec![])?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("reverse-route.log"), |port| {
        format!(
            r#"upstreams:
- name: dead
  url: http://127.0.0.1:{dead_port}
- name: live
  url: http://{live_addr}
- name: mirror
  url: http://{mirror_addr}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: app
    match:
      host:
      - reverse.local
      path:
      - /app/*
    resilience:
      retry:
        attempts: 2
        backoff_ms: 10
    timeout_ms: 1000
    mirrors:
    - percent: 100
      upstreams:
      - mirror
    upstreams:
    - dead
    - live"#
        )
    })?;

    let client = test_client_support::test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/app/test").parse()?;
    let response = client
        .request(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", "reverse.local")
                .body(empty_body())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = collect_body(response.into_body()).await?;
    assert_eq!(&body[..], b"LIVE");
    assert_eq!(live_hits.load(Ordering::Relaxed), 1);
    wait_for_counter(&mirror_hits, 1).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_cache_uses_http_backend_store() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-cache-e2e")?;
    let cfg = dir.join("reverse-cache.yaml");
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cache_state = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let cache_ops = Arc::new(AtomicUsize::new(0));
    let cache_addr = start_http_cache_backend(cache_state.clone(), cache_ops.clone())?;
    let origin_headers = vec![
        (
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("public, max-age=60"),
        ),
        (
            http::header::DATE,
            http::HeaderValue::from_str(&httpdate::fmt_http_date(SystemTime::now()))?,
        ),
    ];
    let (origin_addr, origin_hits) = start_text_backend("CACHE", origin_headers)?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("reverse-cache.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        format!(
            r#"upstreams:
- name: origin
  url: http://{origin_addr}
state_dir:
  {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
cache:
  backends:
  - name: http-cache
    kind: http
    endpoint: http://{cache_addr}
    timeout_ms: 1000
    max_object_bytes: 1048576
reverse:
- name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: cache
    match:
      host:
      - cache.local
      path:
      - /cache
    cache:
      enabled: true
      backend: http-cache
      namespace: reverse-cache
      default_ttl_secs: 60
      max_object_bytes: 1048576
    upstreams:
    - origin"#,
            state_dir_yaml = state_dir_yaml
        )
    })?;

    let client = test_client_support::test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/cache").parse()?;
    let first = client
        .request(
            Request::builder()
                .method("GET")
                .uri(uri.clone())
                .header("host", "cache.local")
                .body(empty_body())?,
        )
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(&collect_body(first.into_body()).await?[..], b"CACHE");
    wait_for_counter(&cache_ops, 2).await?;

    let second = client
        .request(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", "cache.local")
                .body(empty_body())?,
        )
        .await?;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(&collect_body(second.into_body()).await?[..], b"CACHE");

    assert!(
        cache_ops.load(Ordering::Relaxed) >= 3,
        "expected cache GET/PUT/GET flow"
    );
    let cache_entries = cache_state.lock().await;
    assert!(
        !cache_entries.is_empty(),
        "cache backend should contain entries"
    );
    assert!(
        origin_hits.load(Ordering::Relaxed) >= 1,
        "origin should have been contacted at least once"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_preserves_http1_early_hints() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-hints-e2e")?;
    let cfg = dir.join("reverse-hints.yaml");
    let backend_addr = start_raw_backend(
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_vec(),
    )
    .await?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("reverse-hints.log"), |port| {
        format!(
            r#"upstreams:
- name: hints
  url: http://{backend_addr}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: hints
    match:
      host:
      - hints.local
      path:
      - /hints
    upstreams:
    - hints"#
        )
    })?;

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;
    stream
        .write_all(b"GET /hints HTTP/1.1\r\nHost: hints.local\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    timeout(Duration::from_secs(3), stream.read_to_end(&mut raw)).await??;
    let raw = String::from_utf8_lossy(&raw);
    assert!(
        raw.contains("HTTP/1.1 103"),
        "missing early hints response:\n{raw}"
    );
    assert!(
        raw.contains("HTTP/1.1 200 OK"),
        "missing final response:\n{raw}"
    );
    assert!(
        raw.to_ascii_lowercase()
            .contains("link: </style.css>; rel=preload; as=style"),
        "missing Link header:\n{raw}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_websocket_upstream_tunnels_upgraded_bytes() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-websocket-e2e")?;
    let cfg = dir.join("reverse-websocket.yaml");
    let (backend_addr, captured_rx, upgraded_rx) = serve_websocket_stub_once().await?;
    let _ = tokio::net::TcpStream::connect(backend_addr).await?;

    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("reverse-websocket.log"), |port| {
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
- name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: websocket
    match:
      host:
      - ws.local
      path:
      - /socket
    upstreams:
    - ws://{backend_addr}"#
            )
        })?;

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;
    let req = b"GET /socket HTTP/1.1\r\n\
Host: ws.local\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n";
    stream.write_all(req).await?;
    stream.flush().await?;

    let head = read_until(&mut stream, b"\r\n\r\n", 128 * 1024, Duration::from_secs(3)).await?;
    let head_text = String::from_utf8_lossy(&head).to_ascii_lowercase();
    assert!(
        head_text.contains("http/1.1 101 switching protocols"),
        "missing 101 response:\n{head_text}"
    );
    assert!(
        head_text.contains("\r\nupgrade: websocket\r\n"),
        "missing upgrade header:\n{head_text}"
    );
    assert!(
        head_text.contains("\r\nconnection: upgrade\r\n"),
        "missing connection header:\n{head_text}"
    );

    stream.write_all(b"ping").await?;
    stream.flush().await?;
    let mut echoed = [0u8; 32];
    let n = timeout(Duration::from_secs(3), stream.read(&mut echoed)).await??;
    assert_eq!(&echoed[..n], b"server-bytes");

    let captured = timeout(Duration::from_secs(3), captured_rx)
        .await
        .context("timed out waiting for websocket backend request capture")??;
    let captured = String::from_utf8_lossy(&captured).to_ascii_lowercase();
    assert!(
        captured.contains("get /socket http/1.1"),
        "backend request missing path:\n{captured}"
    );
    assert!(
        captured.contains(format!("\r\nhost: {backend_addr}\r\n").as_str()),
        "backend request missing upstream host authority:\n{captured}"
    );
    assert!(
        captured.contains("\r\nupgrade: websocket\r\n"),
        "backend request missing upgrade:\n{captured}"
    );
    assert!(
        captured.contains("\r\nconnection: upgrade\r\n"),
        "backend request missing connection upgrade:\n{captured}"
    );

    let upgraded = timeout(Duration::from_secs(3), upgraded_rx)
        .await
        .context("timed out waiting for websocket upgraded bytes")??;
    assert_eq!(upgraded, b"ping");
    Ok(())
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
