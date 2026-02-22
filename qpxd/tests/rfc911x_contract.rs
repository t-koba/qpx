#![cfg(all(feature = "http3", feature = "tls-rustls"))]

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use hyper::body::to_bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode};
use rand::Rng;
use std::collections::HashMap;
use std::fs;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Instant};

/// RFC 911x / related RFCs contract tests.
///
/// Scope: provides black-box e2e/contract tests that detect regressions in
/// qpxd's implemented RFC compliance points (see docs/rfc911x-compliance.md).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rfc911x_contract() -> Result<()> {
    rfc911x_contract_inner().await
}

async fn rfc911x_contract_inner() -> Result<()> {
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
                    r#"version: 1
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:{port}"
    default_action: {{ type: direct }}
    rules: []
"#,
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

async fn http11_validation_cases(forward_port: u16) -> Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let backend_port = 9_999; // unused; requests are rejected before any upstream I/O.

    // Missing Host (RFC 9112: MUST send Host for HTTP/1.1).
    assert_status(
        addr,
        format!("GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\n\r\n"),
        400,
    )
    .await?;

    // Multiple Host header fields.
    assert_status(
        addr,
        format!(
            "GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nHost: 127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Host header with userinfo is invalid.
    assert_status(
        addr,
        format!(
            "GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: user@127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Host/authority mismatch is rejected.
    assert_status(
        addr,
        format!("GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: other.invalid\r\n\r\n"),
        400,
    )
    .await?;

    // Transfer-Encoding + Content-Length is rejected.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Conflicting multiple Content-Length values are rejected.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Unsupported Expect is rejected with 417.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nExpect: totally-not-100-continue\r\nContent-Length: 0\r\n\r\n"
        ),
        417,
    )
    .await?;

    // CONNECT must be authority-form; absolute-form CONNECT is rejected.
    assert_status(
        addr,
        format!(
            "CONNECT http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // "*" request-target is only valid for OPTIONS; reject GET *.
    assert_status(
        addr,
        "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        400,
    )
    .await?;

    // origin-form must start with "/" (unless "*").
    assert_status(
        addr,
        "GET relative HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        400,
    )
    .await?;

    Ok(())
}

async fn hop_by_hop_and_via_contract(forward_port: u16) -> Result<()> {
    let backend_response = b"HTTP/1.1 200 OK\r\n\
Connection: x-drop\r\n\
X-Drop: 1\r\n\
Keep-Alive: timeout=5\r\n\
Proxy-Authenticate: Basic realm=\"upstream\"\r\n\
Content-Length: 2\r\n\
\r\n\
OK"
    .to_vec();

    let (backend_addr, captured_rx) = serve_http1_capture_once(backend_response).await?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let req = format!(
        "GET http://{}/hop HTTP/1.1\r\n\
Host: {}\r\n\
Connection: keep-alive, x-remove\r\n\
Keep-Alive: timeout=5\r\n\
TE: trailers\r\n\
Proxy-Authorization: Basic abc\r\n\
X-Remove: 1\r\n\
Via: 1.0 old-proxy\r\n\
\r\n",
        backend_addr, backend_addr
    );
    let (status, resp_headers, _rest) =
        send_http1_and_read_head(proxy_addr, req.as_bytes()).await?;
    if status != 200 {
        return Err(anyhow!("expected 200 from proxy, got {status}"));
    }

    // Response: hop-by-hop stripped + Via/Date added.
    assert_header_absent(&resp_headers, "connection");
    assert_header_absent(&resp_headers, "keep-alive");
    assert_header_absent(&resp_headers, "proxy-authenticate");
    assert_header_absent(&resp_headers, "x-drop");
    assert_header_present_contains(&resp_headers, "via", "1.1 qpx");
    assert_header_present(&resp_headers, "date");

    // Request forwarded upstream: hop-by-hop stripped + Via appended, Proxy-Authorization stripped.
    let captured_bytes = timeout(Duration::from_secs(5), captured_rx)
        .await
        .context("timed out waiting for backend request capture")??;
    let captured = String::from_utf8_lossy(&captured_bytes).to_ascii_lowercase();
    assert!(
        !captured.contains("\r\nconnection:"),
        "upstream request contained connection header:\n{captured}"
    );
    assert!(
        !captured.contains("\r\nkeep-alive:"),
        "upstream request contained keep-alive:\n{captured}"
    );
    assert!(
        !captured.contains("\r\nte:"),
        "upstream request contained te:\n{captured}"
    );
    assert!(
        !captured.contains("\r\nproxy-authorization:"),
        "upstream request leaked proxy-authorization:\n{captured}"
    );
    assert!(
        !captured.contains("\r\nx-remove:"),
        "upstream request contained Connection-nominated header:\n{captured}"
    );
    assert!(
        captured.contains("\r\nvia:"),
        "upstream request missing via:\n{captured}"
    );
    assert!(
        captured.contains("1.1 qpx"),
        "upstream request via missing version token:\n{captured}"
    );
    assert!(
        captured.contains("1.0 old-proxy"),
        "upstream request via did not preserve existing entry:\n{captured}"
    );

    Ok(())
}

async fn connect_tunnel_contract(forward_port: u16) -> Result<()> {
    let (target_addr, echo_rx) = serve_tcp_echo_once().await?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(proxy_addr))
        .await
        .context("connect to forward proxy timed out")??;

    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n",
        target = target_addr
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let (status, headers, rest) = read_http1_head(&mut stream).await?;
    if status != 200 {
        return Err(anyhow!("expected CONNECT 200, got {status}"));
    }
    // RFC 9110: successful CONNECT responses must not have message-body framing headers.
    assert_header_absent(&headers, "content-length");
    assert_header_absent(&headers, "transfer-encoding");
    assert_header_absent(&headers, "trailer");

    // Tunnel bytes should flow end-to-end.
    const PING: &[u8] = b"ping";
    stream.write_all(PING).await?;
    stream.flush().await?;

    let got = read_at_least(&mut stream, rest, b"pong".len(), Duration::from_secs(3)).await?;
    if got.as_slice() != b"pong" {
        return Err(anyhow!("expected tunnel pong, got {:?}", got));
    }

    // Ensure the target saw the tunneled bytes.
    let echoed = timeout(Duration::from_secs(3), echo_rx)
        .await
        .context("timed out waiting for tunnel target")??;
    if echoed != PING {
        return Err(anyhow!("target received unexpected bytes: {:?}", echoed));
    }
    Ok(())
}

async fn websocket_upgrade_contract(forward_port: u16) -> Result<()> {
    let (backend_addr, captured_rx, upgraded_rx) = serve_websocket_stub_once().await?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(proxy_addr))
        .await
        .context("connect to forward proxy timed out")??;

    // Minimal WS upgrade request (RFC 6455); we intentionally do not validate Sec-WebSocket-Accept.
    let req = format!(
        "GET ws://{backend}/ws HTTP/1.1\r\n\
Host: {backend}\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Sec-WebSocket-Version: 13\r\n\
\r\n",
        backend = backend_addr
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let (status, headers, rest) = read_http1_head(&mut stream).await?;
    if status != 101 {
        return Err(anyhow!("expected 101 switching protocols, got {status}"));
    }
    assert_header_present_contains(&headers, "upgrade", "websocket");

    // Upgraded tunnel should carry arbitrary bytes.
    const MSG: &[u8] = b"client-bytes";
    stream.write_all(MSG).await?;
    stream.flush().await?;

    let got = read_at_least(
        &mut stream,
        rest,
        b"server-bytes".len(),
        Duration::from_secs(3),
    )
    .await?;
    if got.as_slice() != b"server-bytes" {
        return Err(anyhow!(
            "expected server-bytes through upgraded tunnel, got {:?}",
            got
        ));
    }

    // Backend should see an origin-form request with preserved Upgrade/Connection pair.
    let captured_bytes = timeout(Duration::from_secs(5), captured_rx)
        .await
        .context("timed out waiting for websocket backend request capture")??;
    let captured = String::from_utf8_lossy(&captured_bytes).to_ascii_lowercase();
    assert!(
        captured.starts_with("get /ws http/1.1\r\n"),
        "backend did not receive origin-form ws request:\n{captured}"
    );
    assert!(
        captured.contains("\r\nupgrade: websocket\r\n"),
        "backend request missing upgrade:\n{captured}"
    );
    assert!(
        captured.contains("\r\nconnection: upgrade\r\n"),
        "backend request missing connection: upgrade:\n{captured}"
    );

    // And backend should observe tunneled bytes.
    let upgraded = timeout(Duration::from_secs(3), upgraded_rx)
        .await
        .context("timed out waiting for websocket upgraded bytes")??;
    if upgraded != MSG {
        return Err(anyhow!(
            "websocket backend saw unexpected upgraded bytes: {:?}",
            upgraded
        ));
    }

    Ok(())
}

async fn cache_contract() -> Result<()> {
    let dir = temp_dir("qpxd-rfc911x-cache")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;

    // Origin server: returns cacheable responses for /cacheable, and Set-Cookie for /cookie.
    let origin_hits = Arc::new(AtomicUsize::new(0));
    let (origin_addr, _origin_shutdown) = start_origin_server(origin_hits.clone()).await?;

    // HTTP cache backend: simple in-memory object store.
    let (cache_addr, _cache_shutdown) = start_http_cache_backend().await?;

    let cfg_path = dir.join("qpxd-cache-forward.yaml");
    let (forward_port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg_path, dir.join("qpxd-cache-forward.log"), |port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"version: 1
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
cache:
  backends:
    - name: http-cache
      kind: http
      endpoint: "http://{cache_addr}"
      timeout_ms: 1500
      max_object_bytes: 1048576
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:{port}"
    default_action: {{ type: direct }}
    cache:
      enabled: true
      backend: http-cache
      namespace: "contract"
      default_ttl_secs: 60
      max_object_bytes: 1048576
    rules: []
"#,
                state_dir_yaml = state_dir_yaml
            )
        })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;

    // Cacheable path: first request is MISS and calls origin; second is HIT and does not.
    let origin_uri = format!("http://{origin_addr}/cacheable");
    let h1_req = format!("GET {origin_uri} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    let (_, headers1, _) = send_http1_and_read_head(proxy_addr, h1_req.as_bytes()).await?;
    assert_header_present_contains(&headers1, "x-qpx-cache", "MISS");
    if origin_hits.load(Ordering::SeqCst) != 1 {
        return Err(anyhow!("expected exactly 1 origin hit after first request"));
    }
    let (_, headers2, _) = send_http1_and_read_head(proxy_addr, h1_req.as_bytes()).await?;
    assert_header_present_contains(&headers2, "x-qpx-cache", "HIT");
    if origin_hits.load(Ordering::SeqCst) != 1 {
        return Err(anyhow!("expected cache HIT to avoid origin"));
    }

    // Set-Cookie responses are not stored by default (RFC 9111 shared-cache safety).
    let cookie_uri = format!("http://{origin_addr}/cookie");
    let cookie_req = format!("GET {cookie_uri} HTTP/1.1\r\nHost: {origin_addr}\r\n\r\n");
    let (_, headers3, _) = send_http1_and_read_head(proxy_addr, cookie_req.as_bytes()).await?;
    assert_header_present_contains(&headers3, "x-qpx-cache", "MISS");
    let (_, headers4, _) = send_http1_and_read_head(proxy_addr, cookie_req.as_bytes()).await?;
    assert_header_present_contains(&headers4, "x-qpx-cache", "MISS");
    if origin_hits.load(Ordering::SeqCst) < 3 {
        return Err(anyhow!(
            "expected Set-Cookie responses to bypass storage and hit origin twice"
        ));
    }

    Ok(())
}

async fn http2_h2c_contract() -> Result<()> {
    // Reverse h2c: local_response, verify Via token "2".
    {
        let dir = temp_dir("qpxd-rfc911x-h2c-reverse")?;
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;
        let cfg = dir.join("rev-h2c.yaml");
        let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("rev-h2c.log"), |port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"version: 1
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
  - name: rev-h2c
    listen: "127.0.0.1:{port}"
    routes:
      - match:
          host: ["reverse.local"]
          path: ["/h2"]
        upstreams: []
        local_response:
          status: 200
          body: "H2OK"
"#,
                state_dir_yaml = state_dir_yaml
            )
        })?;

        let stream = timeout(
            Duration::from_secs(3),
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await??;
        let (mut sender, conn) = hyper::client::conn::Builder::new()
            .http2_only(true)
            .handshake(stream)
            .await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let uri: hyper::Uri = format!("http://reverse.local:{port}/h2").parse()?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())?;
        let resp = sender.send_request(req).await?;
        if resp.status() != StatusCode::OK {
            return Err(anyhow!("expected reverse h2c 200, got {}", resp.status()));
        }
        let via = resp
            .headers()
            .get("via")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !via.contains("2 qpx") {
            return Err(anyhow!("expected Via: 2 qpx on h2c response, got {via:?}"));
        }
        let body = to_bytes(resp.into_body()).await?;
        if body.as_ref() != b"H2OK" {
            return Err(anyhow!("unexpected reverse h2c body: {:?}", body));
        }
    }

    // Transparent h2c: incoming is HTTP/2, upstream is HTTP/1.1, verify Via token "2" and header rewrite.
    {
        let dir = temp_dir("qpxd-rfc911x-h2c-transparent")?;
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // Backend expects X-Transparent-Test: enabled.
        let backend_response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nH2TRACE".to_vec();
        let (backend_addr, captured_rx) = serve_http1_capture_once(backend_response).await?;

        let cfg = dir.join("trans-h2c.yaml");
        let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("trans-h2c.log"), |port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"version: 1
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
listeners:
  - name: transparent
    mode: transparent
    listen: "127.0.0.1:{port}"
    default_action: {{ type: direct }}
    rules:
      - name: trace
        match:
          host: ["127.0.0.1"]
          path: ["/trace"]
        action: {{ type: direct }}
        headers:
          request_set:
            X-Transparent-Test: enabled
"#,
                state_dir_yaml = state_dir_yaml
            )
        })?;

        let stream = timeout(
            Duration::from_secs(3),
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await??;
        let (mut sender, conn) = hyper::client::conn::Builder::new()
            .http2_only(true)
            .handshake(stream)
            .await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Connect to proxy port, but set :authority to backend so transparent resolver directs to it.
        let uri: hyper::Uri = format!("http://{backend_addr}/trace").parse()?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())?;
        let resp = sender.send_request(req).await?;
        if resp.status() != StatusCode::OK {
            return Err(anyhow!(
                "expected transparent h2c 200, got {}",
                resp.status()
            ));
        }
        let via = resp
            .headers()
            .get("via")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Response is received from upstream over HTTP/1.1, so Via token is 1.1.
        if !via.contains("1.1 qpx") {
            return Err(anyhow!(
                "expected Via: 1.1 qpx on transparent h2c response, got {via:?}"
            ));
        }

        let captured_bytes = timeout(Duration::from_secs(5), captured_rx).await??;
        let captured = String::from_utf8_lossy(&captured_bytes).to_ascii_lowercase();
        assert!(
            captured.contains("\r\nx-transparent-test: enabled\r\n"),
            "backend missing injected header:\n{captured}"
        );
        assert!(
            captured.contains("\r\nvia: 2 qpx"),
            "backend missing Via: 2 qpx (incoming was not HTTP/2?):\n{captured}"
        );
    }

    Ok(())
}

async fn http2_tls_alpn_contract() -> Result<()> {
    let dir = temp_dir("qpxd-rfc911x-h2-tls")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;

    let (cert_path, key_path) = write_self_signed_cert(&dir, "reverse.local")?;
    let cfg = dir.join("rev-h2-tls.yaml");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("rev-h2-tls.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        let cert_yaml = yaml_quote_path(&cert_path);
        let key_yaml = yaml_quote_path(&key_path);
        format!(
            r#"version: 1
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
  - name: rev-h2
    listen: "127.0.0.1:{port}"
    tls:
      certificates:
        - sni: "reverse.local"
          cert: {cert_yaml}
          key: {key_yaml}
    routes:
      - match:
          host: ["reverse.local"]
          path: ["/h2"]
        upstreams: []
        local_response:
          status: 200
          body: "H2TLS"
"#,
            state_dir_yaml = state_dir_yaml,
            cert_yaml = cert_yaml,
            key_yaml = key_yaml
        )
    })?;

    let tls_stream = connect_tls_with_alpn_h2(("127.0.0.1", port), &cert_path, "reverse.local")
        .await
        .context("tls connect failed")?;

    let (mut sender, conn) = hyper::client::conn::Builder::new()
        .http2_only(true)
        .handshake(tls_stream)
        .await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri: hyper::Uri = format!("https://reverse.local:{port}/h2").parse()?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())?;
    let resp = sender.send_request(req).await?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!(
            "expected reverse tls+h2 200, got {}",
            resp.status()
        ));
    }
    let via = resp
        .headers()
        .get("via")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !via.contains("2 qpx") {
        return Err(anyhow!(
            "expected Via: 2 qpx on tls+h2 response, got {via:?}"
        ));
    }
    let body = to_bytes(resp.into_body()).await?;
    if body.as_ref() != b"H2TLS" {
        return Err(anyhow!("unexpected reverse tls+h2 body: {:?}", body));
    }
    Ok(())
}

async fn http3_reverse_terminate_smoke() -> Result<()> {
    let dir = temp_dir("qpxd-rfc911x-h3")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;

    let (cert_path, key_path) = write_self_signed_cert(&dir, "reverse.local")?;
    let cfg = dir.join("rev-h3.yaml");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("rev-h3.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        let cert_yaml = yaml_quote_path(&cert_path);
        let key_yaml = yaml_quote_path(&key_path);
        format!(
            r#"version: 1
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
reverse:
  - name: rev-h3
    listen: "127.0.0.1:{port}"
    tls:
      certificates:
        - sni: "reverse.local"
          cert: {cert_yaml}
          key: {key_yaml}
    http3:
      enabled: true
    routes:
      - match:
          host: ["reverse.local"]
          path: ["/h3"]
        upstreams: []
        local_response:
          status: 200
          body: "H3OK"
"#,
            state_dir_yaml = state_dir_yaml,
            cert_yaml = cert_yaml,
            key_yaml = key_yaml,
        )
    })?;

    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&cert_path)?);
    let conn = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], port)), "reverse.local")?,
    )
    .await??;

    let mut builder = ::h3::client::builder();
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let uri = http1::Uri::builder()
        .scheme("https")
        .authority(format!("reverse.local:{port}"))
        .path_and_query("/h3")
        .build()?;
    let request = http1::Request::builder()
        .method(http1::Method::GET)
        .uri(uri)
        .body(())?;
    let mut stream = sender.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    if response.status() != http1::StatusCode::OK {
        driver.abort();
        let _ = driver.await;
        return Err(anyhow!("expected h3 200, got {}", response.status()));
    }
    let via = response
        .headers()
        .get("via")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !via.contains("3 qpx") {
        driver.abort();
        let _ = driver.await;
        return Err(anyhow!("expected Via: 3 qpx on h3 response, got {via:?}"));
    }

    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let mut chunk = chunk;
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    if body != b"H3OK" {
        driver.abort();
        let _ = driver.await;
        return Err(anyhow!("unexpected h3 body: {:?}", body));
    }
    driver.abort();
    let _ = driver.await;
    Ok(())
}

struct QpxdHandle {
    child: Child,
}

impl Drop for QpxdHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
    while started.elapsed() < Duration::from_secs(5) {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return Ok(QpxdHandle { child });
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
    let mut rng = rand::thread_rng();
    let suffix: u64 = rng.gen();
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
        let n = timeout(Duration::from_millis(200), stream.read(&mut tmp)).await??;
        if n == 0 {
            break;
        }
        already.extend_from_slice(&tmp[..n]);
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
        let n = timeout(Duration::from_millis(200), stream.read(&mut tmp)).await??;
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
    let hits = hits.clone();
    let make = make_service_fn(move |_conn| {
        let hits = hits.clone();
        async move {
            Ok::<_, std::convert::Infallible>(service_fn(move |req: Request<Body>| {
                let hits = hits.clone();
                async move { Ok::<_, std::convert::Infallible>(handle_origin(req, hits).await) }
            }))
        }
    });
    let server = hyper::Server::bind(&([127, 0, 0, 1], 0).into()).serve(make);
    let addr = server.local_addr();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let graceful = server.with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });
    tokio::spawn(async move {
        let _ = graceful.await;
    });
    Ok((addr, shutdown_tx))
}

async fn handle_origin(req: Request<Body>, hits: Arc<AtomicUsize>) -> Response<Body> {
    hits.fetch_add(1, Ordering::SeqCst);
    match req.uri().path() {
        "/cacheable" => Response::builder()
            .status(StatusCode::OK)
            .header("cache-control", "public, max-age=60")
            .body(Body::from("CACHEABLE"))
            .unwrap(),
        "/cookie" => Response::builder()
            .status(StatusCode::OK)
            .header("cache-control", "public, max-age=60")
            .header("vary", "cookie")
            .header("set-cookie", "sid=abc; Path=/; HttpOnly")
            .body(Body::from("COOKIE"))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .unwrap(),
    }
}

async fn start_http_cache_backend() -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let make = make_service_fn(move |_conn| {
        let store = store.clone();
        async move {
            Ok::<_, std::convert::Infallible>(service_fn(move |req: Request<Body>| {
                let store = store.clone();
                async move { Ok::<_, std::convert::Infallible>(handle_cache_backend(req, store).await) }
            }))
        }
    });
    let server = hyper::Server::bind(&([127, 0, 0, 1], 0).into()).serve(make);
    let addr = server.local_addr();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let graceful = server.with_graceful_shutdown(async move {
        let _ = shutdown_rx.await;
    });
    tokio::spawn(async move {
        let _ = graceful.await;
    });
    Ok((addr, shutdown_tx))
}

async fn handle_cache_backend(
    req: Request<Body>,
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
) -> Response<Body> {
    let path = req.uri().path().to_string();
    let key = path.strip_prefix("/v1/cache/").unwrap_or("").to_string();
    match *req.method() {
        Method::GET => {
            let map = store.lock().await;
            match map.get(&key) {
                Some(v) => Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/octet-stream")
                    .body(Body::from(v.clone()))
                    .unwrap(),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap(),
            }
        }
        Method::PUT => {
            let bytes = to_bytes(req.into_body()).await.unwrap_or_default();
            let mut map = store.lock().await;
            map.insert(key, bytes.to_vec());
            Response::builder()
                .status(StatusCode::CREATED)
                .body(Body::empty())
                .unwrap()
        }
        Method::DELETE => {
            let mut map = store.lock().await;
            map.remove(&key);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::empty())
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
