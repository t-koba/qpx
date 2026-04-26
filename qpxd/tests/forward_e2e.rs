mod common;

use anyhow::{anyhow, Context, Result};
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use async_trait::async_trait;
use base64::Engine;
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
use bytes::Bytes;
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
use common::{build_h3_test_client_config, build_quinn_client_endpoint};
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
use common::{pick_free_tcp_port, spawn_qpxd};
use common::{
    read_http1_head, send_http1_and_read_head, serve_http1_capture_once, serve_tcp_echo_once,
    spawn_qpxd_on_random_port, temp_dir, yaml_quote_path,
};
#[cfg(feature = "digest-auth")]
use sha2::{Digest, Sha256};
use std::fs;
use std::net::SocketAddr;
#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
use std::path::Path;
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
use rcgen::generate_simple_self_signed;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_proxy_supports_basic_and_digest_proxy_auth() -> Result<()> {
    let dir = temp_dir("qpxd-forward-auth-e2e")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-auth.yaml");

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("forward-auth.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        format!(
            r#"listeners:
- name: forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules:
  - name: auth-required
    match:
      path:
      - /auth/*
    auth:
      require:
      - local
    action:
      type: direct
  mode: forward
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
auth:
  users:
  - username: tester
    password: secret"#,
            state_dir_yaml = state_dir_yaml
        )
    })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

    let (basic_backend_addr, basic_capture) = serve_http1_capture_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nBASIC".to_vec(),
    )
    .await?;
    let basic_uri = format!("http://{basic_backend_addr}/auth/basic");
    let unauthorized = format!(
        "GET {basic_uri} HTTP/1.1\r\nHost: {basic_backend_addr}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, _) =
        send_http1_and_read_head(proxy_addr, unauthorized.as_bytes()).await?;
    assert_eq!(status, 407);
    let basic_challenge = header_values(&headers, "proxy-authenticate")
        .into_iter()
        .find(|value| value.starts_with("Basic "))
        .ok_or_else(|| anyhow!("missing Basic challenge"))?;
    #[cfg(feature = "digest-auth")]
    let digest_challenge = header_values(&headers, "proxy-authenticate")
        .into_iter()
        .find(|value| value.starts_with("Digest "))
        .ok_or_else(|| anyhow!("missing Digest challenge"))?;
    assert!(basic_challenge.contains("realm="));
    #[cfg(feature = "digest-auth")]
    assert!(digest_challenge.contains("nonce="));

    let basic_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("tester:secret")
    );
    let authorized = format!(
        "GET {basic_uri} HTTP/1.1\r\nHost: {basic_backend_addr}\r\nProxy-Authorization: {basic_auth}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = send_http1_and_read_head(proxy_addr, authorized.as_bytes()).await?;
    assert_eq!(status, 200);
    let basic_upstream = timeout(Duration::from_secs(5), basic_capture)
        .await
        .context("timed out waiting for upstream basic request")??;
    let basic_upstream = String::from_utf8_lossy(&basic_upstream).to_ascii_lowercase();
    assert!(
        !basic_upstream.contains("\r\nproxy-authorization:"),
        "upstream request leaked proxy auth header:\n{basic_upstream}"
    );

    #[cfg(feature = "digest-auth")]
    {
        let (digest_backend_addr, digest_capture) = serve_http1_capture_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIGEST".to_vec(),
        )
        .await?;
        let digest_uri = format!("http://{digest_backend_addr}/auth/digest");
        let digest_probe = format!(
            "GET {digest_uri} HTTP/1.1\r\nHost: {digest_backend_addr}\r\nConnection: close\r\n\r\n"
        );
        let (status, headers, _) =
            send_http1_and_read_head(proxy_addr, digest_probe.as_bytes()).await?;
        assert_eq!(status, 407);
        let digest_challenge = header_values(&headers, "proxy-authenticate")
            .into_iter()
            .find(|value| value.starts_with("Digest "))
            .ok_or_else(|| anyhow!("missing Digest challenge"))?;
        let digest_auth = build_digest_proxy_authorization(
            &digest_challenge,
            "tester",
            "secret",
            "GET",
            &digest_uri,
        )?;
        let digest_request = format!(
            "GET {digest_uri} HTTP/1.1\r\nHost: {digest_backend_addr}\r\nProxy-Authorization: {digest_auth}\r\nConnection: close\r\n\r\n"
        );
        let (status, _, _) =
            send_http1_and_read_head(proxy_addr, digest_request.as_bytes()).await?;
        assert_eq!(status, 200);
        let digest_upstream = timeout(Duration::from_secs(5), digest_capture)
            .await
            .context("timed out waiting for upstream digest request")??;
        let digest_upstream = String::from_utf8_lossy(&digest_upstream).to_ascii_lowercase();
        assert!(
            !digest_upstream.contains("\r\nproxy-authorization:"),
            "upstream request leaked proxy auth header:\n{digest_upstream}"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_connect_tunnels_bytes() -> Result<()> {
    let dir = temp_dir("qpxd-forward-connect-e2e")?;
    let cfg = dir.join("forward-connect.yaml");
    let (echo_addr, captured) = serve_tcp_echo_once().await?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("forward-connect.log"), |port| {
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
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(proxy_addr)).await??;
    let authority = echo_addr.to_string();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let (status, _, _) = read_http1_head(&mut stream).await?;
    assert_eq!(status, 200);

    stream.write_all(b"ping").await?;
    stream.flush().await?;
    let mut pong = [0u8; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut pong)).await??;
    assert_eq!(&pong, b"pong");

    let echoed = timeout(Duration::from_secs(5), captured)
        .await
        .context("timed out waiting for echo capture")??;
    assert_eq!(echoed, b"ping");
    Ok(())
}

#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_h3_connect_udp_smoke() -> Result<()> {
    let dir = temp_dir("qpxd-forward-connect-udp-e2e")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-connect-udp.yaml");
    let tcp_port = pick_free_tcp_port()?;
    let udp_port = pick_free_tcp_port()?;
    let target_port = pick_free_tcp_port()?;
    let state_dir_yaml = yaml_quote_path(&state_dir);
    fs::write(
        &cfg,
        format!(
            r#"listeners:
- name: forward-h3
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
  mode: forward
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            state_dir_yaml = state_dir_yaml
        ),
    )?;
    let _qpxd = spawn_qpxd(&cfg, tcp_port, dir.join("forward-connect-udp.log"))?;

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

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_h3_qpx_extended_connect_smoke() -> Result<()> {
    let (upstream_addr, upstream_client_config, upstream_task) =
        start_qpx_h3_server(QpxH3ExtendedEchoHandler).await?;
    let dir = temp_dir("qpxd-forward-qpx-extended-connect-e2e")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-qpx-extended-connect.yaml");
    let tcp_port = pick_free_tcp_port()?;
    let udp_port = pick_free_tcp_port()?;
    let state_dir_yaml = yaml_quote_path(&state_dir);
    fs::write(
        &cfg,
        format!(
            r#"listeners:
- name: forward-h3
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
  mode: forward
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            state_dir_yaml = state_dir_yaml
        ),
    )?;
    let _qpxd = spawn_qpxd(&cfg, tcp_port, dir.join("forward-qpx-extended-connect.log"))?;

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

    stream
        .datagrams
        .as_mut()
        .ok_or_else(|| anyhow!("missing extended CONNECT datagrams"))?
        .sender
        .send_datagram(Bytes::from_static(b"dg"))?;
    let echoed_datagram = timeout(
        Duration::from_secs(5),
        stream
            .datagrams
            .as_mut()
            .expect("checked above")
            .receiver
            .recv(),
    )
    .await
    .map_err(|_| anyhow!("timed out waiting for extended CONNECT datagram echo"))?
    .ok_or_else(|| anyhow!("missing extended CONNECT datagram echo"))?;
    assert_eq!(echoed_datagram, Bytes::from_static(b"dg"));

    shutdown_qpx_extended_stream(stream).await?;
    drop(upstream_client_config);
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_h3_qpx_webtransport_rate_limit_scope_enforced() -> Result<()> {
    let (upstream_addr, upstream_client_config, upstream_task) =
        start_qpx_h3_server(QpxH3WebTransportEchoHandler).await?;
    let dir = temp_dir("qpxd-forward-qpx-webtransport-rate-limit-e2e")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-qpx-webtransport-rate-limit.yaml");
    let tcp_port = pick_free_tcp_port()?;
    let udp_port = pick_free_tcp_port()?;
    let state_dir_yaml = yaml_quote_path(&state_dir);
    fs::write(
        &cfg,
        format!(
            r#"listeners:
- name: forward-h3
  listen: 127.0.0.1:{tcp_port}
  default_action:
    type: direct
  tls_inspection:
    enabled: true
    verify_upstream: false
  rules: []
  rate_limit:
    enabled: true
    apply_to: [webtransport]
    key: global
    sessions:
      max_concurrency: 1
  http3:
    enabled: true
    listen: 127.0.0.1:{udp_port}
    connect_udp:
      enabled: true
  mode: forward
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            state_dir_yaml = state_dir_yaml
        ),
    )?;
    let _qpxd = spawn_qpxd(
        &cfg,
        tcp_port,
        dir.join("forward-qpx-webtransport-rate-limit.log"),
    )?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let ca_cert = state_dir.join("ca.crt");
    wait_for_file(&ca_cert).await?;

    let first =
        wait_for_forward_qpx_webtransport_session(udp_port, upstream_addr.port(), &ca_cert).await?;
    assert_eq!(first.response.status(), http::StatusCode::OK);

    let second =
        wait_for_forward_qpx_webtransport_session(udp_port, upstream_addr.port(), &ca_cert).await?;
    assert_eq!(
        second.response.status(),
        http::StatusCode::TOO_MANY_REQUESTS
    );

    shutdown_qpx_extended_stream(first).await?;
    shutdown_qpx_extended_stream(second).await?;
    drop(upstream_client_config);
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_h3_qpx_webtransport_individual_flow_scopes_smoke() -> Result<()> {
    let (upstream_addr, upstream_client_config, upstream_task) =
        start_qpx_h3_server(QpxH3WebTransportEchoHandler).await?;
    let dir = temp_dir("qpxd-forward-qpx-webtransport-e2e")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-qpx-webtransport.yaml");
    let tcp_port = pick_free_tcp_port()?;
    let udp_port = pick_free_tcp_port()?;
    let state_dir_yaml = yaml_quote_path(&state_dir);
    fs::write(
        &cfg,
        format!(
            r#"listeners:
- name: forward-h3
  listen: 127.0.0.1:{tcp_port}
  default_action:
    type: direct
  tls_inspection:
    enabled: true
    verify_upstream: false
  rules: []
  rate_limit:
    enabled: true
    apply_to:
    - webtransport_bidi_downstream
    - webtransport_bidi_upstream
    - webtransport_uni_downstream
    - webtransport_uni_upstream
    - webtransport_datagram_downstream
    - webtransport_datagram_upstream
    key: global
    traffic:
      quota_bytes:
        amount: 1048576
  http3:
    enabled: true
    listen: 127.0.0.1:{udp_port}
    connect_udp:
      enabled: true
  mode: forward
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            state_dir_yaml = state_dir_yaml
        ),
    )?;
    let _qpxd = spawn_qpxd(&cfg, tcp_port, dir.join("forward-qpx-webtransport.log"))?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    let ca_cert = state_dir.join("ca.crt");
    wait_for_file(&ca_cert).await?;
    let mut stream =
        wait_for_forward_qpx_webtransport_ready_session(udp_port, upstream_addr.port(), &ca_cert)
            .await?;

    stream
        .request_stream
        .send_data(Bytes::from_static(b"request-stream"))
        .await?;
    let echoed = timeout(Duration::from_secs(5), stream.request_stream.recv_data())
        .await
        .map_err(|_| anyhow!("timed out waiting for WebTransport request echo"))??
        .ok_or_else(|| anyhow!("missing WebTransport request echo"))?;
    assert_eq!(echoed, Bytes::from_static(b"request-stream"));

    stream
        .datagrams
        .as_mut()
        .ok_or_else(|| anyhow!("missing WebTransport datagrams"))?
        .sender
        .send_datagram(Bytes::from_static(b"wt-dgram"))?;
    let echoed_datagram = timeout(
        Duration::from_secs(5),
        stream
            .datagrams
            .as_mut()
            .expect("checked above")
            .receiver
            .recv(),
    )
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
    drop(upstream_client_config);
    upstream_task.abort();
    let _ = upstream_task.await;
    Ok(())
}

fn header_values(headers: &[(String, String)], name: &str) -> Vec<String> {
    let name = name.to_ascii_lowercase();
    headers
        .iter()
        .filter(|(key, _)| key == &name)
        .map(|(_, value)| value.clone())
        .collect()
}

#[cfg(feature = "digest-auth")]
fn build_digest_proxy_authorization(
    challenge: &str,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
) -> Result<String> {
    let params = parse_digest_challenge(challenge);
    let realm = params
        .get("realm")
        .ok_or_else(|| anyhow!("digest challenge missing realm"))?;
    let nonce = params
        .get("nonce")
        .ok_or_else(|| anyhow!("digest challenge missing nonce"))?;
    let opaque = params
        .get("opaque")
        .ok_or_else(|| anyhow!("digest challenge missing opaque"))?;
    let algorithm = params
        .get("algorithm")
        .map(String::as_str)
        .unwrap_or("SHA-256");
    let cnonce = "abcdef0123456789";
    let nc = "00000001";
    let qop = "auth";
    let ha1 = sha256_hex(format!("{username}:{realm}:{password}").as_bytes());
    let ha2 = sha256_hex(format!("{method}:{uri}").as_bytes());
    let response = sha256_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}").as_bytes());
    Ok(format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm={algorithm}, qop={qop}, nc={nc}, cnonce=\"{cnonce}\", opaque=\"{opaque}\""
    ))
}

#[cfg(feature = "digest-auth")]
fn parse_digest_challenge(input: &str) -> std::collections::HashMap<String, String> {
    let payload = input
        .strip_prefix("Digest ")
        .or_else(|| input.strip_prefix("Digest"))
        .unwrap_or(input)
        .trim();
    let mut out = std::collections::HashMap::new();
    for part in payload.split(',') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        out.insert(
            name.trim().to_ascii_lowercase(),
            value.trim().trim_matches('"').to_string(),
        );
    }
    out
}

#[cfg(feature = "digest-auth")]
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
async fn wait_for_file(path: &Path) -> Result<()> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if path.is_file() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(anyhow!("timed out waiting for {}", path.display()))
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[derive(Clone, Default)]
struct QpxH3ExtendedEchoHandler;

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
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
    ) -> Result<qpx_h3::Response> {
        anyhow::bail!("unexpected buffered request")
    }

    async fn handle_connect_stream(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: qpx_h3::RequestStream,
        _conn: qpx_h3::ConnectionInfo,
        protocol: qpx_h3::Protocol,
        mut datagrams: Option<qpx_h3::StreamDatagrams>,
    ) -> Result<()> {
        match protocol {
            qpx_h3::Protocol::Other(name) if name == "websocket" => {}
            other => return Err(anyhow!("unexpected protocol: {other:?}")),
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
            .send_datagram(payload)?;
        req_stream.finish().await
    }
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[derive(Clone, Default)]
struct QpxH3WebTransportEchoHandler;

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
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
    ) -> Result<qpx_h3::Response> {
        anyhow::bail!("unexpected buffered request")
    }

    async fn handle_webtransport_connect(
        &self,
        _req_head: http::Request<()>,
        mut req_stream: qpx_h3::RequestStream,
        _conn: qpx_h3::ConnectionInfo,
        session: qpx_h3::WebTransportSession,
    ) -> Result<()> {
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
            .send_datagram(payload)?;

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

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn start_qpx_h3_server<H: qpx_h3::RequestHandler>(
    handler: H,
) -> Result<(SocketAddr, quinn::ClientConfig, JoinHandle<Result<()>>)> {
    let (server_config, client_config) = build_qpx_h3_tls_configs()?;
    let endpoint = quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = endpoint.local_addr()?;
    let task = tokio::spawn(async move {
        let connecting = timeout(Duration::from_secs(5), endpoint.accept())
            .await
            .map_err(|_| anyhow!("timed out waiting for inbound QUIC connection"))?
            .ok_or_else(|| anyhow!("server endpoint closed before accept"))?;
        qpx_h3::serve_connection(connecting, addr.port(), handler).await
    });
    Ok((addr, client_config, task))
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
fn build_qpx_h3_tls_configs() -> Result<(quinn::ServerConfig, quinn::ClientConfig)> {
    let certified =
        generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let cert_der = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));

    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut tls = quinn::rustls::ServerConfig::builder_with_provider(provider.clone().into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure test server tls versions"))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;

    let quic_crypto = QuicServerConfig::try_from(tls)
        .map_err(|_| anyhow!("failed to build test QUIC server config"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow!("failed to configure test QUIC transport"))?;
    transport.max_concurrent_bidi_streams(64_u32.into());
    transport.max_concurrent_uni_streams(64_u32.into());
    server_config.migration(false);

    let mut roots = quinn::rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates([cert_der]);
    if added == 0 {
        return Err(anyhow!("failed to add self-signed root certificate"));
    }
    let mut client_tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure test client tls versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let client_quic = QuicClientConfig::try_from(client_tls)
        .map_err(|_| anyhow!("failed to build test QUIC client config"))?;
    let client_config = quinn::ClientConfig::new(Arc::new(client_quic));

    Ok((server_config, client_config))
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
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

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn read_qpx_bidi_stream(stream: qpx_h3::BidiStream) -> Result<Vec<u8>> {
    let (_, mut recv) = stream.split();
    let mut out = Vec::new();
    while let Some(chunk) = recv.recv_chunk().await? {
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn read_qpx_uni_stream(mut stream: qpx_h3::UniRecvStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = stream.recv_chunk().await? {
        out.extend_from_slice(chunk.as_ref());
    }
    Ok(out)
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
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

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn wait_for_forward_qpx_webtransport_session(
    udp_port: u16,
    upstream_port: u16,
    ca_cert: &Path,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let started = tokio::time::Instant::now();
    let mut last_error = None;
    let mut delay = Duration::from_millis(50);
    while started.elapsed() < Duration::from_secs(20) {
        match open_forward_qpx_webtransport_session(udp_port, upstream_port, ca_cert).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_error = Some(err);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(500));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("timed out waiting for WebTransport readiness")))
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn wait_for_forward_qpx_webtransport_ready_session(
    udp_port: u16,
    upstream_port: u16,
    ca_cert: &Path,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let stream =
        wait_for_forward_qpx_webtransport_session(udp_port, upstream_port, ca_cert).await?;
    if stream.response.status() != http::StatusCode::OK {
        let status = stream.response.status();
        shutdown_qpx_extended_stream(stream).await?;
        anyhow::bail!("WebTransport readiness probe returned {status}");
    }
    if stream.datagrams.is_none() || stream.opener.is_none() {
        shutdown_qpx_extended_stream(stream).await?;
        anyhow::bail!("WebTransport readiness probe missed negotiated capabilities");
    }
    Ok(stream)
}

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
async fn open_forward_qpx_webtransport_session(
    udp_port: u16,
    upstream_port: u16,
    ca_cert: &Path,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(ca_cert)?);
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], udp_port)), "localhost")?,
    )
    .await??;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://127.0.0.1:{upstream_port}/webtransport"))
        .body(())?;
    qpx_h3::open_extended_connect_stream(
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
    .await
}
