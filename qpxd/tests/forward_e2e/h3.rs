use super::*;
use bytes::Buf;

#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
pub(super) async fn forward_h3_connect_udp_smoke() -> Result<()> {
    let dir = temp_dir("qpxd-forward-connect-udp-e2e")?;
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
                state_dir_yaml = state_dir_yaml
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

#[cfg(all(
    feature = "http3-backend-qpx",
    feature = "tls-rustls",
    feature = "mitm"
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
pub(super) async fn forward_h3_qpx_extended_connect_smoke() -> Result<()> {
    let (upstream_addr, upstream_client_config, upstream_task) =
        start_qpx_h3_server(QpxH3ExtendedEchoHandler).await?;
    let dir = temp_dir("qpxd-forward-qpx-extended-connect-e2e")?;
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
                state_dir_yaml = state_dir_yaml
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
        .header("sec-websocket-version", "13")
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
        .send_unprefixed_datagram_with_scratch(
            Bytes::from_static(b"dg"),
            &mut bytes::BytesMut::new(),
        )?;
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
pub(super) async fn forward_h3_qpx_webtransport_rate_limit_scope_enforced() -> Result<()> {
    let (upstream_addr, upstream_client_config, upstream_task) =
        start_qpx_h3_server(QpxH3WebTransportEchoHandler).await?;
    let dir = temp_dir("qpxd-forward-qpx-webtransport-rate-limit-e2e")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-qpx-webtransport-rate-limit.yaml");
    let (_tcp_port, udp_port, _qpxd) = spawn_qpxd_on_random_tcp_udp_ports(
        &cfg,
        dir.join("forward-qpx-webtransport-rate-limit.log"),
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
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                state_dir_yaml = state_dir_yaml
            )
        },
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
pub(super) async fn forward_h3_qpx_webtransport_individual_flow_scopes_smoke() -> Result<()> {
    let (upstream_addr, upstream_client_config, upstream_task) =
        start_qpx_h3_server(QpxH3WebTransportEchoHandler).await?;
    let dir = temp_dir("qpxd-forward-qpx-webtransport-e2e")?;
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
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                state_dir_yaml = state_dir_yaml
            )
        },
    )?;

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
        .send_unprefixed_datagram_with_scratch(
            Bytes::from_static(b"wt-dgram"),
            &mut bytes::BytesMut::new(),
        )?;
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

#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
pub(super) async fn forward_h3_asterisk_options_direct_origin_preserves_asterisk_form() -> Result<()>
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = listener.local_addr()?;
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request =
            common::read_until(&mut stream, b"\r\n\r\n", 128 * 1024, Duration::from_secs(5))
                .await?;
        let _ = captured_tx.send(request);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        Ok::<_, anyhow::Error>(())
    });

    let dir = temp_dir("qpxd-forward-h3-asterisk-direct")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-h3-asterisk-direct.yaml");
    let (_tcp_port, udp_port, qpxd) = spawn_qpxd_on_random_tcp_udp_ports(
        &cfg,
        dir.join("forward-h3-asterisk-direct.log"),
        |tcp_port, udp_port| {
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
state_dir: {state_dir}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                state_dir = yaml_quote_path(&state_dir)
            )
        },
    )?;
    let ca_cert = state_dir.join("ca.crt");
    wait_for_file(&ca_cert).await?;

    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&ca_cert)?);
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], udp_port)), "localhost")?,
    )
    .await??;
    let mut builder = ::h3::client::builder();
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let target_authority = origin_addr.to_string();
    let uri = http::Uri::builder()
        .scheme("http")
        .authority(target_authority.as_str())
        .path_and_query("*")
        .build()?;
    let request = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri(uri)
        .header(http::header::HOST, target_authority.as_str())
        .body(())?;
    let mut stream = sender.send_request(request).await?;
    stream.finish().await?;
    let response = timeout(Duration::from_secs(5), stream.recv_response()).await??;
    let status = response.status();
    while let Some(mut chunk) = timeout(Duration::from_secs(5), stream.recv_data()).await?? {
        let len = chunk.remaining();
        let _ = chunk.copy_to_bytes(len);
    }
    assert_eq!(
        status,
        http::StatusCode::OK,
        "qpxd log: {}",
        qpxd.log_tail()
    );
    driver.abort();
    let _ = driver.await;

    let captured = timeout(Duration::from_secs(5), captured_rx)
        .await
        .context("timed out waiting for direct origin request")??;
    let captured = String::from_utf8_lossy(&captured);
    let request_line = captured.split_once("\r\n").map(|(line, _)| line);
    assert_eq!(
        request_line,
        Some("OPTIONS * HTTP/1.1"),
        "direct origin did not receive the asterisk-form request line:\n{captured}"
    );
    origin_task.await??;
    Ok(())
}

#[cfg(all(feature = "http3", feature = "tls-rustls", feature = "mitm"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
pub(super) async fn forward_h3_asterisk_options_reconstructs_upstream_proxy_target() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = listener.local_addr()?;
    let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
    let proxy_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request =
            common::read_until(&mut stream, b"\r\n\r\n", 128 * 1024, Duration::from_secs(5))
                .await?;
        let _ = captured_tx.send(request);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        Ok::<_, anyhow::Error>(())
    });

    let dir = temp_dir("qpxd-forward-h3-asterisk-proxy")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-h3-asterisk-proxy.yaml");
    let (_tcp_port, udp_port, qpxd) = spawn_qpxd_on_random_tcp_udp_ports(
        &cfg,
        dir.join("forward-h3-asterisk-proxy.log"),
        |tcp_port, udp_port| {
            format!(
                r#"upstreams:
- name: test-egress
  url: http://{proxy_addr}
edges:
- kind: forward
  name: forward-h3
  listen: 127.0.0.1:{tcp_port}
  default_action:
    type: proxy
    upstream: test-egress
  tls_inspection:
    enabled: true
    verify_upstream: false
  rules: []
  http3:
    enabled: true
    listen: 127.0.0.1:{udp_port}
state_dir: {state_dir}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                state_dir = yaml_quote_path(&state_dir)
            )
        },
    )?;
    let ca_cert = state_dir.join("ca.crt");
    wait_for_file(&ca_cert).await?;

    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&ca_cert)?);
    let connection = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], udp_port)), "localhost")?,
    )
    .await??;
    let mut builder = ::h3::client::builder();
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let target_authority = "origin.example.test:443";
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(target_authority)
        .path_and_query("*")
        .build()?;
    let request = http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri(uri)
        .header(http::header::HOST, target_authority)
        .body(())?;
    let mut stream = sender.send_request(request).await?;
    stream.finish().await?;
    let response = timeout(Duration::from_secs(5), stream.recv_response()).await??;
    let status = response.status();
    let mut response_body = Vec::new();
    while let Some(mut chunk) = timeout(Duration::from_secs(5), stream.recv_data()).await?? {
        let len = chunk.remaining();
        response_body.extend_from_slice(&chunk.copy_to_bytes(len));
    }
    assert_eq!(
        status,
        http::StatusCode::OK,
        "response body: {}; qpxd log: {}",
        String::from_utf8_lossy(&response_body),
        qpxd.log_tail()
    );
    driver.abort();
    let _ = driver.await;

    let captured = timeout(Duration::from_secs(5), captured_rx)
        .await
        .context("timed out waiting for upstream proxy request")??;
    let captured = String::from_utf8_lossy(&captured);
    assert!(
        captured.starts_with("OPTIONS https://origin.example.test:443 HTTP/1.1\r\n"),
        "upstream proxy did not receive an empty-path absolute-form target:\n{captured}"
    );
    proxy_task.await??;
    Ok(())
}
