use super::*;
use anyhow::anyhow;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_routes_associated_streams_and_datagrams() -> Result<()> {
    let (addr, client_config, server_task) = start_server(WebTransportEchoHandler).await?;
    let (client_endpoint, connection) = connect_client(addr, client_config).await?;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost/webtransport")
        .body(())?;
    let mut stream = qpx_h3::open_extended_connect_stream(
        client_endpoint,
        connection,
        request,
        Some(Protocol::WebTransport),
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 4,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        },
        TEST_TIMEOUT,
    )
    .await?;
    assert_eq!(stream.response.status(), http::StatusCode::OK);

    stream
        .request_stream
        .send_data(Bytes::from_static(b"request-stream"))
        .await?;
    let echoed = timeout(TEST_TIMEOUT, stream.request_stream.recv_data())
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
        TEST_TIMEOUT,
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

    let server_bidi = timeout(TEST_TIMEOUT, associated_bidi.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for server-initiated bidi"))?
        .ok_or_else(|| anyhow!("missing server-initiated bidi"))?;
    assert_eq!(read_bidi_stream(server_bidi).await?, b"server-bidi");

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

    let server_uni = timeout(TEST_TIMEOUT, associated_uni.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for server-initiated uni"))?
        .ok_or_else(|| anyhow!("missing server-initiated uni"))?;
    assert_eq!(read_uni_stream(server_uni).await?, b"server-uni");

    let mut client_uni = opener.open_webtransport_uni(session_id).await?;
    client_uni
        .send_chunk(Bytes::from_static(b"client-uni"))
        .await?;
    client_uni.finish().await?;
    let echoed_uni = timeout(TEST_TIMEOUT, associated_uni.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for echoed uni"))?
        .ok_or_else(|| anyhow!("missing echoed uni"))?;
    assert_eq!(read_uni_stream(echoed_uni).await?, b"client-uni");

    shutdown_extended_stream(stream).await?;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn webtransport_zero_max_sessions_is_enforced() -> Result<()> {
    let (addr, client_config, server_task) = start_server(WebTransportZeroSessionHandler).await?;
    let (client_endpoint, connection) = connect_client(addr, client_config).await?;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost/webtransport")
        .body(())?;

    let result = qpx_h3::open_extended_connect_stream(
        client_endpoint,
        connection.clone(),
        request,
        Some(Protocol::WebTransport),
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 4,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        },
        TEST_TIMEOUT,
    )
    .await;
    let err = match result {
        Ok(_) => return Err(anyhow!("client accepted zero peer WebTransport sessions")),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("zero WebTransport sessions"),
        "unexpected client rejection: {err}"
    );
    server_task.abort();
    let _ = server_task.await;

    let (addr, client_config, server_task) = start_server(WebTransportZeroSessionHandler).await?;
    let (_client_endpoint, connection) = connect_client(addr, client_config).await?;
    open_client_control_stream_with_webtransport(&connection).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    let headers = build_extended_connect_headers_with_protocol(
        &format!("localhost:{}", addr.port()),
        "webtransport",
    );
    write_frame_raw(&mut send, FRAME_HEADERS, &headers).await?;
    send.finish()?;

    let frame = timeout(TEST_TIMEOUT, recv.read_chunk(4096, true))
        .await
        .map_err(|_| anyhow!("timed out waiting for WebTransport max-session rejection"))??
        .ok_or_else(|| anyhow!("missing WebTransport max-session rejection frame"))?;
    let bytes = frame.bytes;
    let (frame_type, used_type) = read_varint(bytes.as_ref())?;
    let (frame_len, used_len) = read_varint(&bytes[used_type..])?;
    let payload_start = used_type + used_len;
    let payload_end = payload_start + frame_len as usize;
    assert_eq!(frame_type, FRAME_HEADERS);
    assert!(payload_end <= bytes.len());
    assert!(
        bytes[payload_start..payload_end]
            .windows(3)
            .any(|window| window == b"429"),
        "server should reject ignored max-session setting with 429"
    );
    assert!(
        bytes[payload_start..payload_end]
            .windows("qpx-test".len())
            .any(|window| window == b"qpx-test"),
        "server early response should use handler-provided Via received-by"
    );

    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_webtransport_connect_exposes_no_associated_stream_state() -> Result<()> {
    let (addr, client_config, server_task) = start_server(WebTransportRejectHandler).await?;
    let (client_endpoint, connection) = connect_client(addr, client_config).await?;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost/webtransport")
        .body(())?;

    let stream = qpx_h3::open_extended_connect_stream(
        client_endpoint,
        connection,
        request,
        Some(Protocol::WebTransport),
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: true,
            max_webtransport_sessions: 4,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        },
        TEST_TIMEOUT,
    )
    .await?;

    assert_eq!(stream.response.status(), http::StatusCode::FORBIDDEN);
    assert!(stream.opener.is_none());
    assert!(stream.associated_bidi.is_none());
    assert!(stream.associated_uni.is_none());
    assert!(stream.datagrams.is_none());

    shutdown_extended_stream(stream).await?;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
