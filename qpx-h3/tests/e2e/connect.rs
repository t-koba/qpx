use super::*;
use anyhow::anyhow;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extended_connect_relays_bytes_and_datagrams() -> Result<()> {
    let (addr, client_config, server_task) = start_server(ExtendedEchoHandler).await?;
    let (client_endpoint, connection) = connect_client(addr, client_config).await?;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost/test")
        .body(())?;
    let mut stream = qpx_h3::open_extended_connect_stream(
        client_endpoint,
        connection,
        request,
        Some(Protocol::Other("websocket".to_string())),
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        },
        TEST_TIMEOUT,
    )
    .await?;
    assert_eq!(stream.response.status(), http::StatusCode::OK);

    stream
        .request_stream
        .send_data(Bytes::from_static(b"ping"))
        .await?;
    let echoed = timeout(TEST_TIMEOUT, stream.request_stream.recv_data())
        .await
        .map_err(|_| anyhow!("timed out waiting for extended CONNECT echo"))??
        .ok_or_else(|| anyhow!("missing extended CONNECT echo"))?;
    assert_eq!(echoed, Bytes::from_static(b"ping"));

    let datagrams = stream
        .datagrams
        .as_mut()
        .ok_or_else(|| anyhow!("missing extended CONNECT datagrams"))?;
    send_test_datagram(datagrams, Bytes::from_static(b"dg"))?;
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
    .map_err(|_| anyhow!("timed out waiting for extended CONNECT datagram echo"))?
    .ok_or_else(|| anyhow!("missing extended CONNECT datagram echo"))?;
    assert_eq!(echoed_datagram, Bytes::from_static(b"dg"));

    shutdown_extended_stream(stream).await?;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_udp_relays_capsules_and_datagrams() -> Result<()> {
    let (addr, client_config, server_task) = start_server(ConnectUdpEchoHandler).await?;
    let (client_endpoint, connection) = connect_client(addr, client_config).await?;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost/.well-known/masque/udp/127.0.0.1/443/")
        .header("capsule-protocol", "?1")
        .body(())?;
    let mut stream = qpx_h3::open_extended_connect_stream(
        client_endpoint,
        connection,
        request,
        Some(Protocol::ConnectUdp),
        Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            read_timeout: TEST_TIMEOUT,
            ..Default::default()
        },
        TEST_TIMEOUT,
    )
    .await?;
    assert_eq!(stream.response.status(), http::StatusCode::OK);
    assert_eq!(
        stream
            .response
            .headers()
            .get("capsule-protocol")
            .and_then(|value| value.to_str().ok()),
        Some("?1")
    );

    let capsule = encode_datagram_capsule(b"capsule-payload");
    stream.request_stream.send_data(capsule.clone()).await?;
    let echoed_capsule = timeout(TEST_TIMEOUT, stream.request_stream.recv_data())
        .await
        .map_err(|_| anyhow!("timed out waiting for CONNECT-UDP capsule echo"))??
        .ok_or_else(|| anyhow!("missing CONNECT-UDP capsule echo"))?;
    assert_eq!(
        decode_datagram_capsule(echoed_capsule.as_ref())?,
        b"capsule-payload"
    );

    let datagrams = stream
        .datagrams
        .as_mut()
        .ok_or_else(|| anyhow!("missing CONNECT-UDP datagrams"))?;
    send_test_datagram(
        datagrams,
        Bytes::from(connect_udp_payload(b"datagram-payload")),
    )?;
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
    .map_err(|_| anyhow!("timed out waiting for CONNECT-UDP datagram echo"))?
    .ok_or_else(|| anyhow!("missing CONNECT-UDP datagram echo"))?;
    assert_eq!(
        decode_connect_udp_payload(echoed_datagram.as_ref())?,
        b"datagram-payload"
    );

    shutdown_extended_stream(stream).await?;
    server_task.abort();
    let _ = server_task.await;
    Ok(())
}
