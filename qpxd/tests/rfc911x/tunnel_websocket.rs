use super::*;
use anyhow::anyhow;

pub(crate) async fn connect_tunnel_contract(forward_port: u16) -> Result<()> {
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

pub(crate) async fn websocket_upgrade_contract(forward_port: u16) -> Result<()> {
    let (backend_addr, captured_rx, upgraded_rx) = serve_websocket_stub_once().await?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(proxy_addr))
        .await
        .context("connect to forward proxy timed out")??;

    // Minimal WS transparent relay request. The proxy preserves the RFC 6455 upgrade tunnel but
    // does not terminate the handshake or validate Sec-WebSocket-Accept.
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
