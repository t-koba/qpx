use super::*;

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
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: websocket
    match:
      host:
      - ws.local
      path:
      - /socket
    target:
      type: upstream
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
