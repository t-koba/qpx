use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
pub(super) async fn forward_connect_tunnels_bytes() -> Result<()> {
    let dir = temp_dir("qpxd-forward-connect-e2e")?;
    let cfg = dir.join("forward-connect.yaml");
    let (echo_addr, captured) = serve_tcp_echo_once().await?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("forward-connect.log"), |port| {
        format!(
            r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules: []
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
