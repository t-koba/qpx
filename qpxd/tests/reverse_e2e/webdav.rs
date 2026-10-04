use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_webdav_slow_readers_allow_concurrent_update_and_fresh_reads() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let directory = fs::canonicalize(directory.path())?;
    let root = directory.join("data");
    fs::create_dir(&root)?;
    let original = vec![b'x'; 1024 * 1024];
    fs::write(root.join("asset"), &original)?;
    let config = directory.join("reverse.yaml");
    let metadata = directory.join("metadata.redb");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&config, directory.join("qpxd.log"), |port| {
        format!(
            r#"runtime:
  worker_threads: 1
  max_blocking_threads: 8
  acceptor_tasks_per_listener: 1
  reuse_port: false
origins:
  webdav:
  - name: dav
    root: {}
    metadata: {}
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: dav
    match: {{}}
    target:
      type: webdav
      origin: dav
"#,
            yaml_quote_path(&root),
            yaml_quote_path(&metadata),
        )
    })?;
    let mut slow_readers = Vec::new();
    for _ in 0..4 {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_recv_buffer_size(4096)?;
        let mut stream = socket.connect(([127, 0, 0, 1], port).into()).await?;
        stream
            .write_all(b"GET /asset HTTP/1.1\r\nHost: dav.test\r\nConnection: close\r\n\r\n")
            .await?;
        let mut received = Vec::new();
        let end = timeout(Duration::from_secs(5), async {
            loop {
                let mut buffer = [0_u8; 2048];
                let count = stream.read(&mut buffer).await?;
                anyhow::ensure!(count > 0, "slow reader closed before response headers");
                received.extend_from_slice(&buffer[..count]);
                if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    return Ok::<_, anyhow::Error>(end + 4);
                }
            }
        })
        .await
        .context("slow reader response headers timeout")??;
        anyhow::ensure!(
            received.starts_with(b"HTTP/1.1 200"),
            "slow reader did not receive HTTP 200"
        );
        slow_readers.push((stream, received.split_off(end)));
    }
    let client = test_client();
    let uri = format!("http://127.0.0.1:{port}/asset");
    let response = timeout(
        Duration::from_secs(5),
        client.request(
            Request::builder()
                .method("PUT")
                .uri(&uri)
                .body(full_body("updated"))?,
        ),
    )
    .await
    .context("concurrent WebDAV update timeout")??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let _ = collect_body(response.into_body()).await?;
    let response = timeout(
        Duration::from_secs(5),
        client.request(Request::builder().uri(&uri).body(empty_body())?),
    )
    .await
    .context("fresh WebDAV read timeout")??;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(collect_body(response.into_body()).await?, "updated");
    let (mut stream, mut received) = slow_readers.pop().unwrap();
    socket2::SockRef::from(&stream).set_recv_buffer_size(1024 * 1024)?;
    timeout(Duration::from_secs(15), stream.read_to_end(&mut received))
        .await
        .context("original WebDAV file snapshot timeout")??;
    assert_eq!(received, original);
    drop(slow_readers);
    Ok(())
}
