use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_h3_bulk_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-reverse-h3-bulk-perf")?;
    let cfg = dir.join("reverse-h3-bulk.yaml");
    let (cert_path, key_path) = write_self_signed_cert(&dir, PERF_TLS_SERVER_NAME)?;
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("reverse-h3-bulk.log"), |port| {
        let cert_yaml = yaml_quote_path(&cert_path);
        let key_yaml = yaml_quote_path(&key_path);
        format!(
            r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: h3-bulk
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: {server_name}
      cert: {cert_yaml}
      key: {key_yaml}
  http3:
    enabled: true
  routes:
  - name: bulk
    match:
      host:
      - {server_name}
      path:
      - /bulk
    target:
      type: local_response
      response:
        status: 200
        body: H3BULK"#,
            server_name = PERF_TLS_SERVER_NAME,
            cert_yaml = cert_yaml,
            key_yaml = key_yaml,
        )
    })?;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let started = Instant::now();
    let connections = 4usize;
    let requests_per_connection = 32usize;
    let mut tasks = Vec::with_capacity(connections);
    for _ in 0..connections {
        let cert_path = cert_path.clone();
        tasks.push(tokio::spawn(async move {
            let mut endpoint = build_quinn_client_endpoint()?;
            endpoint.set_default_client_config(build_h3_test_client_config(&cert_path)?);
            let conn = timeout(
                Duration::from_secs(5),
                endpoint.connect(
                    SocketAddr::from(([127, 0, 0, 1], port)),
                    PERF_TLS_SERVER_NAME,
                )?,
            )
            .await??;
            let mut builder = ::h3::client::builder();
            let (mut h3_conn, mut sender) = builder
                .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
                .await?;
            let driver = tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
            });
            let mut latencies = Vec::with_capacity(requests_per_connection);
            for _ in 0..requests_per_connection {
                let req_started = Instant::now();
                let uri = ::http::Uri::builder()
                    .scheme("https")
                    .authority(format!("{PERF_TLS_SERVER_NAME}:{port}"))
                    .path_and_query("/bulk")
                    .build()?;
                let request = ::http::Request::builder()
                    .method(::http::Method::GET)
                    .uri(uri)
                    .body(())?;
                let mut stream = sender.send_request(request).await?;
                stream.finish().await?;
                let response = stream.recv_response().await?;
                assert_eq!(response.status(), ::http::StatusCode::OK);
                let mut body = Vec::new();
                while let Some(chunk) = stream.recv_data().await? {
                    let mut chunk = chunk;
                    body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                }
                if body != b"H3BULK" {
                    return Err(anyhow!("unexpected h3 bulk response body"));
                }
                latencies.push(req_started.elapsed());
            }
            driver.abort();
            let _ = driver.await;
            Ok::<_, anyhow::Error>(latencies)
        }));
    }
    let mut latencies = Vec::with_capacity(connections * requests_per_connection);
    for task in tasks {
        latencies.extend(task.await.expect("join")?);
    }

    report_perf(
        "reverse_h3_bulk",
        connections * requests_per_connection,
        started.elapsed(),
        latencies,
        PerfThresholds {
            min_req_per_sec: 40.0,
            max_p95: Duration::from_millis(250),
        },
    )
}
