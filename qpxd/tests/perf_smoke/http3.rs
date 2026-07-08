use super::*;

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_http3_terminate_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-reverse-h3-terminate-perf")?;
    let cfg = dir.join("reverse-h3-terminate.yaml");
    let (cert_path, key_path) = write_self_signed_cert(&dir, PERF_TLS_SERVER_NAME)?;

    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("reverse-h3-terminate.log"), |port| {
            let cert_yaml = yaml_quote_path(&cert_path);
            let key_yaml = yaml_quote_path(&key_path);
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: {server_name}
      cert: {cert_yaml}
      key: {key_yaml}
  http3:
    enabled: true
  routes:
  - name: perf
    match:
      host:
      - {server_name}
      path:
      - /perf
    target:
      type: local_response
      response:
        status: 200
        body: H3PERF"#,
                server_name = PERF_TLS_SERVER_NAME,
                cert_yaml = cert_yaml,
                key_yaml = key_yaml,
            )
        })?;

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
                profile_timeout(Duration::from_secs(3)),
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
            assert_h3_get_body(
                &mut sender,
                port,
                "/perf",
                b"H3PERF",
                "h3 terminate warm-up",
            )
            .await?;

            let mut latencies = Vec::with_capacity(requests_per_connection);
            for _ in 0..requests_per_connection {
                let req_started = Instant::now();
                assert_h3_get_body(&mut sender, port, "/perf", b"H3PERF", "h3 terminate").await?;
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
        "reverse_http3_terminate",
        connections * requests_per_connection,
        started.elapsed(),
        latencies,
        PerfThresholds {
            min_req_per_sec: 50.0,
            max_p95: Duration::from_millis(200),
        },
    )
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_http3_passthrough_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let backend_dir = temp_dir("qpxd-reverse-h3-perf-backend")?;
    let front_dir = temp_dir("qpxd-reverse-h3-perf-front")?;
    let backend_cfg = backend_dir.join("backend.yaml");
    let front_cfg = front_dir.join("front.yaml");
    let (cert_path, key_path) = write_self_signed_cert(&backend_dir, PERF_TLS_SERVER_NAME)?;

    let (backend_port, _backend) =
        spawn_qpxd_on_random_port(&backend_cfg, backend_dir.join("backend.log"), |port| {
            let cert_yaml = yaml_quote_path(&cert_path);
            let key_yaml = yaml_quote_path(&key_path);
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: backend
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: {server_name}
      cert: {cert_yaml}
      key: {key_yaml}
  http3:
    enabled: true
  routes:
  - name: perf
    match:
      host:
      - {server_name}
      path:
      - /perf
    target:
      type: local_response
      response:
        status: 200
        body: H3PASS"#,
                server_name = PERF_TLS_SERVER_NAME,
                cert_yaml = cert_yaml,
                key_yaml = key_yaml,
            )
        })?;

    let front_port = pick_free_tcp_port()?;
    let front_log = front_dir.join("front.log");
    let front_state_dir = front_dir.join("state");
    fs::create_dir_all(&front_state_dir)?;
    let front_state_yaml = yaml_quote_path(&front_state_dir);
    fs::write(
        &front_cfg,
        format!(
            r#"state_dir: {front_state_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: passthrough
  listen: 127.0.0.1:{front_port}
  http3:
    enabled: true
    listen: 127.0.0.1:{front_port}
    passthrough_upstreams:
    - 127.0.0.1:{backend_port}
  routes: []"#,
            front_state_yaml = front_state_yaml
        ),
    )?;
    let _front = spawn_qpxd_without_ready_check(&front_cfg, front_log.clone())?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&cert_path)?);
    let conn = timeout(
        profile_timeout(Duration::from_secs(3)),
        endpoint.connect(
            SocketAddr::from(([127, 0, 0, 1], front_port)),
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
    assert_h3_get_body(
        &mut sender,
        front_port,
        "/perf",
        b"H3PASS",
        "h3 passthrough warm-up",
    )
    .await?;

    let started = Instant::now();
    let mut latencies = Vec::with_capacity(64);
    for _ in 0..64usize {
        let req_started = Instant::now();
        assert_h3_get_body(
            &mut sender,
            front_port,
            "/perf",
            b"H3PASS",
            "h3 passthrough",
        )
        .await?;
        latencies.push(req_started.elapsed());
    }
    driver.abort();
    let _ = driver.await;

    report_perf(
        "reverse_http3_passthrough",
        64,
        started.elapsed(),
        latencies,
        PerfThresholds {
            min_req_per_sec: 25.0,
            max_p95: Duration::from_millis(300),
        },
    )
}

#[cfg(all(feature = "http3", feature = "tls-rustls"))]
async fn assert_h3_get_body<T>(
    sender: &mut ::h3::client::SendRequest<T, Bytes>,
    port: u16,
    path: &'static str,
    expected: &'static [u8],
    label: &'static str,
) -> Result<()>
where
    T: ::h3::quic::OpenStreams<Bytes>,
{
    let uri = ::http::Uri::builder()
        .scheme("https")
        .authority(format!("{PERF_TLS_SERVER_NAME}:{port}"))
        .path_and_query(path)
        .build()?;
    let request = ::http::Request::builder()
        .method(::http::Method::GET)
        .uri(uri)
        .body(())?;
    let mut stream = timeout(
        profile_timeout(Duration::from_secs(3)),
        sender.send_request(request),
    )
    .await??;
    timeout(profile_timeout(Duration::from_secs(3)), stream.finish()).await??;
    let response = timeout(
        profile_timeout(Duration::from_secs(3)),
        stream.recv_response(),
    )
    .await??;
    if response.status() != ::http::StatusCode::OK {
        return Err(anyhow!("{label} returned HTTP {}", response.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) =
        timeout(profile_timeout(Duration::from_secs(3)), stream.recv_data()).await??
    {
        let mut chunk = chunk;
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    if body != expected {
        return Err(anyhow!(
            "unexpected {label} response body: expected {:?}, got {:?}",
            String::from_utf8_lossy(expected),
            String::from_utf8_lossy(&body)
        ));
    }
    Ok(())
}
