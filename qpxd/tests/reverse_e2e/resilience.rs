use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_listener_cannot_satisfy_qpxd_readiness() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let directory = fs::canonicalize(directory.path())?;
    let config = directory.join("occupied.yaml");
    let log = directory.join("occupied.log");
    let (foreign, _) = start_text_backend("FOREIGN", vec![]).await?;
    fs::write(
        &config,
        format!(
            "runtime:\n  reuse_port: false\nedges:\n- kind: reverse\n  name: occupied\n  listen: {foreign}\n  routes:\n  - name: occupied\n    match: {{}}\n    target:\n      type: upstream\n      upstreams: [http://{foreign}]\n"
        ),
    )?;
    let outcome = reverse_support::common::spawn_qpxd(&config, foreign.port(), log.clone());
    assert!(
        outcome.is_err(),
        "foreign listener satisfied child readiness"
    );
    let log = fs::read_to_string(log)?;
    assert!(
        log.contains("bind failed"),
        "child did not report its bind failure: {log}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_route_retries_and_mirrors() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-route-e2e")?;
    let cfg = dir.join("reverse-route.yaml");
    let (live_addr, live_hits) = start_text_backend("LIVE", vec![]).await?;
    // Keep the unavailable origin port owned for the entire test. Releasing a
    // picked port can let qpxd or another test bind it and turn retries into
    // recursive proxy requests instead of connection-refused failures.
    let dead_origin = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    dead_origin.bind(&std::net::SocketAddr::from(([127, 0, 0, 1], 0)).into())?;
    let dead_port = dead_origin
        .local_addr()?
        .as_socket()
        .ok_or_else(|| anyhow::anyhow!("unavailable origin socket has no IP address"))?
        .port();
    let (mirror_addr, mirror_hits) = start_text_backend("MIRROR", vec![]).await?;

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("reverse-route.log"), |port| {
        format!(
            r#"upstreams:
- name: dead
  url: http://127.0.0.1:{dead_port}
- name: live
  url: http://{live_addr}
- name: mirror
  url: http://{mirror_addr}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:{port}
  routes:
  - name: app
    streaming_requirement: preferred
    match:
      host:
      - reverse.local
      path:
      - /app/*
    resilience:
      retry:
        attempts: 2
        backoff_ms: 10
    timeout_ms: 1000
    mirrors:
    - percent: 100
      upstreams:
      - mirror
    target:
      type: upstream
      upstreams:
      - dead
      - live"#
        )
    })?;

    let client = test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/app/test").parse()?;
    let response = client
        .request(
            Request::builder()
                .method("GET")
                .uri(uri)
                .header("host", "reverse.local")
                .body(empty_body())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = collect_body(response.into_body()).await?;
    assert_eq!(&body[..], b"LIVE");
    assert_eq!(live_hits.load(Ordering::Relaxed), 1);
    wait_for_counter(&mirror_hits, 1).await?;
    Ok(())
}
