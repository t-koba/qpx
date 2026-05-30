use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_route_retries_and_mirrors() -> Result<()> {
    let dir = temp_dir("qpxd-reverse-route-e2e")?;
    let cfg = dir.join("reverse-route.yaml");
    let (live_addr, live_hits) = start_text_backend("LIVE", vec![])?;
    let dead_port = reverse_support::pick_free_tcp_port()?;
    let (mirror_addr, mirror_hits) = start_text_backend("MIRROR", vec![])?;

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
