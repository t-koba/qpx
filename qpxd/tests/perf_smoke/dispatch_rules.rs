use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_dispatch_rules_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-dispatch-rules-perf")?;
    let cfg = dir.join("dispatch-rules-perf.yaml");
    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("dispatch-rules-perf.log"), |port| {
            dispatch_rules_config(port)
        })?;

    let client = test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/route-199").parse()?;
    let op: PerfOperation = Arc::new(move || {
        let client = client.clone();
        let uri = uri.clone();
        Box::pin(async move {
            let response = client
                .request(
                    Request::builder()
                        .method("GET")
                        .uri(uri.clone())
                        .header("host", "dispatch.local")
                        .header("x-dispatch-route", "allow-199")
                        .body(empty_body())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await?.to_bytes();
            assert_eq!(body.as_ref(), b"RULE-199");
            Ok(())
        })
    });
    measure_parallel_perf(
        "reverse_dispatch_rules_200",
        512,
        32,
        PerfThresholds {
            min_req_per_sec: 600.0,
            max_p95: Duration::from_millis(150),
        },
        op,
    )
    .await
}

fn dispatch_rules_config(port: u16) -> String {
    let mut routes = String::new();
    for idx in 0..200 {
        routes.push_str(&format!(
            r#"  - name: route-{idx}
    match:
      host:
      - dispatch.local
      path:
      - /route-{idx}
      headers:
      - name: x-dispatch-route
        value: allow-{idx}
    target:
      type: local_response
      response:
        status: 200
        body: RULE-{idx}
    http:
      response_rules:
      - name: response-ok-{idx}
        match:
          response_status:
          - '200'
        effects:
          headers:
            response_set:
              X-Dispatch-Rule: route-{idx}
"#
        ));
    }
    format!(
        r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: dispatch-rules
  listen: 127.0.0.1:{port}
  routes:
{routes}"#
    )
}
