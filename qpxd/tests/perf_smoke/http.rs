use super::*;
use anyhow::anyhow;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_local_response_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-perf-smoke")?;
    let cfg = dir.join("perf-smoke.yaml");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("perf-smoke.log"), |port| {
        format!(
            r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: perf
  listen: 127.0.0.1:{port}
  routes:
  - name: perf
    match:
      host:
      - perf.local
      path:
      - /perf
    target:
      type: local_response
      response:
        status: 200
        body: PERF"#
        )
    })?;

    let client = test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/perf").parse()?;

    for _ in 0..64 {
        let response = client
            .request(
                Request::builder()
                    .method("GET")
                    .uri(uri.clone())
                    .header("host", "perf.local")
                    .body(empty_body())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let _ = response.into_body().collect().await?;
    }

    let op: PerfOperation = Arc::new(move || {
        let client = client.clone();
        let uri = uri.clone();
        Box::pin(async move {
            let response = client
                .request(
                    Request::builder()
                        .method("GET")
                        .uri(uri.clone())
                        .header("host", "perf.local")
                        .body(empty_body())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let _ = response.into_body().collect().await?;
            Ok(())
        })
    });
    measure_parallel_perf(
        "reverse_local_response",
        512,
        32,
        PerfThresholds {
            min_req_per_sec: 1000.0,
            max_p95: Duration::from_millis(100),
        },
        op,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forward_connect_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-forward-connect-perf")?;
    let cfg = dir.join("forward-connect-perf.yaml");
    let echo_addr = serve_tcp_echo_loop().await?;
    let authority = echo_addr.to_string();
    let client_hello = Arc::new(build_test_client_hello());

    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("forward-connect-perf.log"), |port| {
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
    let op: PerfOperation = Arc::new(move || {
        let authority = authority.clone();
        let client_hello = client_hello.clone();
        Box::pin(async move {
            let mut stream =
                timeout(Duration::from_secs(3), TcpStream::connect(proxy_addr)).await??;
            let request = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(request.as_bytes()).await?;
            stream.flush().await?;
            let status = read_http1_status(&mut stream).await?;
            if status != 200 {
                return Err(anyhow!("expected CONNECT 200, got {status}"));
            }
            stream.write_all(client_hello.as_slice()).await?;
            stream.flush().await?;
            let mut echoed = vec![0u8; client_hello.len()];
            timeout(Duration::from_secs(3), stream.read_exact(&mut echoed)).await??;
            if echoed != client_hello.as_slice() {
                return Err(anyhow!("unexpected CONNECT echo payload"));
            }
            Ok(())
        })
    });
    measure_parallel_perf(
        "forward_connect",
        128,
        16,
        PerfThresholds {
            min_req_per_sec: 100.0,
            max_p95: Duration::from_millis(200),
        },
        op,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_upstream_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let backend_dir = temp_dir("qpxd-reverse-upstream-backend")?;
    let front_dir = temp_dir("qpxd-reverse-upstream-front")?;
    let backend_cfg = backend_dir.join("backend.yaml");
    let front_cfg = front_dir.join("front.yaml");

    let (backend_port, _backend) =
        spawn_qpxd_on_random_port(&backend_cfg, backend_dir.join("backend.log"), |port| {
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: backend
  listen: 127.0.0.1:{port}
  routes:
  - name: perf
    match:
      path:
      - /perf
    target:
      type: local_response
      response:
        status: 200
        body: PERF"#
            )
        })?;

    let (front_port, _front) =
        spawn_qpxd_on_random_port(&front_cfg, front_dir.join("front.log"), |port| {
            format!(
                r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: front
  listen: 127.0.0.1:{port}
  routes:
  - name: perf
    match:
      host:
      - perf.local
      path:
      - /perf
    target:
      type: upstream
      upstreams:
      - http://127.0.0.1:{backend_port}"#
            )
        })?;

    let client = test_client();
    let uri: hyper::Uri = format!("http://127.0.0.1:{front_port}/perf").parse()?;
    let op: PerfOperation = Arc::new(move || {
        let client = client.clone();
        let uri = uri.clone();
        Box::pin(async move {
            let response = client
                .request(
                    Request::builder()
                        .method("GET")
                        .uri(uri.clone())
                        .header("host", "perf.local")
                        .body(empty_body())?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let _ = response.into_body().collect().await?;
            Ok(())
        })
    });
    measure_parallel_perf(
        "reverse_upstream_http1",
        512,
        32,
        PerfThresholds {
            min_req_per_sec: 400.0,
            max_p95: Duration::from_millis(150),
        },
        op,
    )
    .await
}
