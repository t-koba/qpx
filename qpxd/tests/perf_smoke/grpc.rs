use super::*;
use anyhow::anyhow;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_unary_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-grpc-unary-perf")?;
    let cfg = dir.join("grpc-unary-perf.yaml");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("grpc-unary-perf.log"), |port| {
        format!(
            r#"runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
edges:
- kind: reverse
  name: grpc
  listen: 127.0.0.1:{port}
  routes:
  - name: unary
    match:
      path:
      - /perf.Service/Unary
    target:
      type: local_response
      response:
        status: 200
        body: OK
        rpc:
          protocol: grpc
          status: "0"
          message: ok"#
        )
    })?;

    let request_body = Bytes::from(frame_grpc_message(Bytes::from_static(b"ping")));
    let op: PerfOperation = Arc::new(move || {
        let request_body = request_body.clone();
        Box::pin(async move {
            let mut last_error = None;
            for _ in 0..2 {
                match grpc_unary_once(port, request_body.clone()).await {
                    Ok(()) => return Ok(()),
                    Err(err) => last_error = Some(err),
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(last_error.unwrap_or_else(|| anyhow!("grpc unary request failed")))
        })
    });
    measure_parallel_perf(
        "grpc_unary",
        128,
        8,
        PerfThresholds {
            min_req_per_sec: 50.0,
            max_p95: Duration::from_millis(250),
        },
        op,
    )
    .await
}

async fn grpc_unary_once(port: u16, request_body: Bytes) -> Result<()> {
    let stream = timeout(
        Duration::from_secs(3),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    let (mut sender, conn) = handshake_http2(stream).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let uri: hyper::Uri = format!("http://127.0.0.1:{port}/perf.Service/Unary").parse()?;
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(::http::header::CONTENT_TYPE, "application/grpc")
        .header(::http::header::TE, "trailers")
        .body(full_body(request_body.clone()))?;
    let resp = sender.send_request(req).await?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!("expected grpc unary 200, got {}", resp.status()));
    }
    let collected = resp.into_body().collect().await?;
    let trailers = collected.trailers().cloned();
    let body = collected.to_bytes();
    if body.as_ref() != frame_grpc_message(Bytes::from_static(b"OK")).as_slice() {
        return Err(anyhow!("unexpected grpc unary response body"));
    }
    let trailers = trailers.ok_or_else(|| anyhow!("missing grpc unary trailers"))?;
    let status = trailers
        .get("grpc-status")
        .and_then(|value| value.to_str().ok());
    if status != Some("0") {
        return Err(anyhow!("unexpected grpc unary status: {status:?}"));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_streaming_perf_smoke() -> Result<()> {
    if cfg!(debug_assertions) {
        eprintln!("skipping perf smoke assertions in debug build");
        return Ok(());
    }

    let dir = temp_dir("qpxd-grpc-streaming-perf")?;
    let cfg = dir.join("grpc-streaming-perf.yaml");
    let (port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg, dir.join("grpc-streaming-perf.log"), |port| {
            format!(
                r#"edges:
- kind: forward
  name: grpc-forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules:
  - name: client-streaming
    match:
      path:
      - /perf.Service/ClientStream
    action:
      type: respond
      local_response:
        status: 200
        body: STREAM
        rpc:
          protocol: grpc
          status: "0"
          message: streamed
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#
            )
        })?;

    let mut request_frames = frame_grpc_message(Bytes::from_static(b"one"));
    request_frames.extend_from_slice(&frame_grpc_message(Bytes::from_static(b"two")));
    let request_body = Bytes::from(request_frames);
    let op: PerfOperation = Arc::new(move || {
        let request_body = request_body.clone();
        Box::pin(async move {
            let stream = timeout(
                Duration::from_secs(3),
                TcpStream::connect(("127.0.0.1", port)),
            )
            .await??;
            let (mut sender, conn) = handshake_http2(stream).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let uri: hyper::Uri =
                format!("http://127.0.0.1:{port}/perf.Service/ClientStream").parse()?;
            let req = Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(::http::header::CONTENT_TYPE, "application/grpc")
                .header(::http::header::TE, "trailers")
                .body(full_body(request_body.clone()))?;
            let resp = sender.send_request(req).await?;
            if resp.status() != StatusCode::OK {
                return Err(anyhow!(
                    "expected grpc streaming 200, got {}",
                    resp.status()
                ));
            }
            let collected = resp.into_body().collect().await?;
            let trailers = collected.trailers().cloned();
            let body = collected.to_bytes();
            if body.as_ref() != frame_grpc_message(Bytes::from_static(b"STREAM")).as_slice() {
                return Err(anyhow!("unexpected grpc streaming response body"));
            }
            let trailers = trailers.ok_or_else(|| anyhow!("missing grpc streaming trailers"))?;
            let status = trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok());
            if status != Some("0") {
                return Err(anyhow!("unexpected grpc streaming status: {status:?}"));
            }
            Ok(())
        })
    });
    measure_parallel_perf(
        "grpc_streaming",
        96,
        8,
        PerfThresholds {
            min_req_per_sec: 30.0,
            max_p95: Duration::from_millis(300),
        },
        op,
    )
    .await
}
