use super::*;
use anyhow::anyhow;

pub(crate) async fn http3_reverse_terminate_smoke() -> Result<()> {
    let dir = temp_dir("qpxd-rfc911x-h3")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;

    let (cert_path, key_path) = write_self_signed_cert(&dir, "reverse.local")?;
    let cfg = dir.join("rev-h3.yaml");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("rev-h3.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        let cert_yaml = yaml_quote_path(&cert_path);
        let key_yaml = yaml_quote_path(&key_path);
        format!(
            r#"edges:
- kind: reverse
  name: rev-h3
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: reverse.local
      cert: {cert_yaml}
      key: {key_yaml}
  http3:
    enabled: true
  routes:
  - match:
      host:
      - reverse.local
      path:
      - /h3
    target:
      type: local_response
      response:
        status: 200
        body: H3OK
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            state_dir_yaml = state_dir_yaml,
            cert_yaml = cert_yaml,
            key_yaml = key_yaml,
        )
    })?;

    let mut endpoint = build_quinn_client_endpoint()?;
    endpoint.set_default_client_config(build_h3_test_client_config(&cert_path)?);
    let conn = timeout(
        Duration::from_secs(5),
        endpoint.connect(SocketAddr::from(([127, 0, 0, 1], port)), "reverse.local")?,
    )
    .await??;

    let mut builder = ::h3::client::builder();
    let (mut h3_conn, mut sender) = builder
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
        .await?;
    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    let uri = http::Uri::builder()
        .scheme("https")
        .authority(format!("reverse.local:{port}"))
        .path_and_query("/h3")
        .build()?;
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(())?;
    let mut stream = sender.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    if response.status() != http::StatusCode::OK {
        driver.abort();
        let _ = driver.await;
        return Err(anyhow!("expected h3 200, got {}", response.status()));
    }
    let via = response
        .headers()
        .get("via")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !via.contains("3 qpx") {
        driver.abort();
        let _ = driver.await;
        return Err(anyhow!("expected Via: 3 qpx on h3 response, got {via:?}"));
    }

    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        let mut chunk = chunk;
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    if body != b"H3OK" {
        driver.abort();
        let _ = driver.await;
        return Err(anyhow!("unexpected h3 body: {:?}", body));
    }
    driver.abort();
    let _ = driver.await;
    Ok(())
}
