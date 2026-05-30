use super::*;
use anyhow::anyhow;

pub(crate) async fn http2_h2c_contract() -> Result<()> {
    // Reverse h2c: local_response, verify Via token "2".
    {
        let dir = temp_dir("qpxd-rfc911x-h2c-reverse")?;
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;
        let cfg = dir.join("rev-h2c.yaml");
        let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("rev-h2c.log"), |port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"edges:
- kind: reverse
  name: rev-h2c
  listen: 127.0.0.1:{port}
  routes:
  - match:
      host:
      - reverse.local
      path:
      - /h2
    target:
      type: local_response
      response:
        status: 200
        body: H2OK
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                state_dir_yaml = state_dir_yaml
            )
        })?;

        let stream = timeout(
            Duration::from_secs(3),
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await??;
        let (mut sender, conn) = handshake_http2(stream).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let uri: hyper::Uri = format!("http://reverse.local:{port}/h2").parse()?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(empty_body())?;
        let resp = sender.send_request(req).await?;
        if resp.status() != StatusCode::OK {
            return Err(anyhow!("expected reverse h2c 200, got {}", resp.status()));
        }
        let via = resp
            .headers()
            .get("via")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !via.contains("2 qpx") {
            return Err(anyhow!("expected Via: 2 qpx on h2c response, got {via:?}"));
        }
        let body = collect_body(resp.into_body()).await?;
        if body.as_ref() != b"H2OK" {
            return Err(anyhow!("unexpected reverse h2c body: {:?}", body));
        }
    }

    // Transparent h2c: incoming is HTTP/2, upstream is HTTP/1.1, verify Via token "2" and header rewrite.
    {
        let dir = temp_dir("qpxd-rfc911x-h2c-transparent")?;
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // Backend expects X-Transparent-Test: enabled.
        let backend_response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nH2TRACE".to_vec();
        let (backend_addr, captured_rx) = serve_http1_capture_once(backend_response).await?;

        let cfg = dir.join("trans-h2c.yaml");
        let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("trans-h2c.log"), |port| {
            let state_dir_yaml = yaml_quote_path(&state_dir);
            format!(
                r#"edges:
- kind: transparent
  name: transparent
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules:
  - name: trace
    match:
      host:
      - 127.0.0.1
      path:
      - /trace
    action:
      type: direct
    headers:
      request_set:
        X-Transparent-Test: enabled
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                state_dir_yaml = state_dir_yaml
            )
        })?;

        let stream = timeout(
            Duration::from_secs(3),
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await??;
        let (mut sender, conn) = handshake_http2(stream).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Connect to proxy port, but set :authority to backend so transparent resolver directs to it.
        let uri: hyper::Uri = format!("http://{backend_addr}/trace").parse()?;
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(empty_body())?;
        let resp = sender.send_request(req).await?;
        if resp.status() != StatusCode::OK {
            return Err(anyhow!(
                "expected transparent h2c 200, got {}",
                resp.status()
            ));
        }
        let via = resp
            .headers()
            .get("via")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Response is received from upstream over HTTP/1.1, so Via token is 1.1.
        if !via.contains("1.1 qpx") {
            return Err(anyhow!(
                "expected Via: 1.1 qpx on transparent h2c response, got {via:?}"
            ));
        }

        let captured_bytes = timeout(Duration::from_secs(5), captured_rx).await??;
        let captured = String::from_utf8_lossy(&captured_bytes).to_ascii_lowercase();
        assert!(
            captured.contains("\r\nx-transparent-test: enabled\r\n"),
            "backend missing injected header:\n{captured}"
        );
        assert!(
            captured.contains("\r\nvia: 2 qpx"),
            "backend missing Via: 2 qpx (incoming was not HTTP/2?):\n{captured}"
        );
    }

    Ok(())
}

pub(crate) async fn http2_tls_alpn_contract() -> Result<()> {
    let dir = temp_dir("qpxd-rfc911x-h2-tls")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)
        .with_context(|| format!("create state dir {}", state_dir.display()))?;

    let (cert_path, key_path) = write_self_signed_cert(&dir, "reverse.local")?;
    let cfg = dir.join("rev-h2-tls.yaml");
    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("rev-h2-tls.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        let cert_yaml = yaml_quote_path(&cert_path);
        let key_yaml = yaml_quote_path(&key_path);
        format!(
            r#"edges:
- kind: reverse
  name: rev-h2
  listen: 127.0.0.1:{port}
  tls:
    certificates:
    - sni: reverse.local
      cert: {cert_yaml}
      key: {key_yaml}
  routes:
  - match:
      host:
      - reverse.local
      path:
      - /h2
    target:
      type: local_response
      response:
        status: 200
        body: H2TLS
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
            state_dir_yaml = state_dir_yaml,
            cert_yaml = cert_yaml,
            key_yaml = key_yaml
        )
    })?;

    let tls_stream = connect_tls_with_alpn_h2(("127.0.0.1", port), &cert_path, "reverse.local")
        .await
        .context("tls connect failed")?;

    let (mut sender, conn) = handshake_http2(tls_stream).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri: hyper::Uri = format!("https://reverse.local:{port}/h2").parse()?;
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(empty_body())?;
    let resp = sender.send_request(req).await?;
    if resp.status() != StatusCode::OK {
        return Err(anyhow!(
            "expected reverse tls+h2 200, got {}",
            resp.status()
        ));
    }
    let via = resp
        .headers()
        .get("via")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !via.contains("2 qpx") {
        return Err(anyhow!(
            "expected Via: 2 qpx on tls+h2 response, got {via:?}"
        ));
    }
    let body = collect_body(resp.into_body()).await?;
    if body.as_ref() != b"H2TLS" {
        return Err(anyhow!("unexpected reverse tls+h2 body: {:?}", body));
    }
    Ok(())
}
