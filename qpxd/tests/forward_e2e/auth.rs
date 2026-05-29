use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg(feature = "auth-basic")]
pub(super) async fn forward_proxy_supports_basic_and_digest_proxy_auth() -> Result<()> {
    let dir = temp_dir("qpxd-forward-auth-e2e")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir)?;
    let cfg = dir.join("forward-auth.yaml");

    let (port, _qpxd) = spawn_qpxd_on_random_port(&cfg, dir.join("forward-auth.log"), |port| {
        let state_dir_yaml = yaml_quote_path(&state_dir);
        format!(
            r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:{port}
  default_action:
    type: direct
  rules:
  - name: auth-required
    match:
      path:
      - /auth/*
    auth:
      require:
      - local
    action:
      type: direct
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false
security:
  auth:
    users:
    - username: tester
      password: secret"#,
            state_dir_yaml = state_dir_yaml
        )
    })?;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

    let (basic_backend_addr, basic_capture) = serve_http1_capture_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nBASIC".to_vec(),
    )
    .await?;
    let basic_uri = format!("http://{basic_backend_addr}/auth/basic");
    let unauthorized = format!(
        "GET {basic_uri} HTTP/1.1\r\nHost: {basic_backend_addr}\r\nConnection: close\r\n\r\n"
    );
    let (status, headers, _) =
        send_http1_and_read_head(proxy_addr, unauthorized.as_bytes()).await?;
    assert_eq!(status, 407);
    let basic_challenge = header_values(&headers, "proxy-authenticate")
        .into_iter()
        .find(|value| value.starts_with("Basic "))
        .ok_or_else(|| anyhow!("missing Basic challenge"))?;
    #[cfg(feature = "auth-digest")]
    let digest_challenge = header_values(&headers, "proxy-authenticate")
        .into_iter()
        .find(|value| value.starts_with("Digest "))
        .ok_or_else(|| anyhow!("missing Digest challenge"))?;
    assert!(basic_challenge.contains("realm="));
    #[cfg(feature = "auth-digest")]
    assert!(digest_challenge.contains("nonce="));

    let basic_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("tester:secret")
    );
    let authorized = format!(
        "GET {basic_uri} HTTP/1.1\r\nHost: {basic_backend_addr}\r\nProxy-Authorization: {basic_auth}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = send_http1_and_read_head(proxy_addr, authorized.as_bytes()).await?;
    assert_eq!(status, 200);
    let basic_upstream = timeout(Duration::from_secs(5), basic_capture)
        .await
        .context("timed out waiting for upstream basic request")??;
    let basic_upstream = String::from_utf8_lossy(&basic_upstream).to_ascii_lowercase();
    assert!(
        !basic_upstream.contains("\r\nproxy-authorization:"),
        "upstream request leaked proxy auth header:\n{basic_upstream}"
    );

    #[cfg(feature = "auth-digest")]
    {
        let (digest_backend_addr, digest_capture) = serve_http1_capture_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIGEST".to_vec(),
        )
        .await?;
        let digest_uri = format!("http://{digest_backend_addr}/auth/digest");
        let digest_probe = format!(
            "GET {digest_uri} HTTP/1.1\r\nHost: {digest_backend_addr}\r\nConnection: close\r\n\r\n"
        );
        let (status, headers, _) =
            send_http1_and_read_head(proxy_addr, digest_probe.as_bytes()).await?;
        assert_eq!(status, 407);
        let digest_challenge = header_values(&headers, "proxy-authenticate")
            .into_iter()
            .find(|value| value.starts_with("Digest "))
            .ok_or_else(|| anyhow!("missing Digest challenge"))?;
        let digest_auth = build_digest_proxy_authorization(
            &digest_challenge,
            "tester",
            "secret",
            "GET",
            &digest_uri,
        )?;
        let digest_request = format!(
            "GET {digest_uri} HTTP/1.1\r\nHost: {digest_backend_addr}\r\nProxy-Authorization: {digest_auth}\r\nConnection: close\r\n\r\n"
        );
        let (status, _, _) =
            send_http1_and_read_head(proxy_addr, digest_request.as_bytes()).await?;
        assert_eq!(status, 200);
        let digest_upstream = timeout(Duration::from_secs(5), digest_capture)
            .await
            .context("timed out waiting for upstream digest request")??;
        let digest_upstream = String::from_utf8_lossy(&digest_upstream).to_ascii_lowercase();
        assert!(
            !digest_upstream.contains("\r\nproxy-authorization:"),
            "upstream request leaked proxy auth header:\n{digest_upstream}"
        );
    }

    Ok(())
}
