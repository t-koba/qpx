use super::*;

pub(crate) async fn http11_validation_cases(forward_port: u16) -> Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let backend_port = 9_999; // unused; requests are rejected before any upstream I/O.

    // Missing Host (RFC 9112: MUST send Host for HTTP/1.1).
    assert_status(
        addr,
        format!("GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\n\r\n"),
        400,
    )
    .await?;

    // Multiple Host header fields.
    assert_status(
        addr,
        format!(
            "GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nHost: 127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Host header with userinfo is invalid.
    assert_status(
        addr,
        format!(
            "GET http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: user@127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Transfer-Encoding + Content-Length is rejected.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Conflicting multiple Content-Length values are rejected.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n"
        ),
        400,
    )
    .await?;

    // Unsupported Expect is rejected with 417.
    assert_status(
        addr,
        format!(
            "POST http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nExpect: totally-not-100-continue\r\nContent-Length: 0\r\n\r\n"
        ),
        417,
    )
    .await?;

    // CONNECT must be authority-form; absolute-form CONNECT is rejected.
    assert_status(
        addr,
        format!(
            "CONNECT http://127.0.0.1:{backend_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\n\r\n"
        ),
        400,
    )
    .await?;

    // "*" request-target is only valid for OPTIONS; reject GET *.
    assert_status(
        addr,
        "GET * HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        400,
    )
    .await?;

    // origin-form must start with "/" (unless "*").
    assert_status(
        addr,
        "GET relative HTTP/1.1\r\nHost: example.com\r\n\r\n".to_string(),
        400,
    )
    .await?;

    Ok(())
}

pub(crate) async fn http11_absolute_form_target_authority_wins(forward_port: u16) -> Result<()> {
    let (backend_addr, captured_rx) = serve_http1_capture_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    )
    .await?;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let request = format!(
        "GET http://{backend_addr}/absolute-form HTTP/1.1\r\nHost: other.invalid\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = send_http1_and_read_head(proxy_addr, request.as_bytes()).await?;
    if status != 200 {
        return Err(anyhow!(
            "absolute-form request should route using target authority, got status {status}"
        ));
    }

    let captured = timeout(Duration::from_secs(5), captured_rx)
        .await
        .context("timed out waiting for absolute-form request at target")??;
    let captured = String::from_utf8_lossy(&captured).to_ascii_lowercase();
    let expected_host = format!("\r\nhost: {}\r\n", backend_addr).to_ascii_lowercase();
    if !captured.contains(&expected_host) || captured.contains("\r\nhost: other.invalid\r\n") {
        return Err(anyhow!(
            "proxy did not replace ignored Host with request-target authority:\n{captured}"
        ));
    }
    Ok(())
}

pub(crate) async fn http11_absolute_form_empty_options_uses_asterisk(
    forward_port: u16,
) -> Result<()> {
    let (backend_addr, captured_rx) = serve_http1_capture_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    )
    .await?;
    let proxy_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let request = format!(
        "OPTIONS http://{backend_addr} HTTP/1.1\r\nHost: {backend_addr}\r\nConnection: close\r\n\r\n"
    );
    let (status, _, _) = send_http1_and_read_head(proxy_addr, request.as_bytes()).await?;
    if status != 200 {
        return Err(anyhow!(
            "absolute-form OPTIONS should route to target, got status {status}"
        ));
    }

    let captured = timeout(Duration::from_secs(5), captured_rx)
        .await
        .context("timed out waiting for absolute-form OPTIONS at target")??;
    let captured = String::from_utf8_lossy(&captured);
    if !captured.starts_with("OPTIONS * HTTP/1.1\r\n") {
        return Err(anyhow!(
            "proxy did not normalize empty-path absolute-form OPTIONS to asterisk-form:\n{captured}"
        ));
    }
    Ok(())
}

pub(crate) async fn http11_upstream_proxy_receives_absolute_form() -> Result<()> {
    let (proxy_addr, captured_rx) = serve_http1_capture_once(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    )
    .await?;
    let dir = temp_dir("qpxd-http1-upstream-proxy")?;
    let state_dir = dir.join("state");
    fs::create_dir_all(&state_dir).context("create state dir")?;
    let cfg_path = dir.join("qpxd-forward.yaml");
    let upstream_url = format!("http://{proxy_addr}");
    let state_dir_yaml = yaml_quote_path(&state_dir);
    let (forward_port, _qpxd) =
        spawn_qpxd_on_random_port(&cfg_path, dir.join("qpxd-forward.log"), |port| {
            format!(
                r#"upstreams:
- name: test-egress
  url: {upstream_url}
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:{port}
  default_action:
    type: proxy
    upstream: test-egress
  rules: []
state_dir: {state_dir_yaml}
runtime:
  acceptor_tasks_per_listener: 1
  reuse_port: false"#,
                upstream_url = upstream_url,
                state_dir_yaml = state_dir_yaml
            )
        })?;

    let request =
        "OPTIONS http://127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\nConnection: close\r\n\r\n";
    let proxy_listener_addr: SocketAddr = format!("127.0.0.1:{forward_port}").parse()?;
    let (status, _, _) = send_http1_and_read_head(proxy_listener_addr, request.as_bytes()).await?;
    if status != 200 {
        return Err(anyhow!(
            "expected 200 from configured upstream proxy, got {status}"
        ));
    }

    let captured = timeout(Duration::from_secs(5), captured_rx)
        .await
        .context("timed out waiting for configured upstream proxy request")??;
    let captured = String::from_utf8_lossy(&captured);
    if !captured.starts_with("OPTIONS http://127.0.0.1:9 HTTP/1.1\r\n") {
        return Err(anyhow!(
            "configured upstream proxy did not receive absolute-form with the original empty path:\n{captured}"
        ));
    }
    Ok(())
}
