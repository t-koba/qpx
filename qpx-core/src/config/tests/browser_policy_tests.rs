use super::*;

#[test]
fn load_config_accepts_complete_browser_origin_policy() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("browser-policy.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: browser
  listen: 127.0.0.1:19480
  routes:
  - match:
      path: [/**]
    http:
      fetch_metadata:
        allowed_sites: [same-origin, same-site]
        allowed_modes: [navigate, cors]
        allowed_destinations: [document, empty]
        allow_missing: false
      browser_security:
        content_security_policy: "default-src 'self'"
        referrer_policy: strict-origin-when-cross-origin
        permissions_policy: "camera=(), geolocation=(self)"
        cross_origin_opener_policy: same-origin
        cross_origin_embedder_policy: require-corp
        cross_origin_resource_policy: same-origin
        x_content_type_options: nosniff
        origin_agent_cluster: "?1"
        reporting_endpoints: 'default="/reports"'
        timing_allow_origin: https://app.example
        accept_ch: Sec-CH-UA
        critical_ch: Sec-CH-UA
      cookies:
        require_secure: true
        require_http_only: true
        same_site: lax
        require_partitioned: false
      reporting_collector:
        max_body_bytes: 65536
        max_reports: 32
    target:
      type: local_response
      response:
        status: 204"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load browser policy");
    fs::remove_dir_all(&dir).ok();
    let http = loaded.reverse_edge_configs()[0].routes[0]
        .http
        .as_ref()
        .expect("HTTP policy");
    assert!(http.fetch_metadata.is_some());
    assert!(http.browser_security.is_some());
    assert!(http.cookies.is_some());
    assert_eq!(
        http.reporting_collector
            .as_ref()
            .expect("report collector")
            .max_reports,
        32
    );
}

#[test]
fn load_config_rejects_inconsistent_client_hints() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-client-hints.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: browser
  listen: 127.0.0.1:19480
  routes:
  - match: {path: [/**]}
    http:
      browser_security:
        accept_ch: Sec-CH-UA
        critical_ch: Sec-CH-UA-Platform
    target:
      type: local_response
      response: {status: 204}"#,
    )
    .expect("write");

    let error = load_config(&cfg).expect_err("inconsistent client hints must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(error.to_string().contains("critical client hint"));
}

#[test]
fn load_config_rejects_client_certificate_forwarding_without_mtls() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-client-certificate.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: browser
  listen: 127.0.0.1:19480
  routes:
  - match: {path: [/**]}
    http:
      client_certificate:
        include_chain: true
    target:
      type: local_response
      response: {status: 204}"#,
    )
    .expect("write");

    let error = load_config(&cfg).expect_err("client certificate forwarding needs mTLS");
    fs::remove_dir_all(&dir).ok();
    assert!(error.to_string().contains("requires tls.client_ca"));
}

#[test]
fn load_config_rejects_browser_origin_policy_on_forward_edge() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("forward-browser-policy.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: egress
  listen: 127.0.0.1:18080
  http:
    fetch_metadata:
      allowed_sites: [same-origin]
  default_action:
    type: block"#,
    )
    .expect("write");

    let error = load_config(&cfg).expect_err("forward browser policy must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(error.to_string().contains("only valid on reverse routes"));
}
