use super::*;

#[test]
fn load_config_rejects_invalid_metrics_prefix() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-prefix.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
identity:
  metrics_prefix: 1bad"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("identity.metrics_prefix must start with [A-Za-z_:]"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_empty_message() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-message.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
messages:
  proxy_error: ''"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("messages.proxy_error must not be empty"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_enabled_otel_without_endpoint() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-otel.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
telemetry:
  otel:
    enabled: true"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("otel.endpoint must be set when otel.enabled=true"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_allows_empty_exporter_shm_path() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-exporter-shm-path.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
telemetry:
  exporter:
    enabled: true
    shm_path: ''"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();
    assert!(loaded.telemetry.exporter.is_some());
}

#[test]
fn load_config_allows_disabled_exporter_with_empty_shm_path() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("disabled-exporter.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
telemetry:
  exporter:
    enabled: false
    shm_path: ''"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();
    assert!(loaded.telemetry.exporter.is_some());
}

#[cfg(feature = "tls-rustls")]
#[test]
fn load_config_rejects_acme_invalid_challenge() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-acme-challenge.yaml");
    write_config(
        &cfg,
        r#"state_dir: /tmp/qpx-acme-test
acme:
  enabled: true
  challenge: bogus
  terms_of_service_agreed: true
  http01_listen: 127.0.0.1:18080
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18081
  default_action:
    type: direct"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("acme.challenge must be one of"),
        "unexpected error: {err}"
    );
}

#[cfg(feature = "tls-rustls")]
#[test]
fn load_config_rejects_dns01_without_hook() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("dns-no-hook.yaml");
    write_config(
        &cfg,
        r#"state_dir: /tmp/qpx-acme-test
acme:
  enabled: true
  challenge: dns-01
  terms_of_service_agreed: true
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:18443
  tls:
    certificates:
    - sni: "*.example.com"
  routes:
  - match:
      host:
      - api.example.com
    target:
      type: upstream
      upstreams:
      - http://127.0.0.1:18080"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("acme.dns_hook must be set when acme.challenge=dns-01"),
        "unexpected error: {err}"
    );
}

#[cfg(feature = "tls-rustls")]
#[test]
fn load_config_allows_dns01_wildcard_with_hooks() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("dns-wildcard.yaml");
    write_config(
        &cfg,
        r#"state_dir: /tmp/qpx-acme-test
acme:
  enabled: true
  challenge: dns-01
  terms_of_service_agreed: true
  dns_hook:
    set_command: "true"
    clear_command: "true"
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:18443
  tls:
    certificates:
    - sni: "*.example.com"
  routes:
  - match:
      host:
      - api.example.com
    target:
      type: upstream
      upstreams:
      - http://127.0.0.1:18080"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();
    assert_eq!(loaded.acme.as_ref().unwrap().challenge, "dns-01");
}

#[cfg(feature = "tls-rustls")]
#[test]
fn load_config_rejects_tls_alpn01_without_acme_managed_tls() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("tls-alpn-no-tls.yaml");
    write_config(
        &cfg,
        r#"state_dir: /tmp/qpx-acme-test
acme:
  enabled: true
  challenge: tls-alpn-01
  terms_of_service_agreed: true
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18081
  default_action:
    type: direct"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains(
            "acme.challenge=tls-alpn-01 requires at least one ACME-managed reverse TLS certificate"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_allows_access_and_audit_logs() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("logs.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
telemetry:
  system_log:
    level: info
    format: json
  access_log:
    enabled: true
    path: /tmp/qpx-access.log
    format: json
    rotation: daily
    rotation_count: 30
    exclude:
    - /health
    - /metrics
  audit_log:
    enabled: true
    path: /tmp/qpx-audit.log
    format: json
    rotation: daily
    rotation_count: 365"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert!(loaded.telemetry.access_log.output.enabled);
    assert!(loaded.telemetry.audit_log.output.enabled);
    assert_eq!(
        loaded.telemetry.access_log.exclude,
        vec!["/health", "/metrics"]
    );
}
