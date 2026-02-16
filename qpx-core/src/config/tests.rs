use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, path::PathBuf};

fn unique_tmp_dir() -> PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    dir.push(format!("qpx-config-test-{}", nanos));
    dir
}

#[test]
fn load_config_supports_include_and_env() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");

    let include = dir.join("include.yaml");
    let base = dir.join("base.yaml");

    fs::write(
        &include,
        r#"
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
"#,
    )
    .expect("write include");

    fs::write(
        &base,
        r#"
version: 1
state_dir: "${QPX_TEST_STATE_DIR}"
include:
  - include.yaml
"#,
    )
    .expect("write base");

    std::env::set_var("QPX_TEST_STATE_DIR", "/tmp/qpx-state");
    let loaded = load_config(&base).expect("load config");
    std::env::remove_var("QPX_TEST_STATE_DIR");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.version, 1);
    assert_eq!(loaded.state_dir.as_deref(), Some("/tmp/qpx-state"));
    assert_eq!(loaded.listeners.len(), 1);
    assert_eq!(loaded.listeners[0].name, "forward");
}

#[test]
fn load_config_rejects_invalid_metrics_prefix() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-prefix.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
identity:
  metrics_prefix: "1bad"
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
"#,
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
    fs::write(
        &cfg,
        r#"
version: 1
messages:
  proxy_error: ""
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
"#,
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
fn load_config_rejects_plain_ldap_without_starttls() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-ldap-starttls.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
auth:
  ldap:
    url: "ldap://ad.example.com:389"
    bind_dn: "cn=proxy,dc=example,dc=com"
    bind_password_env: "LDAP_BIND_PASSWORD"
    user_base_dn: "ou=users,dc=example,dc=com"
    group_base_dn: "ou=groups,dc=example,dc=com"
    require_starttls: false
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
"#,
    )
    .expect("write");
    std::env::set_var("LDAP_BIND_PASSWORD", "dummy");
    let err = load_config(&cfg).expect_err("must fail");
    std::env::remove_var("LDAP_BIND_PASSWORD");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("auth.ldap.require_starttls must be true when auth.ldap.url uses ldap://"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_duplicate_upstream_names() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("duplicate-upstreams.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
upstreams:
  - name: egress
    url: http://proxy-a.local:3128
  - name: egress
    url: http://proxy-b.local:3128
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("duplicate upstream name"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_unknown_listener_upstream_reference() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("unknown-upstream-ref.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
upstreams:
  - name: corp-egress
    url: http://proxy-a.local:3128
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    upstream_proxy: typo-egress
    default_action: { type: proxy }
"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("references unknown upstream"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_unknown_keys() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("unknown-keys.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
    unknown_listener_key: true
    rules:
      - name: typo-match
        match:
          hosts: ["example.com"]
        action: { type: direct }
"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("unknown config keys"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("listeners.0.unknown_listener_key"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("listeners.0.rules.0.match") && err.to_string().contains(".hosts"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_invalid_exporter_endpoint() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-exporter-endpoint.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
exporter:
  enabled: true
  endpoint: "not-an-endpoint"
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("exporter.endpoint is invalid"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_non_loopback_exporter_without_tls_by_default() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("non-loopback-exporter-insecure.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
exporter:
  enabled: true
  endpoint: "10.0.0.1:19100"
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("exporter.endpoint is not loopback"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_allows_disabled_exporter_without_tls() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("disabled-exporter.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
exporter:
  enabled: false
  endpoint: "10.0.0.1:19100"
listeners:
  - name: forward
    mode: forward
    listen: "127.0.0.1:18080"
    default_action: { type: direct }
"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();
    assert!(loaded.exporter.is_some());
}

#[test]
fn load_config_allows_reverse_path_rewrite() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("reverse-path-rewrite.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
reverse:
  - name: reverse
    listen: "127.0.0.1:19080"
    routes:
      - match:
          host: ["api.example.com"]
          path: ["/api/v1/*"]
        upstreams: ["http://127.0.0.1:8080"]
        path_rewrite:
          strip_prefix: "/api/v1"
          add_prefix: "/v2"
"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.reverse.len(), 1);
    let route = &loaded.reverse[0].routes[0];
    assert_eq!(
        route.path_rewrite,
        Some(PathRewriteConfig {
            strip_prefix: Some("/api/v1".into()),
            add_prefix: Some("/v2".into()),
            regex: None,
        })
    );
}

#[test]
fn load_config_allows_reverse_backends_mirrors_headers_and_regex_rewrite() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("reverse-advanced.yaml");
    fs::write(
        &cfg,
        r#"
version: 1
reverse:
  - name: reverse
    listen: "127.0.0.1:19080"
    routes:
      - match:
          host: ["api.example.com"]
          path: ["/api/*"]
        backends:
          - name: stable
            weight: 90
            upstreams: ["http://127.0.0.1:8080"]
          - name: canary
            weight: 10
            upstreams: ["http://127.0.0.1:8081"]
        mirrors:
          - name: shadow
            percent: 5
            upstreams: ["http://127.0.0.1:8082"]
        headers:
          request_set:
            X-Proxy: qpx
          response_set:
            X-Proxy-Handled: qpx
        path_rewrite:
          regex:
            pattern: "^/api/(.*)$"
            replace: "/$1"
"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    let route = &loaded.reverse[0].routes[0];
    assert_eq!(route.backends.len(), 2);
    assert_eq!(route.mirrors.len(), 1);
    assert!(route.headers.is_some());
    assert!(route.path_rewrite.as_ref().and_then(|r| r.regex.as_ref()).is_some());
}
