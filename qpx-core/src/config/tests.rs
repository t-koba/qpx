use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs, path::PathBuf};

fn unique_tmp_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut dir = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.push(format!(
        "qpx-config-test-{}-{}-{}",
        std::process::id(),
        nanos,
        seq
    ));
    dir
}

#[test]
fn load_config_supports_multiple_files_last_wins() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");

    let base = dir.join("base.yaml");
    let overlay = dir.join("overlay.yaml");

    fs::write(
        &base,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
system_log:
  level: info
  format: json"#,
    )
    .expect("write base");

    fs::write(
        &overlay,
        r#"reverse:
- name: api
  listen: 127.0.0.1:19080
  routes:
  - match:
      host:
      - example.com
    upstreams:
    - http://127.0.0.1:8080
system_log:
  level: debug
  format: json"#,
    )
    .expect("write overlay");

    let loaded = load_configs(&[base.clone(), overlay.clone()]).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.system_log.level, "debug");
    assert_eq!(loaded.listeners.len(), 1);
    assert_eq!(loaded.listeners[0].name, "forward");
    assert_eq!(loaded.reverse.len(), 1);
    assert_eq!(loaded.reverse[0].name, "api");
}

#[test]
fn load_config_supports_include_and_env() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");

    let include = dir.join("include.yaml");
    let base = dir.join("base.yaml");

    fs::write(
        &include,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward"#,
    )
    .expect("write include");

    fs::write(
        &base,
        r#"include:
- include.yaml
state_dir: ${QPX_TEST_STATE_DIR}"#,
    )
    .expect("write base");

    std::env::set_var("QPX_TEST_STATE_DIR", "/tmp/qpx-state");
    let loaded = load_config(&base).expect("load config");
    std::env::remove_var("QPX_TEST_STATE_DIR");
    fs::remove_dir_all(&dir).ok();

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
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
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
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
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
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
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
fn load_config_rejects_plain_ldap_without_starttls() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-ldap-starttls.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
auth:
  ldap:
    url: ldap://ad.example.com:389
    bind_dn: cn=proxy,dc=example,dc=com
    bind_password_env: LDAP_BIND_PASSWORD
    user_base_dn: ou=users,dc=example,dc=com
    group_base_dn: ou=groups,dc=example,dc=com
    require_starttls: false"#,
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
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
upstreams:
- name: egress
  url: http://proxy-a.local:3128
- name: egress
  url: http://proxy-b.local:3128"#,
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
fn load_config_rejects_connection_filter_non_block_action() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-connection-filter-action.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
  connection_filter:
  - name: bad-filter
    match:
      src_ip:
      - 127.0.0.1/32
    action:
      type: direct"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("connection_filter rule bad-filter action.type must be block"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_connection_filter_host_match() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-connection-filter-host.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
  connection_filter:
  - name: bad-filter
    match:
      host:
      - example.com
    action:
      type: block"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("connection_filter rule bad-filter must not match host"),
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
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: proxy
  upstream_proxy: typo-egress
  mode: forward
upstreams:
- name: corp-egress
  url: http://proxy-a.local:3128"#,
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
fn load_config_rejects_proxy_action_without_upstream_reference() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("missing-upstream-ref.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: proxy
  mode: forward"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("action type Proxy requires action.upstream or listeners[].upstream_proxy"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_tunnel_rule_without_upstream_reference() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("missing-rule-upstream-ref.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  rules:
  - name: tunnel
    match:
      host:
      - example.com
    action:
      type: tunnel
  mode: forward"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains(
            "listener forward rule tunnel: action type Tunnel requires action.upstream or listeners[].upstream_proxy"
        ),
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
        r#"listeners:
- name: forward
  unknown_listener_key: true
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  rules:
  - name: typo-match
    match:
      hosts:
      - example.com
    action:
      type: direct
  mode: forward"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    let error_chain = err
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        error_chain.contains("unknown config keys") || error_chain.contains("unknown field"),
        "unexpected error: {err}"
    );
    assert!(
        error_chain.contains("unknown_listener_key"),
        "unexpected error: {err}"
    );

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_config_allows_empty_exporter_shm_path() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-exporter-shm-path.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
exporter:
  enabled: true
  shm_path: ''"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();
    assert!(loaded.exporter.is_some());
}

#[test]
fn load_config_allows_disabled_exporter_with_empty_shm_path() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("disabled-exporter.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
exporter:
  enabled: false
  shm_path: ''"#,
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
        r#"reverse:
- name: reverse
  listen: 127.0.0.1:19080
  routes:
  - match:
      host:
      - api.example.com
      path:
      - /api/v1/*
    path_rewrite:
      strip_prefix: /api/v1
      add_prefix: /v2
    upstreams:
    - http://127.0.0.1:8080"#,
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
        r#"reverse:
- name: reverse
  listen: 127.0.0.1:19080
  routes:
  - match:
      host:
      - api.example.com
      path:
      - /api/*
    path_rewrite:
      regex:
        pattern: ^/api/(.*)$
        replace: /$1
    mirrors:
    - name: shadow
      percent: 5
      upstreams:
      - http://127.0.0.1:8082
    headers:
      request_set:
        X-Proxy: qpx
      response_set:
        X-Proxy-Handled: qpx
    backends:
    - name: stable
      weight: 90
      upstreams:
      - http://127.0.0.1:8080
    - name: canary
      weight: 10
      upstreams:
      - http://127.0.0.1:8081"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    let route = &loaded.reverse[0].routes[0];
    assert_eq!(route.backends.len(), 2);
    assert_eq!(route.mirrors.len(), 1);
    assert!(route.headers.is_some());
    assert!(route
        .path_rewrite
        .as_ref()
        .and_then(|r| r.regex.as_ref())
        .is_some());
}

#[test]
fn load_config_allows_access_and_audit_logs() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("logs.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
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

    assert!(loaded.access_log.output.enabled);
    assert!(loaded.audit_log.output.enabled);
    assert_eq!(loaded.access_log.exclude, vec!["/health", "/metrics"]);
}

#[test]
fn load_config_supports_http_modules() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("http-modules.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
  http_modules:
  - type: response_compression
    min_body_bytes: 1
    max_body_bytes: 4096
    gzip: true
    brotli: false
    zstd: false
reverse:
- name: api
  listen: 127.0.0.1:19080
  routes:
  - match:
      host:
      - example.com
    upstreams:
    - http://127.0.0.1:8080
    http_modules:
    - type: subrequest
      name: authz
      phase: response_headers
      url: http://127.0.0.1:19091/check
      copy_response_headers_to_response:
      - from: x-decision
        to: x-module-decision"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.listeners[0].http_modules.len(), 1);
    assert_eq!(loaded.reverse[0].routes[0].http_modules.len(), 1);
}

#[test]
fn load_config_rejects_cache_purge_http_module_without_cache() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-cache-purge-module.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
  http_modules:
  - type: cache_purge"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("cache_purge http_modules but cache.enabled is not true"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_allows_custom_http_modules_for_runtime_registry_resolution() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("custom-http-module.yaml");
    fs::write(
        &cfg,
        r#"listeners:
- name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  mode: forward
  http_modules:
  - type: custom_filter
    id: inject
    header_name: x-custom
    header_value: yes"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.listeners[0].http_modules.len(), 1);
    assert_eq!(loaded.listeners[0].http_modules[0].r#type, "custom_filter");
    assert_eq!(
        loaded.listeners[0].http_modules[0].id.as_deref(),
        Some("inject")
    );
}
