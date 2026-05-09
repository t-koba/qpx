use super::*;
use std::collections::BTreeSet;
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

fn write_config(path: &PathBuf, input: &str) -> std::io::Result<()> {
    fs::write(path, input)
}

#[test]
fn canonical_schema_http_module_matches_serde_envelope() {
    let schema = canonical_schema_value();
    let http_module = schema
        .pointer("/$defs/httpModule")
        .expect("httpModule schema");
    assert_eq!(
        http_module
            .get("additionalProperties")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert!(http_module.pointer("/properties/settings").is_some());

    let fields = http_module
        .pointer("/properties")
        .and_then(serde_json::Value::as_object)
        .expect("httpModule properties")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fields,
        ["id", "order", "settings", "type"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>()
    );

    let minimal = serde_yaml::from_str::<HttpModuleConfig>(
        r#"type: response_compression
settings:
  min_body_bytes: 1"#,
    )
    .expect("minimal settings module");
    assert_eq!(minimal.r#type, "response_compression");
    assert!(minimal.settings.get("min_body_bytes").is_some());
}

#[test]
fn load_config_appends_edges_and_overlays_scalar_fields() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");

    let base = dir.join("base.yaml");
    let overlay = dir.join("overlay.yaml");

    write_config(
        &base,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
telemetry:
  system_log:
    level: info
    format: json"#,
    )
    .expect("write base");

    write_config(
        &overlay,
        r#"edges:
- kind: reverse
  name: api
  listen: 127.0.0.1:19080
  routes:
  - match:
      host:
      - example.com
    target:
      type: upstream
      upstreams:
      - http://127.0.0.1:8080
telemetry:
  system_log:
    level: debug
    format: json"#,
    )
    .expect("write overlay");

    let loaded = load_configs(&[base.clone(), overlay.clone()]).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.telemetry.system_log.level, "debug");
    assert_eq!(loaded.ingress_edge_configs().len(), 1);
    assert_eq!(loaded.ingress_edge_configs()[0].name, "forward");
    assert_eq!(loaded.reverse_edge_configs().len(), 1);
    assert_eq!(loaded.reverse_edge_configs()[0].name, "api");
}

#[test]
fn load_config_appends_named_collections_and_rejects_duplicates() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");

    let base = dir.join("base.yaml");
    let overlay = dir.join("overlay.yaml");
    write_config(
        &base,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
upstreams:
- name: egress-a
  url: http://proxy-a.local:3128
caches:
- name: cache-a
  kind: redis
  endpoint: redis://127.0.0.1:6379/11
http:
  module_chains:
  - name: base-chain
    modules:
    - type: response_compression
security:
  identity_sources:
  - name: headers-a
    type: trusted_headers
    from:
      trusted_peers: [127.0.0.1/32]
    headers:
      user: x-user
  decisions:
    ext_authz:
    - name: authz-a
      endpoint: http://127.0.0.1:19091/check
traffic:
  rate_limit_profiles:
  - name: burst-a
    requests:
      rps: 10"#,
    )
    .expect("write base");
    write_config(
        &overlay,
        r#"upstreams:
- name: egress-b
  url: http://proxy-b.local:3128
caches:
- name: cache-b
  kind: redis
  endpoint: redis://127.0.0.1:6379/12
http:
  module_chains:
  - name: overlay-chain
    modules:
    - type: response_compression
security:
  identity_sources:
  - name: headers-b
    type: trusted_headers
    from:
      trusted_peers: [127.0.0.1/32]
    headers:
      user: x-user
  decisions:
    ext_authz:
    - name: authz-b
      endpoint: http://127.0.0.1:19092/check
traffic:
  rate_limit_profiles:
  - name: burst-b
    requests:
      rps: 20"#,
    )
    .expect("write overlay");

    let loaded = load_configs(&[base.clone(), overlay.clone()]).expect("load config");
    assert_eq!(loaded.upstreams.len(), 2);
    assert_eq!(loaded.caches.len(), 2);
    assert_eq!(loaded.http.module_chains.len(), 2);
    assert_eq!(loaded.security.identity_sources.len(), 2);
    assert_eq!(loaded.security.decisions.ext_authz.len(), 2);
    assert_eq!(loaded.traffic.rate_limit_profiles.len(), 2);

    write_config(
        &overlay,
        r#"upstreams:
- name: egress-a
  url: http://proxy-b.local:3128"#,
    )
    .expect("write duplicate overlay");
    let err = load_configs(&[base.clone(), overlay.clone()]).expect_err("duplicate must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("duplicate upstream name: egress-a"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_supports_include_and_env() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");

    let include = dir.join("include.yaml");
    let base = dir.join("base.yaml");

    write_config(
        &include,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct"#,
    )
    .expect("write include");

    write_config(
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
    assert_eq!(loaded.ingress_edge_configs().len(), 1);
    assert_eq!(loaded.ingress_edge_configs()[0].name, "forward");
}

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
fn load_config_rejects_plain_ldap_without_starttls() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-ldap-starttls.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
security:
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
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
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
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
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
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
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
fn load_config_rejects_unknown_edge_upstream_reference() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("unknown-upstream-ref.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: proxy
  upstream_proxy: typo-egress
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
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: proxy"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("action type Proxy requires action.upstream or edges[].upstream_proxy"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_tunnel_rule_without_upstream_reference() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("missing-rule-upstream-ref.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  rules:
  - name: tunnel
    match:
      host:
      - example.com
    action:
      type: tunnel"#,
    )
    .expect("write");
    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains(
            "edge forward rule tunnel: action type Tunnel requires action.upstream or edges[].upstream_proxy"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_unknown_keys() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("unknown-keys.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  unknown_edge_key: true
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  rules:
  - name: typo-match
    match:
      hosts:
      - example.com
    action:
      type: direct"#,
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
        error_chain.contains("unknown_edge_key"),
        "unexpected error: {err}"
    );

    fs::remove_dir_all(&dir).ok();
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

#[test]
fn load_config_allows_reverse_path_rewrite() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("reverse_edges-path-rewrite.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: reverse_edges
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
    target:
      type: upstream
      upstreams:
      - http://127.0.0.1:8080"#,
    )
    .expect("write");
    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.reverse_edge_configs().len(), 1);
    let route = &loaded.reverse_edge_configs()[0].routes[0];
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
    let cfg = dir.join("reverse_edges-advanced.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: reverse_edges
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
    target:
      type: weighted
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

    let route = &loaded.reverse_edge_configs()[0].routes[0];
    let ReverseRouteTargetConfig::Weighted { backends, .. } = &route.target else {
        panic!("expected weighted target");
    };
    assert_eq!(backends.len(), 2);
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

#[test]
fn load_config_supports_http_modules() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("http-modules.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  http_modules:
  - type: response_compression
    settings:
      min_body_bytes: 1
      max_body_bytes: 4096
      gzip: true
      brotli: false
      zstd: false
- kind: reverse
  name: api
  listen: 127.0.0.1:19080
  routes:
  - match:
      host:
      - example.com
    target:
      type: upstream
      upstreams:
      - http://127.0.0.1:8080
    http_modules:
    - type: subrequest
      settings:
        name: authz
        phase: response_headers
        url: http://127.0.0.1:19091/check
        max_response_bytes: 65536
        allowed_schemes:
        - http
        allowed_hosts:
        - 127.0.0.1
        copy_response_headers_to_response:
        - from: x-decision
          to: x-module-decision"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.ingress_edge_configs()[0].http_modules.len(), 1);
    assert_eq!(
        loaded.reverse_edge_configs()[0].routes[0]
            .http_modules
            .len(),
        1
    );
}

#[test]
fn load_config_rejects_inline_http_module_fields() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("inline-http-module.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  http_modules:
  - type: response_compression
    min_body_bytes: 1"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("inline module fields should be rejected");
    fs::remove_dir_all(&dir).ok();

    assert!(
        err.to_string().contains("min_body_bytes") || format!("{err:?}").contains("min_body_bytes"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn load_config_expands_http_module_chains() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("http-module-chains.yaml");
    write_config(
        &cfg,
        r#"http:
  module_chains:
  - name: compress
    modules:
    - type: response_compression
      settings:
        min_body_bytes: 1
        max_body_bytes: 4096
        gzip: true
        brotli: false
        zstd: false
edges:
- kind: reverse
  name: api
  listen: 127.0.0.1:19080
  routes:
  - name: app
    match:
      host:
      - example.com
    modules:
    - compress
    target:
      type: upstream
      upstreams:
      - http://127.0.0.1:8080"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(
        loaded.reverse_edge_configs()[0].routes[0]
            .http_modules
            .len(),
        1
    );
    assert_eq!(
        loaded.reverse_edge_configs()[0].routes[0].http_modules[0].r#type,
        "response_compression"
    );
}

#[test]
fn load_config_rejects_unknown_http_module_chain_ref() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("unknown-http-module-chain.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  modules:
  - missing"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("unknown module chain should fail");
    fs::remove_dir_all(&dir).ok();

    assert!(err
        .to_string()
        .contains("references unknown http.module_chains entry: missing"));
}

#[test]
fn load_config_rejects_cache_purge_http_module_without_cache() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-cache-purge-module.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
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
fn load_config_rejects_plaintext_body_capture_without_limit() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-capture-body.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: edge
  listen: 127.0.0.1:19080
  routes:
  - match:
      host: [example.com]
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
    capture:
      plaintext:
        enabled: true
        headers: true
        body: true"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("capture body without limit should fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("plaintext.max_body_bytes is required"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_allows_custom_http_modules_for_runtime_registry_resolution() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("custom-http-module.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  http_modules:
  - type: custom_filter
    id: inject
    settings:
      header_name: x-custom
      header_value: yes"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.ingress_edge_configs()[0].http_modules.len(), 1);
    assert_eq!(
        loaded.ingress_edge_configs()[0].http_modules[0].r#type,
        "custom_filter"
    );
    assert_eq!(
        loaded.ingress_edge_configs()[0].http_modules[0]
            .id
            .as_deref(),
        Some("inject")
    );
}

#[test]
fn load_config_preserves_transparent_original_dst_source() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("transparent-original-dst.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: transparent
  name: transparent
  listen: 127.0.0.1:18080
  original_dst:
    source: linux_so_original_dst
  default_action:
    type: direct"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    let edge = loaded.ingress_edge_configs()[0];
    assert!(matches!(edge.mode, IngressEdgeMode::Transparent));
    assert_eq!(
        edge.original_dst.as_ref().map(|cfg| &cfg.source),
        Some(&OriginalDstSource::LinuxSoOriginalDst)
    );
}

#[test]
fn load_config_preserves_ipc_body_limits() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("ipc-body.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: reverse
  name: api
  listen: 127.0.0.1:19080
  routes:
  - match:
      path:
      - /api/*
    target:
      type: ipc
      endpoint: unix:///tmp/qpxf.sock
      mode: shm
      timeout_ms: 3000
      body:
        max_request_bytes: 1024
        max_response_bytes: 2048"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    let ReverseRouteTargetConfig::Ipc { config: ipc } =
        &loaded.reverse_edge_configs()[0].routes[0].target
    else {
        panic!("expected ipc target");
    };
    assert_eq!(ipc.body.max_request_bytes, Some(1024));
    assert_eq!(ipc.body.max_response_bytes, Some(2048));
}

#[test]
fn load_config_deserialize_errors_include_config_path() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-type.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen:
  - 127.0.0.1:18080
  default_action:
    type: direct"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must fail");
    fs::remove_dir_all(&dir).ok();

    let error = format!("{err:?}");
    assert!(
        error.contains("failed to deserialize config") && error.contains("invalid-type.yaml"),
        "unexpected error: {error}"
    );
}
