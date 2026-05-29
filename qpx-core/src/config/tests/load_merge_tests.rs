use super::*;

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
  streaming:
    body_channel_capacity: 24
  grpc:
    max_web_trailer_bytes: 8192
  sse:
    idle_timeout_ms: 240000
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
state_dir: ${QPX_TEST_STATE_DIR:-/tmp/qpx-state}"#,
    )
    .expect("write base");

    let loaded = load_config(&base).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.state_dir.as_deref(), Some("/tmp/qpx-state"));
    assert_eq!(loaded.ingress_edge_configs().len(), 1);
    assert_eq!(loaded.ingress_edge_configs()[0].name, "forward");
}
