use super::*;

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
fn load_config_rejects_response_compression_zero_workers() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("response-compression-workers.yaml");
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
      worker_count: 0"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("zero compression worker count should be rejected");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains("worker_count must be in 1..=256"),
        "unexpected error: {err:?}"
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

    assert!(
        err.to_string()
            .contains("references unknown http.module_chains entry: missing")
    );
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
fn load_config_rejects_cache_purge_invalid_response_header_value() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-cache-purge-header.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  cache:
    enabled: true
  default_action:
    type: direct
  http_modules:
  - type: cache_purge
    settings:
      response_headers:
        x-cache-purge: "ok\nbad""#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("invalid cache_purge header should fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("invalid header value"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_cache_purge_invalid_allowed_peer() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-cache-purge-peer.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  cache:
    enabled: true
  default_action:
    type: direct
  http_modules:
  - type: cache_purge
    settings:
      allowed_peers:
      - not-a-cidr"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("invalid cache_purge peer should fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("allowed_peers[] has invalid CIDR"),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_invalid_subrequest_template_syntax() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-subrequest-template.yaml");
    write_config(
        &cfg,
        r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  http_modules:
  - type: subrequest
    settings:
      name: authz
      phase: request_headers
      url: "http://127.0.0.1/check/{request.header.authorization}"
      max_response_bytes: 1024
      allowed_schemes: [http]
      allowed_hosts: [127.0.0.1]"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("invalid subrequest template should fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string()
            .contains("placeholder must be variable:modifier"),
        "unexpected error: {err}"
    );
}
