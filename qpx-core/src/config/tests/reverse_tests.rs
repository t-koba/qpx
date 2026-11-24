use super::*;

#[test]
fn load_config_allows_named_webdav_origin_target() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("webdav-origin.yaml");
    let root = dir.join("documents");
    let metadata = dir.join("documents.redb");
    let root = root.to_string_lossy().replace('\\', "/");
    let metadata = metadata.to_string_lossy().replace('\\', "/");
    write_config(
        &cfg,
        &format!(
            r#"origins:
  webdav:
  - name: documents
    root: {root}
    metadata: {metadata}
    max_depth: 32
    max_multistatus_entries: 10000
    max_lock_timeout_seconds: 86400
edges:
- kind: reverse
  name: dav
  listen: 127.0.0.1:19080
  routes:
  - match:
      path:
      - /dav/**
    http:
      require_precondition: true
    target:
      type: webdav
      origin: documents"#
        ),
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load WebDAV config");
    fs::remove_dir_all(&dir).ok();
    assert_eq!(loaded.http.origins.webdav[0].name, "documents");
    assert!(
        loaded.reverse_edge_configs()[0].routes[0]
            .http
            .as_ref()
            .is_some_and(|http| http.require_precondition)
    );
    assert!(matches!(
        loaded.reverse_edge_configs()[0].routes[0].target,
        ReverseRouteTargetConfig::Webdav { ref origin } if origin == "documents"
    ));
}

#[test]
fn load_config_rejects_webdav_metadata_inside_served_root() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("webdav-origin-unsafe.yaml");
    let root = dir.join("documents");
    let metadata = root.join("private.redb");
    let root = root.to_string_lossy().replace('\\', "/");
    let metadata = metadata.to_string_lossy().replace('\\', "/");
    write_config(
        &cfg,
        &format!(
            r#"origins:
  webdav:
  - name: documents
    root: {root}
    metadata: {metadata}
edges:
- kind: reverse
  name: dav
  listen: 127.0.0.1:19080
  routes:
  - match:
      path: [/dav/**]
    target:
      type: webdav
      origin: documents"#
        ),
    )
    .expect("write");
    let error = load_config(&cfg).expect_err("unsafe metadata placement must fail");
    fs::remove_dir_all(&dir).ok();
    assert!(error.to_string().contains("outside its served root"));
}

#[test]
fn load_config_limits_511_to_explicit_capport_local_routes() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let rejected = dir.join("capport-rejected.yaml");
    let config = |capport: bool| {
        format!(
            r#"edges:
- kind: reverse
  name: captive
  listen: 127.0.0.1:19080
  routes:
  - match:
      path: [/**]
    http:
      capport: {capport}
    target:
      type: local_response
      response:
        status: 511
        body: network authentication required"#
        )
    };
    write_config(&rejected, &config(false)).expect("write");
    assert!(load_config(&rejected).is_err());
    let accepted = dir.join("capport-accepted.yaml");
    write_config(&accepted, &config(true)).expect("write");
    load_config(&accepted).expect("explicit CAPPORT route");
    fs::remove_dir_all(&dir).ok();
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
    let reverse = loaded.reverse_edge_configs()[0];
    let route = &reverse.routes[0];
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
    assert!(
        route
            .path_rewrite
            .as_ref()
            .and_then(|r| r.regex.as_ref())
            .is_some()
    );
}

fn retry_budget_config(retry: &str) -> String {
    format!(
        r#"edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:19080
  routes:
  - match: {{}}
    target:
      type: local_response
      response:
        status: 200
        body: ok
    resilience:
      retry:
{retry}"#
    )
}

#[test]
fn load_config_accepts_explicit_retry_budget_bounds_and_attempts_one() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("retry-budget.yaml");
    for (percent, burst, attempts) in [(1, 1, 2), (100, 42_949_672, 4), (25, 4, 1)] {
        write_config(
            &cfg,
            &retry_budget_config(&format!(
                "        attempts: {attempts}\n        budget:\n          retry_percent: {percent}\n          burst_tokens: {burst}\n"
            )),
        )
        .expect("write");
        let loaded = load_config(&cfg).expect("valid retry budget");
        let retry = loaded.reverse_edge_configs()[0].routes[0]
            .resilience
            .as_ref()
            .and_then(|resilience| resilience.retry.as_ref())
            .expect("retry");
        let budget = retry.budget.as_ref().expect("budget");
        assert_eq!(
            (budget.retry_percent, budget.burst_tokens),
            (percent, burst)
        );
        assert_eq!(retry.attempts, attempts);
    }
    write_config(&cfg, &retry_budget_config("        attempts: 2\n")).expect("write");
    load_config(&cfg).expect("omitted budget keeps the default policy");
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn load_config_rejects_retry_budget_outside_bounds() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("retry-budget-invalid.yaml");
    for (percent, burst, field) in [
        (0, 4, "retry_percent"),
        (101, 4, "retry_percent"),
        (25, 0, "burst_tokens"),
        (25, 42_949_673, "burst_tokens"),
    ] {
        write_config(
            &cfg,
            &retry_budget_config(&format!(
                "        attempts: 2\n        budget:\n          retry_percent: {percent}\n          burst_tokens: {burst}\n"
            )),
        )
        .expect("write");
        let error = load_config(&cfg).expect_err("out-of-bounds budget must fail");
        assert!(error.to_string().contains(field), "{error}");
    }
    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn load_config_rejects_old_and_unknown_retry_budget_fields() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("retry-budget-unknown.yaml");
    for budget in [
        "          ratio: 20\n          min_retry_tokens: 4\n",
        "          retry_percent: 25\n          burst_tokens: 4\n          ratio: 20\n",
        "          retry_percent: 25\n",
    ] {
        write_config(
            &cfg,
            &retry_budget_config(&format!("        attempts: 2\n        budget:\n{budget}")),
        )
        .expect("write");
        let error = load_config(&cfg).expect_err("unknown or incomplete budget must fail");
        let message = error.to_string();
        assert!(
            message.contains("unknown field") || message.contains("missing field"),
            "{message}"
        );
    }
    fs::remove_dir_all(&dir).expect("cleanup");
}
