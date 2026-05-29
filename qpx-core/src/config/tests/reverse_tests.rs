use super::*;

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
