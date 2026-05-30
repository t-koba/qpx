use super::*;

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
