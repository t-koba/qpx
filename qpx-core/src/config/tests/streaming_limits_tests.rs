use super::*;

#[test]
fn load_config_preserves_streaming_grpc_and_sse_knobs() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("streaming.yaml");
    write_config(
        &cfg,
        r#"runtime:
  body_channel_capacity: 8
  h3_request_body_drain:
    mode: bounded
    max_concurrent: 9
    timeout_ms: 3000
  max_grpc_message_bytes: 4194304
  max_grpc_web_trailer_bytes: 32768
  sse:
    disable_compression: true
    flush_policy: low_latency
    idle_timeout_ms: 120000
    max_stream_duration_ms: 600000
    max_line_bytes: 4096
    max_event_id_bytes: 128
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  streaming:
    body_channel_capacity: 12
  grpc:
    max_message_bytes: 1048576
    max_web_trailer_bytes: 16384
  sse:
    idle_timeout_ms: 90000
  default_action:
    type: direct
- kind: reverse
  name: api
  listen: 127.0.0.1:19080
  routes:
  - name: realtime
    match:
      path:
      - /events
    streaming_requirement: required
    streaming:
      body_channel_capacity: 32
    grpc:
      max_message_bytes: 2097152
    sse:
      max_stream_duration_ms: 3600000
      max_line_bytes: 8192
      max_event_id_bytes: 256
    target:
      type: local_response
      response:
        status: 200
        body: ok"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("load config");
    fs::remove_dir_all(&dir).ok();

    assert_eq!(loaded.runtime.body_channel_capacity, 8);
    assert!(matches!(
        loaded.runtime.h3_request_body_drain.mode,
        H3RequestBodyDrainMode::Bounded
    ));
    assert_eq!(loaded.runtime.h3_request_body_drain.max_concurrent, 9);
    assert_eq!(loaded.runtime.h3_request_body_drain.timeout_ms, 3000);
    assert_eq!(loaded.runtime.max_grpc_web_trailer_bytes, 32768);
    assert_eq!(loaded.runtime.sse.idle_timeout_ms, 120000);
    assert_eq!(loaded.runtime.sse.max_line_bytes, 4096);
    assert_eq!(loaded.runtime.sse.max_event_id_bytes, 128);
    let ingress = loaded.ingress_edge_configs()[0];
    assert_eq!(
        ingress
            .streaming
            .as_ref()
            .and_then(|cfg| cfg.body_channel_capacity),
        Some(12)
    );
    assert_eq!(
        ingress
            .grpc
            .as_ref()
            .and_then(|cfg| cfg.max_web_trailer_bytes),
        Some(16384)
    );
    assert_eq!(
        ingress.sse.as_ref().map(|cfg| cfg.idle_timeout_ms),
        Some(90000)
    );
    let route = &loaded.reverse_edge_configs()[0].routes[0];
    assert!(matches!(
        route.streaming_requirement,
        Some(StreamingRequirement::Required)
    ));
    assert_eq!(
        route
            .streaming
            .as_ref()
            .and_then(|cfg| cfg.body_channel_capacity),
        Some(32)
    );
    assert_eq!(
        route.grpc.as_ref().and_then(|cfg| cfg.max_message_bytes),
        Some(2_097_152)
    );
    assert_eq!(
        route.sse.as_ref().map(|cfg| cfg.max_stream_duration_ms),
        Some(3_600_000)
    );
    assert_eq!(route.sse.as_ref().map(|cfg| cfg.max_line_bytes), Some(8192));
    assert_eq!(
        route.sse.as_ref().map(|cfg| cfg.max_event_id_bytes),
        Some(256)
    );
}

#[test]
fn load_config_rejects_h3_drain_max_concurrent_zero() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("h3-drain-max-concurrent.yaml");
    write_config(
        &cfg,
        r#"runtime:
  h3_request_body_drain:
    max_concurrent: 0
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must reject zero H3 drain concurrency");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains("h3_request_body_drain.max_concurrent must be >= 1"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn load_config_rejects_h3_drain_timeout_zero() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("h3-drain-timeout.yaml");
    write_config(
        &cfg,
        r#"runtime:
  h3_request_body_drain:
    timeout_ms: 0
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must reject zero H3 drain timeout");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains("h3_request_body_drain.timeout_ms must be >= 1"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn load_config_rejects_sse_stream_duration_above_safe_limit() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("sse-duration.yaml");
    write_config(
        &cfg,
        &format!(
            r#"runtime:
  sse:
    idle_timeout_ms: 1000
    max_stream_duration_ms: {}
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct"#,
            MAX_SSE_STREAM_DURATION_MS + 1
        ),
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must reject oversized SSE stream duration");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains("sse.max_stream_duration_ms must be <="),
        "unexpected error: {err:?}"
    );
}

#[test]
fn load_config_rejects_grpc_stream_duration_above_safe_limit() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("grpc-duration.yaml");
    write_config(
        &cfg,
        &format!(
            r#"runtime:
  max_grpc_stream_duration_ms: {}
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct"#,
            MAX_GRPC_STREAM_DURATION_MS + 1
        ),
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must reject oversized gRPC stream duration");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains("max_grpc_stream_duration_ms must be <="),
        "unexpected error: {err:?}"
    );
}

#[test]
fn load_config_rejects_runtime_grpc_web_trailer_limit_above_safe_limit() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("grpc-web-trailer-runtime.yaml");
    write_config(
        &cfg,
        &format!(
            r#"runtime:
  max_grpc_web_trailer_bytes: {}
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct"#,
            MAX_GRPC_WEB_TRAILER_BYTES + 1
        ),
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must reject oversized gRPC-Web trailer limit");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains("max_grpc_web_trailer_bytes must be <="),
        "unexpected error: {err:?}"
    );
}

#[test]
fn load_config_rejects_reverse_retry_template_limit_above_safe_limit() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("reverse-retry-template-runtime.yaml");
    write_config(
        &cfg,
        &format!(
            r#"runtime:
  max_reverse_retry_template_body_bytes: {}
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct"#,
            MAX_REVERSE_RETRY_TEMPLATE_BODY_BYTES + 1
        ),
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must reject oversized reverse retry template limit");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains("max_reverse_retry_template_body_bytes must be <="),
        "unexpected error: {err:?}"
    );
}

#[test]
fn load_config_rejects_reverse_retry_threshold_above_template_limit() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("reverse-retry-threshold-template-cap.yaml");
    write_config(
        &cfg,
        r#"runtime:
  max_reverse_retry_template_body_bytes: 1024
edges:
- kind: reverse
  name: reverse
  listen: 127.0.0.1:19080
  routes:
  - match:
      host:
      - api.example.com
    resilience:
      retry:
        attempts: 2
        retry_body_threshold_bytes: 2048
    target:
      type: upstream
      upstreams:
      - http://127.0.0.1:8080"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must reject retry threshold above template cap");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains(
            "retry_body_threshold_bytes must be <= runtime.max_reverse_retry_template_body_bytes"
        ),
        "unexpected error: {err:?}"
    );
}

#[test]
fn load_config_rejects_edge_grpc_web_trailer_limit_above_safe_limit() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("grpc-web-trailer-edge.yaml");
    write_config(
        &cfg,
        &format!(
            r#"edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:18080
  default_action:
    type: direct
  grpc:
    max_web_trailer_bytes: {}"#,
            MAX_GRPC_WEB_TRAILER_BYTES + 1
        ),
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("must reject oversized gRPC-Web trailer limit");
    fs::remove_dir_all(&dir).ok();

    assert!(
        format!("{err:?}").contains("grpc.max_web_trailer_bytes must be <="),
        "unexpected error: {err:?}"
    );
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

#[test]
fn load_config_h3_flow_control_defaults_and_overrides() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("h3-windows.yaml");
    let defaults = RuntimeConfig::default();
    assert_eq!(
        (
            defaults.h3_stream_receive_window_bytes,
            defaults.h3_connection_receive_window_bytes,
            defaults.h3_send_window_bytes
        ),
        (1048576, 4194304, 4194304)
    );
    for (runtime, expected) in [
        (String::new(), (1048576, 4194304, 4194304)),
        ("runtime:\n  h3_stream_receive_window_bytes: 1\n  h3_connection_receive_window_bytes: 2\n  h3_send_window_bytes: 3\n".to_string(), (1, 2, 3)),
        (format!("runtime:\n  h3_stream_receive_window_bytes: {0}\n  h3_connection_receive_window_bytes: {0}\n  h3_send_window_bytes: {1}\n", (1_u64 << 62) - 1, u64::MAX), ((1_u64 << 62) - 1, (1_u64 << 62) - 1, u64::MAX)),
    ] {
        write_config(&cfg, &format!("{runtime}edges:\n- kind: forward\n  name: forward\n  listen: 127.0.0.1:18080\n  default_action:\n    type: direct\n")).expect("write");
        let loaded = load_config(&cfg).expect("load config");
        assert_eq!(
            (loaded.runtime.h3_stream_receive_window_bytes, loaded.runtime.h3_connection_receive_window_bytes, loaded.runtime.h3_send_window_bytes),
            expected
        );
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_config_h3_max_uni_streams_defaults_and_overrides() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("h3-uni-streams.yaml");
    assert_eq!(RuntimeConfig::default().h3_max_uni_streams, 1024);
    for (runtime, expected) in [
        (String::new(), 1024usize),
        ("runtime:\n  h3_max_uni_streams: 77\n".to_string(), 77),
        (
            format!("runtime:\n  h3_max_uni_streams: {}\n", u32::MAX),
            u32::MAX as usize,
        ),
    ] {
        write_config(&cfg, &format!("{runtime}edges:\n- kind: forward\n  name: forward\n  listen: 127.0.0.1:18080\n  default_action:\n    type: direct\n")).expect("write");
        let loaded = load_config(&cfg).expect("load config");
        assert_eq!(loaded.runtime.h3_max_uni_streams, expected);
    }
    for invalid in ["0".to_string(), format!("{}", u64::from(u32::MAX) + 1)] {
        write_config(&cfg, &format!("runtime:\n  h3_max_uni_streams: {invalid}\nedges:\n- kind: forward\n  name: forward\n  listen: 127.0.0.1:18080\n  default_action:\n    type: direct\n")).expect("write");
        assert!(
            load_config(&cfg).is_err(),
            "h3_max_uni_streams={invalid} must be rejected"
        );
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_config_h3_allow_connection_migration_defaults_and_overrides() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("h3-allow-migration.yaml");
    assert!(!RuntimeConfig::default().h3_allow_connection_migration);
    for (runtime, expected) in [
        (String::new(), false),
        (
            "runtime:\n  h3_allow_connection_migration: true\n".to_string(),
            true,
        ),
    ] {
        write_config(&cfg, &format!("{runtime}edges:\n- kind: forward\n  name: forward\n  listen: 127.0.0.1:18080\n  default_action:\n    type: direct\n")).expect("write");
        let loaded = load_config(&cfg).expect("load config");
        assert_eq!(loaded.runtime.h3_allow_connection_migration, expected);
    }
    write_config(&cfg, "runtime:\n  h3_allow_connection_migration: 1\nedges:\n- kind: forward\n  name: forward\n  listen: 127.0.0.1:18080\n  default_action:\n    type: direct\n").expect("write");
    assert!(
        load_config(&cfg).is_err(),
        "h3_allow_connection_migration=1 must be rejected"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_config_rejects_invalid_h3_flow_control_windows() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("h3-windows-invalid.yaml");
    for (field, value) in [
        ("h3_stream_receive_window_bytes", 0),
        ("h3_connection_receive_window_bytes", 0),
        ("h3_send_window_bytes", 0),
        ("h3_stream_receive_window_bytes", 1_u64 << 62),
        ("h3_connection_receive_window_bytes", 1_u64 << 62),
    ] {
        write_config(&cfg, &format!("runtime:\n  {field}: {value}\nedges:\n- kind: forward\n  name: forward\n  listen: 127.0.0.1:18080\n  default_action:\n    type: direct\n")).expect("write");
        let err = load_config(&cfg).expect_err("invalid flow-control window");
        assert!(
            format!("{err:#}").contains(&format!("runtime.{field} must be")),
            "{err:#}"
        );
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_config_h2_server_limits_defaults_and_overrides() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("h2-server-limits.yaml");
    let defaults = RuntimeConfig::default();
    assert_eq!(defaults.h2_server_max_header_list_size_bytes, 128 * 1024);
    assert_eq!(defaults.h2_server_max_concurrent_streams, 256);
    for (runtime, expected) in [
        (String::new(), (128 * 1024, 256)),
        ("runtime: {}\n".to_string(), (128 * 1024, 256)),
        ("runtime:\n  h2_server_max_header_list_size_bytes: 12345\n  h2_server_max_concurrent_streams: 7\n".to_string(), (12345, 7)),
        ("runtime:\n  h2_server_max_header_list_size_bytes: 1\n  h2_server_max_concurrent_streams: 1\n".to_string(), (1, 1)),
        (format!("runtime:\n  h2_server_max_header_list_size_bytes: {0}\n  h2_server_max_concurrent_streams: {0}\n", u32::MAX), (u32::MAX, u32::MAX)),
    ] {
        write_config(&cfg, &format!("{runtime}edges:\n- kind: forward\n  name: forward\n  listen: 127.0.0.1:18080\n  default_action:\n    type: direct\n")).expect("write");
        let loaded = load_config(&cfg).expect("load config");
        assert_eq!(
            (loaded.runtime.h2_server_max_header_list_size_bytes, loaded.runtime.h2_server_max_concurrent_streams),
            expected
        );
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_config_rejects_invalid_h2_server_limits() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("h2-server-limits-invalid.yaml");
    for field in [
        "h2_server_max_header_list_size_bytes",
        "h2_server_max_concurrent_streams",
    ] {
        for value in ["0", "-1", "4294967296"] {
            write_config(&cfg, &format!("runtime:\n  {field}: {value}\nedges:\n- kind: forward\n  name: forward\n  listen: 127.0.0.1:18080\n  default_action:\n    type: direct\n")).expect("write");
            let err = load_config(&cfg).expect_err("invalid HTTP/2 server limit");
            let diagnostic = if value == "0" {
                format!("runtime.{field} must be >= 1")
            } else {
                "expected u32".to_string()
            };
            assert!(format!("{err:#}").contains(&diagnostic), "{err:#}");
        }
    }
    fs::remove_dir_all(&dir).ok();
}
