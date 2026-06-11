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
