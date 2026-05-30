use super::*;

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
        body: full"#,
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
fn load_config_accepts_plaintext_stream_sample_capture() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("stream-sample-capture.yaml");
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
    streaming_requirement: required
    capture:
      plaintext:
        enabled: true
        headers: true
        body: stream_sample
        body_sample_bytes: 4096"#,
    )
    .expect("write");

    let loaded = load_config(&cfg).expect("stream_sample capture should load");
    fs::remove_dir_all(&dir).ok();
    let route = &loaded.reverse_edge_configs()[0].routes[0];
    let capture = route.capture.as_ref().expect("capture");
    assert_eq!(capture.plaintext.body, CaptureBodyMode::StreamSample);
}

#[test]
fn load_config_rejects_oversized_plaintext_stream_sample_capture() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("oversized-stream-sample-capture.yaml");
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
        body: stream_sample
        body_sample_bytes: 1048577"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("oversized stream_sample capture should fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("body_sample_bytes must be <="),
        "unexpected error: {err}"
    );
}

#[test]
fn load_config_rejects_invalid_capture_json_path() {
    let dir = unique_tmp_dir();
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg = dir.join("invalid-capture-json-path.yaml");
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
        body: stream_sample
        body_sample_bytes: 128
        redact:
          json_paths: ["password"]"#,
    )
    .expect("write");

    let err = load_config(&cfg).expect_err("invalid json path should fail");
    fs::remove_dir_all(&dir).ok();
    assert!(
        err.to_string().contains("json_paths[] is invalid"),
        "unexpected error: {err}"
    );
}
