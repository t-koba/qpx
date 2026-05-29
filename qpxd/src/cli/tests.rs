use super::*;
use crate::cli_render::{render_explain_plan, render_match_plan};
use crate::runtime::{RuntimePlan, RuntimeState};
use crate::startup::init_template_yaml;
use anyhow::Result;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn render_test_match_plan(
    plan: &RuntimePlan,
    edge: &str,
    ctx: qpx_core::rules::RuleMatchContext<'_>,
) -> Result<String> {
    render_match_plan(plan, crate::cli_render::MatchPlanRequest { edge, ctx })
}

#[test]
fn init_templates_are_valid_canonical_configs() {
    for template in [
        InitTemplate::ReverseBasic,
        InitTemplate::ForwardEgress,
        InitTemplate::TransparentLinux,
        InitTemplate::IpcGateway,
        InitTemplate::TrustedIdentityExtAuthz,
    ] {
        let path = temp_config_path(template);
        fs::write(&path, init_template_yaml(template)).expect("write template config");
        let loaded = qpx_core::config::load_config(&path)
            .unwrap_or_else(|err| panic!("{template:?} template failed to load: {err:?}"));
        let _runtime = RuntimeState::build(loaded)
            .unwrap_or_else(|err| panic!("{template:?} template failed runtime build: {err:?}"));
        let _ = fs::remove_file(path);
    }
}

#[test]
fn schema_command_covers_canonical_cli_surface() {
    let schema = qpx_core::config::canonical_schema_value();
    assert_eq!(
        schema
            .pointer("/$schema")
            .and_then(serde_json::Value::as_str),
        Some("https://json-schema.org/draft/2020-12/schema")
    );
    assert_eq!(
        schema
            .pointer("/required/0")
            .and_then(serde_json::Value::as_str),
        Some("edges")
    );
    assert!(schema.pointer("/$defs/capturePolicy").is_some());
    assert!(schema.pointer("/$defs/routeTarget/oneOf").is_some());
    assert!(schema.pointer("/$defs/ipcBodyLimit").is_some());
    assert!(schema.pointer("/$defs/originalDst").is_some());
    assert_eq!(
        schema
            .pointer("/$defs/httpModule/additionalProperties")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert!(
        schema
            .pointer("/$defs/httpModule/properties/settings")
            .is_some()
    );
    assert!(schema.pointer("/properties/edges/items/oneOf").is_some());

    let json = serde_json::to_string_pretty(&schema).expect("json schema render");
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"reverse\""));
    assert!(json.contains("\"original_dst\""));
    assert!(json.contains("\"max_request_bytes\""));
    assert!(json.contains("\"module_chains\""));

    let yaml = serde_yaml::to_string(&schema).expect("yaml schema render");
    assert!(yaml.contains("capturePolicy"));
    assert!(yaml.contains("routeTarget"));
}

#[test]
fn explain_renderer_uses_compiled_runtime_plan_flags() {
    let state = runtime_state_from_template(InitTemplate::ReverseBasic);
    let output = render_explain_plan(state.plan.as_ref(), Some("public-http"), Some("app"));

    assert!(output.contains("edge public-http"));
    assert!(output.contains("  kind: reverse"));
    assert!(output.contains("  route app match_criteria"));
    assert!(output.contains("    host"));
    assert!(output.contains("      mode: exact"));
    assert!(output.contains("  route app target"));
    assert!(output.contains("    type: upstream"));
    assert!(output.contains("  route app"));
    assert!(output.contains("    cache_lookup: off"));
    assert!(output.contains("    capture_plaintext: off"));
}

#[test]
fn explain_renderer_reports_buffering_reasons() {
    let state = runtime_state_from_yaml(
        "buffering-reasons",
        r#"runtime:
  unknown_length_exact_size: buffer
edges:
- kind: reverse
  name: public-http
  listen: 127.0.0.1:18080
  routes:
  - name: inspect
    streaming_requirement: preferred
    match:
      request_size: [">1m"]
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
    capture:
      plaintext:
        enabled: true
        headers: true
        body: full
        max_body_bytes: 4096
"#,
    );
    let output = render_explain_plan(state.plan.as_ref(), Some("public-http"), Some("inspect"));

    assert!(output.contains("    buffering"));
    assert!(output.contains("      mode: explicit"));
    assert!(output.contains("        - request.size_exact_unknown"));
    assert!(!output.contains("        - capture.body_full"));
}

#[test]
fn match_renderer_uses_compiled_matchers() {
    let state = runtime_state_from_template(InitTemplate::ReverseBasic);
    let matched = render_test_match_plan(
        state.plan.as_ref(),
        "public-http",
        qpx_core::rules::RuleMatchContext {
            host: Some("localhost"),
            method: Some("GET"),
            path: Some("/"),
            ..Default::default()
        },
    )
    .expect("match render");
    assert!(matched.contains("edge: public-http"));
    assert!(matched.contains("kind: reverse"));
    assert!(matched.contains("route: app"));
    assert!(matched.contains("matched_by\n"));
    assert!(matched.contains("  host\n"));
    assert!(matched.contains("    mode: exact\n"));
    assert!(matched.contains("    configured: localhost\n"));
    assert!(matched.contains("    actual: localhost\n"));
    assert!(matched.contains("    result: on\n"));
    assert!(matched.contains("target"));
    assert!(matched.contains("type: upstream"));

    let missed = render_test_match_plan(
        state.plan.as_ref(),
        "public-http",
        qpx_core::rules::RuleMatchContext {
            host: Some("example.invalid"),
            method: Some("GET"),
            path: Some("/"),
            ..Default::default()
        },
    )
    .expect("match render");
    assert!(missed.contains("route: <no match>"));
}

#[test]
fn match_renderer_reports_reverse_forward_and_transparent_reasons() {
    let state = runtime_state_from_yaml(
        "trace",
        r#"
edges:
- kind: reverse
  name: trace-reverse
  listen: 127.0.0.1:0
  routes:
  - name: api
    match:
      src_ip: [10.0.0.0/8]
      sni: [api.example.com]
      host: [api.example.com]
      method: [GET]
      path:
      - /v1/*
      - /files/*.json
      - re:^/v[0-9]+/users$
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
- kind: forward
  name: trace-forward
  listen: 127.0.0.1:0
  default_action:
    type: block
  rules:
  - name: upload
    match:
      src_ip: [192.0.2.0/24]
      method: [POST]
      path: [/upload/*]
    action:
      type: direct
- kind: transparent
  name: trace-transparent
  listen: 127.0.0.1:0
  original_dst:
    source: linux_so_original_dst
  default_action:
    type: block
  rules:
  - name: internal
    match:
      host: [internal.example.com]
      dst_port: [8080]
    action:
      type: direct
"#,
    );

    let reverse = render_test_match_plan(
        state.plan.as_ref(),
        "trace-reverse",
        qpx_core::rules::RuleMatchContext {
            src_ip: Some("10.1.2.3".parse().expect("ip")),
            sni: Some("api.example.com"),
            host: Some("api.example.com"),
            method: Some("GET"),
            path: Some("/v2/users"),
            ..Default::default()
        },
    )
    .expect("reverse match");
    assert!(reverse.contains("route: api"));
    assert!(reverse.contains("  src_ip\n"));
    assert!(reverse.contains("    mode: cidr\n"));
    assert!(reverse.contains("  sni\n"));
    assert!(reverse.contains("  host\n"));
    assert!(reverse.contains("  method\n"));
    assert!(reverse.contains("    mode: prefix\n"));
    assert!(reverse.contains("    mode: glob\n"));
    assert!(reverse.contains("    mode: regex\n"));

    let forward = render_test_match_plan(
        state.plan.as_ref(),
        "trace-forward",
        qpx_core::rules::RuleMatchContext {
            src_ip: Some("192.0.2.44".parse().expect("ip")),
            method: Some("POST"),
            path: Some("/upload/file"),
            ..Default::default()
        },
    )
    .expect("forward match");
    assert!(forward.contains("kind: forward"));
    assert!(forward.contains("rule: upload"));
    assert!(forward.contains("  src_ip\n"));
    assert!(forward.contains("  path\n"));

    let transparent = render_test_match_plan(
        state.plan.as_ref(),
        "trace-transparent",
        qpx_core::rules::RuleMatchContext {
            dst_port: Some(8080),
            host: Some("internal.example.com"),
            method: Some("GET"),
            path: Some("/"),
            ..Default::default()
        },
    )
    .expect("transparent match");
    assert!(transparent.contains("kind: transparent"));
    assert!(transparent.contains("rule: internal"));
    assert!(transparent.contains("  host\n"));
    assert!(transparent.contains("  dst_port\n"));
}

#[test]
fn explain_renderer_reports_all_reverse_target_kinds_and_generated_route_id() {
    let state = runtime_state_from_yaml(
        "target-kinds",
        r#"
edges:
- kind: reverse
  name: targets
  listen: 127.0.0.1:0
  tls:
    certificates:
    - sni: fallback.example.com
      cert: /tmp/qpx-test.crt
      key: /tmp/qpx-test.key
  routes:
  - match:
      host: [upstream.example.com]
    target:
      type: upstream
      upstreams: [http://127.0.0.1:8080]
  - name: weighted
    match:
      host: [weighted.example.com]
    target:
      type: weighted
      backends:
      - name: stable
        weight: 90
        upstreams: [http://127.0.0.1:8081]
      - name: canary
        weight: 10
        upstreams: [http://127.0.0.1:8082]
  - name: ipc
    match:
      host: [ipc.example.com]
    target:
      type: ipc
      endpoint: 127.0.0.1:19090
      mode: tcp
  - name: local
    match:
      host: [local.example.com]
    target:
      type: local_response
      response:
        status: 204
  tls_passthrough_routes:
  - match:
      dst_port: [443]
      sni: [tls.example.com]
    upstreams: [127.0.0.1:8443]
"#,
    );

    let output = render_explain_plan(state.plan.as_ref(), Some("targets"), None);
    assert!(output.contains("  route route[0] match_criteria"));
    assert!(output.contains("  route route[0] target"));
    assert!(output.contains("    type: upstream"));
    assert!(output.contains("  route weighted target"));
    assert!(output.contains("    type: weighted"));
    assert!(output.contains("  route ipc target"));
    assert!(output.contains("    type: ipc"));
    assert!(output.contains("  route local target"));
    assert!(output.contains("    type: local_response"));
    assert!(output.contains("  route tls_passthrough[0] target"));
    assert!(output.contains("    type: tls_passthrough"));
}

fn runtime_state_from_template(template: InitTemplate) -> RuntimeState {
    let path = temp_config_path(template);
    fs::write(&path, init_template_yaml(template)).expect("write template config");
    let loaded = qpx_core::config::load_config(&path).expect("template config loads");
    let _ = fs::remove_file(path);
    RuntimeState::build(loaded).expect("template runtime builds")
}

fn runtime_state_from_yaml(name: &str, yaml: &str) -> RuntimeState {
    let mut path = std::env::temp_dir();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    path.push(format!("qpxd-cli-{name}-{}-{now}.yaml", std::process::id()));
    fs::write(&path, yaml).expect("write config");
    let loaded = qpx_core::config::load_config(&path).expect("config loads");
    let _ = fs::remove_file(path);
    RuntimeState::build(loaded).expect("runtime builds")
}

fn temp_config_path(template: InitTemplate) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    path.push(format!(
        "qpxd-cli-template-{}-{}-{template:?}.yaml",
        std::process::id(),
        now
    ));
    path
}
