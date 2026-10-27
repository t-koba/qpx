use super::*;
use crate::test_util::{decode_gzip, spawn_static_http_server};
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
    HttpGuardJsonConfig, HttpGuardLimitsConfig, HttpGuardProfileConfig, IdentityConfig,
    IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig, StreamingConfig,
    StreamingRequirement, SystemLogConfig,
};
use qpx_http::body::to_bytes;
use std::net::{IpAddr, Ipv4Addr};

fn transparent_test_runtime(
    streaming: Option<StreamingConfig>,
    guard_profiles: Vec<HttpGuardProfileConfig>,
    http_guard_profile: Option<String>,
    http_modules: Vec<qpx_core::config::HttpModuleConfig>,
) -> Runtime {
    Runtime::new(Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        telemetry: qpx_core::config::TelemetryConfig {
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: qpx_core::config::SecurityConfig {
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            decisions: qpx_core::config::DecisionConfig {
                services: Vec::new(),
            },
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig {
            guard_profiles,
            ..Default::default()
        },
        traffic: qpx_core::config::TrafficConfig::default(),
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
            name: "transparent".to_string(),
            mode: IngressEdgeMode::Transparent,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            streaming,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            capture: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile,
            destination_resolution: None,
            http_modules,
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime")
}

#[tokio::test]
async fn transparent_http_modules_can_compress_responses() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "text/plain".to_string())],
        "transparent compression".to_string(),
        1,
    )
    .await;
    let runtime = transparent_test_runtime(
        None,
        Vec::new(),
        None,
        vec![
            serde_yaml::from_str(
                r#"type: response_compression
settings:
  min_body_bytes: 1
  max_body_bytes: 65536
  content_types:
    - text/plain
  gzip: true
  brotli: false
  zstd: false
  gzip_level: 6
  brotli_level: 5
  zstd_level: 3"#,
            )
            .expect("http module config"),
        ],
    );
    let request = hyper::Request::builder()
        .method(http::Method::GET)
        .uri(format!("http://{upstream_addr}/asset"))
        .header("host", upstream_addr.to_string())
        .header("accept-encoding", "gzip")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = dispatch_transparent_request(
        Request::from_http(request),
        runtime,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        None,
        "transparent",
    )
    .await
    .expect("response");

    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        Some("gzip")
    );
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(decode_gzip(body.as_ref()), "transparent compression");
}

#[tokio::test]
async fn transparent_early_response_respects_response_body_cap() {
    let runtime = transparent_test_runtime(
        Some(StreamingConfig {
            max_response_body_bytes: Some(1),
            ..Default::default()
        }),
        vec![HttpGuardProfileConfig {
            name: "early-cap".to_string(),
            normalize: Default::default(),
            protocol_safety: Default::default(),
            limits: HttpGuardLimitsConfig {
                body_bytes: Some(1),
                ..Default::default()
            },
            json: HttpGuardJsonConfig {
                max_depth: Some(1),
                ..Default::default()
            },
            multipart: Default::default(),
        }],
        Some("early-cap".to_string()),
        Vec::new(),
    );
    let request = hyper::Request::builder()
        .method(http::Method::POST)
        .uri("http://example.com/")
        .header("host", "example.com")
        .header("content-type", "application/json")
        .version(http::Version::HTTP_11)
        .body(Body::from("{}"))
        .expect("request");

    let response = dispatch_transparent_request(
        Request::from_http(request),
        runtime,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
        None,
        "transparent",
    )
    .await
    .expect("response");

    assert_eq!(response.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        response
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .is_none(),
        "truncated early response must not retain a stale Content-Length"
    );
    // The 22-byte rejection body is capped to `max_response_body_bytes = 1` via
    // `limit_response_body_for_plan`, which enforces the limit as a read cap:
    // collecting past the first byte surfaces `response body limit exceeded`.
    match to_bytes(response.into_body()).await {
        Ok(body) => assert_eq!(
            body.len(),
            1,
            "early response body must be capped to 1 byte"
        ),
        Err(err) => assert!(
            err.to_string().contains("response body limit exceeded"),
            "capped early response must enforce the 1-byte limit, got: {err}"
        ),
    }
}
