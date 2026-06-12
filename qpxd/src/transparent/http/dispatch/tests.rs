use super::*;
use crate::test_util::{decode_gzip, spawn_static_http_server};
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config, IdentityConfig,
    IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig, StreamingRequirement,
    SystemLogConfig,
};
use qpx_http::body::to_bytes;
use std::net::{IpAddr, Ipv4Addr};

#[tokio::test]
async fn transparent_http_modules_can_compress_responses() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "text/plain".to_string())],
        "transparent compression".to_string(),
        1,
    )
    .await;
    let runtime = Runtime::new(Config {
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
                ext_authz: Vec::new(),
            },
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
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
            streaming: None,
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
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: vec![
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
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");
    let request = Request::builder()
        .method(http::Method::GET)
        .uri(format!("http://{upstream_addr}/asset"))
        .header("host", upstream_addr.to_string())
        .header("accept-encoding", "gzip")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = dispatch_transparent_request(
        request,
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
