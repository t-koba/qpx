use super::extended::normalize_h2_upstream_connect_headers;
use super::*;
use crate::tls::TlsClientHelloInfo;
use http::{HeaderMap, Uri};
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CertificateMatchConfig,
    Config, IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MatchConfig, MessagesConfig,
    RuleConfig, RuntimeConfig, SystemLogConfig, TlsFingerprintMatchConfig,
};
use qpx_core::tls::UpstreamCertificateInfo;

fn connect_runtime() -> Runtime {
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
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Tunnel,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: vec![RuleConfig {
                name: "inspect-ja4".to_string(),
                r#match: Some(MatchConfig {
                    tls_fingerprint: Some(TlsFingerprintMatchConfig {
                        ja3: Vec::new(),
                        ja4: vec!["t13dh2_03_05_02".to_string()],
                    }),
                    ..Default::default()
                }),
                auth: None,
                action: Some(ActionConfig {
                    kind: ActionKind::Inspect,
                    upstream: None,
                    local_response: None,
                }),
                headers: None,
                rate_limit: None,
            }],
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: None,
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime")
}

#[tokio::test]
async fn connect_client_hello_policy_can_upgrade_tunnel_to_inspect() {
    let runtime = connect_runtime();
    let sanitized_headers = HeaderMap::new();
    let identity = crate::policy_context::ResolvedIdentity::default();
    let client_hello = TlsClientHelloInfo {
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
        tls_version: Some("tls1.3".to_string()),
        ja3: Some("771,4865-4866-4867,0-10-16-43-45,29-23,0".to_string()),
        ja4: Some("t13dh2_03_05_02".to_string()),
    };
    let action = decide_connect_action_from_client_hello(ConnectPolicyInput {
        runtime: &runtime,
        listener_name: "forward",
        remote_addr: SocketAddr::from(([127, 0, 0, 1], 12345)),
        host: "example.com",
        port: 443,
        authority: "example.com:443",
        sanitized_headers: &sanitized_headers,
        identity: &identity,
        client_hello: &client_hello,
        upstream_cert: None,
    })
    .await
    .expect("action");
    assert!(matches!(action.kind, ActionKind::Inspect));
}

#[tokio::test]
async fn connect_upstream_cert_policy_can_block_after_client_hello() {
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
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Tunnel,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: vec![RuleConfig {
                name: "block-present-upstream-cert".to_string(),
                r#match: Some(MatchConfig {
                    upstream_cert: Some(CertificateMatchConfig {
                        present: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                auth: None,
                action: Some(ActionConfig {
                    kind: ActionKind::Block,
                    upstream: None,
                    local_response: None,
                }),
                headers: None,
                rate_limit: None,
            }],
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: None,
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");
    let sanitized_headers = HeaderMap::new();
    let identity = crate::policy_context::ResolvedIdentity::default();
    let client_hello = TlsClientHelloInfo {
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
        tls_version: Some("tls1.3".to_string()),
        ja3: Some("771,4865-4866-4867,0-10-16-43-45,29-23,0".to_string()),
        ja4: Some("t13dh2_03_05_02".to_string()),
    };
    let upstream_cert = UpstreamCertificateInfo {
        present: true,
        ..Default::default()
    };

    let action = decide_connect_action_from_tls_metadata(ConnectPolicyInput {
        runtime: &runtime,
        listener_name: "forward",
        remote_addr: SocketAddr::from(([127, 0, 0, 1], 12345)),
        host: "example.com",
        port: 443,
        authority: "example.com:443",
        sanitized_headers: &sanitized_headers,
        identity: &identity,
        client_hello: &client_hello,
        upstream_cert: Some(&upstream_cert),
    })
    .await
    .expect("action");
    assert!(matches!(action.kind, ActionKind::Block));
}

#[tokio::test]
async fn normalize_h2_upstream_connect_headers_strips_proxy_auth_and_adds_via() {
    let uri: Uri = "https://example.com:443/chat".parse().expect("uri");
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::PROXY_AUTHORIZATION,
        http::HeaderValue::from_static("Basic abc"),
    );
    headers.insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("keep-alive"),
    );

    let normalized = normalize_h2_upstream_connect_headers(&uri, &headers, "qpx").expect("headers");
    assert!(
        normalized
            .get(::http::header::PROXY_AUTHORIZATION)
            .is_none()
    );
    assert!(normalized.get(::http::header::CONNECTION).is_none());
    assert_eq!(
        normalized
            .get(::http::header::VIA)
            .and_then(|value| value.to_str().ok()),
        Some("2 qpx")
    );
    assert_eq!(
        normalized
            .get(::http::header::HOST)
            .and_then(|value| value.to_str().ok()),
        Some("example.com:443")
    );
}
