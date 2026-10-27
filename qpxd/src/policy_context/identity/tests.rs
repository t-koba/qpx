use super::*;
use crate::runtime::RuntimeState;
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, AuthConfig, Config, DecisionConfig, HttpGlobalConfig,
    IdentityConfig, MessagesConfig, RuntimeConfig, SecurityConfig, SystemLogConfig,
    TelemetryConfig, TrafficConfig,
};
use std::net::{IpAddr, Ipv4Addr};

fn trusted_headers_source(name: &str, trusted_peers: Vec<&str>) -> IdentitySourceConfig {
    IdentitySourceConfig {
        name: name.to_string(),
        kind: IdentitySourceKind::TrustedHeaders,
        from: qpx_core::config::IdentitySourceFromConfig {
            trusted_peers: trusted_peers.into_iter().map(str::to_string).collect(),
            client_ca: None,
        },
        headers: Some(IdentitySourceHeadersConfig {
            user: Some("x-user".to_string()),
            groups: Some("x-groups".to_string()),
            roles: Some("x-roles".to_string()),
            entitlements: Some("x-entitlements".to_string()),
            device_id: Some("x-device".to_string()),
            posture: Some("x-posture".to_string()),
            tenant: Some("x-tenant".to_string()),
            auth_strength: Some("x-strength".to_string()),
            idp: Some("x-idp".to_string()),
        }),
        map: None,
        assertion: None,
        bearer: None,
        strip_from_untrusted: true,
    }
}

fn runtime_with_sources(sources: Vec<IdentitySourceConfig>) -> RuntimeState {
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        telemetry: TelemetryConfig {
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: SecurityConfig {
            auth: AuthConfig::default(),
            identity_sources: sources,
            decisions: DecisionConfig::default(),
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: HttpGlobalConfig::default(),
        traffic: TrafficConfig::default(),
        acme: None,
        edges: Vec::new(),
        upstreams: Vec::new(),
        caches: Vec::new(),
    };
    RuntimeState::build(config).expect("runtime")
}

#[test]
fn merged_deduplicates_sources() {
    let base = PolicyContextConfig {
        identity_sources: vec!["a".into(), "b".into()],
        decision_service: None,
    };
    let overlay = PolicyContextConfig {
        identity_sources: vec!["b".into(), "c".into()],
        decision_service: None,
    };
    let merged = EffectivePolicyContext::merged(Some(&base), Some(&overlay));
    assert_eq!(merged.identity_sources, vec!["a", "b", "c"]);
}

#[test]
fn merged_overlay_decision_service() {
    let base = PolicyContextConfig {
        identity_sources: Vec::new(),
        decision_service: Some("base".into()),
    };
    let overlay = PolicyContextConfig {
        identity_sources: Vec::new(),
        decision_service: Some("overlay".into()),
    };
    assert_eq!(
        EffectivePolicyContext::merged(Some(&base), Some(&overlay))
            .decision_service
            .as_deref(),
        Some("overlay")
    );
}

#[test]
fn from_single_none() {
    let policy = EffectivePolicyContext::from_single(None);
    assert!(policy.identity_sources.is_empty());
    assert!(policy.decision_service.is_none());
}

#[test]
fn sanitize_strips_untrusted_headers() {
    let state = runtime_with_sources(vec![trusted_headers_source("headers", vec!["10.0.0.0/8"])]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["headers".into()],
        decision_service: None,
    };
    let mut request = http::Request::new(());
    let headers = request.headers_mut();
    headers.insert("x-user", "alice".parse().unwrap());
    let mut headers = qpx_core::http_message::Request::from_http(request)
        .headers()
        .clone();
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        &mut headers,
    )
    .unwrap();
    assert!(!headers.contains_key(&OrdinaryHeaderName::try_from("x-user").unwrap()));
}

#[test]
fn sanitize_strips_global_untrusted_headers_even_when_policy_does_not_use_source() {
    let state = runtime_with_sources(vec![trusted_headers_source(
        "global-dangerous",
        vec!["10.0.0.0/8"],
    )]);
    let policy = EffectivePolicyContext {
        identity_sources: Vec::new(),
        decision_service: None,
    };
    let mut request = http::Request::new(());
    let headers = request.headers_mut();
    headers.insert("x-user", "alice".parse().unwrap());
    headers.insert("x-groups", "eng".parse().unwrap());
    let mut headers = qpx_core::http_message::Request::from_http(request)
        .headers()
        .clone();
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        &mut headers,
    )
    .unwrap();
    assert!(!headers.contains_key(&OrdinaryHeaderName::try_from("x-user").unwrap()));
    assert!(!headers.contains_key(&OrdinaryHeaderName::try_from("x-groups").unwrap()));
}

#[test]
fn sanitize_preserves_trusted_headers() {
    let state = runtime_with_sources(vec![trusted_headers_source(
        "headers",
        vec!["127.0.0.1/32"],
    )]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["headers".into()],
        decision_service: None,
    };
    let mut request = http::Request::new(());
    let headers = request.headers_mut();
    headers.insert("x-user", "alice".parse().unwrap());
    let mut headers = qpx_core::http_message::Request::from_http(request)
        .headers()
        .clone();
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &mut headers,
    )
    .unwrap();
    assert_eq!(
        headers
            .get(&OrdinaryHeaderName::try_from("x-user").unwrap())
            .unwrap(),
        "alice"
    );
}

#[test]
fn sanitize_strips_header_untrusted_by_any_declaring_source() {
    let state = runtime_with_sources(vec![
        trusted_headers_source("trusted-for-peer", vec!["127.0.0.1/32"]),
        trusted_headers_source("untrusted-for-peer", vec!["10.0.0.0/8"]),
    ]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["trusted-for-peer".into()],
        decision_service: None,
    };
    let mut request = http::Request::new(());
    let headers = request.headers_mut();
    headers.insert("x-user", "alice".parse().unwrap());
    let mut headers = qpx_core::http_message::Request::from_http(request)
        .headers()
        .clone();
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &mut headers,
    )
    .unwrap();
    assert!(!headers.contains_key(&OrdinaryHeaderName::try_from("x-user").unwrap()));
}

#[test]
fn sanitize_empty_headers() {
    let state = runtime_with_sources(vec![trusted_headers_source(
        "headers",
        vec!["127.0.0.1/32"],
    )]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["headers".into()],
        decision_service: None,
    };
    let request = http::Request::new(());
    let mut headers = qpx_core::http_message::Request::from_http(request)
        .headers()
        .clone();
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &mut headers,
    )
    .unwrap();
    assert!(headers.iter().next().is_none());
    assert!(!headers.contains_content_length());
}

#[tokio::test]
async fn resolve_identity_extracts_trusted_headers() {
    let state = runtime_with_sources(vec![trusted_headers_source(
        "headers",
        vec!["127.0.0.1/32"],
    )]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["headers".into()],
        decision_service: None,
    };
    let mut request = http::Request::new(());
    let headers = request.headers_mut();
    headers.insert("x-user", "alice".parse().unwrap());
    headers.append("x-groups", "eng, ops, eng".parse().unwrap());
    headers.append("x-groups", ", ops, ".parse().unwrap());
    headers.append("x-groups", http::HeaderValue::from_bytes(b"\xff").unwrap());
    let headers = qpx_core::http_message::Request::from_http(request)
        .headers()
        .clone();
    let identity = resolve_identity(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(&headers),
        None,
    )
    .await
    .unwrap();
    assert_eq!(identity.user.as_deref(), Some("alice"));
    assert_eq!(identity.groups, vec!["eng".to_string(), "ops".to_string()]);
    assert_eq!(identity.identity_source.as_deref(), Some("headers"));
}

#[tokio::test]
async fn trusted_identity_uses_configured_content_length_literal_values() {
    let mut source = trusted_headers_source("literal", vec!["127.0.0.1/32"]);
    let fields = source.headers.as_mut().unwrap();
    fields.user = Some("Content-Length".into());
    fields.groups = Some("content-length".into());
    let state = runtime_with_sources(vec![source]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["literal".into()],
        decision_service: None,
    };
    let mut ingress = http::Request::new(());
    for value in [&b"\xff"[..], b" ", b" 007, 7, 007, A, a ", b"8, A"] {
        ingress.headers_mut().append(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_bytes(value).unwrap(),
        );
    }
    let request = qpx_core::http_message::Request::from_http(ingress);
    let identity = resolve_identity(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(request.headers()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(identity.user.as_deref(), Some("007, 7, 007, A, a"));
    assert_eq!(identity.groups, ["007", "7", "A", "a", "8"]);
    assert_eq!(identity.identity_source.as_deref(), Some("literal"));
}
