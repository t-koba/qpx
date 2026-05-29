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
            device_id: Some("x-device".to_string()),
            posture: Some("x-posture".to_string()),
            tenant: Some("x-tenant".to_string()),
            auth_strength: Some("x-strength".to_string()),
            idp: Some("x-idp".to_string()),
        }),
        map: None,
        assertion: None,
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
        ext_authz: None,
    };
    let overlay = PolicyContextConfig {
        identity_sources: vec!["b".into(), "c".into()],
        ext_authz: None,
    };
    let merged = EffectivePolicyContext::merged(Some(&base), Some(&overlay));
    assert_eq!(merged.identity_sources, vec!["a", "b", "c"]);
}

#[test]
fn merged_overlay_ext_authz() {
    let base = PolicyContextConfig {
        identity_sources: Vec::new(),
        ext_authz: Some("base".into()),
    };
    let overlay = PolicyContextConfig {
        identity_sources: Vec::new(),
        ext_authz: Some("overlay".into()),
    };
    assert_eq!(
        EffectivePolicyContext::merged(Some(&base), Some(&overlay))
            .ext_authz
            .as_deref(),
        Some("overlay")
    );
}

#[test]
fn from_single_none() {
    let policy = EffectivePolicyContext::from_single(None);
    assert!(policy.identity_sources.is_empty());
    assert!(policy.ext_authz.is_none());
}

#[test]
fn sanitize_strips_untrusted_headers() {
    let state = runtime_with_sources(vec![trusted_headers_source("headers", vec!["10.0.0.0/8"])]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["headers".into()],
        ext_authz: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-user", "alice".parse().unwrap());
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        &mut headers,
    )
    .unwrap();
    assert!(!headers.contains_key("x-user"));
}

#[test]
fn sanitize_strips_global_untrusted_headers_even_when_policy_does_not_use_source() {
    let state = runtime_with_sources(vec![trusted_headers_source(
        "global-dangerous",
        vec!["10.0.0.0/8"],
    )]);
    let policy = EffectivePolicyContext {
        identity_sources: Vec::new(),
        ext_authz: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-user", "alice".parse().unwrap());
    headers.insert("x-groups", "eng".parse().unwrap());
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        &mut headers,
    )
    .unwrap();
    assert!(!headers.contains_key("x-user"));
    assert!(!headers.contains_key("x-groups"));
}

#[test]
fn sanitize_preserves_trusted_headers() {
    let state = runtime_with_sources(vec![trusted_headers_source(
        "headers",
        vec!["127.0.0.1/32"],
    )]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["headers".into()],
        ext_authz: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-user", "alice".parse().unwrap());
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &mut headers,
    )
    .unwrap();
    assert_eq!(headers.get("x-user").unwrap(), "alice");
}

#[test]
fn sanitize_strips_header_untrusted_by_any_declaring_source() {
    let state = runtime_with_sources(vec![
        trusted_headers_source("trusted-for-peer", vec!["127.0.0.1/32"]),
        trusted_headers_source("untrusted-for-peer", vec!["10.0.0.0/8"]),
    ]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["trusted-for-peer".into()],
        ext_authz: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-user", "alice".parse().unwrap());
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &mut headers,
    )
    .unwrap();
    assert!(!headers.contains_key("x-user"));
}

#[test]
fn sanitize_empty_headers() {
    let state = runtime_with_sources(vec![trusted_headers_source(
        "headers",
        vec!["127.0.0.1/32"],
    )]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["headers".into()],
        ext_authz: None,
    };
    let mut headers = HeaderMap::new();
    sanitize_headers_for_policy(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &mut headers,
    )
    .unwrap();
    assert!(headers.is_empty());
}

#[test]
fn resolve_identity_extracts_trusted_headers() {
    let state = runtime_with_sources(vec![trusted_headers_source(
        "headers",
        vec!["127.0.0.1/32"],
    )]);
    let policy = EffectivePolicyContext {
        identity_sources: vec!["headers".into()],
        ext_authz: None,
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-user", "alice".parse().unwrap());
    headers.insert("x-groups", "eng, ops, eng".parse().unwrap());
    let identity = resolve_identity(
        &state,
        &policy,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(&headers),
        None,
    )
    .unwrap();
    assert_eq!(identity.user.as_deref(), Some("alice"));
    assert_eq!(identity.groups, vec!["eng".to_string(), "ops".to_string()]);
    assert_eq!(identity.identity_source.as_deref(), Some("headers"));
}
