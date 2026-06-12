use super::*;
use crate::runtime::Runtime;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hyper::HeaderMap;
use hyper::header::HeaderValue;
use qpx_core::config::{
    ActionConfig, ActionKind, AuthConfig, Config, DecisionConfig, HttpGlobalConfig, IdentityConfig,
    IngressEdgeConfig, IngressEdgeMode, LocalUser, MatchConfig, MessagesConfig, RuleAuthConfig,
    RuleConfig, RuntimeConfig, SecurityConfig, StreamingRequirement, TelemetryConfig,
    TrafficConfig, UnknownLengthExactSizePolicy,
};

#[tokio::test]
async fn groups_mismatch_continues_to_next_rule() {
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig {
            unknown_length_exact_size: UnknownLengthExactSizePolicy::Buffer,
            ..RuntimeConfig::default()
        },
        telemetry: TelemetryConfig::default(),
        security: SecurityConfig {
            auth: AuthConfig {
                users: vec![LocalUser {
                    username: "user".to_string(),
                    password: Some("pass".to_string()),
                    ha1: None,
                }],
                ldap: None,
            },
            identity_sources: Vec::new(),
            decisions: DecisionConfig::default(),
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: HttpGlobalConfig::default(),
        traffic: TrafficConfig::default(),
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: vec![
                RuleConfig {
                    name: "grouped".to_string(),
                    r#match: None,
                    auth: Some(RuleAuthConfig {
                        require: vec!["local".to_string()],
                        groups: vec!["dev".to_string()],
                    }),
                    action: Some(ActionConfig {
                        kind: ActionKind::Block,
                        upstream: None,
                        local_response: None,
                    }),
                    headers: None,
                    rate_limit: None,
                },
                RuleConfig {
                    name: "fallback".to_string(),
                    r#match: None,
                    auth: None,
                    action: Some(ActionConfig {
                        kind: ActionKind::Direct,
                        upstream: None,
                        local_response: None,
                    }),
                    headers: None,
                    rate_limit: None,
                },
            ],
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    };

    let runtime = Runtime::new(config).expect("runtime");

    let credentials = BASE64.encode("user:pass");
    let mut headers = HeaderMap::new();
    headers.insert(
        "proxy-authorization",
        HeaderValue::from_str(format!("Basic {}", credentials).as_str()).unwrap(),
    );

    let ctx = RuleMatchContext {
        src_ip: None,
        dst_port: None,
        host: None,
        sni: None,
        method: Some("GET"),
        path: Some("/"),
        headers: None,
        user: None,
        user_groups: &[],
        device_id: None,
        posture: &[],
        tenant: None,
        auth_strength: None,
        idp: None,
        ..Default::default()
    };

    let decision = evaluate_forward_policy(
        &runtime,
        "forward",
        ctx,
        &headers,
        "GET",
        "http://example.com/",
    )
    .await
    .expect("policy");
    match decision {
        ForwardPolicyDecision::Allow(policy) => {
            assert!(matches!(policy.action.kind, ActionKind::Direct));
        }
        _ => panic!("unexpected decision"),
    }
}

#[tokio::test]
async fn staged_policy_does_not_request_body_for_later_size_rule_after_header_match() {
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig {
            unknown_length_exact_size: UnknownLengthExactSizePolicy::Buffer,
            ..RuntimeConfig::default()
        },
        telemetry: TelemetryConfig::default(),
        security: SecurityConfig::default(),
        http: HttpGlobalConfig::default(),
        traffic: TrafficConfig::default(),
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: None,
            rules: vec![
                RuleConfig {
                    name: "body-dependent-nonmatch".to_string(),
                    r#match: Some(MatchConfig {
                        host: vec!["other.example".to_string()],
                        request_size: vec![">=1".to_string()],
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
                },
                RuleConfig {
                    name: "body-dependent-auth-nonmatch".to_string(),
                    r#match: Some(MatchConfig {
                        host: vec!["example.com".to_string()],
                        request_size: vec![">=1".to_string()],
                        ..Default::default()
                    }),
                    auth: Some(RuleAuthConfig {
                        require: Vec::new(),
                        groups: vec!["dev".to_string()],
                    }),
                    action: Some(ActionConfig {
                        kind: ActionKind::Block,
                        upstream: None,
                        local_response: None,
                    }),
                    headers: None,
                    rate_limit: None,
                },
                RuleConfig {
                    name: "method-first".to_string(),
                    r#match: Some(MatchConfig {
                        method: vec!["GET".to_string()],
                        ..Default::default()
                    }),
                    auth: None,
                    action: Some(ActionConfig {
                        kind: ActionKind::Direct,
                        upstream: None,
                        local_response: None,
                    }),
                    headers: None,
                    rate_limit: None,
                },
                RuleConfig {
                    name: "size-later".to_string(),
                    r#match: Some(MatchConfig {
                        request_size: vec![">=1".to_string()],
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
                },
            ],
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let headers = HeaderMap::new();
    let ctx = RuleMatchContext {
        method: Some("GET"),
        host: Some("example.com"),
        path: Some("/"),
        headers: Some(&headers),
        user_groups: &[],
        posture: &[],
        ..Default::default()
    };

    let decision = evaluate_forward_policy_staged(
        &runtime,
        "forward",
        ctx,
        &headers,
        "GET",
        "http://example.com/",
    )
    .await
    .expect("policy");

    match decision {
        PolicyStage::Decision(ForwardPolicyDecision::Allow(policy)) => {
            assert!(matches!(policy.action.kind, ActionKind::Direct));
            assert_eq!(policy.matched_rule.as_deref(), Some("method-first"));
        }
        PolicyStage::Observe(_) => {
            panic!("later request_size rule should not force observation")
        }
        _ => panic!("unexpected policy decision"),
    }
}
