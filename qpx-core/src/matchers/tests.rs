use super::*;
use crate::config::{
    DestinationDimensionMatchConfig, DestinationMatchConfig, HeaderMatch, MatchConfig,
    RpcMatchConfig,
};
use crate::prefilter::StringInterner;
use crate::rules::RuleMatchContext;
use http::HeaderMap;
use http::HeaderValue;

#[test]
fn compiled_match_method_is_case_insensitive() {
    let cfg = MatchConfig {
        method: vec!["get".to_string()],
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let ctx = RuleMatchContext {
        src_ip: None,
        dst_port: None,
        host: None,
        sni: None,
        method: Some("GET"),
        path: None,
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
    assert!(compiled.matches(&ctx));
}

#[test]
fn compiled_match_path_requires_path() {
    let cfg = MatchConfig {
        path: vec!["/foo".to_string()],
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let ctx = RuleMatchContext {
        src_ip: None,
        dst_port: None,
        host: None,
        sni: None,
        method: None,
        path: None,
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
    assert!(!compiled.matches(&ctx));
}

#[test]
fn compiled_match_supports_destination_source_and_confidence() {
    let cfg = MatchConfig {
        destination: Some(DestinationMatchConfig {
            category: Some(DestinationDimensionMatchConfig {
                value: vec!["ai".to_string()],
                source: vec!["host".to_string()],
                confidence: vec![">=90".to_string()],
            }),
            reputation: None,
            application: Some(DestinationDimensionMatchConfig {
                value: vec!["https".to_string()],
                source: vec!["heuristic".to_string()],
                confidence: vec!["40".to_string()],
            }),
        }),
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let ctx = RuleMatchContext {
        destination_category: Some("ai"),
        destination_category_source: Some("host"),
        destination_category_confidence: Some(100),
        destination_application: Some("https"),
        destination_application_source: Some("heuristic"),
        destination_application_confidence: Some(40),
        ..Default::default()
    };
    assert!(compiled.matches(&ctx));
}

#[test]
fn compiled_match_trace_reports_exact_prefix_glob_regex_and_cidr() {
    let cfg = MatchConfig {
        src_ip: vec!["10.0.0.0/8".to_string()],
        host: vec!["api.example.com".to_string()],
        method: vec!["GET".to_string()],
        path: vec![
            "/v1/*".to_string(),
            "/files/*.json".to_string(),
            "re:^/v[0-9]+/users$".to_string(),
        ],
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let ctx = RuleMatchContext {
        src_ip: Some("10.1.2.3".parse().expect("ip")),
        host: Some("api.example.com"),
        method: Some("GET"),
        path: Some("/v1/users"),
        ..Default::default()
    };

    let trace = compiled.matches_with_trace(&ctx);

    assert!(trace.result);
    assert!(
        trace
            .reasons
            .iter()
            .any(|reason| matches!(reason, MatchReason::SrcIp { result: true, .. }))
    );
    assert!(trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Host {
            mode: MatchMode::Exact,
            result: true,
            ..
        }
    )));
    assert!(trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Path {
            mode: MatchMode::Prefix,
            result: true,
            ..
        }
    )));
    assert!(trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Path {
            mode: MatchMode::Glob,
            ..
        }
    )));
    assert!(trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Path {
            mode: MatchMode::Regex,
            ..
        }
    )));
}

#[test]
fn compiled_match_supports_rpc_request_fields() {
    let cfg = MatchConfig {
        rpc: Some(RpcMatchConfig {
            protocol: vec!["grpc".to_string()],
            service: vec!["demo.Echo".to_string()],
            method: vec!["Say".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let ctx = RuleMatchContext {
        rpc_protocol: Some("grpc"),
        rpc_service: Some("demo.Echo"),
        rpc_method: Some("Say"),
        ..Default::default()
    };
    assert!(compiled.matches(&ctx));
}

#[test]
fn compiled_match_supports_rpc_response_trailers() {
    let cfg = MatchConfig {
        rpc: Some(RpcMatchConfig {
            status: vec!["14".to_string()],
            trailers: vec![HeaderMatch {
                name: "grpc-message".to_string(),
                value: Some("unavailable".to_string()),
                regex: None,
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-message", HeaderValue::from_static("unavailable"));
    let ctx = RuleMatchContext {
        rpc_status: Some("14"),
        rpc_trailers: Some(&trailers),
        ..Default::default()
    };
    assert!(compiled.matches(&ctx));
    assert!(compiled.requires_response_context());
    assert!(compiled.requires_response_size());
}

#[test]
fn response_rpc_streaming_requires_request_body_observation() {
    let cfg = MatchConfig {
        rpc: Some(RpcMatchConfig {
            streaming: vec!["client".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    assert!(compiled.requires_response_request_rpc_context());
    assert!(compiled.requires_response_request_body_observation());
    assert!(compiled.requires_response_rpc_context());
    assert!(compiled.requires_response_rpc_observation());
}
