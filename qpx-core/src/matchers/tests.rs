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
fn empty_destination_match_does_not_require_destination_context() {
    let cfg = MatchConfig {
        destination: Some(DestinationMatchConfig::default()),
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");

    assert!(!compiled.requires_destination_context());
    assert!(compiled.matches(&RuleMatchContext::default()));
}

#[test]
fn only_an_empty_match_is_unconditional() {
    let mut interner = StringInterner::default();
    let (empty, _) = CompiledMatch::compile(&MatchConfig::default(), &mut interner)
        .expect("compile empty match");
    assert!(empty.is_unconditional());

    let configured = MatchConfig {
        method: vec!["GET".to_string()],
        ..Default::default()
    };
    let (configured, _) =
        CompiledMatch::compile(&configured, &mut interner).expect("compile configured match");
    assert!(!configured.is_unconditional());
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
    assert!(compiled.requires_destination_context());
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

#[test]
fn known_request_response_rule_match_does_not_evaluate_headers() {
    let cfg = MatchConfig {
        headers: vec![HeaderMatch {
            name: "x-response-mode".to_string(),
            value: Some("slow".to_string()),
            regex: None,
        }],
        rpc: Some(RpcMatchConfig {
            streaming: vec!["client".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let mut request_headers = HeaderMap::new();
    request_headers.insert("x-response-mode", HeaderValue::from_static("fast"));
    let ctx = RuleMatchContext {
        headers: Some(&request_headers),
        ..Default::default()
    };

    assert!(!compiled.matches(&ctx));
    assert!(compiled.matches_known_request_without_body_observation(&ctx));
}

#[test]
fn unary_streaming_matcher_selects_connect_get_label() {
    let cfg = MatchConfig {
        rpc: Some(RpcMatchConfig {
            streaming: vec!["unary".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let unary = RuleMatchContext {
        rpc_streaming: Some("unary"),
        ..Default::default()
    };
    assert!(compiled.matches(&unary));
    let server = RuleMatchContext {
        rpc_streaming: Some("server"),
        ..Default::default()
    };
    assert!(!compiled.matches(&server));
}

#[test]
fn host_and_sni_regex_preserve_uppercase_escapes() {
    let mut interner = StringInterner::default();
    let (host_compiled, _) = CompiledMatch::compile(
        &MatchConfig {
            host: vec![r"re:^api-\D+$".to_string()],
            ..Default::default()
        },
        &mut interner,
    )
    .expect("compile host regex");
    let letters = RuleMatchContext {
        host: Some("api-abc"),
        ..Default::default()
    };
    assert!(host_compiled.matches(&letters));
    let letters_trace = host_compiled.matches_with_trace(&letters);
    assert!(letters_trace.result);
    assert!(letters_trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Host {
            mode: MatchMode::Regex,
            result: true,
            ..
        }
    )));
    let digits = RuleMatchContext {
        host: Some("api-123"),
        ..Default::default()
    };
    assert!(!host_compiled.matches(&digits));
    let digits_trace = host_compiled.matches_with_trace(&digits);
    assert!(!digits_trace.result);
    assert!(digits_trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Host {
            mode: MatchMode::Regex,
            result: false,
            ..
        }
    )));

    let mut interner = StringInterner::default();
    let (sni_compiled, _) = CompiledMatch::compile(
        &MatchConfig {
            sni: vec![r"RE:^api-\D+$".to_string()],
            ..Default::default()
        },
        &mut interner,
    )
    .expect("compile sni regex");
    let letters = RuleMatchContext {
        sni: Some("api-abc"),
        ..Default::default()
    };
    assert!(sni_compiled.matches(&letters));
    let letters_trace = sni_compiled.matches_with_trace(&letters);
    assert!(letters_trace.result);
    assert!(letters_trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Sni {
            mode: MatchMode::Regex,
            result: true,
            ..
        }
    )));
    let digits = RuleMatchContext {
        sni: Some("api-123"),
        ..Default::default()
    };
    assert!(!sni_compiled.matches(&digits));
    let digits_trace = sni_compiled.matches_with_trace(&digits);
    assert!(!digits_trace.result);
    assert!(digits_trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Sni {
            mode: MatchMode::Regex,
            result: false,
            ..
        }
    )));

    let mut interner = StringInterner::default();
    let (literal, _) = CompiledMatch::compile(
        &MatchConfig {
            host: vec![r"re:^hello$".to_string()],
            ..Default::default()
        },
        &mut interner,
    )
    .expect("compile literal regex");
    let upper = RuleMatchContext {
        host: Some("HELLO"),
        ..Default::default()
    };
    assert!(literal.matches(&upper));
    let upper_trace = literal.matches_with_trace(&upper);
    assert!(upper_trace.result);
    assert!(upper_trace.reasons.iter().any(|reason| matches!(
        reason,
        MatchReason::Host {
            mode: MatchMode::Regex,
            result: true,
            ..
        }
    )));
}

#[test]
fn path_regex_stays_case_sensitive_and_preserves_escapes() {
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(
        &MatchConfig {
            path: vec![r"re:^/v1/\D+$".to_string()],
            ..Default::default()
        },
        &mut interner,
    )
    .expect("compile path regex");
    let letters = RuleMatchContext {
        path: Some("/v1/ABC"),
        ..Default::default()
    };
    assert!(compiled.matches(&letters));
    assert!(compiled.matches_with_trace(&letters).result);
    let digits = RuleMatchContext {
        path: Some("/v1/123"),
        ..Default::default()
    };
    assert!(!compiled.matches(&digits));
    assert!(!compiled.matches_with_trace(&digits).result);

    let mut interner = StringInterner::default();
    let (case, _) = CompiledMatch::compile(
        &MatchConfig {
            path: vec![r"re:^/V1/ABC$".to_string()],
            ..Default::default()
        },
        &mut interner,
    )
    .expect("compile case-sensitive path regex");
    let exact = RuleMatchContext {
        path: Some("/V1/ABC"),
        ..Default::default()
    };
    assert!(case.matches(&exact));
    assert!(case.matches_with_trace(&exact).result);
    let lower = RuleMatchContext {
        path: Some("/v1/abc"),
        ..Default::default()
    };
    assert!(!case.matches(&lower));
    assert!(!case.matches_with_trace(&lower).result);
}

#[test]
fn header_trace_reports_later_duplicate_exact_match() {
    let cfg = MatchConfig {
        headers: vec![HeaderMatch {
            name: "x-token".to_string(),
            value: Some("secret".to_string()),
            regex: None,
        }],
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let mut headers = HeaderMap::new();
    headers.append("x-token", HeaderValue::from_static("other"));
    headers.append("x-token", HeaderValue::from_static("secret"));
    let ctx = RuleMatchContext {
        headers: Some(&headers),
        ..Default::default()
    };
    assert!(compiled.matches(&ctx));
    let trace = compiled.matches_with_trace(&ctx);
    assert!(trace.result);
    let reason = trace
        .reasons
        .iter()
        .find_map(|reason| match reason {
            MatchReason::Header {
                name,
                configured,
                actual,
                result,
            } if name == "x-token" => Some((configured, actual, result)),
            _ => None,
        })
        .expect("header reason");
    assert!(*reason.2);
    assert_eq!(reason.1.as_deref(), Some("secret"));
    assert_eq!(reason.0, "secret");
}

#[test]
fn header_trace_reports_first_value_when_no_duplicate_exact_match() {
    let cfg = MatchConfig {
        headers: vec![HeaderMatch {
            name: "x-token".to_string(),
            value: Some("secret".to_string()),
            regex: None,
        }],
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let mut headers = HeaderMap::new();
    headers.append("x-token", HeaderValue::from_static("other"));
    headers.append("x-token", HeaderValue::from_static("another"));
    let ctx = RuleMatchContext {
        headers: Some(&headers),
        ..Default::default()
    };
    assert!(!compiled.matches(&ctx));
    let trace = compiled.matches_with_trace(&ctx);
    assert!(!trace.result);
    let reason = trace
        .reasons
        .iter()
        .find_map(|reason| match reason {
            MatchReason::Header {
                name,
                actual,
                result,
                ..
            } if name == "x-token" => Some((actual, result)),
            _ => None,
        })
        .expect("header reason");
    assert!(!*reason.1);
    assert_eq!(reason.0.as_deref(), Some("other"));
}

#[test]
fn header_trace_reports_later_duplicate_regex_match() {
    let cfg = MatchConfig {
        headers: vec![HeaderMatch {
            name: "x-tag".to_string(),
            value: None,
            regex: Some("^ab[0-9]+$".to_string()),
        }],
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let mut headers = HeaderMap::new();
    headers.append("x-tag", HeaderValue::from_static("nope"));
    headers.append("x-tag", HeaderValue::from_static("ab123"));
    let ctx = RuleMatchContext {
        headers: Some(&headers),
        ..Default::default()
    };
    assert!(compiled.matches(&ctx));
    let trace = compiled.matches_with_trace(&ctx);
    assert!(trace.result);
    let reason = trace
        .reasons
        .iter()
        .find_map(|reason| match reason {
            MatchReason::Header {
                name,
                actual,
                result,
                ..
            } if name == "x-tag" => Some((actual, result)),
            _ => None,
        })
        .expect("header reason");
    assert!(*reason.1);
    assert_eq!(reason.0.as_deref(), Some("ab123"));
}

#[test]
fn header_trace_reports_first_value_when_no_duplicate_regex_match() {
    let cfg = MatchConfig {
        headers: vec![HeaderMatch {
            name: "x-tag".to_string(),
            value: None,
            regex: Some("^ab[0-9]+$".to_string()),
        }],
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let mut headers = HeaderMap::new();
    headers.append("x-tag", HeaderValue::from_static("nope"));
    headers.append("x-tag", HeaderValue::from_static("still-no"));
    let ctx = RuleMatchContext {
        headers: Some(&headers),
        ..Default::default()
    };
    assert!(!compiled.matches(&ctx));
    let trace = compiled.matches_with_trace(&ctx);
    assert!(!trace.result);
    let reason = trace
        .reasons
        .iter()
        .find_map(|reason| match reason {
            MatchReason::Header {
                name,
                actual,
                result,
                ..
            } if name == "x-tag" => Some((actual, result)),
            _ => None,
        })
        .expect("header reason");
    assert!(!*reason.1);
    assert_eq!(reason.0.as_deref(), Some("nope"));
}

#[test]
fn impossible_request_size_never_matches() {
    let cfg = MatchConfig {
        request_size: vec!["<0".to_string()],
        ..Default::default()
    };
    let mut interner = StringInterner::default();
    let (compiled, _) = CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    assert!(!compiled.is_unconditional());
    for request_size in [0, 1, u64::MAX] {
        let ctx = RuleMatchContext {
            request_size: Some(request_size),
            ..Default::default()
        };
        assert!(
            !compiled.matches(&ctx),
            "request-size <0 must never match {request_size}"
        );
    }
}
