// Extracted from runtime/plan.rs; public surface is re-exported by mod.rs.
use super::compiler::{
    apply_matcher_flags, resolve_streaming_limits, validate_streaming_required_route,
    validate_streaming_requirement,
};
use super::*;
use crate::http::modules::CompiledHttpModuleChain;
use crate::http::policy::response_policy::HttpResponseRuleEngine;
use qpx_core::config::{
    CaptureRedactionConfig, GrpcConfig, RuntimeConfig, SseStreamingPolicy, StreamingConfig,
    StreamingRequirement,
};
use qpx_core::matchers::CompiledMatch;
use qpx_core::prefilter::StringInterner;
use std::sync::Arc;

#[test]
fn streaming_limits_resolve_route_over_listener_over_runtime() {
    let runtime = RuntimeConfig {
        body_channel_capacity: 8,
        h3_read_timeout_ms: 1000,
        max_h3_request_body_bytes: 10,
        max_h3_response_body_bytes: 20,
        max_grpc_message_bytes: 30,
        max_grpc_web_trailer_bytes: 40,
        max_grpc_stream_duration_ms: 50,
        sse: SseStreamingPolicy {
            idle_timeout_ms: 60,
            max_stream_duration_ms: 70,
            ..SseStreamingPolicy::default()
        },
        ..RuntimeConfig::default()
    };
    let listener_streaming = StreamingConfig {
        body_channel_capacity: Some(16),
        body_read_timeout_ms: Some(2000),
        body_send_timeout_ms: Some(3000),
        max_request_body_bytes: Some(100),
        max_response_body_bytes: Some(200),
    };
    let route_streaming = StreamingConfig {
        body_channel_capacity: Some(32),
        body_read_timeout_ms: None,
        body_send_timeout_ms: Some(4000),
        max_request_body_bytes: None,
        max_response_body_bytes: Some(400),
    };
    let listener_grpc = GrpcConfig {
        max_message_bytes: Some(300),
        max_web_trailer_bytes: Some(400),
        max_stream_duration_ms: Some(500),
        observe_messages: Some(false),
    };
    let route_grpc = GrpcConfig {
        max_message_bytes: Some(600),
        max_web_trailer_bytes: None,
        max_stream_duration_ms: Some(700),
        observe_messages: None,
    };
    let listener_sse = SseStreamingPolicy {
        idle_timeout_ms: 800,
        max_stream_duration_ms: 900,
        ..SseStreamingPolicy::default()
    };
    let route_sse = SseStreamingPolicy {
        idle_timeout_ms: 1000,
        max_stream_duration_ms: 1100,
        ..SseStreamingPolicy::default()
    };

    let resolved = resolve_streaming_limits(
        &runtime,
        Some(&listener_streaming),
        Some(&route_streaming),
        Some(&listener_grpc),
        Some(&route_grpc),
        Some(&listener_sse),
        Some(&route_sse),
    );

    assert_eq!(resolved.body_channel_capacity, 32);
    assert_eq!(resolved.body_read_timeout_ms, 2000);
    assert_eq!(resolved.body_send_timeout_ms, 4000);
    assert_eq!(resolved.max_request_body_bytes, 100);
    assert_eq!(resolved.max_response_body_bytes, 400);
    assert_eq!(resolved.max_grpc_message_bytes, 600);
    assert_eq!(resolved.max_grpc_web_trailer_bytes, 400);
    assert_eq!(resolved.max_grpc_stream_duration_ms, 700);
    assert!(!resolved.observe_grpc_messages);
    assert_eq!(resolved.sse.idle_timeout_ms, 1000);
    assert_eq!(resolved.sse.max_stream_duration_ms, 1100);
}

#[test]
fn streaming_required_rejects_buffering_module_chain() {
    let chain = CompiledHttpModuleChain::test_with_body_access(
        crate::http::modules::BodyAccess::ResponseBodyBuffered { max_bytes: 1024 },
    );

    let err = validate_streaming_requirement(Some(&StreamingRequirement::Required), &chain)
        .expect_err("buffering module should be rejected");

    assert!(err.to_string().contains("streaming_requirement: required"));
    assert!(err.to_string().contains("aggregate module body access"));
}

#[test]
fn omitted_streaming_requirement_rejects_implicit_buffering() {
    let mut interner = StringInterner::default();
    let (matcher, _) =
        CompiledMatch::compile(&qpx_core::config::MatchConfig::default(), &mut interner)
            .expect("matcher");
    let mut plan = ExecutionPlan::empty();
    plan.add_buffering_reason("retry.body_template");

    let err = validate_streaming_required_route(None, &matcher, &plan)
        .expect_err("implicit buffering should require explicit preferred");

    assert!(err.to_string().contains("streaming_requirement: preferred"));
    assert!(err.to_string().contains("retry.body_template"));
}

#[test]
fn observation_limits_use_request_and_response_streaming_caps_separately() {
    let mut plan = ExecutionPlan::empty();
    plan.streaming.max_request_body_bytes = 1024;
    plan.streaming.max_response_body_bytes = 64 * 1024;

    assert_eq!(plan.request_body_observation_limit(128 * 1024), 1024);
    assert_eq!(plan.response_body_observation_limit(128 * 1024), 64 * 1024);
}

#[test]
fn preferred_streaming_requirement_allows_explicit_buffering() {
    let mut interner = StringInterner::default();
    let (matcher, _) =
        CompiledMatch::compile(&qpx_core::config::MatchConfig::default(), &mut interner)
            .expect("matcher");
    let mut plan = ExecutionPlan::empty();
    plan.add_buffering_reason("retry.body_template");

    validate_streaming_required_route(Some(&StreamingRequirement::Preferred), &matcher, &plan)
        .expect("preferred should explicitly allow buffering features");
}

#[test]
fn streaming_required_rejects_size_matchers() {
    let mut interner = StringInterner::default();
    let mut config = qpx_core::config::MatchConfig {
        request_size: vec![">1m".to_string()],
        ..qpx_core::config::MatchConfig::default()
    };
    let (matcher, _) = CompiledMatch::compile(&config, &mut interner).expect("request matcher");
    let err = validate_streaming_required_route(
        Some(&StreamingRequirement::Required),
        &matcher,
        &ExecutionPlan::empty(),
    )
    .expect_err("request_size should be rejected");
    assert!(err.to_string().contains("match.request_size"));

    config.request_size.clear();
    config.response_size = vec!["0-1024".to_string()];
    let (matcher, _) = CompiledMatch::compile(&config, &mut interner).expect("response matcher");
    let err = validate_streaming_required_route(
        Some(&StreamingRequirement::Required),
        &matcher,
        &ExecutionPlan::empty(),
    )
    .expect_err("response_size should be rejected");
    assert!(err.to_string().contains("match.response_size"));
}

#[test]
fn streaming_first_allows_rpc_request_metadata_matchers() {
    let mut interner = StringInterner::default();
    let config = qpx_core::config::MatchConfig {
        rpc: Some(qpx_core::config::RpcMatchConfig {
            protocol: vec!["grpc".to_string()],
            service: vec!["demo.Echo".to_string()],
            method: vec!["Say".to_string()],
            ..qpx_core::config::RpcMatchConfig::default()
        }),
        ..qpx_core::config::MatchConfig::default()
    };
    let (matcher, _) = CompiledMatch::compile(&config, &mut interner).expect("rpc matcher");
    let mut plan = ExecutionPlan::empty();
    apply_matcher_flags(&matcher, &mut plan);

    assert!(matcher.requires_request_rpc_context());
    assert!(!matcher.requires_request_body_observation());
    assert!(!plan.flags.contains(PlanFlags::REQUEST_BODY_OBSERVE));
    assert!(plan.buffering_reasons.is_empty());
    validate_streaming_required_route(None, &matcher, &plan)
        .expect("RPC metadata matchers must stay on the streaming-first path");
    validate_streaming_required_route(Some(&StreamingRequirement::Required), &matcher, &plan)
        .expect("RPC metadata matchers do not require body buffering");
}

#[test]
fn rpc_body_matchers_are_not_labeled_as_exact_size_matchers() {
    let mut interner = StringInterner::default();
    let config = qpx_core::config::MatchConfig {
        rpc: Some(qpx_core::config::RpcMatchConfig {
            message_size: vec![">1024".to_string()],
            ..qpx_core::config::RpcMatchConfig::default()
        }),
        ..qpx_core::config::MatchConfig::default()
    };
    let (matcher, _) = CompiledMatch::compile(&config, &mut interner).expect("rpc matcher");
    let mut plan = ExecutionPlan::empty();
    apply_matcher_flags(&matcher, &mut plan);

    assert!(matcher.requires_request_body_observation());
    assert!(plan.flags.contains(PlanFlags::REQUEST_BODY_OBSERVE));
    assert!(
        plan.buffering_reasons
            .iter()
            .any(|reason| reason.as_ref() == "rpc.body")
    );
    assert!(
        !plan
            .buffering_reasons
            .iter()
            .any(|reason| reason.as_ref() == "request.size_exact_unknown")
    );
}

#[test]
fn streaming_required_rejects_rpc_matchers_that_need_body_observation() {
    let mut interner = StringInterner::default();
    let request_config = qpx_core::config::MatchConfig {
        rpc: Some(qpx_core::config::RpcMatchConfig {
            message_size: vec![">1024".to_string()],
            ..qpx_core::config::RpcMatchConfig::default()
        }),
        ..qpx_core::config::MatchConfig::default()
    };
    let (matcher, _) =
        CompiledMatch::compile(&request_config, &mut interner).expect("request rpc matcher");
    let err = validate_streaming_required_route(
        Some(&StreamingRequirement::Required),
        &matcher,
        &ExecutionPlan::empty(),
    )
    .expect_err("request RPC body matcher should be rejected");
    assert!(err.to_string().contains("full request body observation"));

    let response_config = qpx_core::config::MatchConfig {
        rpc: Some(qpx_core::config::RpcMatchConfig {
            status: vec!["0".to_string()],
            ..qpx_core::config::RpcMatchConfig::default()
        }),
        ..qpx_core::config::MatchConfig::default()
    };
    let (matcher, _) =
        CompiledMatch::compile(&response_config, &mut interner).expect("response rpc matcher");
    let err = validate_streaming_required_route(
        Some(&StreamingRequirement::Required),
        &matcher,
        &ExecutionPlan::empty(),
    )
    .expect_err("response RPC body matcher should be rejected");
    assert!(err.to_string().contains("full response body observation"));
}

#[test]
fn streaming_required_allows_streaming_full_plaintext_body_capture() {
    let mut interner = StringInterner::default();
    let (matcher, _) =
        CompiledMatch::compile(&qpx_core::config::MatchConfig::default(), &mut interner)
            .expect("matcher");
    let mut plan = ExecutionPlan::empty();
    plan.capture.plaintext = Some(CompiledPlaintextCapturePlan {
        headers: false,
        body: qpx_core::config::CaptureBodyMode::Full,
        body_sample_bytes: None,
        sample_percent: None,
        max_body_bytes: Some(1024),
        redact: CaptureRedactionConfig::default(),
    });
    plan.flags.insert(PlanFlags::CAPTURE_BODY);

    validate_streaming_required_route(Some(&StreamingRequirement::Required), &matcher, &plan)
        .expect("full body capture is streaming and should not be treated as buffering");
    assert!(
        !plan
            .buffering_reasons
            .iter()
            .any(|reason| reason.as_ref() == "capture.body_full")
    );
}

#[test]
fn streaming_required_rejects_response_rules_that_need_body_size() {
    let mut interner = StringInterner::default();
    let (matcher, _) =
        CompiledMatch::compile(&qpx_core::config::MatchConfig::default(), &mut interner)
            .expect("matcher");
    let mut plan = ExecutionPlan::empty();
    plan.response_rules =
        HttpResponseRuleEngine::new(&[qpx_core::config::HttpResponseRuleConfig {
            name: "large-response".to_string(),
            r#match: Some(qpx_core::config::MatchConfig {
                response_size: vec![">1m".to_string()],
                ..qpx_core::config::MatchConfig::default()
            }),
            effects: qpx_core::config::HttpResponseEffectsConfig::default(),
        }])
        .expect("response rules")
        .map(Arc::new);

    let err =
        validate_streaming_required_route(Some(&StreamingRequirement::Required), &matcher, &plan)
            .expect_err("response_size rule should be rejected");
    assert!(err.to_string().contains("response_rules"));
}

#[test]
fn streaming_required_rejects_response_rules_that_need_request_body_observation() {
    let mut interner = StringInterner::default();
    let (matcher, _) =
        CompiledMatch::compile(&qpx_core::config::MatchConfig::default(), &mut interner)
            .expect("matcher");
    let mut plan = ExecutionPlan::empty();
    plan.response_rules =
        HttpResponseRuleEngine::new(&[qpx_core::config::HttpResponseRuleConfig {
            name: "streaming-rpc".to_string(),
            r#match: Some(qpx_core::config::MatchConfig {
                rpc: Some(qpx_core::config::RpcMatchConfig {
                    streaming: vec!["bidi".to_string()],
                    ..qpx_core::config::RpcMatchConfig::default()
                }),
                ..qpx_core::config::MatchConfig::default()
            }),
            effects: qpx_core::config::HttpResponseEffectsConfig::default(),
        }])
        .expect("response rules")
        .map(Arc::new);

    let err =
        validate_streaming_required_route(Some(&StreamingRequirement::Required), &matcher, &plan)
            .expect_err("response rule request body observation should be rejected");
    assert!(err.to_string().contains("response_rules"));
}
