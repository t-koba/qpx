use super::super::types::*;
use crate::http::modules::CompiledHttpModuleChain;
use anyhow::{Result, anyhow};
use qpx_core::config::{
    GrpcConfig, RuntimeConfig, SseStreamingPolicy, StreamingConfig, StreamingRequirement,
    UnknownLengthExactSizePolicy,
};
use qpx_core::matchers::CompiledMatch;

pub(in crate::runtime::plan) fn validate_streaming_requirement(
    requirement: Option<&StreamingRequirement>,
    modules: &CompiledHttpModuleChain,
) -> Result<()> {
    let aggregate = modules.aggregate();
    let buffers = matches!(
        aggregate.body_access,
        crate::http::modules::BodyAccess::RequestBodyBuffered { .. }
            | crate::http::modules::BodyAccess::ResponseBodyBuffered { .. }
            | crate::http::modules::BodyAccess::RequestAndResponseBodyBuffered { .. }
    );
    match (requirement, buffers) {
        (Some(StreamingRequirement::Required), true) => Err(anyhow!(
            "route has streaming_requirement: required but its HTTP module chain requires body buffering"
        )),
        (None, true) => Err(anyhow!(
            "route can buffer bodies through its HTTP module chain; set streaming_requirement: preferred to allow explicit buffering or required to reject it"
        )),
        _ => Ok(()),
    }
}

pub(super) fn collect_plan_buffering_reasons<'a>(
    plan: &'a ExecutionPlan,
    extra: &mut Vec<&'a str>,
) {
    for reason in &plan.buffering_reasons {
        extra.push(reason.as_ref());
    }
    if plan
        .guard
        .as_ref()
        .is_some_and(|guard| guard.may_require_request_body_buffering())
        && !extra.contains(&"http_guard.body")
    {
        extra.push("http_guard.body");
    }
    if let Some(rules) = plan.response_rules.as_ref() {
        if rules.any_rule_requires_response_body_observation()
            && !extra.contains(&"response_rules.response_body")
        {
            extra.push("response_rules.response_body");
        }
        if rules.any_rule_requires_response_size_matcher()
            && !extra.contains(&"response_rules.response_size_exact_unknown")
        {
            extra.push("response_rules.response_size_exact_unknown");
        }
        if rules.any_rule_requires_response_request_body_observation()
            && !extra.contains(&"response_rules.request_body")
        {
            extra.push("response_rules.request_body");
        }
    }
}

pub(super) fn validate_explicit_streaming_contract(
    requirement: Option<&StreamingRequirement>,
    reasons: &[&str],
) -> Result<()> {
    if reasons.is_empty() || matches!(requirement, Some(StreamingRequirement::Preferred)) {
        return Ok(());
    }
    match requirement {
        Some(StreamingRequirement::Preferred) => Ok(()),
        Some(StreamingRequirement::Required) => Err(anyhow!(
            "route has streaming_requirement: required but it can buffer bodies because: {}",
            reasons.join(", ")
        )),
        None => Err(anyhow!(
            "route can buffer bodies because: {}; set streaming_requirement: preferred to allow exact inspection/buffering, or required to reject buffering features",
            reasons.join(", ")
        )),
        Some(StreamingRequirement::Disabled) => {
            Err(anyhow!("streaming_requirement: disabled is not supported"))
        }
    }
}

pub(in crate::runtime::plan) fn validate_streaming_required_route(
    requirement: Option<&StreamingRequirement>,
    matcher: &CompiledMatch,
    plan: &ExecutionPlan,
) -> Result<()> {
    if matches!(requirement, Some(StreamingRequirement::Required)) {
        if matcher.requires_request_body_observation() {
            return Err(anyhow!(
                "route has streaming_requirement: required but its match.rpc request predicates require full request body observation"
            ));
        }
        if matcher.requires_response_body_observation() {
            return Err(anyhow!(
                "route has streaming_requirement: required but its match.rpc response predicates require full response body observation"
            ));
        }
        if matcher.requires_request_size_matcher() {
            return Err(anyhow!(
                "route has streaming_requirement: required but its match.request_size requires full request body sizing"
            ));
        }
        if matcher.requires_response_size_matcher() {
            return Err(anyhow!(
                "route has streaming_requirement: required but its match.response_size requires full response body sizing"
            ));
        }
    }
    validate_streaming_required_plan(requirement, plan)
}

pub(super) fn validate_streaming_required_plan(
    requirement: Option<&StreamingRequirement>,
    plan: &ExecutionPlan,
) -> Result<()> {
    match requirement {
        Some(StreamingRequirement::Preferred) => return Ok(()),
        Some(StreamingRequirement::Required) | None => {}
        Some(StreamingRequirement::Disabled) => {
            return Err(anyhow!("streaming_requirement: disabled is not supported"));
        }
    }
    let mut reasons = Vec::new();
    collect_plan_buffering_reasons(plan, &mut reasons);
    validate_explicit_streaming_contract(requirement, &reasons)
}

pub(super) fn validate_unknown_length_exact_size_policy(
    requirement: Option<&StreamingRequirement>,
    plan: &ExecutionPlan,
    policy: UnknownLengthExactSizePolicy,
) -> Result<()> {
    let needs_unknown_exact_size = plan.buffering_reasons.iter().any(|reason| {
        matches!(
            reason.as_ref(),
            "request.size_exact_unknown"
                | "response.size_exact_unknown"
                | "response_rules.response_size_exact_unknown"
        )
    });
    if !needs_unknown_exact_size {
        return Ok(());
    }
    if !matches!(requirement, Some(StreamingRequirement::Preferred)) {
        return Ok(());
    }
    match policy {
        UnknownLengthExactSizePolicy::Buffer => Ok(()),
        UnknownLengthExactSizePolicy::Reject => Err(anyhow!(
            "unknown-length exact size matching requires runtime.unknown_length_exact_size: buffer"
        )),
    }
}

pub(super) fn add_module_buffering_reasons(
    body_access: crate::http::modules::BodyAccess,
    plan: &mut ExecutionPlan,
) {
    match body_access {
        crate::http::modules::BodyAccess::RequestBodyBuffered { .. } => {
            plan.add_buffering_reason("http_modules.request_body");
        }
        crate::http::modules::BodyAccess::ResponseBodyBuffered { .. } => {
            plan.add_buffering_reason("http_modules.response_body");
        }
        crate::http::modules::BodyAccess::RequestAndResponseBodyBuffered { .. } => {
            plan.add_buffering_reason("http_modules.request_body");
            plan.add_buffering_reason("http_modules.response_body");
        }
        crate::http::modules::BodyAccess::HeadersOnly
        | crate::http::modules::BodyAccess::Streaming => {}
    }
}

pub(in crate::runtime::plan) fn resolve_streaming_limits(
    runtime: &RuntimeConfig,
    listener_streaming: Option<&StreamingConfig>,
    route_streaming: Option<&StreamingConfig>,
    listener_grpc: Option<&GrpcConfig>,
    route_grpc: Option<&GrpcConfig>,
    listener_sse: Option<&SseStreamingPolicy>,
    route_sse: Option<&SseStreamingPolicy>,
) -> ResolvedStreamingLimits {
    let streaming_value = |route: Option<usize>,
                           listener: Option<usize>,
                           runtime_default: usize|
     -> usize { route.or(listener).unwrap_or(runtime_default) };
    let streaming_u64 = |route: Option<u64>, listener: Option<u64>, runtime_default: u64| -> u64 {
        route.or(listener).unwrap_or(runtime_default)
    };

    let sse = route_sse
        .copied()
        .or_else(|| listener_sse.copied())
        .unwrap_or(runtime.sse);
    ResolvedStreamingLimits {
        body_channel_capacity: streaming_value(
            route_streaming.and_then(|cfg| cfg.body_channel_capacity),
            listener_streaming.and_then(|cfg| cfg.body_channel_capacity),
            runtime.body_channel_capacity,
        )
        .max(1),
        body_read_timeout_ms: streaming_u64(
            route_streaming.and_then(|cfg| cfg.body_read_timeout_ms),
            listener_streaming.and_then(|cfg| cfg.body_read_timeout_ms),
            runtime.h3_read_timeout_ms,
        )
        .max(1),
        body_send_timeout_ms: streaming_u64(
            route_streaming.and_then(|cfg| cfg.body_send_timeout_ms),
            listener_streaming.and_then(|cfg| cfg.body_send_timeout_ms),
            runtime.h3_read_timeout_ms,
        )
        .max(1),
        max_request_body_bytes: streaming_value(
            route_streaming.and_then(|cfg| cfg.max_request_body_bytes),
            listener_streaming.and_then(|cfg| cfg.max_request_body_bytes),
            runtime.max_h3_request_body_bytes,
        ),
        max_response_body_bytes: streaming_value(
            route_streaming.and_then(|cfg| cfg.max_response_body_bytes),
            listener_streaming.and_then(|cfg| cfg.max_response_body_bytes),
            runtime.max_h3_response_body_bytes,
        ),
        max_grpc_message_bytes: streaming_u64(
            route_grpc.and_then(|cfg| cfg.max_message_bytes),
            listener_grpc.and_then(|cfg| cfg.max_message_bytes),
            runtime.max_grpc_message_bytes,
        ),
        max_grpc_web_trailer_bytes: streaming_u64(
            route_grpc.and_then(|cfg| cfg.max_web_trailer_bytes),
            listener_grpc.and_then(|cfg| cfg.max_web_trailer_bytes),
            runtime.max_grpc_web_trailer_bytes,
        ),
        max_grpc_stream_duration_ms: streaming_u64(
            route_grpc.and_then(|cfg| cfg.max_stream_duration_ms),
            listener_grpc.and_then(|cfg| cfg.max_stream_duration_ms),
            runtime.max_grpc_stream_duration_ms,
        ),
        observe_grpc_messages: route_grpc
            .and_then(|cfg| cfg.observe_messages)
            .or_else(|| listener_grpc.and_then(|cfg| cfg.observe_messages))
            .unwrap_or(true),
        sse,
    }
}
