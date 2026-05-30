use super::super::types::*;
use super::streaming::{
    add_module_buffering_reasons, resolve_streaming_limits, validate_streaming_requirement,
};
use crate::http::modules::compile_http_modules;
use crate::http::policy::guard::compile_http_guard_profile;
use crate::http::policy::response_policy::HttpResponseRuleEngine;
use crate::policy_context::EffectivePolicyContext;
use crate::rate_limit::{CompiledRateLimitPlan, RateLimitSet};
use crate::runtime::RuntimeResources;
use crate::tls::trust::CompiledUpstreamTlsTrust;
use anyhow::{Result, anyhow};
use qpx_core::config::{
    ActionConfig, ActionKind, DestinationResolutionOverrideConfig, GrpcConfig, IngressEdgeConfig,
    LocalResponseConfig, ReverseRouteConfig, SseStreamingPolicy, StreamingConfig,
    StreamingRequirement,
};
use std::sync::Arc;

pub(super) struct ExecutionPlanInputs<'a> {
    pub(super) listener_streaming: Option<&'a StreamingConfig>,
    pub(super) route_streaming: Option<&'a StreamingConfig>,
    pub(super) listener_grpc: Option<&'a GrpcConfig>,
    pub(super) route_grpc: Option<&'a GrpcConfig>,
    pub(super) listener_sse: Option<&'a SseStreamingPolicy>,
    pub(super) route_sse: Option<&'a SseStreamingPolicy>,
    pub(super) policy_context: EffectivePolicyContext,
    pub(super) destination_resolution:
        Option<&'a qpx_core::config::DestinationResolutionOverrideConfig>,
    pub(super) http_guard_profile: Option<&'a str>,
    pub(super) cache: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) capture: Option<&'a qpx_core::config::CapturePolicyConfig>,
    pub(super) rate_limit: Option<&'a qpx_core::config::RateLimitConfig>,
    pub(super) http: Option<&'a qpx_core::config::HttpPolicyConfig>,
    pub(super) http_modules: &'a [qpx_core::config::HttpModuleConfig],
    pub(super) streaming_requirement: Option<&'a StreamingRequirement>,
}

pub(super) fn execution_plan_for_reverse_route(
    config: &RuntimeResources,
    reverse_edges: &qpx_core::config::ReverseEdgeConfig,
    route: &ReverseRouteConfig,
) -> Result<ExecutionPlan> {
    let mut plan = execution_plan_for_common(
        config,
        ExecutionPlanInputs {
            listener_streaming: reverse_edges.streaming.as_ref(),
            route_streaming: route.streaming.as_ref(),
            listener_grpc: reverse_edges.grpc.as_ref(),
            route_grpc: route.grpc.as_ref(),
            listener_sse: reverse_edges.sse.as_ref(),
            route_sse: route.sse.as_ref(),
            policy_context: EffectivePolicyContext::merged(
                reverse_edges.policy_context.as_ref(),
                route.policy_context.as_ref(),
            ),
            destination_resolution: merge_destination_resolution_override(
                reverse_edges.destination_resolution.as_ref(),
                route.destination_resolution.as_ref(),
            )
            .as_ref(),
            http_guard_profile: route.http_guard_profile.as_deref(),
            cache: route.cache.as_ref(),
            capture: route.capture.as_ref(),
            rate_limit: route.rate_limit.as_ref(),
            http: route.http.as_ref(),
            http_modules: route.http_modules.as_slice(),
            streaming_requirement: route.streaming_requirement.as_ref(),
        },
    )?;
    plan.rate_limits = CompiledRateLimitPlan::from_sets(
        RateLimitSet::default(),
        RateLimitSet::from_config(route.rate_limit.as_ref()),
    );
    if route.target.is_ipc() {
        plan.flags.insert(PlanFlags::IPC);
    }
    if !route.mirrors.is_empty() {
        plan.flags.insert(PlanFlags::MIRRORING);
    }
    if route
        .resilience
        .as_ref()
        .and_then(|r| r.retry.as_ref())
        .is_some_and(|retry| retry.attempts > 1)
    {
        plan.flags.insert(PlanFlags::RETRY_BODY_BUFFER);
        plan.add_buffering_reason("retry.body_template");
    }
    Ok(plan)
}

pub(super) fn execution_plan_for_forward_action(
    config: &RuntimeResources,
    inputs: ExecutionPlanInputs<'_>,
    action: Option<&ActionConfig>,
) -> Result<ExecutionPlan> {
    let mut plan = execution_plan_for_common(config, inputs)?;
    if action
        .map(|action| matches!(&action.kind, ActionKind::Tunnel))
        .unwrap_or(false)
    {
        plan.flags.insert(PlanFlags::WEBSOCKET);
    }
    if let Some(local_response) = action.and_then(|action| action.local_response.as_ref()) {
        plan.local_response = Some(compile_local_response_plan(local_response));
    }
    Ok(plan)
}

fn compile_local_response_plan(local: &LocalResponseConfig) -> CompiledLocalResponsePlan {
    CompiledLocalResponsePlan {
        status: local.status,
        content_type: local.content_type.as_deref().map(Arc::<str>::from),
        header_count: local.headers.len(),
        body_bytes: local.body.len(),
        rpc_protocol: local
            .rpc
            .as_ref()
            .map(|rpc| Arc::<str>::from(rpc.protocol.as_str())),
        rpc_status: local
            .rpc
            .as_ref()
            .and_then(|rpc| rpc.status.as_deref().map(Arc::<str>::from)),
        rpc_http_status: local.rpc.as_ref().and_then(|rpc| rpc.http_status),
    }
}

pub(super) fn compile_ingress_edge_settings(
    listener: &IngressEdgeConfig,
) -> Result<CompiledListenerSettings> {
    let upstream_trust = CompiledUpstreamTlsTrust::from_config(
        listener
            .tls_inspection
            .as_ref()
            .and_then(|cfg| cfg.upstream_trust.as_ref()),
    )?;
    let requires_upstream_cert_preview = listener.rules.iter().any(|rule| {
        rule.r#match
            .as_ref()
            .and_then(|m| m.upstream_cert.as_ref())
            .is_some()
    }) || upstream_trust.is_some();
    Ok(CompiledListenerSettings {
        upstream_proxy: listener.upstream_proxy.as_deref().map(Arc::from),
        ftp: listener.ftp.clone(),
        tls_inspection: listener
            .tls_inspection
            .as_ref()
            .map(|cfg| CompiledTlsInspectionSettings {
                enabled: cfg.enabled,
                verify_upstream: cfg.verify_upstream,
                upstream_trust: upstream_trust.clone(),
            }),
        requires_upstream_cert_preview,
    })
}

fn execution_plan_for_common(
    config: &RuntimeResources,
    inputs: ExecutionPlanInputs<'_>,
) -> Result<ExecutionPlan> {
    let mut plan = ExecutionPlan::empty();
    plan.streaming = resolve_streaming_limits(
        &config.operational.runtime,
        inputs.listener_streaming,
        inputs.route_streaming,
        inputs.listener_grpc,
        inputs.route_grpc,
        inputs.listener_sse,
        inputs.route_sse,
    );
    plan.modules =
        compile_http_modules(inputs.http_modules, config.http_module_registry().as_ref())?;
    validate_streaming_requirement(inputs.streaming_requirement, plan.modules.as_ref())?;
    add_module_buffering_reasons(plan.modules.aggregate().body_access, &mut plan);
    plan.cache = inputs.cache.filter(|cache| cache.enabled).cloned();
    plan.destination_resolution = inputs.destination_resolution.cloned();
    plan.policy_context = inputs.policy_context;
    if let Some(exporter) = config
        .operational
        .telemetry
        .exporter
        .as_ref()
        .filter(|exporter| exporter.enabled)
        && exporter.capture.encrypted
    {
        plan.flags.insert(PlanFlags::CAPTURE_ENCRYPTED);
        plan.capture.encrypted = true;
    }
    if !plan.policy_context.identity_sources.is_empty() {
        plan.flags.insert(PlanFlags::IDENTITY_SOURCES);
    }
    if plan.policy_context.ext_authz.is_some() {
        plan.flags.insert(PlanFlags::EXT_AUTHZ);
    }
    if plan.destination_resolution.is_some() {
        plan.flags.insert(PlanFlags::DESTINATION_INTEL);
    }
    plan.guard = inputs
        .http_guard_profile
        .map(|name| {
            config
                .operational
                .http
                .guard_profiles
                .iter()
                .find(|profile| profile.name == name)
                .map(compile_http_guard_profile)
                .ok_or_else(|| anyhow!("http_guard_profile not found: {name}"))
        })
        .transpose()?;
    if plan.guard.is_some() {
        plan.flags.insert(PlanFlags::HTTP_GUARD);
        if plan
            .guard
            .as_ref()
            .is_some_and(|guard| guard.may_require_request_body_buffering())
        {
            plan.add_buffering_reason("http_guard.body");
        }
    }
    if plan.cache.is_some() {
        plan.flags.insert(PlanFlags::CACHE_LOOKUP);
        plan.flags.insert(PlanFlags::CACHE_STORE);
    }
    if let Some(capture) = inputs.capture {
        if capture.encrypted {
            plan.flags.insert(PlanFlags::CAPTURE_ENCRYPTED);
            plan.capture.encrypted = true;
        }
        if capture.plaintext.enabled {
            plan.flags.insert(PlanFlags::CAPTURE_PLAINTEXT);
            plan.capture.plaintext = Some(CompiledPlaintextCapturePlan {
                headers: capture.plaintext.headers,
                body: capture.plaintext.body,
                body_sample_bytes: capture.plaintext.body_sample_bytes,
                sample_percent: capture.plaintext.sample_percent,
                max_body_bytes: capture.plaintext.max_body_bytes,
                redact: capture.plaintext.redact.clone(),
            });
            if capture.plaintext.body.is_full() {
                if plan
                    .capture
                    .plaintext
                    .as_ref()
                    .and_then(|plaintext| plaintext.max_body_bytes)
                    .is_none()
                {
                    return Err(anyhow!(
                        "plaintext body capture requires plaintext.max_body_bytes"
                    ));
                }
                plan.flags.insert(PlanFlags::CAPTURE_BODY);
            }
        }
    }
    if inputs
        .rate_limit
        .as_ref()
        .map(|r| r.enabled)
        .unwrap_or(false)
    {
        plan.flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
    }
    plan.response_rules = inputs
        .http
        .as_ref()
        .and_then(|http| HttpResponseRuleEngine::new(http.response_rules.as_slice()).transpose())
        .transpose()?
        .map(Arc::new);
    if plan.response_rules.is_some() {
        plan.flags.insert(PlanFlags::RESPONSE_RULES);
        if let Some(rules) = plan.response_rules.clone() {
            if rules.any_rule_requires_response_body_observation()
                || rules.any_rule_requires_response_size()
                || rules.any_rule_requires_response_rpc_observation()
            {
                plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
            }
            if rules.any_rule_requires_response_body_observation() {
                plan.add_buffering_reason("response_rules.response_body");
            }
            if rules.any_rule_requires_response_size_matcher() {
                plan.add_buffering_reason("response_rules.response_size_exact_unknown");
            }
            if rules.any_rule_requires_response_rpc_observation() {
                plan.add_buffering_reason("response_rules.rpc.body");
            }
            if rules.any_rule_requires_response_request_body_observation() {
                plan.add_buffering_reason("response_rules.request_body");
            }
        }
    }
    apply_module_flags(plan.modules.as_ref(), &mut plan.flags);
    Ok(plan)
}

fn merge_destination_resolution_override(
    base: Option<&DestinationResolutionOverrideConfig>,
    route: Option<&DestinationResolutionOverrideConfig>,
) -> Option<DestinationResolutionOverrideConfig> {
    match (base, route) {
        (None, None) => None,
        (Some(base), None) => Some(base.clone()),
        (None, Some(route)) => Some(route.clone()),
        (Some(base), Some(route)) => Some(DestinationResolutionOverrideConfig {
            precedence: route.precedence.clone().or_else(|| base.precedence.clone()),
            conflict_mode: route.conflict_mode.or(base.conflict_mode),
            merge_mode: route.merge_mode.or(base.merge_mode),
            min_confidence: match (&base.min_confidence, &route.min_confidence) {
                (None, None) => None,
                (Some(base), None) => Some(base.clone()),
                (None, Some(route)) => Some(route.clone()),
                (Some(base), Some(route)) => {
                    Some(qpx_core::config::DestinationMinConfidenceConfig {
                        category: route.category.or(base.category),
                        reputation: route.reputation.or(base.reputation),
                        application: route.application.or(base.application),
                    })
                }
            },
        }),
    }
}

fn apply_module_flags(
    chain: &crate::http::modules::CompiledHttpModuleChain,
    flags: &mut PlanFlags,
) {
    let aggregate = chain.aggregate();
    if chain.has_request_side_modules() {
        flags.insert(PlanFlags::REQUEST_MODULES);
    }
    if chain.has_response_side_modules() {
        flags.insert(PlanFlags::RESPONSE_MODULES);
    }
    match aggregate.body_access {
        crate::http::modules::BodyAccess::HeadersOnly => {}
        crate::http::modules::BodyAccess::RequestBodyBuffered { .. } => {
            flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
        }
        crate::http::modules::BodyAccess::ResponseBodyBuffered { .. } => {
            flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
        }
        crate::http::modules::BodyAccess::RequestAndResponseBodyBuffered { .. }
        | crate::http::modules::BodyAccess::Streaming => {
            flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
            flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
        }
    }
    if chain.needs_frozen_request() {
        flags.insert(PlanFlags::FROZEN_REQUEST);
    }
}
