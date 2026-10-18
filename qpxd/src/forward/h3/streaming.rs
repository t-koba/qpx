use crate::destination::{DestinationInputs, DestinationMetadata};
use crate::http::policy::rule_context::{
    RequestRuleContextInput, build_request_rule_match_context,
};
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::policy_context::sanitize_headers_for_policy;
use crate::runtime::{ResolvedStreamingLimits, Runtime};
use http::Request;
use std::net::SocketAddr;

pub(super) fn request_streaming_limits_for_head(
    runtime: &Runtime,
    listener_name: &str,
    req_head: &Request<()>,
    remote_addr: SocketAddr,
    fallback: ResolvedStreamingLimits,
) -> ResolvedStreamingLimits {
    let state = runtime.state();
    let Some(edge) = state.plan.forward_edge(listener_name) else {
        return fallback;
    };
    let base = extract_base_request_fields(
        req_head,
        BaseRequestContext {
            peer_ip: Some(remote_addr.ip()),
            scheme: req_head.uri().scheme().cloned(),
            ..Default::default()
        },
    );
    let Some(host) = base.host() else {
        return fallback;
    };
    let prefilter_ctx = qpx_core::prefilter::MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: base.dst_port,
        src_ip: Some(remote_addr.ip()),
        host: Some(host),
        sni: None,
        path: base.path(),
    };
    let Some(engine) = state.policy.rules_by_listener.get(listener_name) else {
        return fallback;
    };
    let candidates = engine.candidate_rule_indices(prefilter_ctx);
    if candidates.is_empty() {
        return fallback;
    }

    let mut deferred_limits: Option<ResolvedStreamingLimits> = None;
    for idx in candidates {
        let Some(rule) = engine.rule_at(idx) else {
            continue;
        };
        let matched_rule_name = rule.name();
        let Some(compiled_rule) = edge
            .rules
            .iter()
            .find(|compiled| compiled.name.as_ref() == matched_rule_name)
        else {
            continue;
        };
        let effective_policy = compiled_rule.plan.policy_context.clone();
        let mut sanitized_headers = req_head.headers().clone();
        if sanitize_headers_for_policy(
            &state,
            &effective_policy,
            remote_addr.ip(),
            &mut sanitized_headers,
        )
        .is_err()
        {
            return fallback;
        }
        let identity = match crate::policy_context::resolve_identity_local(
            &state,
            &effective_policy,
            remote_addr.ip(),
            Some(&sanitized_headers),
            None,
        ) {
            Ok(identity) => identity,
            Err(_) => return fallback,
        };
        let destination = classify_forward_h3_destination(
            &state,
            &base,
            compiled_rule.plan.destination_resolution.as_ref(),
        );
        let ctx = build_request_rule_match_context(RequestRuleContextInput {
            base: &base,
            headers: &sanitized_headers,
            destination: &destination,
            identity: &identity,
            request_size: None,
            rpc: None,
            client_cert: None,
            upstream_cert: None,
        });
        let requirements = rule.request_observation_requirements();
        if !requirements.is_empty() {
            if rule.matches_without_request_body_observation(&ctx) {
                let current = deferred_limits.unwrap_or(fallback);
                deferred_limits =
                    Some(current.request_side_fail_closed(compiled_rule.plan.streaming));
            }
            continue;
        }
        if rule.matches(&ctx) {
            return deferred_limits
                .map(|limits| limits.request_side_fail_closed(compiled_rule.plan.streaming))
                .unwrap_or(compiled_rule.plan.streaming);
        }
    }
    deferred_limits.unwrap_or(fallback)
}

fn classify_forward_h3_destination(
    state: &crate::runtime::RuntimeState,
    base: &crate::http::protocol::base_fields::BaseRequestFields,
    resolution_override: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
) -> DestinationMetadata {
    state.classify_destination(
        &DestinationInputs {
            host: base.host(),
            ip: base.host().and_then(|host| host.parse().ok()),
            scheme: base.scheme.as_ref().map(http::uri::Scheme::as_str),
            port: base.dst_port,
            alpn: Some("h3"),
            ..Default::default()
        },
        resolution_override,
    )
}
