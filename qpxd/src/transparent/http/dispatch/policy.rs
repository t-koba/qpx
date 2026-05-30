use super::super::ConnectTarget;
use super::types::{TransparentPolicyEvaluation, TransparentPolicyInput, TransparentPolicyStage};
use crate::http::body::size::observed_request_size;
use crate::http::policy::rule_context::{
    RequestRuleContextInput, build_request_rule_match_context,
};
use crate::http::policy::{ListenerPolicyDecision, evaluate_listener_policy};
use crate::http::protocol::common::forbidden_response as forbidden;
use anyhow::Result;
use qpx_core::prefilter::MatchPrefilterContext;
use std::net::SocketAddr;

pub(super) fn transparent_prefilter_context<'a>(
    base: &'a crate::http::protocol::base_fields::BaseRequestFields,
    connect_target: &ConnectTarget,
    remote_addr: SocketAddr,
    host_for_match: &'a Option<String>,
) -> MatchPrefilterContext<'a> {
    MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: Some(connect_target.port()),
        src_ip: Some(remote_addr.ip()),
        host: host_for_match.as_deref(),
        sni: None,
        path: base.path.as_deref(),
    }
}

pub(super) fn evaluate_transparent_policy(
    input: TransparentPolicyInput<'_>,
) -> Result<TransparentPolicyEvaluation> {
    let TransparentPolicyInput {
        engine,
        req,
        base,
        sanitized_headers,
        destination,
        identity,
        request_rpc,
        proxy_name,
        forbidden_message,
    } = input;
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base,
        headers: sanitized_headers,
        destination,
        identity,
        request_size: observed_request_size(req),
        rpc: request_rpc,
        client_cert: None,
        upstream_cert: None,
    });
    let decision = evaluate_listener_policy(
        engine,
        &ctx,
        req.method(),
        req.version(),
        proxy_name,
        forbidden,
        forbidden_message,
    )?;
    let (policy, early_response, matched_rule) = match decision {
        ListenerPolicyDecision::Proceed(mut policy) => {
            let matched_rule = policy.matched_rule.take();
            (Some(policy), None, matched_rule)
        }
        ListenerPolicyDecision::Early(response, matched_rule) => {
            (None, Some(response), matched_rule)
        }
    };
    Ok(TransparentPolicyEvaluation {
        policy,
        early_response,
        matched_rule,
        request_rpc: request_rpc.cloned(),
    })
}

pub(super) fn evaluate_transparent_policy_staged(
    input: TransparentPolicyInput<'_>,
) -> Result<TransparentPolicyStage> {
    let TransparentPolicyInput {
        engine,
        req,
        base,
        sanitized_headers,
        destination,
        identity,
        request_rpc,
        proxy_name,
        forbidden_message,
    } = input;
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base,
        headers: sanitized_headers,
        destination,
        identity,
        request_size: observed_request_size(req),
        rpc: request_rpc,
        client_cert: None,
        upstream_cert: None,
    });
    let prefilter_ctx = MatchPrefilterContext {
        method: ctx.method,
        dst_port: ctx.dst_port,
        src_ip: ctx.src_ip,
        host: ctx.host,
        sni: ctx.sni,
        path: ctx.path,
    };
    let candidates = engine.candidate_rule_indices(prefilter_ctx);
    for (pos, idx) in candidates.iter().copied().enumerate() {
        let Some(rule) = engine.rule_at(idx) else {
            continue;
        };
        let requirements = rule.request_observation_requirements();
        if !requirements.is_empty() {
            if !rule.matches_without_request_body_observation(&ctx) {
                continue;
            }
            let mut combined = qpx_core::rules::CandidateRequestObservationRequirements::default();
            for later_idx in candidates.iter().copied().skip(pos) {
                if let Some(later) = engine.rule_at(later_idx) {
                    let later_requirements = later.request_observation_requirements();
                    if later_requirements.is_empty()
                        || later.matches_without_request_body_observation(&ctx)
                    {
                        combined.include(later_requirements);
                    }
                }
            }
            return Ok(TransparentPolicyStage::Observe(combined));
        }
        if rule.matches(&ctx) {
            return evaluate_transparent_policy(TransparentPolicyInput {
                engine,
                req,
                base,
                sanitized_headers,
                destination,
                identity,
                request_rpc,
                proxy_name,
                forbidden_message,
            })
            .map(Box::new)
            .map(TransparentPolicyStage::Decision);
        }
    }
    evaluate_transparent_policy(TransparentPolicyInput {
        engine,
        req,
        base,
        sanitized_headers,
        destination,
        identity,
        request_rpc,
        proxy_name,
        forbidden_message,
    })
    .map(Box::new)
    .map(TransparentPolicyStage::Decision)
}
