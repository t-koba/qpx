use super::super::ConnectTarget;
use super::types::*;
use crate::http::dispatch::{
    DispatchAuditInput, ProxyKind, build_dispatch_audit_context, rate_limit_response_for_parts,
};
use crate::rate_limit::{RateLimitContext, TransportScope};
use anyhow::Result;
use hyper::Request;
use qpx_http::body::Body;
use std::net::SocketAddr;

pub(super) struct TransparentBuildInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) state: std::sync::Arc<crate::runtime::RuntimeState>,
    pub(super) proxy_name_owned: String,
    pub(super) listener_name: &'a str,
    pub(super) listener_cfg: crate::runtime::CompiledListenerSettings,
    pub(super) remote_addr: SocketAddr,
    pub(super) base: crate::http::protocol::base_fields::BaseRequestFields,
    pub(super) connect_target: ConnectTarget,
    pub(super) host_for_match: Option<String>,
    pub(super) effective_policy: crate::policy_context::EffectivePolicyContext,
    pub(super) destination: crate::destination::DestinationMetadata,
    pub(super) identity: crate::policy_context::ResolvedIdentity,
    pub(super) sanitized_headers: http::HeaderMap,
    pub(super) response_engine:
        Option<std::sync::Arc<crate::http::policy::response_policy::HttpResponseRuleEngine>>,
    pub(super) selected_plan: crate::runtime::ExecutionPlan,
    pub(super) response_request_observation:
        qpx_core::rules::CandidateRequestObservationRequirements,
    pub(super) max_observed_request_body_bytes: usize,
    pub(super) body_read_timeout: std::time::Duration,
    pub(super) request_body_observed: bool,
    pub(super) request_rpc_observed: bool,
    pub(super) policy_evaluation: TransparentPolicyEvaluation,
}

pub(super) fn build_transparent_prepared(
    input: TransparentBuildInput<'_>,
) -> Result<TransparentPrepareOutcome> {
    let TransparentBuildInput {
        req,
        state,
        proxy_name_owned,
        listener_name,
        listener_cfg,
        remote_addr,
        base,
        connect_target,
        host_for_match,
        effective_policy,
        destination,
        identity,
        sanitized_headers,
        response_engine,
        selected_plan,
        response_request_observation,
        max_observed_request_body_bytes,
        body_read_timeout,
        request_body_observed,
        request_rpc_observed,
        policy_evaluation,
    } = input;
    let TransparentPolicyEvaluation {
        policy,
        early_response,
        matched_rule,
        request_rpc,
    } = policy_evaluation;
    let proxy_name = proxy_name_owned.as_str();
    let request_limit_ctx =
        RateLimitContext::from_identity(remote_addr.ip(), &identity, matched_rule.as_deref(), None);
    let crate::rate_limit::RequestLimitAcquire {
        limits: request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        let response = rate_limit_response_for_parts(
            req.method(),
            req.version(),
            proxy_name,
            Some(retry_after),
            build_dispatch_audit_context(DispatchAuditInput {
                state: state.clone(),
                kind: ProxyKind::Transparent,
                scope_name: listener_name,
                remote_addr,
                host: host_for_match.clone(),
                sni: None,
                request_method: req.method().clone(),
                path: base.path.clone(),
                matched_rule: matched_rule.clone(),
                matched_route: None,
                identity: &identity,
                destination: &destination,
                ext_authz: None,
            }),
        );
        let response =
            crate::http::capture::stream::limit_response_body_for_plan(response, &selected_plan);
        return Ok(TransparentPrepareOutcome::Response(Box::new(response)));
    }
    Ok(TransparentPrepareOutcome::Prepared(Box::new(
        TransparentPreparedRequest {
            req,
            context: crate::http::pipeline::types::RequestContext {
                runtime: None,
                state,
                proxy_name: proxy_name_owned,
                listener_name: listener_name.to_string(),
                listener_cfg,
                remote_addr,
            },
            limits: crate::http::pipeline::types::RequestLimits {
                request_limits,
                request_limit_ctx,
                max_observed_request_body_bytes,
                body_read_timeout,
            },
            observation: crate::http::pipeline::types::RequestObservation {
                request_rpc,
                response_request_observation,
                request_body_observed,
                request_rpc_observed,
            },
            mode: TransparentPreparedMode {
                connect_target,
                host_for_match,
            },
            base,
            policy: TransparentPreparedPolicy {
                effective_policy,
                destination,
                identity,
                sanitized_headers,
                response_engine,
                selected_plan,
                policy,
                early_response,
                matched_rule,
            },
        },
    )))
}
