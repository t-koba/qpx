mod response;

use crate::http::body::Body;
use crate::http::body::observation::RequestObservationPlan;
use crate::http::body::size::{is_observed_body_limit_exceeded, limit_request_body};
use crate::http::policy::guard::CompiledHttpGuardProfile;
use crate::http::policy::response_policy::ResponseRuleCandidates;
use crate::policy_context::{
    EffectivePolicyContext, ResolvedIdentity, resolve_identity, sanitize_headers_for_policy,
};
use anyhow::Result;
use hyper::{Method, Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::rules::RuleEngine;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

pub(crate) struct DispatchRequestPrepareInput<'a> {
    pub(crate) req: Request<Body>,
    pub(crate) rule_engine: &'a RuleEngine,
    pub(crate) response_candidates: &'a ResponseRuleCandidates,
    pub(crate) prefilter_ctx: MatchPrefilterContext<'a>,
    pub(crate) defer_policy_observation: bool,
    pub(crate) http_guard: Option<&'a CompiledHttpGuardProfile>,
    pub(crate) max_observed_request_body_bytes: usize,
    pub(crate) read_timeout: Duration,
    pub(crate) request_method: &'a Method,
    pub(crate) request_version: http::Version,
    pub(crate) proxy_name: &'a str,
    pub(crate) state: &'a Arc<crate::runtime::RuntimeState>,
    pub(crate) effective_policy: &'a EffectivePolicyContext,
    pub(crate) remote_ip: IpAddr,
}

pub(crate) struct PreparedDispatchRequest {
    pub(crate) req: Request<Body>,
    pub(crate) observation_plan: RequestObservationPlan,
    pub(crate) sanitized_headers: http::HeaderMap,
    pub(crate) identity: ResolvedIdentity,
    pub(crate) request_rpc: Option<crate::http::rpc::RpcMatchContext>,
}

pub(crate) async fn prepare_dispatch_request(
    input: DispatchRequestPrepareInput<'_>,
) -> Result<Result<PreparedDispatchRequest, Response<Body>>> {
    let mut observation_plan = if input.defer_policy_observation {
        RequestObservationPlan::default()
    } else {
        RequestObservationPlan::from_policy_candidates(
            input.rule_engine,
            input.response_candidates,
            input.prefilter_ctx,
        )
    };
    observation_plan.include_body_with_reason(
        input
            .http_guard
            .is_some_and(|profile| profile.requires_request_body_buffering(&input.req)),
        "http_guard.body",
    );
    let req = match observation_plan
        .observe_request(
            input.req,
            input.max_observed_request_body_bytes,
            input.read_timeout,
        )
        .await
    {
        Ok(req) => req,
        Err(err) if is_observed_body_limit_exceeded(&err) => {
            return Ok(Err(response::request_body_too_large_response(
                input.request_method,
                input.request_version,
                input.proxy_name,
            )?));
        }
        Err(err) => return Err(err),
    };
    let req = if let Some(limit) = input
        .http_guard
        .and_then(|profile| profile.request_body_streaming_limit())
    {
        match limit_request_body(req, limit) {
            Ok(req) => req,
            Err(err) if is_observed_body_limit_exceeded(&err) => {
                return Ok(Err(response::request_body_too_large_response(
                    input.request_method,
                    input.request_version,
                    input.proxy_name,
                )?));
            }
            Err(err) => return Err(err),
        }
    } else {
        req
    };
    let mut sanitized_headers = req.headers().clone();
    sanitize_headers_for_policy(
        input.state,
        input.effective_policy,
        input.remote_ip,
        &mut sanitized_headers,
    )?;
    let identity = resolve_identity(
        input.state,
        input.effective_policy,
        input.remote_ip,
        Some(&sanitized_headers),
        None,
    )?;
    let request_rpc = if observation_plan.needs_rpc {
        Some(crate::http::rpc::inspect_request(&req).await)
    } else {
        None
    };
    Ok(Ok(PreparedDispatchRequest {
        req,
        observation_plan,
        sanitized_headers,
        identity,
        request_rpc,
    }))
}
