use crate::http::body::Body;
use crate::http::body_size::is_observed_body_limit_exceeded;
use crate::http::guard::CompiledHttpGuardProfile;
use crate::http::l7::finalize_response_for_request;
use crate::http::observation::RequestObservationPlan;
use crate::http::response_policy::ResponseRuleCandidates;
use crate::policy_context::{
    EffectivePolicyContext, ResolvedIdentity, resolve_identity, sanitize_headers_for_policy,
};
use anyhow::Result;
use hyper::{Method, Request, Response, StatusCode};
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
    pub(crate) http_guard: Option<&'a CompiledHttpGuardProfile>,
    pub(crate) capture_body: bool,
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
    let mut observation_plan = RequestObservationPlan::from_policy_candidates(
        input.rule_engine,
        input.response_candidates,
        input.prefilter_ctx,
    );
    observation_plan.include_body(input.capture_body);
    observation_plan.include_body(
        input
            .http_guard
            .is_some_and(|profile| profile.requires_request_body_buffering(&input.req)),
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
            return Ok(Err(finalize_response_for_request(
                input.request_method,
                input.request_version,
                input.proxy_name,
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request body too large"))?,
                false,
            )));
        }
        Err(err) => return Err(err),
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
    let request_rpc = observation_plan
        .needs_rpc
        .then(|| crate::http::rpc::inspect_request(&req));
    Ok(Ok(PreparedDispatchRequest {
        req,
        observation_plan,
        sanitized_headers,
        identity,
        request_rpc,
    }))
}
