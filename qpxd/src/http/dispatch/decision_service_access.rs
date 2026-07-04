use super::{
    DispatchAuditContext, DispatchOutcome, annotate_dispatch_response, annotated_local_response,
    rate_limit_response_for_parts,
};
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::policy_context::{
    DecisionServiceAllowControls, DecisionServiceDeny, DecisionServiceEnforcement,
    DecisionServiceMode, merge_header_controls, prepare_decision_service_allow_controls,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext, RateLimiters, TransportScope};
use anyhow::Result;
use hyper::{Method, Response};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use std::sync::Arc;

pub(crate) type DecisionServiceRateLimit<'a> = (
    &'a mut AppliedRateLimits,
    &'a RateLimitContext,
    &'a RateLimiters,
);

pub(crate) struct DecisionServiceHttpAccessInput<'a> {
    pub(crate) enforcement: DecisionServiceEnforcement,
    pub(crate) mode: DecisionServiceMode,
    pub(crate) base_headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) request_limit: Option<DecisionServiceRateLimit<'a>>,
    pub(crate) request_head: (&'a Method, http::Version),
    pub(crate) proxy_name: &'a str,
    pub(crate) default_deny_response: Response<Body>,
    pub(crate) audit: &'a DispatchAuditContext,
}

pub(crate) enum DecisionServiceHttpAccessOutcome {
    Continue(DecisionServiceAllowControls),
    Blocked(Response<Body>, bool),
}

pub(crate) fn apply_decision_service_http_access(
    input: DecisionServiceHttpAccessInput<'_>,
) -> Result<DecisionServiceHttpAccessOutcome> {
    match input.enforcement {
        DecisionServiceEnforcement::Continue(allow) => {
            let allow =
                prepare_decision_service_allow_controls(allow, input.mode, input.base_headers)?;
            if let Some((request_limits, request_limit_ctx, rate_limiters)) = input.request_limit
                && let Some(retry_after) = request_limits.merge_profile_and_check(
                    rate_limiters,
                    allow.rate_limit_profile.as_deref(),
                    TransportScope::Request,
                    request_limit_ctx,
                    1,
                )?
            {
                return Ok(DecisionServiceHttpAccessOutcome::Blocked(
                    rate_limit_response_for_parts(
                        input.request_head.0,
                        input.request_head.1,
                        input.proxy_name,
                        Some(retry_after),
                        input.audit.clone(),
                    ),
                    true,
                ));
            }
            Ok(DecisionServiceHttpAccessOutcome::Continue(allow))
        }
        DecisionServiceEnforcement::Deny(deny) => Ok(DecisionServiceHttpAccessOutcome::Blocked(
            decision_service_deny_response(
                deny,
                input.base_headers,
                input.request_head.0,
                input.request_head.1,
                input.proxy_name,
                input.default_deny_response,
                input.audit,
            )?,
            false,
        )),
    }
}

fn decision_service_deny_response(
    deny: DecisionServiceDeny,
    base_headers: Option<Arc<CompiledHeaderControl>>,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    default_response: Response<Body>,
    audit: &DispatchAuditContext,
) -> Result<Response<Body>> {
    let merged_headers = merge_header_controls(base_headers, deny.headers);
    if let Some(local) = deny.local_response.as_ref() {
        return annotated_local_response(
            request_method,
            request_version,
            proxy_name,
            local,
            merged_headers.as_deref(),
            audit,
            DispatchOutcome::DecisionServiceLocalResponse,
        );
    }
    let mut response = finalize_response_with_headers(
        request_method,
        request_version,
        proxy_name,
        default_response,
        merged_headers.as_deref(),
        false,
    );
    annotate_dispatch_response(
        &mut response,
        audit,
        DispatchOutcome::DecisionServiceDeny,
        &[],
    );
    Ok(response)
}
