use crate::http::dispatch::DispatchOutcome;
use crate::http::local_response::finalized_local_response;
use crate::http::protocol::common::{forbidden_response, too_many_requests_response};
use crate::http::protocol::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::policy_context::{
    DecisionServiceAllow, DecisionServiceEnforcement, DecisionServiceMode,
    prepare_decision_service_allow,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext, RateLimiters, TransportScope};
use ::http::{Method, Response, Version};
use anyhow::Result;
use qpx_core::config::ActionConfig;
use qpx_http::body::Body;
use std::ops::ControlFlow;

#[allow(clippy::too_many_arguments)]
pub(in crate::forward) fn apply_connect_decision_service(
    enforcement: DecisionServiceEnforcement,
    req_version: Version,
    proxy_name: &str,
    forbidden_message: &str,
    rate_limiters: &RateLimiters,
    request_limits: &mut AppliedRateLimits,
    request_limit_ctx: &RateLimitContext,
    action: &mut ActionConfig,
) -> Result<ControlFlow<(Response<Body>, DispatchOutcome), DecisionServiceAllow>> {
    match enforcement {
        DecisionServiceEnforcement::Continue(allow) => {
            let allow =
                prepare_decision_service_allow(allow, DecisionServiceMode::ForwardConnect, None)?;
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                rate_limiters,
                allow.rate_limit_profile.as_deref(),
                TransportScope::Connect,
                request_limit_ctx,
                1,
            )? {
                let mut response = finalize_response_for_request(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    too_many_requests_response(Some(retry_after)),
                    false,
                );
                request_limits.apply_rate_limit_fields(response.headers_mut(), Some(retry_after));
                return Ok(ControlFlow::Break((response, DispatchOutcome::RateLimited)));
            }
            allow.apply_action_overrides(action);
            Ok(ControlFlow::Continue(allow))
        }
        DecisionServiceEnforcement::Deny(deny) => {
            let outcome = if deny.local_response.is_some() {
                DispatchOutcome::DecisionServiceLocalResponse
            } else {
                DispatchOutcome::DecisionServiceDeny
            };
            let response = if let Some(local) = deny.local_response.as_ref() {
                finalized_local_response(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    local,
                    deny.headers.as_deref(),
                )?
            } else {
                finalize_response_with_headers(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    forbidden_response(forbidden_message),
                    deny.headers.as_deref(),
                    false,
                )
            };
            Ok(ControlFlow::Break((response, outcome)))
        }
    }
}
