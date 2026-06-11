use super::{
    DispatchAuditContext, DispatchOutcome, annotate_dispatch_response, annotated_local_response,
    rate_limit_response_for_parts,
};
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::policy_context::{
    ExtAuthzAllowControls, ExtAuthzDeny, ExtAuthzEnforcement, ExtAuthzMode, merge_header_controls,
    prepare_ext_authz_allow_controls,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext, RateLimiters, TransportScope};
use anyhow::Result;
use hyper::{Method, Response};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use std::sync::Arc;

pub(crate) type ExtAuthzRateLimit<'a> = (
    &'a mut AppliedRateLimits,
    &'a RateLimitContext,
    &'a RateLimiters,
);

pub(crate) struct ExtAuthzHttpAccessInput<'a> {
    pub(crate) enforcement: ExtAuthzEnforcement,
    pub(crate) mode: ExtAuthzMode,
    pub(crate) base_headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) request_limit: Option<ExtAuthzRateLimit<'a>>,
    pub(crate) request_head: (&'a Method, http::Version),
    pub(crate) proxy_name: &'a str,
    pub(crate) default_deny_response: Response<Body>,
    pub(crate) audit: &'a DispatchAuditContext,
}

pub(crate) enum ExtAuthzHttpAccessOutcome {
    Continue(ExtAuthzAllowControls),
    Blocked(Response<Body>, bool),
}

pub(crate) fn apply_ext_authz_http_access(
    input: ExtAuthzHttpAccessInput<'_>,
) -> Result<ExtAuthzHttpAccessOutcome> {
    match input.enforcement {
        ExtAuthzEnforcement::Continue(allow) => {
            let allow = prepare_ext_authz_allow_controls(allow, input.mode, input.base_headers)?;
            if let Some((request_limits, request_limit_ctx, rate_limiters)) = input.request_limit
                && let Some(retry_after) = request_limits.merge_profile_and_check(
                    rate_limiters,
                    allow.rate_limit_profile.as_deref(),
                    TransportScope::Request,
                    request_limit_ctx,
                    1,
                )?
            {
                return Ok(ExtAuthzHttpAccessOutcome::Blocked(
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
            Ok(ExtAuthzHttpAccessOutcome::Continue(allow))
        }
        ExtAuthzEnforcement::Deny(deny) => Ok(ExtAuthzHttpAccessOutcome::Blocked(
            ext_authz_deny_response(
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

fn ext_authz_deny_response(
    deny: ExtAuthzDeny,
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
            DispatchOutcome::ExtAuthzLocalResponse,
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
    annotate_dispatch_response(&mut response, audit, DispatchOutcome::ExtAuthzDeny, &[]);
    Ok(response)
}
