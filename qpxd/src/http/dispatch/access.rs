use super::{DispatchAuditContext, DispatchOutcome, annotate_dispatch_response};
use crate::http::body::Body;
use crate::http::local_response::build_local_response;
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::policy_context::{ExtAuthzEnforcement, merge_header_controls};
use anyhow::{Result, anyhow};
use hyper::{Method, Response};
use qpx_core::rules::CompiledHeaderControl;
use std::sync::Arc;

pub(crate) struct ExtAuthzDenyResponseInput<'a> {
    pub(crate) ext_authz: ExtAuthzEnforcement,
    pub(crate) base_headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) request_method: &'a Method,
    pub(crate) request_version: http::Version,
    pub(crate) proxy_name: &'a str,
    pub(crate) default_response: Response<Body>,
    pub(crate) audit: &'a DispatchAuditContext,
}

pub(crate) fn ext_authz_deny_response(
    input: ExtAuthzDenyResponseInput<'_>,
) -> Result<Response<Body>> {
    let ExtAuthzEnforcement::Deny(deny) = input.ext_authz else {
        return Err(anyhow!(
            "ext_authz_deny_response requires a deny enforcement result"
        ));
    };
    let merged_headers = merge_header_controls(input.base_headers, deny.headers);
    let local_response = deny.local_response.is_some();
    let mut response = if let Some(local) = deny.local_response.as_ref() {
        finalize_response_with_headers(
            input.request_method,
            input.request_version,
            input.proxy_name,
            build_local_response(local)?,
            merged_headers.as_deref(),
            false,
        )
    } else {
        finalize_response_with_headers(
            input.request_method,
            input.request_version,
            input.proxy_name,
            input.default_response,
            merged_headers.as_deref(),
            false,
        )
    };
    let outcome = if local_response {
        DispatchOutcome::ExtAuthzLocalResponse
    } else {
        DispatchOutcome::ExtAuthzDeny
    };
    annotate_dispatch_response(&mut response, input.audit, outcome.audit_outcome(), &[]);
    Ok(response)
}
