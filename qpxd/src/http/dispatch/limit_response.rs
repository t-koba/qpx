use super::{DispatchAuditContext, DispatchOutcome, annotate_dispatch_response};
use crate::http::protocol::common::too_many_requests_response;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::rate_limit::AppliedRateLimits;
use hyper::{Method, Response};
use qpx_http::body::Body;
use std::time::Duration;

pub(crate) fn rate_limit_response_for_parts_with_limits(
    method: &Method,
    version: http::Version,
    proxy_name: &str,
    retry_after: Option<Duration>,
    limits: &AppliedRateLimits,
    audit: DispatchAuditContext,
) -> Response<Body> {
    let mut response = too_many_requests_dispatch_response(
        method,
        version,
        proxy_name,
        retry_after,
        audit,
        DispatchOutcome::RateLimited,
    );
    limits.apply_rate_limit_fields(response.headers_mut(), retry_after);
    response
}

fn too_many_requests_dispatch_response(
    method: &Method,
    version: http::Version,
    proxy_name: &str,
    retry_after: Option<Duration>,
    audit: DispatchAuditContext,
    outcome: DispatchOutcome,
) -> Response<Body> {
    let mut response = finalize_response_for_request(
        method,
        version,
        proxy_name,
        too_many_requests_response(retry_after),
        false,
    );
    annotate_dispatch_response(&mut response, &audit, outcome, &[]);
    response
}

pub(crate) fn concurrency_limited_response_for_parts_with_limits(
    method: &Method,
    version: http::Version,
    proxy_name: &str,
    limits: &AppliedRateLimits,
    retry_after: Option<Duration>,
    audit: DispatchAuditContext,
) -> Response<Body> {
    let mut response = too_many_requests_dispatch_response(
        method,
        version,
        proxy_name,
        retry_after,
        audit,
        DispatchOutcome::ConcurrencyLimited,
    );
    limits.apply_rate_limit_fields(response.headers_mut(), retry_after);
    response
}
