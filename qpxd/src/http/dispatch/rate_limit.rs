use super::{DispatchAuditContext, DispatchOutcome, annotate_dispatch_response};
use crate::http::body::Body;
use crate::http::protocol::common::too_many_requests_response;
use crate::http::protocol::l7::finalize_response_for_request;
use hyper::{Request, Response};
use std::time::Duration;

pub(crate) struct DispatchRateLimitInput<'a> {
    pub(crate) req: &'a Request<Body>,
    pub(crate) proxy_name: &'a str,
    pub(crate) retry_after: Option<Duration>,
    pub(crate) audit: DispatchAuditContext,
}

pub(crate) fn rate_limit_response(input: DispatchRateLimitInput<'_>) -> Response<Body> {
    let mut response = finalize_response_for_request(
        input.req.method(),
        input.req.version(),
        input.proxy_name,
        too_many_requests_response(input.retry_after),
        false,
    );
    annotate_dispatch_response(
        &mut response,
        &input.audit,
        DispatchOutcome::RateLimited.audit_outcome(),
        &[],
    );
    response
}
