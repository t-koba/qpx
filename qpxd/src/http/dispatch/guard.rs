use super::{DispatchAuditContext, DispatchOutcome, annotate_dispatch_response};
use crate::destination::DestinationMetadata;
use crate::http::body::Body;
use crate::http::guard::CompiledHttpGuardProfile;
use crate::http::l7::finalize_response_for_request;
use crate::http::rule_context::attach_destination_trace;
use anyhow::Result;
use hyper::{Request, Response};

pub(crate) struct DispatchGuardInput<'a> {
    pub(crate) profile: Option<&'a CompiledHttpGuardProfile>,
    pub(crate) req: &'a Request<Body>,
    pub(crate) destination: &'a DestinationMetadata,
    pub(crate) proxy_name: &'a str,
    pub(crate) audit: DispatchAuditContext,
}

pub(crate) fn evaluate_http_guard(input: DispatchGuardInput<'_>) -> Result<Option<Response<Body>>> {
    let Some(profile) = input.profile else {
        return Ok(None);
    };
    let Some(reject) = profile.evaluate_request(input.req)? else {
        return Ok(None);
    };
    let mut audit = input.audit;
    attach_destination_trace(&mut audit.log_context, input.destination);
    let mut response = finalize_response_for_request(
        input.req.method(),
        input.req.version(),
        input.proxy_name,
        Response::builder()
            .status(reject.status)
            .body(Body::from(reject.body))?,
        false,
    );
    annotate_dispatch_response(
        &mut response,
        &audit,
        DispatchOutcome::GuardReject.audit_outcome(),
        &[],
    );
    Ok(Some(response))
}
