use super::{DispatchAuditContext, DispatchOutcome, annotate_dispatch_response};
use crate::destination::DestinationMetadata;
use crate::http::body::Body;
use crate::http::policy::guard::CompiledHttpGuardProfile;
use crate::http::policy::rule_context::attach_destination_trace;
use crate::http::protocol::l7::finalize_response_for_request;
use anyhow::Result;
use hyper::{Request, Response};

pub(crate) struct DispatchGuardInput<'a> {
    pub(crate) profile: Option<&'a CompiledHttpGuardProfile>,
    pub(crate) req: &'a Request<Body>,
    pub(crate) destination: &'a DestinationMetadata,
    pub(crate) proxy_name: &'a str,
    pub(crate) audit: DispatchAuditContext,
}

pub(crate) fn evaluate_http_guard(
    input: DispatchGuardInput<'_>,
) -> impl std::future::Future<Output = Result<Option<Response<Body>>>> + Send + 'static {
    let method = input.req.method().clone();
    let version = input.req.version();
    let proxy_name = input.proxy_name.to_string();
    let mut audit = input.audit;
    attach_destination_trace(&mut audit.log_context, input.destination);
    let evaluated = input
        .profile
        .map(|profile| profile.evaluate_request_async(input.req));
    async move {
        let Some(evaluated) = evaluated else {
            return Ok(None);
        };
        let Some(reject) = evaluated.await? else {
            return Ok(None);
        };
        let mut response = finalize_response_for_request(
            &method,
            version,
            proxy_name.as_str(),
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
}
