use super::{DispatchAuditContext, DispatchOutcome, annotate_dispatch_response};
use crate::destination::DestinationMetadata;
use crate::http::policy::guard::{CompiledHttpGuardProfile, HttpGuardReject};
use crate::http::policy::rule_context::attach_destination_trace;
use crate::http::protocol::l7::finalize_response_for_request;
use anyhow::Result;
use hyper::{Request, Response};
use qpx_http::body::Body;

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
    let (immediate, pending) = match input.profile {
        None => (Ok(None), None),
        Some(profile) => match profile.evaluate_request_head(input.req) {
            Err(error) => (Err(error), None),
            Ok(Some(reject)) => {
                let mut audit = input.audit;
                attach_destination_trace(&mut audit.log_context, input.destination);
                (
                    build_guard_rejection(
                        input.req.method(),
                        input.req.version(),
                        input.proxy_name,
                        audit,
                        reject,
                    )
                    .map(Some),
                    None,
                )
            }
            Ok(None) if !profile.may_require_request_body_buffering() => (Ok(None), None),
            Ok(None) => {
                let evaluation = profile.evaluate_request_body_async(input.req);
                let method = input.req.method().clone();
                let version = input.req.version();
                let proxy_name = input.proxy_name.to_string();
                let mut audit = input.audit;
                attach_destination_trace(&mut audit.log_context, input.destination);
                (
                    Ok(None),
                    Some((evaluation, method, version, proxy_name, audit)),
                )
            }
        },
    };
    async move {
        let Some((evaluation, method, version, proxy_name, audit)) = pending else {
            return immediate;
        };
        let Some(reject) = evaluation.await? else {
            return Ok(None);
        };
        build_guard_rejection(&method, version, proxy_name.as_str(), audit, reject).map(Some)
    }
}

fn build_guard_rejection(
    method: &hyper::Method,
    version: hyper::Version,
    proxy_name: &str,
    audit: DispatchAuditContext,
    reject: HttpGuardReject,
) -> Result<Response<Body>> {
    let mut response = finalize_response_for_request(
        method,
        version,
        proxy_name,
        Response::builder()
            .status(reject.status)
            .body(Body::from(reject.body))?,
        false,
    );
    annotate_dispatch_response(&mut response, &audit, DispatchOutcome::GuardReject, &[]);
    Ok(response)
}
