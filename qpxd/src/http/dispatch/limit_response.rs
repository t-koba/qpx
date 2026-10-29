use super::{DispatchAuditContext, DispatchOutcome, annotate_dispatch_response};
use crate::http::protocol::common::too_many_requests_response;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::rate_limit::AppliedRateLimits;
use hyper::Method;
use qpx_core::http_message::Response;
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
        Response::from_http(too_many_requests_response(retry_after)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::dispatch::{DispatchError, ProxyKind, request_body_too_large_response};
    use crate::http::pipeline::PrepareOutcome;

    #[tokio::test]
    async fn prepared_errors_and_rate_limits_keep_status_retry_and_head_semantics() {
        for method in [Method::GET, Method::HEAD] {
            let audit = DispatchAuditContext::new(
                None,
                ProxyKind::Forward,
                None,
                "127.0.0.1:1234".parse().unwrap(),
                method.clone(),
                None,
                Default::default(),
            );
            let limits = AppliedRateLimits::default();
            for (response, status, body) in [
                (
                    request_body_too_large_response(
                        &method,
                        http::Version::HTTP_2,
                        "qpx-test",
                        Some(&audit),
                    )
                    .unwrap(),
                    http::StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large",
                ),
                (
                    rate_limit_response_for_parts_with_limits(
                        &method,
                        http::Version::HTTP_2,
                        "qpx-test",
                        Some(Duration::ZERO),
                        &limits,
                        audit.clone(),
                    ),
                    http::StatusCode::TOO_MANY_REQUESTS,
                    "too many requests",
                ),
                (
                    concurrency_limited_response_for_parts_with_limits(
                        &method,
                        http::Version::HTTP_2,
                        "qpx-test",
                        &limits,
                        Some(Duration::from_secs(3)),
                        audit.clone(),
                    ),
                    http::StatusCode::TOO_MANY_REQUESTS,
                    "too many requests",
                ),
            ] {
                let outcome: PrepareOutcome<()> = PrepareOutcome::Response(Box::new(response));
                let PrepareOutcome::Response(response) = outcome else {
                    panic!("lost rejection")
                };
                let mut response = if status == http::StatusCode::TOO_MANY_REQUESTS {
                    DispatchError::RateLimited { response }
                        .into_response_result()
                        .unwrap()
                } else {
                    *response
                };
                assert_eq!(response.status(), status);
                assert_eq!(response.version(), http::Version::HTTP_11);
                assert_eq!(
                    response.headers().get(&"via".try_into().unwrap()).unwrap(),
                    "2 qpx-test"
                );
                let retry = response.headers().get(&"retry-after".try_into().unwrap());
                assert_eq!(
                    retry.is_some(),
                    status == http::StatusCode::TOO_MANY_REQUESTS
                );
                if let Some(retry) = retry {
                    assert!(matches!(retry.to_str().unwrap(), "1" | "3"));
                }
                let body_bytes = qpx_http::body::to_bytes(std::mem::take(response.body_mut()))
                    .await
                    .unwrap();
                assert_eq!(body_bytes, if method == Method::HEAD { "" } else { body });
            }
        }
    }
}
