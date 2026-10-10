use crate::http::body::size::{limit_request_body, observed_request_size};
use crate::http::dispatch::request_body_too_large_response;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::reverse::transport::{InterimList, ReverseConnInfo, empty_interim_response};
use anyhow::Result;
use hyper::{Method, Request, Response, StatusCode};
use qpx_http::body::Body;
use tracing::warn;

pub(super) type ReverseEarlyResult<T> = std::result::Result<T, (InterimList, Response<Body>)>;

pub(super) fn reverse_security_rejection(
    req: &Request<Body>,
    conn: &ReverseConnInfo,
    state: &crate::runtime::RuntimeState,
    compiled: &crate::reverse::CompiledReverse,
) -> Result<Option<(InterimList, Response<Body>)>> {
    let Err(err) = compiled.security_policy.validate_request(
        req,
        conn.tls_sni.as_deref(),
        conn.tls_terminated,
    ) else {
        return Ok(None);
    };
    warn!(error = ?err, "reverse TLS host policy rejected request");
    Ok(Some(empty_interim_response(finalize_response_for_request(
        req.method(),
        req.version(),
        state.plan.identity.proxy_name.as_ref(),
        Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(Body::from("misdirected request"))?,
        false,
    ))))
}

pub(super) fn enforce_selected_reverse_route_constraints(
    mut req: Request<Body>,
    route: &crate::reverse::router::HttpRoute,
    request_method: &Method,
    state: &crate::runtime::RuntimeState,
    conn: &ReverseConnInfo,
) -> Result<ReverseEarlyResult<Request<Body>>> {
    let request_version = req.version();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    if let Err(error) = route.plan.client_certificate.apply(
        req.headers_mut(),
        conn.peer_certificates.as_deref().map(Vec::as_slice),
    ) {
        if matches!(
            error,
            qpx_http::client_cert::ClientCertError::InboundHeader { .. }
        ) {
            let status = StatusCode::BAD_REQUEST;
            let body = qpx_http::problem::ProblemDetails::new(
                status,
                "Untrusted client certificate field",
            )
            .with_detail(error.to_string())
            .to_json()?;
            let response = Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
                .body(Body::from(body))?;
            return Ok(Err(empty_interim_response(finalize_response_for_request(
                request_method,
                request_version,
                proxy_name,
                response,
                false,
            ))));
        }
        return Err(error.into());
    }
    if let Some(policy) = route.plan.fetch_metadata.as_deref() {
        let decision = match policy.evaluate_headers(req.headers()) {
            Ok(decision) => decision,
            Err(error) => {
                return fetch_metadata_rejection(
                    request_method,
                    request_version,
                    proxy_name,
                    route,
                    conn,
                    (
                        StatusCode::BAD_REQUEST,
                        "Invalid Fetch Metadata",
                        error.to_string(),
                    ),
                );
            }
        };
        if decision != qpx_core::browser_policy::FetchMetadataDecision::Allowed {
            return fetch_metadata_rejection(
                request_method,
                request_version,
                proxy_name,
                route,
                conn,
                (
                    StatusCode::FORBIDDEN,
                    "Fetch Metadata policy rejected request",
                    format!("request rejected by {decision:?} policy decision"),
                ),
            );
        }
    }
    if route.plan.require_precondition
        && qpx_http::protocol::method::precondition_is_missing(request_method, req.headers())
    {
        let status = StatusCode::PRECONDITION_REQUIRED;
        let body = qpx_http::problem::ProblemDetails::new(status, "Precondition required")
            .with_detail("This route requires If-Match or If-Unmodified-Since")
            .to_json()?;
        let response = Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
            .body(Body::from(body))?;
        return Ok(Err(empty_interim_response(finalize_response_for_request(
            request_method,
            request_version,
            proxy_name,
            response,
            false,
        ))));
    }
    let max_request_body_bytes = route.plan.streaming.max_request_body_bytes;
    if let Some(size) = observed_request_size(&req)
        && size > max_request_body_bytes as u64
    {
        return Ok(Err(request_body_too_large_response(
            request_method,
            request_version,
            proxy_name,
            None,
        )
        .map(empty_interim_response)?));
    }
    req = match limit_request_body(req, max_request_body_bytes) {
        Ok(req) => req,
        Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
            return Ok(Err(request_body_too_large_response(
                request_method,
                request_version,
                proxy_name,
                None,
            )
            .map(empty_interim_response)?));
        }
        Err(err) => return Err(err),
    };
    Ok(Ok(req))
}

fn fetch_metadata_rejection(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    route: &crate::reverse::router::HttpRoute,
    conn: &ReverseConnInfo,
    problem: (StatusCode, &'static str, String),
) -> Result<ReverseEarlyResult<Request<Body>>> {
    let (status, title, detail) = problem;
    let body = qpx_http::problem::ProblemDetails::new(status, title)
        .with_detail(detail)
        .to_json()?;
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
        .body(Body::from(body))?;
    let mut response =
        finalize_response_for_request(request_method, request_version, proxy_name, response, false);
    super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
    Ok(Err(empty_interim_response(response)))
}
