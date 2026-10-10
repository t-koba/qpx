use super::PreparedReverseRequest;
use super::prepare_cors::prepare_cors_preflight;
use super::prepare_finalize::finalize_reverse_route_selection;
use super::prepare_initial::{
    InitialReverseScan, initial_scan_reverse_routes, reverse_prefilter_context,
};
use super::prepare_scan::observe_body_and_rescan_reverse_routes;
use super::prepare_single::{SingleHttpPrepare, try_prepare_single_http_reverse_request};
use super::route_constraints::reverse_security_rejection;
use crate::http::dispatch::request_body_too_large_response;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::reverse::transport::{InterimList, ReverseConnInfo};
use anyhow::Result;
use hyper::{Method, Request, Response};
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::time::Duration;

pub(super) fn attach_streaming_limits(
    mut result: (InterimList, Response<Body>),
    streaming: crate::runtime::ResolvedStreamingLimits,
    downstream_version: http::Version,
) -> (InterimList, Response<Body>) {
    if downstream_version == http::Version::HTTP_3 {
        result.1.extensions_mut().insert(streaming);
    }
    result
}

pub(super) async fn buffer_reverse_guarded_request(
    req: Request<Body>,
    route_http_guard: Option<&crate::http::policy::guard::CompiledHttpGuardProfile>,
    max_observed_request_body_bytes: usize,
    read_timeout: Duration,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
) -> Result<std::result::Result<Request<Body>, Response<Body>>> {
    let limit_response = || -> Result<Response<Body>> {
        request_body_too_large_response(request_method, request_version, proxy_name, None)
    };
    let mut req = if !route_http_guard
        .is_some_and(|profile| profile.requires_request_body_buffering(&req))
        || crate::http::body::size::has_observed_request_bytes(&req)
    {
        req
    } else {
        match crate::http::body::size::buffer_request_body_with_reason(
            req,
            max_observed_request_body_bytes,
            read_timeout,
            "http_guard.body",
        )
        .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return Ok(Err(limit_response()?));
            }
            Err(err) => return Err(err),
        }
    };
    if let Some(limit) = route_http_guard.and_then(|profile| profile.request_body_streaming_limit())
    {
        req = match crate::http::body::size::limit_request_body(req, limit) {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return Ok(Err(limit_response()?));
            }
            Err(err) => return Err(err),
        };
    }
    Ok(Ok(req))
}

pub(super) async fn prepare_reverse_request(
    mut req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: Arc<crate::runtime::RuntimeState>,
    compiled: Arc<crate::reverse::CompiledReverse>,
    cors_request: Option<&qpx_core::cors::CorsRequest>,
) -> Result<std::result::Result<PreparedReverseRequest, (InterimList, Response<Body>)>> {
    let router = &compiled.router;
    if let Some(response) = reverse_security_rejection(&req, conn, &state, &compiled)? {
        return Ok(Err(response));
    }

    if let Some(cors_request) = cors_request.filter(|request| request.is_preflight())
        && let Some(response) = prepare_cors_preflight(
            req.headers().clone(),
            req.version(),
            base,
            conn,
            &state,
            router,
            cors_request,
        )
        .await?
    {
        return Ok(Err(response));
    }

    match try_prepare_single_http_reverse_request(req, base, conn, &state, &compiled, cors_request)?
    {
        SingleHttpPrepare::Hit(fast) => {
            return match *fast {
                Ok(prepared) => Ok(Ok(prepared)),
                Err(response) => Ok(Err(response)),
            };
        }
        SingleHttpPrepare::Miss(req_back) => {
            req = *req_back;
        }
    }
    let host = base.host().unwrap_or_default();
    let prefilter_ctx = reverse_prefilter_context(base, conn, host);
    let InitialReverseScan {
        mut selection,
        owned_sanitized_headers,
        identity_request,
    } = match initial_scan_reverse_routes(
        req.headers(),
        req.version(),
        base,
        conn,
        &state,
        router,
        host,
        prefilter_ctx.clone(),
    )
    .await?
    {
        Ok(initial) => initial,
        Err(response) => return Ok(Err(response)),
    };

    let (observed_req, request_rpc) = match observe_body_and_rescan_reverse_routes(
        req,
        base,
        conn,
        &state,
        &compiled,
        host,
        prefilter_ctx,
        identity_request.as_ref(),
        &mut selection,
        &owned_sanitized_headers,
    )
    .await?
    {
        Ok(observed) => observed,
        Err(response) => return Ok(Err(response)),
    };
    req = observed_req;

    finalize_reverse_route_selection(
        req,
        base,
        conn,
        &state,
        &compiled,
        cors_request,
        host,
        selection,
        owned_sanitized_headers,
        request_rpc,
    )
}
