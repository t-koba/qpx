use super::super::mirrors::{
    record_reverse_upstream_error, record_reverse_upstream_status, record_reverse_upstream_timeout,
};
use super::super::{InterimList, ReverseConnInfo};
use super::apply_reverse_route_metadata;
use super::prepare::{enforce_selected_reverse_route_constraints, reverse_security_rejection};
use crate::http::codec::lazy_timeout::timeout_after_pending;
use crate::reverse::ReloadableReverse;
use crate::reverse::router::HttpRoute;
use crate::upstream::origin::{
    PreparedPlainHttp1ConnectionAffinity, prepare_proxy_http1_request,
    proxy_direct_plain_http1_raw_response_with_interim,
    proxy_direct_plain_http1_raw_response_with_interim_on_connection,
};
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use qpx_http::body::Body;
use std::sync::Arc;

pub(in crate::reverse::transport) async fn try_dispatch_unconditional_plain_reverse_request(
    req: Request<Body>,
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<std::result::Result<(InterimList, Response<Body>), Request<Body>>> {
    let request_version = req.version();
    if state.destination_trace_enabled()
        || qpx_observability::metrics_enabled()
        || qpx_observability::request_spans_enabled()
        || !state.security.identity_sources.sources.is_empty()
        || req.method() == http::Method::CONNECT
        || !matches!(
            request_version,
            http::Version::HTTP_11 | http::Version::HTTP_2
        )
        || req.headers().contains_key(http::header::UPGRADE)
    {
        return Ok(Err(req));
    }
    let Some(compiled) = reverse.compiled_if_current(state) else {
        return Ok(Err(req));
    };
    let Some(route) = compiled.router.single_plain_http_route() else {
        return Ok(Err(req));
    };
    if !route.matches_every_request() || route.available_plain_http_upstream().is_none() {
        return Ok(Err(req));
    }
    if let Some(response) = reverse_security_rejection(&req, conn, state, &compiled)? {
        return Ok(Ok(response));
    }
    let request_method = req.method().clone();
    let req =
        match enforce_selected_reverse_route_constraints(req, route, &request_method, state, conn)?
        {
            Ok(req) => req,
            Err(mut response) => {
                apply_reverse_route_metadata(route, conn.tls_terminated, &mut response.1)?;
                return Ok(Ok(response));
            }
        };
    let (interim, mut response) = dispatch_plain_reverse_http(
        req,
        state,
        route,
        &request_method,
        request_version,
        state.plan.identity.proxy_name.as_ref(),
        connection_pool,
    )
    .await?;
    apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
    Ok(Ok((interim, response)))
}

pub(super) async fn dispatch_plain_reverse_http(
    req: Request<Body>,
    state: &crate::runtime::RuntimeState,
    route: &HttpRoute,
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, Response<Body>)> {
    let selected_upstream = route
        .available_plain_http_upstream()
        .ok_or_else(|| anyhow!("plain HTTP fast path requires one static HTTP upstream"))?;
    let (connect_authority, host_authority) = selected_upstream
        .origin
        .direct_plain_http1_authorities()
        .ok_or_else(|| anyhow!("plain HTTP fast path requires a precompiled HTTP authority"))?;
    let req = prepare_proxy_http1_request(req, host_authority, proxy_name)?;
    let started = route
        .policy
        .passive_health
        .as_ref()
        .is_some_and(|policy| policy.latency_threshold.is_some())
        .then(tokio::time::Instant::now);
    let response = timeout_after_pending(route.policy.timeout, async {
        if let Some(connection_pool) = connection_pool {
            proxy_direct_plain_http1_raw_response_with_interim_on_connection(
                &state.pools,
                req,
                connect_authority,
                host_authority,
                request_version,
                proxy_name,
                connection_pool,
            )
            .await
        } else {
            proxy_direct_plain_http1_raw_response_with_interim(
                &state.pools,
                req,
                connect_authority,
                host_authority,
                request_version,
                proxy_name,
            )
            .await
        }
    })
    .await;
    let (interim, response, response_finalized) = match response {
        Ok(Ok(response)) => (
            response.interim,
            response.response,
            response.response_finalized,
        ),
        Ok(Err(err)) => {
            record_reverse_upstream_error(selected_upstream, &route.policy, &err);
            return Err(err);
        }
        Err(_) => {
            record_reverse_upstream_timeout(selected_upstream, &route.policy);
            return Err(anyhow!("upstream timeout"));
        }
    };
    record_reverse_upstream_status(selected_upstream, &route.policy, response.status(), started);
    let mut response = response;
    crate::http::capture::stream::limit_response_body_for_plan_in_place(&mut response, &route.plan);
    if !response_finalized {
        crate::http::protocol::l7::finalize_response_with_headers_in_place(
            request_method,
            request_version,
            proxy_name,
            &mut response,
            None,
            false,
        );
    }
    debug_assert_ne!(request_version, http::Version::HTTP_3);
    Ok((interim, response))
}
