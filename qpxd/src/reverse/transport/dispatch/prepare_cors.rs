use super::prepare::{ReverseRouteSelection, scan_reverse_routes};
use super::{InlineCache, empty_interim_response};
use crate::http::body::observation::RequestObservationPlan;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::policy_context::EffectivePolicyContext;
use crate::reverse::transport::{InterimList, ReverseConnInfo, ReverseRouter};
use anyhow::{Result, anyhow};
use hyper::{Method, Response, StatusCode};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
use std::sync::Arc;

pub(super) async fn prepare_cors_preflight(
    request_headers: http::HeaderMap,
    request_version: http::Version,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    router: &ReverseRouter,
    cors_request: &qpx_core::cors::CorsRequest,
) -> Result<Option<(InterimList, Response<Body>)>> {
    let preflight = cors_request
        .preflight()
        .ok_or_else(|| anyhow!("CORS preflight facts are missing"))?;
    let mut route_base = base.clone();
    route_base.method = preflight.method().clone();
    let host = route_base.host().unwrap_or_default();
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(route_base.method.as_str()),
        dst_port: Some(conn.dst_port),
        src_ip: Some(conn.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host),
        sni: conn.tls_sni.as_deref(),
        path: route_base.path(),
    };
    let mut selection = ReverseRouteSelection {
        route_idx: None,
        selected_policy: EffectivePolicyContext::default(),
        selected_identity: None,
        request_destination_cache: InlineCache::new(),
        identity_cache: InlineCache::new(),
        observation_plan: RequestObservationPlan::default(),
        max_observed_request_body_bytes: state.plan.limits.body.max_observed_request_body_bytes,
        collect_observation_from_remaining: false,
    };
    scan_reverse_routes(
        router,
        &request_headers,
        &request_headers,
        &route_base,
        state,
        conn,
        host,
        prefilter_ctx,
        None,
        None,
        true,
        None,
        &mut selection,
    )
    .await?;
    let Some(route_idx) = selection.route_idx else {
        return Ok(None);
    };
    let route = router
        .route_at(route_idx)
        .ok_or_else(|| anyhow!("selected CORS route is unavailable"))?;
    let policy = route
        .plan
        .cors
        .as_deref()
        .ok_or_else(|| anyhow!("selected CORS route has no compiled policy"))?;
    if let Some(fetch_metadata) = route.plan.fetch_metadata.as_deref() {
        let (status, detail) = match fetch_metadata.evaluate_headers(&request_headers) {
            Ok(qpx_core::browser_policy::FetchMetadataDecision::Allowed) => (StatusCode::OK, None),
            Ok(decision) => (
                StatusCode::FORBIDDEN,
                Some(format!("request rejected by {decision:?} policy decision")),
            ),
            Err(error) => (StatusCode::BAD_REQUEST, Some(error.to_string())),
        };
        if let Some(detail) = detail {
            let body = qpx_http::problem::ProblemDetails::new(
                status,
                "Fetch Metadata policy rejected preflight",
            )
            .with_detail(detail)
            .to_json()?;
            let mut response = Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
                .body(Body::from(body))?;
            crate::http::protocol::l7::finalize_response_with_headers_in_place(
                &Method::OPTIONS,
                request_version,
                state.plan.identity.proxy_name.as_ref(),
                &mut response,
                route.headers.as_deref(),
                false,
            );
            policy.apply_actual_response(Some(cors_request), response.headers_mut());
            super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
            return Ok(Some(empty_interim_response(response)));
        }
    }
    let mut response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())?;
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        &Method::OPTIONS,
        request_version,
        state.plan.identity.proxy_name.as_ref(),
        &mut response,
        route.headers.as_deref(),
        false,
    );
    if let Err(rejection) = policy.apply_preflight_response(cors_request, response.headers_mut()) {
        let status = StatusCode::FORBIDDEN;
        let body = qpx_http::problem::ProblemDetails::new(status, "CORS preflight rejected")
            .with_detail(rejection.to_string())
            .to_json()?;
        response = Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
            .body(Body::from(body))?;
        crate::http::protocol::l7::finalize_response_with_headers_in_place(
            &Method::OPTIONS,
            request_version,
            state.plan.identity.proxy_name.as_ref(),
            &mut response,
            route.headers.as_deref(),
            false,
        );
        policy.apply_actual_response(None, response.headers_mut());
    }
    super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
    Ok(Some(empty_interim_response(response)))
}

pub(super) fn apply_cors_to_early_response(
    route: &crate::reverse::router::HttpRoute,
    cors_request: Option<&qpx_core::cors::CorsRequest>,
    response: &mut Response<Body>,
) {
    if let Some(policy) = route.plan.cors.as_deref() {
        policy.apply_actual_response(cors_request, response.headers_mut());
    }
}
