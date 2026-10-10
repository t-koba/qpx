use super::prepare_cors::{apply_cors_to_early_response, prepare_cors_preflight};
use super::prepare_scan::{
    ReverseRouteSelection, observe_body_and_rescan_reverse_routes,
    sanitized_headers_for_route_scan, scan_reverse_routes,
};
use super::prepare_single::{SingleHttpPrepare, try_prepare_single_http_reverse_request};
use super::route_constraints::{
    enforce_selected_reverse_route_constraints, reverse_security_rejection,
};
use super::{InlineCache, PreparedReverseRequest, ReversePreparedContext, ReversePreparedRoute};
use crate::http::body::observation::RequestObservationPlan;
use crate::http::dispatch::request_body_too_large_response;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::policy_context::{
    EffectivePolicyContext, IdentityRequestContext, authentication_response_for_error,
};
use crate::reverse::transport::destination::classify_reverse_destination;
use crate::reverse::transport::{InterimList, ReverseConnInfo, empty_interim_response};
use anyhow::{Result, anyhow};
use hyper::{Method, Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
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
    let proxy_name = state.plan.identity.proxy_name.as_ref();
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
    let request_method = &base.method;
    let request_version = req.version();
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(request_method.as_str()),
        dst_port: Some(conn.dst_port),
        src_ip: Some(conn.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host),
        sni: conn.tls_sni.as_deref(),
        path: base.path(),
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
    let sanitized_route_headers = sanitized_headers_for_route_scan(&req, &state, conn)?;
    let identity_request = if state.security.identity_sources.sources.is_empty() {
        None
    } else {
        IdentityRequestContext::from_base(base, if conn.tls_terminated { "https" } else { "http" })
    };
    if let Err(error) = scan_reverse_routes(
        router,
        req.headers(),
        sanitized_route_headers.as_ref(),
        base,
        &state,
        conn,
        host,
        prefilter_ctx.clone(),
        None,
        None,
        false,
        identity_request.as_ref(),
        &mut selection,
    )
    .await
    {
        if let Some(response) =
            authentication_response_for_error(request_method, request_version, proxy_name, &error)
        {
            return Ok(Err(empty_interim_response(response?)));
        }
        return Err(error);
    }
    let mut owned_sanitized_headers = match sanitized_route_headers {
        std::borrow::Cow::Borrowed(_) => None,
        std::borrow::Cow::Owned(headers) => Some(headers),
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

    let selected_route_idx = selection
        .route_idx
        .ok_or_else(|| anyhow!("no route matched"))?;
    let selected_route = router
        .route_at(selected_route_idx)
        .ok_or_else(|| anyhow!("selected reverse route is unavailable"))?;
    let selected_resolution_override = selected_route.plan.destination_resolution.as_ref();
    let selected_override_key = super::destination_override_key(selected_resolution_override);
    if !selection
        .request_destination_cache
        .contains(selected_override_key)
    {
        let destination = if selected_route.requires_destination_after_selection()
            || state.destination_trace_enabled()
        {
            classify_reverse_destination(&state, conn, host, None, selected_resolution_override)
        } else {
            crate::destination::DestinationMetadata::default()
        };
        selection
            .request_destination_cache
            .push(selected_override_key, destination);
    }
    req = match enforce_selected_reverse_route_constraints(
        req,
        selected_route,
        &base.method,
        &state,
        conn,
    )? {
        Ok(req) => req,
        Err(mut response) => {
            super::apply_reverse_route_metadata(
                selected_route,
                conn.tls_terminated,
                &mut response.1,
            )?;
            apply_cors_to_early_response(selected_route, cors_request, &mut response.1);
            return Ok(Err(response));
        }
    };

    Ok(Ok(PreparedReverseRequest {
        req,
        context: ReversePreparedContext { compiled, state },
        route: ReversePreparedRoute {
            route_idx: selected_route_idx,
            selected_policy: selection.selected_policy,
            identity: selection
                .selected_identity
                .ok_or_else(|| anyhow!("identity missing for selected reverse route"))?,
            sanitized_headers: owned_sanitized_headers.take(),
            request_destination_cache: selection.request_destination_cache,
            max_observed_request_body_bytes: selection.max_observed_request_body_bytes,
        },
        observation: crate::http::pipeline::types::RequestObservation {
            request_rpc,
            response_request_observation: Default::default(),
            request_body_observed: selection.observation_plan.needs_body,
            request_rpc_observed: selection.observation_plan.needs_rpc,
        },
    }))
}
