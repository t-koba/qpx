use super::mirrors::request_seed;
use super::{InterimList, ReverseConnInfo, empty_interim_response};
use crate::http::dispatch::annotated_max_forwards_response;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::websocket::is_websocket_upgrade;
use crate::reverse::ReloadableReverse;
use crate::reverse::router::HttpRoute;
use crate::runtime::Runtime;
use crate::upstream::origin::PreparedPlainHttp1ConnectionAffinity;
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::time::Duration;

mod access;
mod attempt;
mod browser_reports;
mod dispatch_cache;
mod dispatch_http;
mod dispatch_ipc;
mod modules;
mod outcome;
mod plain;
mod prepare;
mod types;
mod webdav;

/// Cache key for per-request destination classification, keyed by the
/// identity of the route's compiled `destination_resolution` override. The
/// override lives in the compiled route plan, so its address is stable for
/// the request lifetime; `0` is reserved for "no override" since references
/// are never null. Identity (not value) equality only affects cache sharing
/// between routes with equal overrides, where re-classification yields the
/// same result.
pub(super) fn destination_override_key(
    resolution_override: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
) -> usize {
    resolution_override.map_or(0, |config| std::ptr::from_ref(config) as usize)
}

use self::access::enforce_reverse_access_control;
use self::attempt::{
    ReverseHttpAttemptTransport, build_reverse_attempt_request, proxy_reverse_http_attempt,
    reverse_continue_response_rule,
};
use self::browser_reports::collect_browser_reports;
use self::dispatch_cache::prepare_reverse_cache;
use self::dispatch_http::dispatch_reverse_http_route;
use self::dispatch_ipc::{dispatch_reverse_ipc_route, handle_reverse_websocket_upgrade};
use self::modules::prepare_reverse_modules;
use self::outcome::{
    ReverseUpstreamFailureInput, acquire_reverse_upstream_concurrency,
    capture_reverse_response_outcome, consume_reverse_retry_budget,
    finish_reverse_upstream_failure, prepare_reverse_http_retry, record_reverse_http_loop_error,
    record_reverse_http_loop_timeout, record_reverse_loop_error, record_reverse_success_metrics,
    reverse_retry_backoff,
};
use self::plain::dispatch_plain_reverse_http;
pub(super) use self::plain::try_dispatch_unconditional_plain_reverse_request;
use self::prepare::{
    attach_streaming_limits, buffer_reverse_guarded_request, prepare_reverse_request,
    prepare_reverse_retry_dispatch, prepare_single_local_response_reverse_request,
    prepare_single_plain_reverse_request, prepare_single_webdav_reverse_request,
};
use self::types::*;
#[cfg(test)]
pub(super) use self::webdav::apply_webdav_file_region;
use self::webdav::{
    ReverseWebDavDispatch, dispatch_reverse_webdav, execute_webdav_service,
    prepare_direct_webdav_resource,
};

pub(super) async fn dispatch_reverse_request(
    req: Request<Body>,
    base: BaseRequestFields,
    reverse: &ReloadableReverse,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    state: Arc<crate::runtime::RuntimeState>,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, Response<Body>)> {
    use tracing::Instrument as _;
    if qpx_observability::request_spans_enabled() {
        let span = tracing::info_span!(
            "dispatch_reverse_request",
            kind = "reverse",
            host = %base.host().unwrap_or(""),
            method = %base.method,
        );
        return execute_reverse_dispatch(req, base, reverse, runtime, conn, state, connection_pool)
            .instrument(span)
            .await;
    }
    execute_reverse_dispatch(req, base, reverse, runtime, conn, state, connection_pool).await
}

async fn execute_reverse_dispatch(
    req: Request<Body>,
    base: BaseRequestFields,
    reverse: &ReloadableReverse,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    state: Arc<crate::runtime::RuntimeState>,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, Response<Body>)> {
    let (state, compiled) = reverse.compiled_snapshot(state).await;
    let request_version = req.version();
    let cors_request = match qpx_core::cors::CorsRequest::parse(req.method(), req.headers()) {
        Ok(request) => request,
        Err(error) => {
            let status = http::StatusCode::BAD_REQUEST;
            let body = qpx_http::problem::ProblemDetails::new(status, "Invalid CORS request")
                .with_detail(error.to_string())
                .to_json()?;
            let mut response = Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
                .body(Body::from(body))?;
            crate::http::protocol::l7::finalize_response_with_headers_in_place(
                req.method(),
                request_version,
                state.plan.identity.proxy_name.as_ref(),
                &mut response,
                None,
                false,
            );
            return Ok(empty_interim_response(response));
        }
    };
    if !state.destination_trace_enabled()
        && !qpx_observability::metrics_enabled()
        && state.security.identity_sources.sources.is_empty()
        && base.method != http::Method::CONNECT
        && matches!(
            request_version,
            http::Version::HTTP_11 | http::Version::HTTP_2
        )
        && !req.headers().contains_key(http::header::UPGRADE)
        && let Some(route) = compiled
            .router
            .single_plain_http_route()
            .filter(|route| route.available_plain_http_upstream().is_some())
    {
        match prepare_single_plain_reverse_request(req, &base, conn, &state, &compiled)? {
            Ok(Some(req)) => {
                let secure_transport = conn.tls_terminated;
                let (interim, mut response) = dispatch_plain_reverse_http(
                    req,
                    &state,
                    route,
                    &base.method,
                    request_version,
                    state.plan.identity.proxy_name.as_ref(),
                    connection_pool,
                )
                .await?;
                apply_reverse_route_metadata(route, secure_transport, &mut response)?;
                return Ok((interim, response));
            }
            Ok(None) => {
                return Err(anyhow!("no route matched"));
            }
            Err(response) => return Ok(response),
        }
    }
    if !state.destination_trace_enabled()
        && !qpx_observability::metrics_enabled()
        && state.security.identity_sources.sources.is_empty()
        && base.method != http::Method::CONNECT
        && matches!(
            request_version,
            http::Version::HTTP_11 | http::Version::HTTP_2
        )
        && !req.headers().contains_key(http::header::UPGRADE)
        && let Some(route) = compiled.router.single_direct_local_response_route()
    {
        match prepare_single_local_response_reverse_request(req, &base, conn, &state, &compiled)? {
            Ok(Some(_req)) => {
                let local = route
                    .local_response
                    .as_ref()
                    .ok_or_else(|| anyhow!("direct local-response route has no response"))?;
                let mut response = crate::http::local_response::finalized_compiled_local_response(
                    &base.method,
                    request_version,
                    state.plan.identity.proxy_name.as_ref(),
                    local,
                    None,
                )?;
                apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
                return Ok(empty_interim_response(response));
            }
            Ok(None) => return Err(anyhow!("no route matched")),
            Err(response) => return Ok(response),
        }
    }
    if !state.destination_trace_enabled()
        && !qpx_observability::metrics_enabled()
        && state.security.identity_sources.sources.is_empty()
        && base.method != http::Method::CONNECT
        && matches!(
            request_version,
            http::Version::HTTP_11 | http::Version::HTTP_2
        )
        && !req.headers().contains_key(http::header::UPGRADE)
        && let Some(route) = compiled.router.single_direct_webdav_route()
    {
        match prepare_single_webdav_reverse_request(req, &base, conn, &state, &compiled)? {
            Ok(Some(mut req)) => {
                let identity = crate::policy_context::ResolvedIdentity::default();
                let service = route
                    .webdav
                    .as_ref()
                    .ok_or_else(|| anyhow!("direct WebDAV route has no service"))?
                    .clone();
                let request_resource =
                    prepare_direct_webdav_resource(&mut req, route, service.as_ref())?;
                let mut response = execute_webdav_service(
                    req,
                    service,
                    &identity,
                    route.plan.streaming.max_request_body_bytes,
                    request_version == http::Version::HTTP_11 && !conn.tls_terminated,
                    Some(request_resource),
                )
                .await?;
                crate::http::protocol::l7::finalize_response_with_headers_in_place(
                    &base.method,
                    request_version,
                    state.plan.identity.proxy_name.as_ref(),
                    &mut response,
                    None,
                    false,
                );
                apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
                return Ok(empty_interim_response(response));
            }
            Ok(None) => return Err(anyhow!("no route matched")),
            Err(response) => return Ok(response),
        }
    }
    let prepared =
        match prepare_reverse_request(req, &base, conn, state, compiled, cors_request.as_ref())
            .await?
        {
            Ok(prepared) => prepared,
            Err(response) => return Ok(response),
        };
    let route = prepared
        .context
        .compiled
        .router
        .route_at(prepared.route.route_idx);
    let api_metadata = route.and_then(|route| route.plan.api_metadata.clone());
    let hsts = route.and_then(|route| route.plan.hsts);
    let cors = route.and_then(|route| route.plan.cors.clone());
    let cookies = route.and_then(|route| route.plan.cookies.clone());
    let fetch_metadata = route.and_then(|route| route.plan.fetch_metadata.clone());
    let browser_security = route.and_then(|route| route.plan.browser_security.clone());
    let proxy_name = prepared.context.state.plan.identity.proxy_name.clone();
    let reverse_error = prepared.context.state.messages.reverse_error.clone();
    let request_method = base.method.clone();
    let secure_transport = conn.tls_terminated;
    let (interim, mut response) = match execute_reverse_request(
        prepared,
        base,
        reverse,
        runtime,
        conn,
        connection_pool,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(error = ?error, "reverse handling failed");
            empty_interim_response(super::response_rules::reverse_gateway_error_response(
                &request_method,
                request_version,
                proxy_name.as_ref(),
                reverse_error.as_str(),
            ))
        }
    };
    if let Some(metadata) = api_metadata {
        metadata.apply(response.headers_mut());
    }
    if secure_transport && let Some(hsts) = hsts {
        response.headers_mut().insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            hsts.to_header_value()?,
        );
    }
    if let Some(cors) = cors {
        cors.apply_actual_response(cors_request.as_ref(), response.headers_mut());
    }
    if let Some(cookies) = cookies {
        cookies.apply_response(response.headers_mut(), secure_transport)?;
    }
    if let Some(fetch_metadata) = fetch_metadata {
        fetch_metadata.apply_response_vary(response.headers_mut());
    }
    if let Some(browser_security) = browser_security {
        browser_security.apply(response.headers_mut());
    }
    Ok((interim, response))
}

pub(super) fn apply_reverse_route_metadata(
    route: &HttpRoute,
    secure_transport: bool,
    response: &mut Response<Body>,
) -> Result<()> {
    if let Some(metadata) = route.plan.api_metadata.as_deref() {
        metadata.apply(response.headers_mut());
    }
    if secure_transport && let Some(hsts) = route.plan.hsts {
        response.headers_mut().insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            hsts.to_header_value()?,
        );
    }
    if let Some(cookies) = route.plan.cookies.as_ref() {
        cookies.apply_response(response.headers_mut(), secure_transport)?;
    }
    if let Some(fetch_metadata) = route.plan.fetch_metadata.as_deref() {
        fetch_metadata.apply_response_vary(response.headers_mut());
    }
    if let Some(browser_security) = route.plan.browser_security.as_deref() {
        browser_security.apply(response.headers_mut());
    }
    Ok(())
}

async fn execute_reverse_request(
    prepared: PreparedReverseRequest,
    base: BaseRequestFields,
    reverse: &ReloadableReverse,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, Response<Body>)> {
    let PreparedReverseRequest {
        mut req,
        context,
        route: prepared_route,
        observation,
    } = prepared;
    let compiled = context.compiled;
    let router = &compiled.router;
    let state = context.state;
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let host = base.host().unwrap_or_default();
    let request_method = &base.method;
    let request_version = req.version();
    let path = base.path();
    let request_uri = base.request_uri();
    let route_idx = prepared_route.route_idx;
    let selected_policy = prepared_route.selected_policy;
    let identity = prepared_route.identity;
    let sanitized_headers = prepared_route.sanitized_headers;
    let request_destination_cache = prepared_route.request_destination_cache;
    let max_observed_request_body_bytes = prepared_route.max_observed_request_body_bytes;
    let request_rpc = observation.request_rpc;
    let route = Some(route_idx)
        .and_then(|idx| router.route_at(idx))
        .ok_or_else(|| anyhow!("no route matched"))?;
    let streaming = route.plan.streaming;
    debug_assert_reverse_route_target(route);
    if route.supports_plain_http_dispatch()
        && route.available_plain_http_upstream().is_some()
        && !state.destination_trace_enabled()
        && !qpx_observability::metrics_enabled()
        && request_method != http::Method::CONNECT
        && matches!(
            request_version,
            http::Version::HTTP_11 | http::Version::HTTP_2
        )
        && !req.headers().contains_key(http::header::UPGRADE)
    {
        return dispatch_plain_reverse_http(
            req,
            &state,
            route,
            request_method,
            request_version,
            proxy_name,
            connection_pool,
        )
        .await;
    }
    let resolution_override = route.plan.destination_resolution.as_ref();
    let route_http_guard = route.plan.guard.as_deref();
    let route_max_observed_request_body_bytes = route_http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(max_observed_request_body_bytes))
        .unwrap_or(max_observed_request_body_bytes);
    let override_key = destination_override_key(resolution_override);
    let request_destination = request_destination_cache
        .get(override_key)
        .ok_or_else(|| anyhow!("selected route destination context was not prepared"))?;
    req = match buffer_reverse_guarded_request(
        req,
        route_http_guard,
        route_max_observed_request_body_bytes,
        Duration::from_millis(streaming.body_read_timeout_ms),
        request_method,
        request_version,
        proxy_name,
    )
    .await?
    {
        Ok(req) => req,
        Err(response) => return Ok(empty_interim_response(response)),
    };
    let (seed, sticky_seed) = if route.selection_is_seed_independent() {
        (0, 0)
    } else {
        (
            request_seed(conn, host, &req),
            route.affinity_seed(conn, host, &req, &identity),
        )
    };
    let access = match enforce_reverse_access_control(ReverseAccessInput {
        state: &state,
        reverse_name: reverse.name.as_ref(),
        proxy_name,
        conn,
        host,
        request_method,
        path,
        request_uri,
        req,
        route,
        selected_policy: &selected_policy,
        identity: &identity,
        sanitized_headers: sanitized_headers.as_ref(),
        request_destination,
    })
    .await?
    {
        ReverseAccessOutcome::Response(response) => {
            return Ok(attach_streaming_limits(
                empty_interim_response(*response),
                streaming,
                request_version,
            ));
        }
        ReverseAccessOutcome::Continue(access) => access,
    };
    let ReverseAccessControl {
        mut req,
        audit_ctx,
        route_headers,
        override_upstream,
        route_timeout,
        cache_bypass,
        decision_service_mirror_upstreams,
        authorization_decision,
        request_limit_ctx,
        mut request_limits,
    } = access;

    crate::http::protocol::forwarded::apply_forwarded_policy(
        req.headers_mut(),
        route.plan.forwarded.as_deref(),
        conn.remote_addr.ip(),
        if conn.tls_terminated { "https" } else { "http" },
        Some(host),
    )?;

    if (*request_method == http::Method::TRACE || *request_method == http::Method::OPTIONS)
        && req.headers().contains_key(http::header::MAX_FORWARDS)
        && let Some(response) = annotated_max_forwards_response(
            &mut req,
            proxy_name,
            state.plan.limits.general.trace_reflect_all_headers,
            state.plan.limits.body.max_observed_request_body_bytes,
            std::time::Duration::from_millis(streaming.body_read_timeout_ms),
            &audit_ctx,
        )
        .await
    {
        return Ok(attach_streaming_limits(
            empty_interim_response(response),
            streaming,
            request_version,
        ));
    }

    let module_dispatch = match prepare_reverse_modules(ReverseModuleInput {
        req,
        state: &state,
        selected_policy: &selected_policy,
        conn,
        route,
        reverse_name: reverse.name.as_ref(),
        proxy_name,
        identity: &identity,
        route_headers: route_headers.as_deref(),
        cache_bypass,
        audit_ctx: &audit_ctx,
    })
    .await?
    {
        ReverseModuleOutcome::Response(response) => {
            let response =
                crate::http::capture::stream::limit_response_body_for_plan(*response, &route.plan);
            return Ok(attach_streaming_limits(
                empty_interim_response(response),
                streaming,
                request_version,
            ));
        }
        ReverseModuleOutcome::Continue(dispatch) => dispatch,
    };
    let ReverseModuleDispatch {
        req,
        http_modules,
        request_cache_policy,
    } = module_dispatch;
    if let Some(collector) = route.plan.reporting_collector.as_ref() {
        let response = collect_browser_reports(
            req,
            collector,
            request_method,
            request_version,
            proxy_name,
            route_headers.as_deref(),
        )
        .await?;
        return Ok(attach_streaming_limits(
            empty_interim_response(response),
            streaming,
            request_version,
        ));
    }
    let result = complete_reverse_after_modules(ReversePostModuleInput {
        req,
        http_modules,
        request_cache_policy,
        base: &base,
        runtime,
        state: &state,
        conn,
        host,
        route,
        resolution_override,
        request_destination,
        request_method,
        request_version,
        request_rpc: request_rpc.as_ref(),
        identity: &identity,
        authorization_decision: authorization_decision.as_ref(),
        route_headers,
        override_upstream: override_upstream.as_deref(),
        decision_service_mirror_upstreams,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        request_limits: &mut request_limits,
        request_limit_ctx: &request_limit_ctx,
        audit_ctx: &audit_ctx,
        connection_pool,
    })
    .await?;
    Ok(attach_streaming_limits(result, streaming, request_version))
}

fn debug_assert_reverse_route_target(route: &HttpRoute) {
    debug_assert!(match &route.target {
        crate::runtime::CompiledReverseRouteTarget::Upstream { .. }
        | crate::runtime::CompiledReverseRouteTarget::Weighted { .. } =>
            route.local_response.is_none() && route.ipc.is_none() && route.webdav.is_none(),
        crate::runtime::CompiledReverseRouteTarget::Ipc { .. } =>
            route.local_response.is_none() && route.ipc.is_some() && route.webdav.is_none(),
        crate::runtime::CompiledReverseRouteTarget::LocalResponse { .. } =>
            route.local_response.is_some() && route.ipc.is_none() && route.webdav.is_none(),
        crate::runtime::CompiledReverseRouteTarget::Webdav { .. } =>
            route.local_response.is_none() && route.ipc.is_none() && route.webdav.is_some(),
        crate::runtime::CompiledReverseRouteTarget::TlsPassthrough { .. } => false,
    });
}

async fn complete_reverse_after_modules(
    input: ReversePostModuleInput<'_>,
) -> Result<(InterimList, Response<Body>)> {
    let ReversePostModuleInput {
        req,
        mut http_modules,
        request_cache_policy,
        base,
        runtime,
        state,
        conn,
        host,
        route,
        resolution_override,
        request_destination,
        request_method,
        request_version,
        request_rpc,
        identity,
        authorization_decision,
        route_headers,
        override_upstream,
        decision_service_mirror_upstreams,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        request_limits,
        request_limit_ctx,
        audit_ctx,
        connection_pool,
    } = input;
    if override_upstream.is_none()
        && let Some(webdav) = route.webdav.as_ref()
    {
        let response = dispatch_reverse_webdav(ReverseWebDavDispatch {
            req,
            service: webdav.clone(),
            identity,
            request_method,
            request_version,
            proxy_name,
            route_headers: route_headers.as_deref(),
            http_modules: &mut http_modules,
            max_request_body_bytes: route.plan.streaming.max_request_body_bytes,
            allow_file_backed: request_version == http::Version::HTTP_11 && !conn.tls_terminated,
        })
        .await?;
        return Ok(empty_interim_response(response));
    }
    if is_websocket_upgrade(req.method(), req.headers())? {
        return handle_reverse_websocket_upgrade(ReverseWebsocketDispatch {
            req,
            state,
            route,
            conn,
            override_upstream,
            seed,
            sticky_seed,
            request_limit_ctx,
            request_limits,
            route_timeout,
            proxy_name,
            route_headers: route_headers.as_deref(),
            request_method,
            http_modules: &mut http_modules,
            audit_ctx,
        })
        .await;
    }
    let cache_state = match prepare_reverse_cache(ReverseCacheInput {
        req,
        runtime,
        state,
        route,
        conn,
        request_method,
        request_version,
        proxy_name,
        route_headers: route_headers.as_deref(),
        request_cache_policy: request_cache_policy.as_ref(),
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        http_modules: &mut http_modules,
        audit_ctx,
    })
    .await?
    {
        ReverseCacheOutcome::Response(response) => {
            let mut response = *response;
            let export_session = state.export_session_for_plan(&route.plan, conn.remote_addr, host);
            response = crate::http::capture::stream::emit_optional_response_for_export(
                response,
                &route.plan,
                export_session.as_ref(),
            )
            .await;
            return Ok(empty_interim_response(response));
        }
        ReverseCacheOutcome::Continue(state) => state,
    };
    let ReverseCacheState {
        req,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        cache_collapse_guard,
    } = cache_state;
    let cache_policy = request_cache_policy.as_ref();
    let ReverseRetryDispatch {
        attempts,
        first_request,
        template,
        replay_recorder,
        mirror_upstreams,
    } = prepare_reverse_retry_dispatch(ReverseRetryPrepareInput {
        req,
        route,
        state,
        request_method,
        seed,
        sticky_seed,
        decision_service_mirror_upstreams,
        route_timeout,
        proxy_name,
    })
    .await?;
    if override_upstream.is_none() && route.ipc.is_some() {
        return dispatch_reverse_ipc_route(ReverseIpcDispatchInput {
            base,
            state,
            conn,
            route,
            request_destination,
            request_method,
            request_version,
            request_rpc,
            identity,
            authorization_decision,
            route_headers,
            cache_policy,
            request_headers_snapshot: request_headers_snapshot.as_ref(),
            cache_lookup_key: cache_lookup_key.as_ref(),
            cache_target_key: cache_target_key.as_ref(),
            revalidation_state,
            cache_collapse_guard,
            first_request,
            template,
            replay_recorder,
            mirror_upstreams,
            attempts,
            route_timeout,
            proxy_name,
            http_modules: &mut http_modules,
            request_limits,
            request_limit_ctx,
            audit_ctx,
        })
        .await;
    }
    dispatch_reverse_http_route(ReverseHttpDispatchInput {
        base,
        state,
        conn,
        host,
        route,
        resolution_override,
        request_method,
        request_version,
        request_rpc,
        request_destination,
        identity,
        route_headers,
        cache_policy,
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        cache_target_key: cache_target_key.as_ref(),
        revalidation_state,
        cache_collapse_guard,
        first_request,
        template,
        replay_recorder,
        mirror_upstreams,
        attempts,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        http_modules: &mut http_modules,
        request_limits,
        request_limit_ctx,
        audit_ctx,
        connection_pool,
    })
    .await
}
