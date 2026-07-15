use super::mirrors::{
    record_reverse_upstream_error, record_reverse_upstream_status, record_reverse_upstream_timeout,
    request_seed,
};
use super::request_template::{ReverseReplayRecorder, ReverseRequestTemplate};
use super::{InterimList, ReverseConnInfo, empty_interim_response};
use crate::http::codec::lazy_timeout::timeout_after_pending;
use crate::http::dispatch::{DispatchResponsePolicyOutcome, annotated_max_forwards_response};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::websocket::is_websocket_upgrade;
use crate::ipc_client::proxy_ipc;
use crate::reverse::ReloadableReverse;
use crate::reverse::router::HttpRoute;
use crate::runtime::Runtime;
use crate::upstream::origin::{
    OriginEndpoint, prepare_proxy_http1_request,
    proxy_direct_plain_http1_raw_response_with_interim, proxy_http,
    proxy_http_with_interim_timeout,
};
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use url::Url;

mod access;
mod dispatch_cache;
mod dispatch_http;
mod dispatch_ipc;
mod modules;
mod outcome;
mod prepare;
mod types;

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
use self::prepare::{
    attach_streaming_limits, buffer_reverse_guarded_request,
    enforce_selected_reverse_route_constraints, prepare_reverse_request,
    prepare_reverse_retry_dispatch, prepare_single_plain_reverse_request,
    prepare_single_webdav_reverse_request, reverse_security_rejection,
};
use self::types::*;

pub(super) async fn dispatch_reverse_request(
    req: Request<Body>,
    base: BaseRequestFields,
    reverse: &ReloadableReverse,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    state: Arc<crate::runtime::RuntimeState>,
) -> Result<(InterimList, Response<Body>)> {
    use tracing::Instrument as _;
    if qpx_observability::request_spans_enabled() {
        let span = tracing::info_span!(
            "dispatch_reverse_request",
            kind = "reverse",
            host = %base.host().unwrap_or(""),
            method = %base.method,
        );
        return execute_reverse_dispatch(req, base, reverse, runtime, conn, state)
            .instrument(span)
            .await;
    }
    execute_reverse_dispatch(req, base, reverse, runtime, conn, state).await
}

pub(super) async fn try_dispatch_unconditional_plain_reverse_request(
    req: Request<Body>,
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
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
    let req = match enforce_selected_reverse_route_constraints(req, route, &request_method, state)?
    {
        Ok(req) => req,
        Err(response) => return Ok(Ok(response)),
    };
    dispatch_plain_reverse_http(
        req,
        state,
        route,
        &request_method,
        request_version,
        state.plan.identity.proxy_name.as_ref(),
    )
    .await
    .map(Ok)
}

async fn execute_reverse_dispatch(
    req: Request<Body>,
    base: BaseRequestFields,
    reverse: &ReloadableReverse,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    state: Arc<crate::runtime::RuntimeState>,
) -> Result<(InterimList, Response<Body>)> {
    let (state, compiled) = reverse.compiled_snapshot(state).await;
    let request_version = req.version();
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
                let secure_transport = conn.tls_sni.is_some();
                let (interim, mut response) = dispatch_plain_reverse_http(
                    req,
                    &state,
                    route,
                    &base.method,
                    request_version,
                    state.plan.identity.proxy_name.as_ref(),
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
                apply_reverse_route_metadata(route, conn.tls_sni.is_some(), &mut response)?;
                return Ok(empty_interim_response(response));
            }
            Ok(None) => return Err(anyhow!("no route matched")),
            Err(response) => return Ok(response),
        }
    }
    let prepared = match prepare_reverse_request(req, &base, conn, state, compiled).await? {
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
    let secure_transport = conn.tls_sni.is_some();
    let (interim, mut response) =
        execute_reverse_request(prepared, base, reverse, runtime, conn).await?;
    if let Some(metadata) = api_metadata {
        metadata.apply(response.headers_mut());
    }
    if secure_transport && let Some(hsts) = hsts {
        response.headers_mut().insert(
            http::header::STRICT_TRANSPORT_SECURITY,
            hsts.to_header_value()?,
        );
    }
    Ok((interim, response))
}

fn prepare_direct_webdav_resource(
    req: &mut Request<Body>,
    route: &HttpRoute,
    service: &crate::reverse::router::WebDavOriginService,
) -> Result<qpx_webdav::ResourceId> {
    if let Some(rewrite) = route.path_rewrite.as_ref()
        && rewrite.add_prefix.is_none()
        && rewrite.regex.is_none()
        && req.uri().query().is_none()
        && let Some(prefix) = rewrite.strip_prefix.as_deref()
        && let Some(rest) = req.uri().path().strip_prefix(prefix)
    {
        if rest.is_empty() {
            return service.resource_for_path("/");
        }
        if rest.starts_with('/') {
            return service.resource_for_path(rest);
        }
        return service.resource_for_path(format!("/{rest}").as_str());
    }
    if let Some(rewrite) = route.path_rewrite.as_ref() {
        crate::reverse::transport::path_rewrite::apply_path_rewrite(req, rewrite);
    }
    service.resource_for_path(req.uri().path())
}

fn apply_reverse_route_metadata(
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
    Ok(())
}

async fn execute_reverse_request(
    prepared: PreparedReverseRequest,
    base: BaseRequestFields,
    reverse: &ReloadableReverse,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
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
        if conn.tls_sni.is_some() {
            "https"
        } else {
            "http"
        },
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
    })
    .await?;
    Ok(attach_streaming_limits(result, streaming, request_version))
}

async fn dispatch_plain_reverse_http(
    req: Request<Body>,
    state: &crate::runtime::RuntimeState,
    route: &HttpRoute,
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
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
    let response = timeout_after_pending(
        route.policy.timeout,
        proxy_direct_plain_http1_raw_response_with_interim(
            &state.pools,
            req,
            connect_authority,
            host_authority,
            request_version,
            proxy_name,
        ),
    )
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
    })
    .await
}

struct ReverseWebDavDispatch<'a> {
    req: Request<Body>,
    service: Arc<crate::reverse::router::WebDavOriginService>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    request_method: &'a http::Method,
    request_version: http::Version,
    proxy_name: &'a str,
    route_headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    max_request_body_bytes: usize,
}

async fn dispatch_reverse_webdav(input: ReverseWebDavDispatch<'_>) -> Result<Response<Body>> {
    let ReverseWebDavDispatch {
        req,
        service,
        identity,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        http_modules,
        max_request_body_bytes,
    } = input;
    let response =
        execute_webdav_service(req, service, identity, max_request_body_bytes, None).await?;
    let mut response = http_modules.on_upstream_response(response).await?;
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        request_method,
        request_version,
        proxy_name,
        &mut response,
        route_headers,
        false,
    );
    Ok(response)
}

async fn execute_webdav_service(
    req: Request<Body>,
    service: Arc<crate::reverse::router::WebDavOriginService>,
    identity: &crate::policy_context::ResolvedIdentity,
    max_request_body_bytes: usize,
    request_resource: Option<qpx_webdav::ResourceId>,
) -> Result<Response<Body>> {
    let request_resource = match request_resource {
        Some(resource) => resource,
        None => service.resource_for_path(req.uri().path())?,
    };
    let (parts, mut body) = req.into_parts();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let next = collected
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("WebDAV request body length overflow"))?;
        if next > max_request_body_bytes {
            return Err(anyhow!(
                "WebDAV request body exceeds route limit of {} bytes",
                max_request_body_bytes
            ));
        }
        collected.extend_from_slice(&chunk);
    }
    let request = Request::from_parts(parts, collected);
    let context = qpx_webdav::WebDavRequestContext {
        subject: identity.user.clone(),
        tenant: identity.tenant.clone(),
        groups: identity.groups.clone(),
        roles: identity.roles.clone(),
        entitlements: identity.entitlements.clone(),
        assurance: identity.auth_strength.clone(),
    };
    let response = tokio::task::spawn_blocking(move || {
        service.handle_bytes_for_resource(request, &context, request_resource)
    })
    .await
    .map_err(|error| anyhow!("WebDAV worker failed: {error}"))??;
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Body::from(body)))
}

async fn reverse_continue_response_rule(
    input: ReverseResponseRuleInput<'_>,
) -> Result<std::result::Result<ReverseResponseRuleContinue, ReverseAttemptOutcome>> {
    let ReverseResponseRuleInput {
        response_rule,
        http_modules,
        state,
        route,
        selected_upstream,
        attempt_idx,
        attempts,
        started,
    } = input;
    match response_rule {
        DispatchResponsePolicyOutcome::Continue {
            response,
            headers,
            cache_bypass,
            policy_tags,
            suppress_retry,
            mirror,
        } => {
            if response.status().is_server_error() && attempt_idx + 1 < attempts && !suppress_retry
            {
                if let Some(upstream) = selected_upstream {
                    record_reverse_upstream_status(
                        upstream,
                        &route.policy,
                        response.status(),
                        started,
                    );
                }
                let retry_reason = format!("upstream returned {}", response.status());
                let err = anyhow!(retry_reason.clone());
                if !consume_reverse_retry_budget(state, route) {
                    return Ok(Err(ReverseAttemptOutcome::Stop(err)));
                }
                http_modules
                    .on_retry(attempt_idx + 2, retry_reason.as_str())
                    .await?;
                reverse_retry_backoff(route).await;
                return Ok(Err(ReverseAttemptOutcome::Retry(err)));
            }
            Ok(Ok((response, headers, cache_bypass, policy_tags, mirror)))
        }
        DispatchResponsePolicyOutcome::Response(response) => Ok(Err(
            ReverseAttemptOutcome::Response(empty_interim_response(response)),
        )),
    }
}

async fn build_reverse_attempt_request(
    attempt_idx: usize,
    first_request: &mut Option<Request<Body>>,
    template: Option<&ReverseRequestTemplate>,
    replay_recorder: Option<&ReverseReplayRecorder>,
) -> Result<Request<Body>> {
    if attempt_idx == 0 {
        return match first_request.take() {
            Some(req) => Ok(req),
            None => template
                .ok_or_else(|| anyhow!("missing reverse request for first attempt"))?
                .build(),
        };
    }
    if let Some(template) = template {
        return template.build();
    }
    if let Some(recorder) = replay_recorder
        && let Some(template) = recorder.template().await
    {
        return template.build();
    }
    Err(anyhow!("reverse retry template missing or incomplete"))
}

async fn proxy_reverse_http_attempt(
    pools: &crate::pool::PoolRegistry,
    req_for_upstream: Request<Body>,
    upstream_origin: &OriginEndpoint,
    request_version: http::Version,
    proxy_name: &str,
    route: &HttpRoute,
    route_timeout: Duration,
) -> std::result::Result<
    Result<(
        InterimList,
        Response<Body>,
        Option<qpx_core::tls::UpstreamCertificateInfo>,
    )>,
    tokio::time::error::Elapsed,
> {
    timeout(route_timeout, async {
        if upstream_origin.upstream.starts_with("ipc://")
            || upstream_origin.upstream.starts_with("ipc+unix://")
        {
            let url = Url::parse(upstream_origin.upstream.as_str())
                .map_err(|err| anyhow!("invalid ipc upstream url: {}", err))?;
            return Ok((
                Vec::new(),
                proxy_ipc(pools, req_for_upstream, &url, proxy_name).await?,
                None,
            ));
        }
        if matches!(
            request_version,
            http::Version::HTTP_10
                | http::Version::HTTP_11
                | http::Version::HTTP_2
                | http::Version::HTTP_3
        ) {
            let proxied = proxy_http_with_interim_timeout(
                pools,
                req_for_upstream,
                upstream_origin,
                proxy_name,
                route.upstream_trust.as_deref(),
                route_timeout,
            )
            .await?;
            return Ok((proxied.interim, proxied.response, proxied.upstream_cert));
        }
        Ok((
            Vec::new(),
            proxy_http(
                pools,
                req_for_upstream,
                upstream_origin,
                proxy_name,
                route.upstream_trust.as_deref(),
            )
            .await?,
            None,
        ))
    })
    .await
}
