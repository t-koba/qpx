use super::*;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchCacheCollapseOutcome, DispatchCacheLookupOutcome,
    DispatchCacheWriteInput, DispatchCachedResponseInput, DispatchGuardInput,
    DispatchRateLimitInput, ExtAuthzDenyResponseInput, annotate_dispatch_response,
    evaluate_http_guard, ext_authz_deny_response, finalize_dispatch_cached_response,
    finalize_dispatch_stale_if_error_response, prepare_dispatch_cache_keys, rate_limit_response,
    record_cache_lookup_duration, record_cache_lookup_result, record_response_policy_action,
    record_upstream_request_duration, write_dispatch_cache_result,
};
use crate::http::observation::RequestObservationPlan;
use crate::reverse::ReloadableReverse;
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::HttpRoute;
use crate::runtime;
use qpx_core::rules::CompiledHeaderControl;
use qpx_observability::access_log::RequestLogContext;

#[path = "transport_dispatch_cache.rs"]
mod transport_dispatch_cache;
#[path = "transport_dispatch_http.rs"]
mod transport_dispatch_http;
#[path = "transport_dispatch_ipc.rs"]
mod transport_dispatch_ipc;

use self::transport_dispatch_cache::prepare_reverse_cache;
use self::transport_dispatch_http::dispatch_reverse_http_route;
use self::transport_dispatch_ipc::{dispatch_reverse_ipc_route, handle_reverse_websocket_upgrade};

struct PreparedReverseRequest {
    req: Request<Body>,
    router: Arc<ReverseRouter>,
    state: Arc<runtime::RuntimeState>,
    proxy_name: String,
    host: String,
    request_method: Method,
    request_version: http::Version,
    path_owned: Option<String>,
    request_uri: String,
    request_rpc: Option<crate::http::rpc::RpcMatchContext>,
    route_idx: usize,
    selected_policy: EffectivePolicyContext,
    identity: crate::policy_context::ResolvedIdentity,
    sanitized_headers: http::HeaderMap,
    request_destination_cache:
        std::collections::HashMap<String, crate::destination::DestinationMetadata>,
    max_observed_request_body_bytes: usize,
}

struct ReverseWebsocketDispatch<'a> {
    req: Request<Body>,
    state: &'a Arc<runtime::RuntimeState>,
    route: &'a HttpRoute,
    conn: &'a ReverseConnInfo,
    override_upstream: Option<&'a str>,
    seed: u64,
    sticky_seed: u64,
    request_limit_ctx: &'a RateLimitContext,
    request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    route_timeout: Duration,
    proxy_name: &'a str,
    route_headers: Option<&'a CompiledHeaderControl>,
    request_method: &'a Method,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a DispatchAuditContext,
}

enum ReverseAccessOutcome {
    Response(Box<Response<Body>>),
    Continue(Box<ReverseAccessControl>),
}

struct ReverseAccessControl {
    req: Request<Body>,
    log_context: RequestLogContext,
    ext_authz_policy_id: Option<String>,
    route_headers: Option<Arc<CompiledHeaderControl>>,
    override_upstream: Option<String>,
    route_timeout: Duration,
    cache_bypass: bool,
    ext_authz_mirror_upstreams: Vec<String>,
    request_limit_ctx: RateLimitContext,
    request_limits: crate::rate_limit::AppliedRateLimits,
}

struct ReverseExtAuthzAllow {
    route_headers: Option<Arc<CompiledHeaderControl>>,
    override_upstream: Option<String>,
    timeout_override: Option<Duration>,
    cache_bypass: bool,
    mirror_upstreams: Vec<String>,
    rate_limit_profile: Option<String>,
}

struct ReverseAccessInput<'a> {
    state: &'a Arc<runtime::RuntimeState>,
    reverse_name: &'a str,
    proxy_name: &'a str,
    conn: &'a ReverseConnInfo,
    host: &'a str,
    request_method: &'a Method,
    path: Option<&'a str>,
    request_uri: &'a str,
    req: Request<Body>,
    route: &'a HttpRoute,
    selected_policy: &'a EffectivePolicyContext,
    identity: &'a crate::policy_context::ResolvedIdentity,
    sanitized_headers: &'a http::HeaderMap,
    request_destination: &'a crate::destination::DestinationMetadata,
}

enum ReverseModuleOutcome {
    Response(Box<Response<Body>>),
    Continue(Box<ReverseModuleDispatch>),
}

struct ReverseModuleDispatch {
    req: Request<Body>,
    http_modules: crate::http::modules::HttpModuleExecution,
    request_cache_policy: Option<qpx_core::config::CachePolicyConfig>,
}

struct ReverseModuleInput<'a> {
    req: Request<Body>,
    state: &'a Arc<runtime::RuntimeState>,
    selected_policy: &'a EffectivePolicyContext,
    conn: &'a ReverseConnInfo,
    route: &'a HttpRoute,
    reverse_name: &'a str,
    proxy_name: &'a str,
    identity: &'a crate::policy_context::ResolvedIdentity,
    route_headers: Option<&'a CompiledHeaderControl>,
    cache_bypass: bool,
    audit_ctx: &'a DispatchAuditContext,
}

enum ReverseCacheOutcome {
    Response(Box<Response<Body>>),
    Continue(Box<ReverseCacheState>),
}

struct ReverseCacheState {
    req: Request<Body>,
    request_headers_snapshot: Option<http::HeaderMap>,
    cache_lookup_key: Option<CacheRequestKey>,
    cache_target_key: Option<CacheRequestKey>,
    revalidation_state: Option<crate::cache::RevalidationState>,
    _cache_collapse_guard: Option<crate::cache::RequestCollapseGuard>,
}

struct ReverseCacheInput<'a> {
    req: Request<Body>,
    runtime: &'a Runtime,
    state: &'a Arc<runtime::RuntimeState>,
    route: &'a HttpRoute,
    conn: &'a ReverseConnInfo,
    request_method: &'a Method,
    request_version: http::Version,
    proxy_name: &'a str,
    route_headers: Option<&'a CompiledHeaderControl>,
    request_cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    override_upstream: Option<&'a str>,
    seed: u64,
    sticky_seed: u64,
    route_timeout: Duration,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a DispatchAuditContext,
}

struct ReverseRetryDispatch {
    attempts: usize,
    first_request: Option<Request<Body>>,
    template: Option<ReverseRequestTemplate>,
    mirror_upstreams: Vec<Arc<UpstreamEndpoint>>,
}

struct ReverseHttpDispatchInput<'a> {
    base: &'a BaseRequestFields,
    state: &'a Arc<runtime::RuntimeState>,
    conn: &'a ReverseConnInfo,
    host: &'a str,
    route: &'a HttpRoute,
    resolution_override: Option<&'a qpx_core::config::DestinationResolutionOverrideConfig>,
    request_method: &'a Method,
    request_version: http::Version,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    route_headers: Option<Arc<CompiledHeaderControl>>,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    cache_target_key: Option<&'a CacheRequestKey>,
    revalidation_state: Option<crate::cache::RevalidationState>,
    first_request: Option<Request<Body>>,
    template: Option<ReverseRequestTemplate>,
    mirror_upstreams: Vec<Arc<UpstreamEndpoint>>,
    attempts: usize,
    override_upstream: Option<&'a str>,
    seed: u64,
    sticky_seed: u64,
    route_timeout: Duration,
    proxy_name: &'a str,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: &'a RateLimitContext,
    audit_ctx: &'a DispatchAuditContext,
}

struct ReverseIpcDispatchInput<'a> {
    base: &'a BaseRequestFields,
    state: &'a Arc<runtime::RuntimeState>,
    conn: &'a ReverseConnInfo,
    route: &'a HttpRoute,
    request_destination: &'a crate::destination::DestinationMetadata,
    request_method: &'a Method,
    request_version: http::Version,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    route_headers: Option<Arc<CompiledHeaderControl>>,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    cache_target_key: Option<&'a CacheRequestKey>,
    revalidation_state: Option<crate::cache::RevalidationState>,
    first_request: Option<Request<Body>>,
    template: Option<ReverseRequestTemplate>,
    mirror_upstreams: Vec<Arc<UpstreamEndpoint>>,
    attempts: usize,
    route_timeout: Duration,
    proxy_name: &'a str,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: &'a RateLimitContext,
    audit_ctx: &'a DispatchAuditContext,
}

struct ReversePostModuleInput<'a> {
    req: Request<Body>,
    http_modules: crate::http::modules::HttpModuleExecution,
    request_cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    base: &'a BaseRequestFields,
    runtime: &'a Runtime,
    state: &'a Arc<runtime::RuntimeState>,
    conn: &'a ReverseConnInfo,
    host: &'a str,
    route: &'a HttpRoute,
    resolution_override: Option<&'a qpx_core::config::DestinationResolutionOverrideConfig>,
    request_destination: &'a crate::destination::DestinationMetadata,
    request_method: &'a Method,
    request_version: http::Version,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    route_headers: Option<Arc<CompiledHeaderControl>>,
    override_upstream: Option<&'a str>,
    ext_authz_mirror_upstreams: Vec<String>,
    seed: u64,
    sticky_seed: u64,
    route_timeout: Duration,
    proxy_name: &'a str,
    request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: &'a RateLimitContext,
    audit_ctx: &'a DispatchAuditContext,
}

enum ReverseAttemptOutcome {
    Response(Box<(ReverseInterimResponses, Response<Body>)>),
    Retry(anyhow::Error),
    Stop(anyhow::Error),
}

type ReverseResponseRuleContinue = (
    Response<Body>,
    Option<Arc<CompiledHeaderControl>>,
    bool,
    Arc<[String]>,
    Option<bool>,
);

struct ReverseResponseRuleInput<'a> {
    response_rule: ResponseRuleDecision,
    request_method: &'a Method,
    request_version: http::Version,
    proxy_name: &'a str,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a DispatchAuditContext,
    state: &'a runtime::RuntimeState,
    route: &'a HttpRoute,
    selected_upstream: Option<&'a Arc<UpstreamEndpoint>>,
    attempt_idx: usize,
    attempts: usize,
    started: Instant,
}

struct ReverseHttpSuccessInput<'a> {
    base: &'a BaseRequestFields,
    state: &'a Arc<runtime::RuntimeState>,
    conn: &'a ReverseConnInfo,
    host: &'a str,
    route: &'a HttpRoute,
    resolution_override: Option<&'a qpx_core::config::DestinationResolutionOverrideConfig>,
    request_method: &'a Method,
    request_version: http::Version,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    route_headers: Option<Arc<CompiledHeaderControl>>,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    cache_target_key: Option<&'a CacheRequestKey>,
    revalidation_state: &'a mut Option<crate::cache::RevalidationState>,
    template: Option<&'a ReverseRequestTemplate>,
    mirror_upstreams: &'a mut Vec<Arc<UpstreamEndpoint>>,
    attempts: usize,
    route_timeout: Duration,
    proxy_name: &'a str,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a DispatchAuditContext,
    attempt_idx: usize,
    selected_upstream: Option<&'a Arc<UpstreamEndpoint>>,
    started: Instant,
    interim: ReverseInterimResponses,
    response: Response<Body>,
    upstream_cert: Option<crate::tls::cert_info::UpstreamCertificateInfo>,
    export_session: Option<&'a crate::exporter::ExportSession>,
}

struct ReverseIpcSuccessInput<'a> {
    base: &'a BaseRequestFields,
    state: &'a Arc<runtime::RuntimeState>,
    conn: &'a ReverseConnInfo,
    route: &'a HttpRoute,
    request_destination: &'a crate::destination::DestinationMetadata,
    request_method: &'a Method,
    request_version: http::Version,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    route_headers: Option<Arc<CompiledHeaderControl>>,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    cache_target_key: Option<&'a CacheRequestKey>,
    revalidation_state: &'a mut Option<crate::cache::RevalidationState>,
    template: Option<&'a ReverseRequestTemplate>,
    mirror_upstreams: &'a mut Vec<Arc<UpstreamEndpoint>>,
    attempts: usize,
    route_timeout: Duration,
    proxy_name: &'a str,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a DispatchAuditContext,
    attempt_idx: usize,
    started: Instant,
    response: Response<Body>,
    export_session: Option<&'a crate::exporter::ExportSession>,
}

#[tracing::instrument(
    skip_all,
    fields(kind = "reverse", host = %base.host.as_deref().unwrap_or(""), method = %base.method)
)]
pub(super) async fn dispatch_reverse_request(
    req: Request<Body>,
    base: BaseRequestFields,
    reverse: ReloadableReverse,
    runtime: Runtime,
    conn: ReverseConnInfo,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let compiled = reverse.compiled().await;
    let prepared = match prepare_reverse_request(req, &base, &runtime, &conn, compiled).await? {
        Ok(prepared) => prepared,
        Err(response) => return Ok(response),
    };
    execute_reverse_request(prepared, base, reverse, runtime, conn).await
}

async fn execute_reverse_request(
    prepared: PreparedReverseRequest,
    base: BaseRequestFields,
    reverse: ReloadableReverse,
    runtime: Runtime,
    conn: ReverseConnInfo,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let PreparedReverseRequest {
        mut req,
        router,
        state,
        proxy_name,
        host,
        request_method,
        request_version,
        path_owned,
        request_uri,
        request_rpc,
        route_idx,
        selected_policy,
        identity,
        sanitized_headers,
        request_destination_cache,
        max_observed_request_body_bytes,
    } = prepared;
    let route = Some(route_idx)
        .and_then(|idx| router.route_at(idx))
        .ok_or_else(|| anyhow!("no route matched"))?;
    debug_assert!(match &route.target {
        crate::runtime::CompiledReverseRouteTarget::Upstream { .. }
        | crate::runtime::CompiledReverseRouteTarget::Weighted { .. } =>
            route.local_response.is_none() && route.ipc.is_none(),
        crate::runtime::CompiledReverseRouteTarget::Ipc { .. } =>
            route.local_response.is_none() && route.ipc.is_some(),
        crate::runtime::CompiledReverseRouteTarget::LocalResponse { .. } =>
            route.local_response.is_some() && route.ipc.is_none(),
        crate::runtime::CompiledReverseRouteTarget::TlsPassthrough { .. } => false,
    });
    let resolution_override = route.plan.destination_resolution.as_ref();
    let route_http_guard = route.plan.guard.as_deref();
    let route_max_observed_request_body_bytes = route_http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(max_observed_request_body_bytes))
        .unwrap_or(max_observed_request_body_bytes);
    let request_destination = request_destination_cache
        .get(&format!("{:?}", resolution_override))
        .cloned()
        .unwrap_or_else(|| {
            classify_reverse_destination(&state, &conn, host.as_str(), None, resolution_override)
        });
    req = match buffer_reverse_guarded_request(
        req,
        route_http_guard,
        route_max_observed_request_body_bytes,
        Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
        &request_method,
        request_version,
        proxy_name.as_ref(),
    )
    .await?
    {
        Ok(req) => req,
        Err(response) => return Ok(empty_interim_response(response)),
    };
    let seed = request_seed(&conn, host.as_str(), &req);
    let sticky_seed = route.affinity_seed(&conn, host.as_str(), &req, &identity);
    let access = match enforce_reverse_access_control(ReverseAccessInput {
        state: &state,
        reverse_name: reverse.name.as_ref(),
        proxy_name: proxy_name.as_ref(),
        conn: &conn,
        host: host.as_str(),
        request_method: &request_method,
        path: path_owned.as_deref(),
        request_uri: request_uri.as_str(),
        req,
        route,
        selected_policy: &selected_policy,
        identity: &identity,
        sanitized_headers: &sanitized_headers,
        request_destination: &request_destination,
    })
    .await?
    {
        ReverseAccessOutcome::Response(response) => return Ok(empty_interim_response(*response)),
        ReverseAccessOutcome::Continue(access) => *access,
    };
    let ReverseAccessControl {
        mut req,
        log_context,
        ext_authz_policy_id,
        route_headers,
        override_upstream,
        route_timeout,
        cache_bypass,
        ext_authz_mirror_upstreams,
        request_limit_ctx,
        mut request_limits,
    } = access;
    let audit_ctx = DispatchAuditContext::new(
        state.clone(),
        crate::http::dispatch::ProxyKind::Reverse,
        reverse.name.as_ref(),
        conn.remote_addr,
        request_method.clone(),
        path_owned.clone(),
        log_context,
    )
    .with_host((!host.is_empty()).then_some(host.clone()))
    .with_sni(conn.tls_sni.as_deref().map(ToOwned::to_owned))
    .with_matched_route(route.name.as_deref().map(ToOwned::to_owned))
    .with_ext_authz_policy_id(ext_authz_policy_id);

    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name.as_str(),
        state.plan.limits.trace_reflect_all_headers,
        state.plan.limits.max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
    )
    .await
    {
        let mut response = response;
        annotate_dispatch_response(
            &mut response,
            &audit_ctx,
            crate::http::dispatch::DispatchOutcome::MaxForwards,
            &[],
        );
        return Ok(empty_interim_response(response));
    }

    let module_dispatch = match prepare_reverse_modules(ReverseModuleInput {
        req,
        state: &state,
        selected_policy: &selected_policy,
        conn: &conn,
        route,
        reverse_name: reverse.name.as_ref(),
        proxy_name: proxy_name.as_ref(),
        identity: &identity,
        route_headers: route_headers.as_deref(),
        cache_bypass,
        audit_ctx: &audit_ctx,
    })
    .await?
    {
        ReverseModuleOutcome::Response(response) => return Ok(empty_interim_response(*response)),
        ReverseModuleOutcome::Continue(dispatch) => *dispatch,
    };
    let ReverseModuleDispatch {
        req,
        http_modules,
        request_cache_policy,
    } = module_dispatch;
    complete_reverse_after_modules(ReversePostModuleInput {
        req,
        http_modules,
        request_cache_policy,
        base: &base,
        runtime: &runtime,
        state: &state,
        conn: &conn,
        host: host.as_str(),
        route,
        resolution_override,
        request_destination: &request_destination,
        request_method: &request_method,
        request_version,
        request_rpc: request_rpc.as_ref(),
        identity: &identity,
        route_headers,
        override_upstream: override_upstream.as_deref(),
        ext_authz_mirror_upstreams,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name: proxy_name.as_str(),
        request_limits: &mut request_limits,
        request_limit_ctx: &request_limit_ctx,
        audit_ctx: &audit_ctx,
    })
    .await
}

async fn buffer_reverse_guarded_request(
    req: Request<Body>,
    route_http_guard: Option<&crate::http::guard::CompiledHttpGuardProfile>,
    max_observed_request_body_bytes: usize,
    read_timeout: Duration,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
) -> Result<std::result::Result<Request<Body>, Response<Body>>> {
    if !route_http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req))
        || crate::http::body_size::observed_request_bytes(&req).is_some()
    {
        return Ok(Ok(req));
    }
    match buffer_request_body(req, max_observed_request_body_bytes, read_timeout).await {
        Ok(req) => Ok(Ok(req)),
        Err(err) if crate::http::body_size::is_observed_body_limit_exceeded(&err) => {
            Ok(Err(finalize_response_for_request(
                request_method,
                request_version,
                proxy_name,
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request body too large"))?,
                false,
            )))
        }
        Err(err) => Err(err),
    }
}

async fn prepare_reverse_retry_dispatch(
    req: Request<Body>,
    route: &HttpRoute,
    state: &runtime::RuntimeState,
    request_method: &Method,
    seed: u64,
    sticky_seed: u64,
    ext_authz_mirror_upstreams: Vec<String>,
) -> Result<ReverseRetryDispatch> {
    let can_retry = request_is_retryable(&req, request_method);
    let attempts = if can_retry {
        route.policy.retry_attempts
    } else {
        1
    };
    let max_template_body_bytes = state.plan.limits.max_reverse_retry_template_body_bytes;
    let mut mirror_upstreams = if request_is_templateable(&req, max_template_body_bytes) {
        route.select_mirror_upstreams(seed, sticky_seed)
    } else {
        Vec::new()
    };
    mirror_upstreams.extend(
        ext_authz_mirror_upstreams
            .into_iter()
            .map(UpstreamEndpoint::new)
            .map(Arc::new),
    );
    let need_template = attempts > 1 || !mirror_upstreams.is_empty();
    let (first_request, template) = if need_template {
        (
            None,
            Some(
                ReverseRequestTemplate::from_request(
                    req,
                    max_template_body_bytes,
                    Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
                )
                .await?,
            ),
        )
    } else {
        (Some(req), None)
    };
    Ok(ReverseRetryDispatch {
        attempts,
        first_request,
        template,
        mirror_upstreams,
    })
}

async fn complete_reverse_after_modules(
    input: ReversePostModuleInput<'_>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
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
        route_headers,
        override_upstream,
        ext_authz_mirror_upstreams,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        request_limits,
        request_limit_ctx,
        audit_ctx,
    } = input;
    if is_websocket_upgrade(req.headers()) {
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
        ReverseCacheOutcome::Response(response) => return Ok(empty_interim_response(*response)),
        ReverseCacheOutcome::Continue(state) => *state,
    };
    let ReverseCacheState {
        req,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        _cache_collapse_guard,
    } = cache_state;
    let cache_policy = request_cache_policy.as_ref();
    let ReverseRetryDispatch {
        attempts,
        first_request,
        template,
        mirror_upstreams,
    } = prepare_reverse_retry_dispatch(
        req,
        route,
        state,
        request_method,
        seed,
        sticky_seed,
        ext_authz_mirror_upstreams,
    )
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
            route_headers,
            cache_policy,
            request_headers_snapshot: request_headers_snapshot.as_ref(),
            cache_lookup_key: cache_lookup_key.as_ref(),
            cache_target_key: cache_target_key.as_ref(),
            revalidation_state,
            first_request,
            template,
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
        identity,
        route_headers,
        cache_policy,
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        cache_target_key: cache_target_key.as_ref(),
        revalidation_state,
        first_request,
        template,
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

async fn reverse_continue_response_rule(
    input: ReverseResponseRuleInput<'_>,
) -> Result<std::result::Result<ReverseResponseRuleContinue, ReverseAttemptOutcome>> {
    let ReverseResponseRuleInput {
        response_rule,
        request_method,
        request_version,
        proxy_name,
        http_modules,
        audit_ctx,
        state,
        route,
        selected_upstream,
        attempt_idx,
        attempts,
        started,
    } = input;
    match response_rule {
        ResponseRuleDecision::Continue {
            response,
            route_headers,
            cache_bypass,
            policy_tags,
            suppress_retry,
            mirror,
        } => {
            record_response_policy_action(audit_ctx.kind, "continue");
            if response.status().is_server_error() && attempt_idx + 1 < attempts && !suppress_retry
            {
                if let Some(upstream) = selected_upstream {
                    record_reverse_upstream_status(
                        upstream,
                        &route.policy,
                        response.status(),
                        started.elapsed(),
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
            Ok(Ok((
                response,
                route_headers,
                cache_bypass,
                policy_tags,
                mirror,
            )))
        }
        ResponseRuleDecision::LocalResponse {
            response,
            route_headers,
            policy_tags,
        } => {
            let response = http_modules.prepare_downstream_response(response).await?;
            let mut response = finalize_response_with_headers(
                request_method,
                request_version,
                proxy_name,
                response,
                route_headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_dispatch_response(
                &mut response,
                audit_ctx,
                crate::http::dispatch::DispatchOutcome::ResponseRuleLocalResponse,
                policy_tags.as_ref(),
            );
            Ok(Err(ReverseAttemptOutcome::Response(Box::new(
                empty_interim_response(response),
            ))))
        }
    }
}

fn build_reverse_attempt_request(
    attempt_idx: usize,
    first_request: &mut Option<Request<Body>>,
    template: Option<&ReverseRequestTemplate>,
) -> Result<Request<Body>> {
    if attempt_idx == 0 {
        return match (template, first_request.take()) {
            (Some(template), _) => template.build(),
            (None, Some(req)) => Ok(req),
            (None, None) => Err(anyhow!("missing reverse request for first attempt")),
        };
    }
    template
        .ok_or_else(|| anyhow!("reverse retry template missing"))?
        .build()
}

async fn proxy_reverse_http_attempt(
    req_for_upstream: Request<Body>,
    upstream_origin: &OriginEndpoint,
    request_version: http::Version,
    proxy_name: &str,
    route: &HttpRoute,
    route_timeout: Duration,
) -> std::result::Result<
    Result<(
        ReverseInterimResponses,
        Response<Body>,
        Option<crate::tls::cert_info::UpstreamCertificateInfo>,
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
                proxy_ipc(req_for_upstream, &url, proxy_name).await?,
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
            let proxied = proxy_http_with_interim(
                req_for_upstream,
                upstream_origin,
                proxy_name,
                route.upstream_trust.as_deref(),
            )
            .await?;
            return Ok((proxied.interim, proxied.response, proxied.upstream_cert));
        }
        Ok((
            Vec::new(),
            proxy_http(
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

fn consume_reverse_retry_budget(state: &runtime::RuntimeState, route: &HttpRoute) -> bool {
    if route.policy.retry_budget.try_consume_retry() {
        return true;
    }
    counter!(
        state
            .observability
            .metric_names
            .reverse_retry_budget_exhausted_total
            .clone()
    )
    .increment(1);
    false
}

async fn reverse_retry_backoff(route: &HttpRoute) {
    if route.policy.retry_backoff > Duration::ZERO {
        sleep(route.policy.retry_backoff).await;
    }
}

fn record_reverse_success_metrics(state: &runtime::RuntimeState, started: Instant) {
    record_upstream_request_duration(crate::http::dispatch::ProxyKind::Reverse, started.elapsed());
    histogram!(
        state
            .observability
            .metric_names
            .reverse_upstream_latency_ms
            .clone()
    )
    .record(started.elapsed().as_secs_f64() * 1000.0);
    counter!(
        state.observability.metric_names.reverse_requests_total.clone(),
        "result" => "ok"
    )
    .increment(1);
}

async fn record_reverse_loop_error(
    state: &runtime::RuntimeState,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    err: anyhow::Error,
    result: &'static str,
) -> anyhow::Error {
    http_modules.on_error(&err).await;
    counter!(
        state.observability.metric_names.reverse_requests_total.clone(),
        "result" => result
    )
    .increment(1);
    err
}

async fn record_reverse_http_loop_error(
    state: &runtime::RuntimeState,
    route: &HttpRoute,
    selected_upstream: Option<&Arc<UpstreamEndpoint>>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    err: anyhow::Error,
) -> anyhow::Error {
    http_modules.on_error(&err).await;
    if let Some(upstream) = selected_upstream {
        record_reverse_upstream_error(upstream, &route.policy, &err);
    }
    counter!(
        state.observability.metric_names.reverse_requests_total.clone(),
        "result" => "error"
    )
    .increment(1);
    err
}

async fn record_reverse_http_loop_timeout(
    state: &runtime::RuntimeState,
    route: &HttpRoute,
    selected_upstream: Option<&Arc<UpstreamEndpoint>>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
) -> anyhow::Error {
    let err = anyhow!("upstream timeout");
    http_modules.on_error(&err).await;
    if let Some(upstream) = selected_upstream {
        record_reverse_upstream_timeout(upstream, &route.policy);
    }
    counter!(
        state.observability.metric_names.reverse_requests_total.clone(),
        "result" => "timeout"
    )
    .increment(1);
    err
}

async fn finish_reverse_upstream_failure(
    revalidation_state: Option<&crate::cache::RevalidationState>,
    request_method: &Method,
    proxy_name: &str,
    route_headers: Option<&CompiledHeaderControl>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &DispatchAuditContext,
    last_err: Option<anyhow::Error>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    if let Some(stale) = finalize_dispatch_stale_if_error_response(
        revalidation_state,
        request_method,
        proxy_name,
        route_headers,
        http_modules,
        audit_ctx,
    )
    .await?
    {
        return Ok(empty_interim_response(stale));
    }
    if let Some(err) = last_err.as_ref() {
        http_modules.on_error(err).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow!("upstream request failed")))
}

async fn enforce_reverse_access_control(
    input: ReverseAccessInput<'_>,
) -> Result<ReverseAccessOutcome> {
    let ReverseAccessInput {
        state,
        reverse_name,
        proxy_name,
        conn,
        host,
        request_method,
        path,
        request_uri,
        req,
        route,
        selected_policy,
        identity,
        sanitized_headers,
        request_destination,
    } = input;
    let ext_authz = enforce_ext_authz(
        state,
        selected_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Reverse,
            proxy_name,
            scope_name: reverse_name,
            remote_ip: conn.remote_addr.ip(),
            dst_port: Some(conn.dst_port),
            host: (!host.is_empty()).then_some(host),
            sni: conn.tls_sni.as_deref(),
            method: Some(request_method.as_str()),
            path,
            uri: Some(request_uri),
            matched_rule: None,
            matched_route: route.name.as_deref(),
            action: None,
            headers: Some(sanitized_headers),
            identity,
        },
    )
    .await?;
    let ext_authz_policy_id = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    };
    let ext_authz_policy_tags = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
    };
    let mut log_context =
        identity.to_log_context(None, route.name.as_deref(), ext_authz_policy_id.as_deref());
    crate::http::rule_context::attach_destination_trace(&mut log_context, request_destination);
    log_context.policy_tags = ext_authz_policy_tags;
    let audit_ctx = DispatchAuditContext::new(
        state.clone(),
        crate::http::dispatch::ProxyKind::Reverse,
        reverse_name,
        conn.remote_addr,
        request_method.clone(),
        path.map(ToOwned::to_owned),
        log_context.clone(),
    )
    .with_host((!host.is_empty()).then_some(host.to_string()))
    .with_sni(conn.tls_sni.as_deref().map(ToOwned::to_owned))
    .with_matched_route(route.name.as_deref().map(ToOwned::to_owned))
    .with_ext_authz_policy_id(ext_authz_policy_id.clone());
    if let Some(response) = evaluate_http_guard(DispatchGuardInput {
        profile: route.plan.guard.as_deref(),
        req: &req,
        destination: request_destination,
        proxy_name,
        audit: audit_ctx.clone(),
    })? {
        return Ok(ReverseAccessOutcome::Response(Box::new(response)));
    }
    let allowed = match resolve_reverse_ext_authz(
        ext_authz,
        route.headers.clone(),
        &req,
        request_method,
        proxy_name,
        state,
        &audit_ctx,
    )? {
        Ok(values) => values,
        Err(response) => return Ok(ReverseAccessOutcome::Response(Box::new(response))),
    };
    let route_timeout = allowed.timeout_override.unwrap_or(route.policy.timeout);
    let request_limit_ctx = RateLimitContext::from_identity(
        conn.remote_addr.ip(),
        identity,
        route.name.as_deref(),
        allowed.override_upstream.as_deref(),
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &route.plan.rate_limits,
        None,
        crate::rate_limit::TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        return Ok(ReverseAccessOutcome::Response(Box::new(
            rate_limit_response(DispatchRateLimitInput {
                req: &req,
                proxy_name,
                retry_after: Some(retry_after),
                audit: audit_ctx.clone(),
            }),
        )));
    }
    if let Some(retry_after) = request_limits.merge_profile_and_check(
        &state.policy.rate_limiters,
        allowed.rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Request,
        &request_limit_ctx,
        1,
    )? {
        return Ok(ReverseAccessOutcome::Response(Box::new(
            rate_limit_response(DispatchRateLimitInput {
                req: &req,
                proxy_name,
                retry_after: Some(retry_after),
                audit: audit_ctx.clone(),
            }),
        )));
    }
    if let Some(response) = reverse_local_route_response(
        route,
        request_method,
        req.version(),
        proxy_name,
        allowed.route_headers.as_deref(),
        &audit_ctx,
    )? {
        return Ok(ReverseAccessOutcome::Response(Box::new(response)));
    }
    Ok(ReverseAccessOutcome::Continue(Box::new(
        ReverseAccessControl {
            req,
            log_context,
            ext_authz_policy_id,
            route_headers: allowed.route_headers,
            override_upstream: allowed.override_upstream,
            route_timeout,
            cache_bypass: allowed.cache_bypass,
            ext_authz_mirror_upstreams: allowed.mirror_upstreams,
            request_limit_ctx,
            request_limits,
        },
    )))
}

fn resolve_reverse_ext_authz(
    ext_authz: ExtAuthzEnforcement,
    mut route_headers: Option<Arc<CompiledHeaderControl>>,
    req: &Request<Body>,
    request_method: &Method,
    proxy_name: &str,
    state: &runtime::RuntimeState,
    audit_ctx: &DispatchAuditContext,
) -> Result<std::result::Result<ReverseExtAuthzAllow, Response<Body>>> {
    match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ReverseHttp)?;
            route_headers = merge_header_controls(route_headers, allow.headers);
            Ok(Ok(ReverseExtAuthzAllow {
                route_headers,
                override_upstream: allow.override_upstream,
                timeout_override: allow.timeout_override,
                cache_bypass: allow.cache_bypass,
                mirror_upstreams: allow.mirror_upstreams,
                rate_limit_profile: allow.rate_limit_profile,
            }))
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let response = ext_authz_deny_response(ExtAuthzDenyResponseInput {
                ext_authz: ExtAuthzEnforcement::Deny(deny),
                base_headers: route_headers,
                request_method,
                request_version: req.version(),
                proxy_name,
                default_response: Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from(state.messages.reverse_error.clone()))?,
                audit: audit_ctx,
            })?;
            Ok(Err(response))
        }
    }
}

fn reverse_local_route_response(
    route: &HttpRoute,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    route_headers: Option<&CompiledHeaderControl>,
    audit_ctx: &DispatchAuditContext,
) -> Result<Option<Response<Body>>> {
    let Some(local) = route.local_response.as_ref() else {
        return Ok(None);
    };
    let mut response = finalize_response_with_headers(
        request_method,
        request_version,
        proxy_name,
        build_local_response(local)?,
        route_headers,
        false,
    );
    counter!(
        audit_ctx
            .state
            .observability
            .metric_names
            .reverse_local_response_total
            .clone()
    )
    .increment(1);
    annotate_dispatch_response(
        &mut response,
        audit_ctx,
        crate::http::dispatch::DispatchOutcome::Respond,
        &[],
    );
    Ok(Some(response))
}

async fn prepare_reverse_modules(input: ReverseModuleInput<'_>) -> Result<ReverseModuleOutcome> {
    let ReverseModuleInput {
        mut req,
        state,
        selected_policy,
        conn,
        route,
        reverse_name,
        proxy_name,
        identity,
        route_headers,
        cache_bypass,
        audit_ctx,
    } = input;
    strip_untrusted_identity_headers(
        state,
        selected_policy,
        conn.remote_addr.ip(),
        req.headers_mut(),
    )?;
    if let Some(rewrite) = route.path_rewrite.as_ref() {
        apply_path_rewrite(&mut req, rewrite);
    }
    apply_request_headers(req.headers_mut(), route_headers);
    let request_cache_policy = route.plan.cache.as_ref().filter(|_| !cache_bypass).cloned();
    let mut http_modules = route.plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Reverse,
            proxy_name,
            scope_name: reverse_name,
            route_name: route.name.as_deref(),
            remote_ip: conn.remote_addr.ip(),
            sni: conn.tls_sni.as_deref(),
            identity_user: identity.user.as_deref(),
            cache_policy: request_cache_policy.clone(),
            cache_default_scheme: Some(if conn.tls_terminated { "https" } else { "http" }),
        },
    );
    match http_modules.on_request_headers(&mut req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => Ok(
            ReverseModuleOutcome::Continue(Box::new(ReverseModuleDispatch {
                req,
                http_modules,
                request_cache_policy,
            })),
        ),
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let mut response = http_modules.prepare_downstream_response(*response).await?;
            let response_version = response.version();
            finalize_response_with_headers_in_place(
                &audit_ctx.request_method,
                response_version,
                proxy_name,
                &mut response,
                route_headers,
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_dispatch_response(
                &mut response,
                audit_ctx,
                crate::http::dispatch::DispatchOutcome::HttpModuleLocalResponse,
                &[],
            );
            Ok(ReverseModuleOutcome::Response(Box::new(response)))
        }
    }
}

async fn prepare_reverse_request(
    req: Request<Body>,
    base: &BaseRequestFields,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    compiled: Arc<crate::reverse::CompiledReverse>,
) -> Result<std::result::Result<PreparedReverseRequest, (ReverseInterimResponses, Response<Body>)>>
{
    let router: Arc<ReverseRouter> = compiled.router.clone();
    let security_policy = compiled.security_policy.as_ref();
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.to_string();
    if let Err(err) =
        security_policy.validate_request(&req, conn.tls_sni.as_deref(), conn.tls_terminated)
    {
        warn!(error = ?err, "reverse TLS host policy rejected request");
        let request_method = req.method().clone();
        return Ok(Err(empty_interim_response(finalize_response_for_request(
            &request_method,
            req.version(),
            state.plan.identity.proxy_name.as_ref(),
            Response::builder()
                .status(StatusCode::MISDIRECTED_REQUEST)
                .body(Body::from("misdirected request"))?,
            false,
        ))));
    }

    let host = base.host.clone().unwrap_or_default();
    let request_method = req.method().clone();
    let request_version = req.version();
    let path_owned = base.path.clone();
    let request_uri = base.request_uri.clone();
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(request_method.as_str()),
        dst_port: Some(conn.dst_port),
        src_ip: Some(conn.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host.as_str()),
        sni: conn.tls_sni.as_deref(),
        path: path_owned.as_deref(),
    };
    let mut observation_plan = RequestObservationPlan::default();
    let mut max_observed_request_body_bytes = state.plan.limits.max_observed_request_body_bytes;
    router.try_for_each_candidate_route(prefilter_ctx.clone(), |_idx, route| {
        let route_http_guard = route.plan.guard.as_deref();
        if let Some(cap) =
            route_http_guard.and_then(|profile| profile.request_body_observation_cap())
        {
            max_observed_request_body_bytes = max_observed_request_body_bytes.min(cap);
        }
        max_observed_request_body_bytes = route
            .plan
            .body_observation_limit(max_observed_request_body_bytes);
        let guard_requires_buffering =
            route_http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req));
        Ok::<bool, anyhow::Error>(
            observation_plan.include(
                route.requires_request_size(),
                route.requires_request_body_observation()
                    || route.response_rules_require_request_body_observation()
                    || route
                        .plan
                        .flags
                        .contains(crate::runtime::PlanFlags::CAPTURE_BODY)
                    || guard_requires_buffering,
                route.requires_request_rpc_context()
                    || route.response_rules_require_request_rpc_context(),
            ),
        )
    })?;
    let req = match observation_plan
        .observe_request(
            req,
            max_observed_request_body_bytes,
            std::time::Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
        )
        .await
    {
        Ok(req) => req,
        Err(err) if crate::http::body_size::is_observed_body_limit_exceeded(&err) => {
            return Ok(Err(empty_interim_response(finalize_response_for_request(
                &request_method,
                request_version,
                proxy_name.as_ref(),
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request body too large"))?,
                false,
            ))));
        }
        Err(err) => return Err(err),
    };
    let request_rpc = observation_plan
        .needs_rpc
        .then(|| crate::http::rpc::inspect_request(&req));

    let mut route_idx = None;
    let mut selected_policy = EffectivePolicyContext::default();
    let mut selected_identity = None;
    let mut selected_headers = None;
    let mut request_destination_cache =
        std::collections::HashMap::<String, crate::destination::DestinationMetadata>::new();
    router.try_for_each_candidate_route(prefilter_ctx, |idx, candidate| {
        let resolution_override = candidate.plan.destination_resolution.as_ref();
        let effective_policy = candidate.plan.policy_context.clone();
        let mut sanitized_headers = req.headers().clone();
        sanitize_headers_for_policy(
            &state,
            &effective_policy,
            conn.remote_addr.ip(),
            &mut sanitized_headers,
        )?;
        let identity = resolve_identity(
            &state,
            &effective_policy,
            conn.remote_addr.ip(),
            Some(&sanitized_headers),
            conn.peer_certificates
                .as_deref()
                .map(|certs| certs.as_slice()),
        )?;
        let request_destination = request_destination_cache
            .entry(format!("{:?}", resolution_override))
            .or_insert_with(|| {
                classify_reverse_destination(&state, conn, host.as_str(), None, resolution_override)
            })
            .clone();
        let ctx = crate::http::rule_context::build_request_rule_match_context(
            crate::http::rule_context::RequestRuleContextInput {
                base,
                headers: &sanitized_headers,
                destination: &request_destination,
                identity: &identity,
                request_size: observed_request_size(&req),
                rpc: request_rpc.as_ref(),
                client_cert: conn.peer_certificate_info.as_deref(),
                upstream_cert: None,
            },
        );
        if candidate.matches(&ctx) {
            route_idx = Some(idx);
            selected_policy = effective_policy;
            selected_identity = Some(identity);
            selected_headers = Some(sanitized_headers);
            Ok::<bool, anyhow::Error>(true)
        } else {
            Ok::<bool, anyhow::Error>(false)
        }
    })?;

    Ok(Ok(PreparedReverseRequest {
        req,
        router,
        state,
        proxy_name,
        host,
        request_method,
        request_version,
        path_owned,
        request_uri,
        request_rpc,
        route_idx: route_idx.ok_or_else(|| anyhow!("no route matched"))?,
        selected_policy,
        identity: selected_identity
            .ok_or_else(|| anyhow!("identity missing for selected reverse route"))?,
        sanitized_headers: selected_headers
            .ok_or_else(|| anyhow!("sanitized headers missing for selected reverse route"))?,
        request_destination_cache,
        max_observed_request_body_bytes,
    }))
}
