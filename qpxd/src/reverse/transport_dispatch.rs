use super::*;
use crate::http::observation::RequestObservationPlan;
use crate::reverse::ReloadableReverse;
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::HttpRoute;
use crate::runtime;
use qpx_core::rules::CompiledHeaderControl;
use qpx_observability::access_log::RequestLogContext;

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

struct ReverseAuditContext<'a> {
    state: &'a Arc<runtime::RuntimeState>,
    reverse_name: &'a str,
    conn: &'a ReverseConnInfo,
    host: &'a str,
    request_method: &'a Method,
    path: Option<&'a str>,
    route: &'a HttpRoute,
    ext_authz_policy_id: Option<&'a str>,
    log_context: &'a RequestLogContext,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
}

struct ReverseRetryDispatch {
    attempts: usize,
    first_request: Option<Request<Body>>,
    template: Option<ReverseRequestTemplate>,
    mirror_upstreams: Vec<Arc<UpstreamEndpoint>>,
}

struct ReverseHttpDispatchInput<'a> {
    base: &'a BaseRequestFields,
    runtime: &'a Runtime,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
}

struct ReverseIpcDispatchInput<'a> {
    base: &'a BaseRequestFields,
    runtime: &'a Runtime,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
}

struct ReverseCacheWriteInput<'a> {
    runtime: &'a Runtime,
    request_method: &'a Method,
    response_delay_secs: u64,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    response_cache_bypass: bool,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_target_key: Option<&'a CacheRequestKey>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    revalidation_state: &'a mut Option<crate::cache::RevalidationState>,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
    state: &'a runtime::RuntimeState,
    route: &'a HttpRoute,
    selected_upstream: Option<&'a Arc<UpstreamEndpoint>>,
    attempt_idx: usize,
    attempts: usize,
    started: Instant,
}

struct ReverseCachedResponseInput<'a> {
    response: Response<Body>,
    outcome: &'static str,
    request_method: &'a Method,
    request_version: http::Version,
    proxy_name: &'a str,
    route_headers: Option<&'a CompiledHeaderControl>,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a ReverseAuditContext<'a>,
}

struct ReverseHttpSuccessInput<'a> {
    base: &'a BaseRequestFields,
    runtime: &'a Runtime,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
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
    runtime: &'a Runtime,
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
    audit_ctx: &'a ReverseAuditContext<'a>,
    attempt_idx: usize,
    started: Instant,
    response: Response<Body>,
    export_session: Option<&'a crate::exporter::ExportSession>,
}

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
    let audit_ctx = ReverseAuditContext {
        state: &state,
        reverse_name: reverse.name.as_ref(),
        conn: &conn,
        host: host.as_str(),
        request_method: &request_method,
        path: path_owned.as_deref(),
        route,
        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        log_context: &log_context,
    };

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
        annotate_reverse_response(&audit_ctx, &mut response, "max_forwards", &[]);
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
            runtime,
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
        runtime,
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

async fn dispatch_reverse_http_route(
    input: ReverseHttpDispatchInput<'_>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let ReverseHttpDispatchInput {
        base,
        runtime,
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
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        mut revalidation_state,
        mut first_request,
        template,
        mut mirror_upstreams,
        attempts,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        http_modules,
        request_limits,
        request_limit_ctx,
        audit_ctx,
    } = input;
    let mut last_err = None;
    for attempt_idx in 0..attempts {
        let selected_upstream = if override_upstream.is_none() {
            Some(
                route
                    .select_upstream(seed, sticky_seed)
                    .ok_or_else(|| anyhow!("no upstream"))?,
            )
        } else {
            None
        };
        let override_origin = override_upstream.map(OriginEndpoint::direct);
        let upstream_origin = override_origin
            .as_ref()
            .or_else(|| selected_upstream.as_ref().map(|upstream| &upstream.origin))
            .ok_or_else(|| anyhow!("no upstream"))?;
        let export_session = state.export_session_for_plan(
            &route.plan,
            conn.remote_addr,
            upstream_origin.upstream.as_str(),
        );
        let mut concurrency_ctx = request_limit_ctx.clone();
        if concurrency_ctx.upstream.is_none() {
            concurrency_ctx.upstream = selected_upstream
                .as_ref()
                .map(|upstream| upstream.target.clone());
        }
        let _concurrency_permits = match request_limits.acquire_concurrency(&concurrency_ctx) {
            Some(permits) => permits,
            None => {
                let mut response = finalize_response_for_request(
                    request_method,
                    request_version,
                    proxy_name,
                    too_many_requests(None),
                    false,
                );
                annotate_reverse_response(audit_ctx, &mut response, "concurrency_limited", &[]);
                return Ok(empty_interim_response(response));
            }
        };
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_add(1, Ordering::Relaxed);
        }
        let started = Instant::now();
        let mut req_for_upstream =
            build_reverse_attempt_request(attempt_idx, &mut first_request, template.as_ref())?;
        http_modules
            .on_upstream_request(&mut req_for_upstream)
            .await?;
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_request_preview(&req_for_upstream);
            session.emit_plaintext(true, &preview);
        }
        let response = proxy_reverse_http_attempt(
            req_for_upstream,
            upstream_origin,
            request_version,
            proxy_name,
            route,
            route_timeout,
        )
        .await;
        if let Some(upstream) = selected_upstream.as_ref() {
            upstream.inflight.fetch_sub(1, Ordering::Relaxed);
        }
        match response {
            Ok(Ok((interim, resp, upstream_cert))) => {
                match handle_reverse_http_success(ReverseHttpSuccessInput {
                    base,
                    runtime,
                    state,
                    conn,
                    host,
                    route,
                    resolution_override,
                    request_method,
                    request_version,
                    request_rpc,
                    identity,
                    route_headers: route_headers.clone(),
                    cache_policy,
                    request_headers_snapshot,
                    cache_lookup_key,
                    cache_target_key,
                    revalidation_state: &mut revalidation_state,
                    template: template.as_ref(),
                    mirror_upstreams: &mut mirror_upstreams,
                    attempts,
                    route_timeout,
                    proxy_name,
                    http_modules,
                    audit_ctx,
                    attempt_idx,
                    selected_upstream: selected_upstream.as_ref(),
                    started,
                    interim,
                    response: resp,
                    upstream_cert,
                    export_session: export_session.as_ref(),
                })
                .await?
                {
                    ReverseAttemptOutcome::Response(response) => return Ok(*response),
                    ReverseAttemptOutcome::Retry(err) => {
                        last_err = Some(err);
                        continue;
                    }
                    ReverseAttemptOutcome::Stop(err) => {
                        last_err = Some(err);
                        break;
                    }
                }
            }
            Ok(Err(err)) => {
                last_err = Some(
                    record_reverse_http_loop_error(
                        state,
                        route,
                        selected_upstream.as_ref(),
                        http_modules,
                        err,
                    )
                    .await,
                );
            }
            Err(_) => {
                last_err = Some(
                    record_reverse_http_loop_timeout(
                        state,
                        route,
                        selected_upstream.as_ref(),
                        http_modules,
                    )
                    .await,
                );
            }
        }
        if attempt_idx + 1 < attempts {
            if !consume_reverse_retry_budget(state, route) {
                break;
            }
            if let Some(err) = last_err.as_ref() {
                let retry_reason = err.to_string();
                http_modules
                    .on_retry(attempt_idx + 2, retry_reason.as_str())
                    .await?;
            }
            reverse_retry_backoff(route).await;
        }
    }
    finish_reverse_upstream_failure(
        revalidation_state.as_ref(),
        request_method,
        proxy_name,
        route_headers.as_deref(),
        http_modules,
        audit_ctx,
        last_err,
    )
    .await
}

async fn dispatch_reverse_ipc_route(
    input: ReverseIpcDispatchInput<'_>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let ReverseIpcDispatchInput {
        base,
        runtime,
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
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        mut revalidation_state,
        mut first_request,
        template,
        mut mirror_upstreams,
        attempts,
        route_timeout,
        proxy_name,
        http_modules,
        request_limits,
        request_limit_ctx,
        audit_ctx,
    } = input;
    let ipc = route
        .ipc
        .as_ref()
        .ok_or_else(|| anyhow!("reverse IPC route missing"))?;
    let _concurrency_permits = match request_limits.acquire_concurrency(request_limit_ctx) {
        Some(permits) => permits,
        None => {
            let mut response = finalize_response_for_request(
                request_method,
                request_version,
                proxy_name,
                too_many_requests(None),
                false,
            );
            annotate_reverse_response(audit_ctx, &mut response, "concurrency_limited", &[]);
            return Ok(empty_interim_response(response));
        }
    };
    let ipc_conn = ClientConnInfo {
        remote_addr: Some(conn.remote_addr),
    };
    let timeout_dur = std::cmp::min(route_timeout, ipc.timeout());
    let mut last_err = None;
    for attempt_idx in 0..attempts {
        let started = Instant::now();
        let mut req_for_upstream =
            build_reverse_attempt_request(attempt_idx, &mut first_request, template.as_ref())?;
        http_modules
            .on_upstream_request(&mut req_for_upstream)
            .await?;
        let export_session =
            state.export_session_for_plan(&route.plan, conn.remote_addr, ipc.endpoint_label());
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_request_preview(&req_for_upstream);
            session.emit_plaintext(true, &preview);
        }
        let response = timeout(
            timeout_dur,
            proxy_ipc_upstream(req_for_upstream, ipc, proxy_name, ipc_conn, route_timeout),
        )
        .await;
        match response {
            Ok(Ok(resp)) => {
                match handle_reverse_ipc_success(ReverseIpcSuccessInput {
                    base,
                    runtime,
                    state,
                    conn,
                    route,
                    request_destination,
                    request_method,
                    request_version,
                    request_rpc,
                    identity,
                    route_headers: route_headers.clone(),
                    cache_policy,
                    request_headers_snapshot,
                    cache_lookup_key,
                    cache_target_key,
                    revalidation_state: &mut revalidation_state,
                    template: template.as_ref(),
                    mirror_upstreams: &mut mirror_upstreams,
                    attempts,
                    route_timeout,
                    proxy_name,
                    http_modules,
                    audit_ctx,
                    attempt_idx,
                    started,
                    response: resp,
                    export_session: export_session.as_ref(),
                })
                .await?
                {
                    ReverseAttemptOutcome::Response(response) => return Ok(*response),
                    ReverseAttemptOutcome::Retry(err) => {
                        last_err = Some(err);
                        continue;
                    }
                    ReverseAttemptOutcome::Stop(err) => {
                        last_err = Some(err);
                        break;
                    }
                }
            }
            Ok(Err(err)) => {
                last_err = Some(record_reverse_loop_error(state, http_modules, err, "error").await);
            }
            Err(_) => {
                let err = anyhow!("upstream timeout");
                last_err =
                    Some(record_reverse_loop_error(state, http_modules, err, "timeout").await);
            }
        }
        if attempt_idx + 1 < attempts {
            if !consume_reverse_retry_budget(state, route) {
                break;
            }
            if let Some(err) = last_err.as_ref() {
                let retry_reason = err.to_string();
                http_modules
                    .on_retry(attempt_idx + 2, retry_reason.as_str())
                    .await?;
            }
            reverse_retry_backoff(route).await;
        }
    }
    if let Some(stale) = reverse_stale_if_error_response(
        revalidation_state.as_ref(),
        request_method,
        proxy_name,
        route_headers.as_deref(),
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

async fn handle_reverse_http_success(
    input: ReverseHttpSuccessInput<'_>,
) -> Result<ReverseAttemptOutcome> {
    let ReverseHttpSuccessInput {
        base,
        runtime,
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
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        template,
        mirror_upstreams,
        attempts,
        route_timeout,
        proxy_name,
        http_modules,
        audit_ctx,
        attempt_idx,
        selected_upstream,
        started,
        interim,
        response,
        upstream_cert,
        export_session,
    } = input;
    let resp = http_modules.on_upstream_response(response).await?;
    let response_destination = classify_reverse_destination(
        state,
        conn,
        host,
        upstream_cert.as_ref(),
        resolution_override,
    );
    let response_rule = apply_response_rules(ResponseRuleInput {
        route,
        base,
        conn,
        destination: &response_destination,
        upstream_cert: upstream_cert.as_ref(),
        identity,
        request_rpc,
        route_headers: route_headers.clone(),
        response: resp,
        max_observed_response_body_bytes: route
            .plan
            .body_observation_limit(state.plan.limits.max_observed_response_body_bytes),
        response_body_read_timeout: Duration::from_millis(
            state.plan.limits.upstream_http_timeout_ms.max(1),
        ),
        force_response_body_observation: route
            .plan
            .flags
            .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
    })
    .await?;
    let (mut resp, route_headers_for_response, response_cache_bypass, policy_tags, mirror) =
        match reverse_continue_response_rule(ReverseResponseRuleInput {
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
        })
        .await?
        {
            Ok(values) => values,
            Err(outcome) => return Ok(outcome),
        };
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_response_preview(&resp);
        session.emit_plaintext(false, &preview);
    }
    if resp.status().is_server_error()
        && let Some(stale) = reverse_stale_if_error_response(
            revalidation_state.as_ref(),
            request_method,
            proxy_name,
            route_headers.as_deref(),
            http_modules,
            audit_ctx,
        )
        .await?
    {
        if let Some(upstream) = selected_upstream {
            record_reverse_upstream_status(
                upstream,
                &route.policy,
                resp.status(),
                started.elapsed(),
            );
        }
        return Ok(ReverseAttemptOutcome::Response(Box::new(
            empty_interim_response(stale),
        )));
    }
    if let Some(upstream) = selected_upstream {
        record_reverse_upstream_status(upstream, &route.policy, resp.status(), started.elapsed());
    }
    record_reverse_success_metrics(state, started);
    resp = write_reverse_cache_result(
        resp,
        ReverseCacheWriteInput {
            runtime,
            request_method,
            response_delay_secs: started.elapsed().as_secs(),
            cache_policy,
            response_cache_bypass,
            request_headers_snapshot,
            cache_target_key,
            cache_lookup_key,
            revalidation_state,
        },
    )
    .await?;
    resp = http_modules.prepare_downstream_response(resp).await?;
    let resp_version = resp.version();
    finalize_response_with_headers_in_place(
        request_method,
        resp_version,
        proxy_name,
        &mut resp,
        route_headers_for_response.as_deref(),
        false,
    );
    if mirror.unwrap_or(true)
        && !mirror_upstreams.is_empty()
        && let Some(template) = template
    {
        dispatch_mirrors(
            template,
            std::mem::take(mirror_upstreams),
            route_timeout,
            route.policy.health.clone(),
            route.policy.lifecycle.clone(),
            route.upstream_trust.clone(),
            proxy_name,
        );
    }
    http_modules.on_logging(Some(resp.status()), None).await;
    annotate_reverse_response(audit_ctx, &mut resp, "allow", policy_tags.as_ref());
    Ok(ReverseAttemptOutcome::Response(Box::new((interim, resp))))
}

async fn handle_reverse_ipc_success(
    input: ReverseIpcSuccessInput<'_>,
) -> Result<ReverseAttemptOutcome> {
    let ReverseIpcSuccessInput {
        base,
        runtime,
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
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        template,
        mirror_upstreams,
        attempts,
        route_timeout,
        proxy_name,
        http_modules,
        audit_ctx,
        attempt_idx,
        started,
        response,
        export_session,
    } = input;
    let resp = http_modules.on_upstream_response(response).await?;
    let response_rule = apply_response_rules(ResponseRuleInput {
        route,
        base,
        conn,
        destination: request_destination,
        upstream_cert: None,
        identity,
        request_rpc,
        route_headers: route_headers.clone(),
        response: resp,
        max_observed_response_body_bytes: route
            .plan
            .body_observation_limit(state.plan.limits.max_observed_response_body_bytes),
        response_body_read_timeout: Duration::from_millis(
            state.plan.limits.upstream_http_timeout_ms.max(1),
        ),
        force_response_body_observation: route
            .plan
            .flags
            .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
    })
    .await?;
    let (mut resp, route_headers_for_response, response_cache_bypass, policy_tags, mirror) =
        match reverse_continue_response_rule(ReverseResponseRuleInput {
            response_rule,
            request_method,
            request_version,
            proxy_name,
            http_modules,
            audit_ctx,
            state,
            route,
            selected_upstream: None,
            attempt_idx,
            attempts,
            started,
        })
        .await?
        {
            Ok(values) => values,
            Err(outcome) => return Ok(outcome),
        };
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_response_preview(&resp);
        session.emit_plaintext(false, &preview);
    }
    if resp.status().is_server_error()
        && let Some(stale) = reverse_stale_if_error_response(
            revalidation_state.as_ref(),
            request_method,
            proxy_name,
            route_headers.as_deref(),
            http_modules,
            audit_ctx,
        )
        .await?
    {
        return Ok(ReverseAttemptOutcome::Response(Box::new(
            empty_interim_response(stale),
        )));
    }
    record_reverse_success_metrics(state, started);
    resp = write_reverse_cache_result(
        resp,
        ReverseCacheWriteInput {
            runtime,
            request_method,
            response_delay_secs: started.elapsed().as_secs(),
            cache_policy,
            response_cache_bypass,
            request_headers_snapshot,
            cache_target_key,
            cache_lookup_key,
            revalidation_state,
        },
    )
    .await?;
    resp = http_modules.prepare_downstream_response(resp).await?;
    let resp_version = resp.version();
    finalize_response_with_headers_in_place(
        request_method,
        resp_version,
        proxy_name,
        &mut resp,
        route_headers_for_response.as_deref(),
        false,
    );
    if mirror.unwrap_or(true)
        && !mirror_upstreams.is_empty()
        && let Some(template) = template
    {
        dispatch_mirrors(
            template,
            std::mem::take(mirror_upstreams),
            route_timeout,
            route.policy.health.clone(),
            route.policy.lifecycle.clone(),
            route.upstream_trust.clone(),
            proxy_name,
        );
    }
    http_modules.on_logging(Some(resp.status()), None).await;
    annotate_reverse_response(audit_ctx, &mut resp, "allow", policy_tags.as_ref());
    Ok(ReverseAttemptOutcome::Response(Box::new(
        empty_interim_response(resp),
    )))
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
            annotate_reverse_response(
                audit_ctx,
                &mut response,
                "response_rule_local_response",
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

async fn write_reverse_cache_result(
    mut resp: Response<Body>,
    input: ReverseCacheWriteInput<'_>,
) -> Result<Response<Body>> {
    let ReverseCacheWriteInput {
        runtime,
        request_method,
        response_delay_secs,
        cache_policy,
        response_cache_bypass,
        request_headers_snapshot,
        cache_target_key,
        cache_lookup_key,
        revalidation_state,
    } = input;
    if let (Some(policy), Some(snapshot)) = (
        cache_policy.filter(|_| !response_cache_bypass),
        request_headers_snapshot,
    ) {
        resp = process_upstream_response_for_cache(
            resp,
            CacheWritebackContext {
                request_method,
                response_delay_secs,
                cache_target_key,
                cache_lookup_key,
                cache_policy: Some(policy),
                request_headers_snapshot: snapshot,
                revalidation_state: revalidation_state.take(),
                body_read_timeout: Duration::from_millis(
                    runtime.state().plan.limits.upstream_http_timeout_ms.max(1),
                ),
                backends: &runtime.state().cache.backends,
            },
        )
        .await?;
    } else if let Some(policy) = cache_policy.filter(|_| !response_cache_bypass) {
        crate::cache::maybe_invalidate(
            request_method,
            resp.status(),
            resp.headers(),
            cache_target_key,
            policy,
            &runtime.state().cache.backends,
        )
        .await?;
    }
    Ok(resp)
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
    audit_ctx: &ReverseAuditContext<'_>,
    last_err: Option<anyhow::Error>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    if let Some(stale) = reverse_stale_if_error_response(
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
            proxy_kind: "reverse",
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
    let audit_ctx = ReverseAuditContext {
        state,
        reverse_name,
        conn,
        host,
        request_method,
        path,
        route,
        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        log_context: &log_context,
    };
    if let Some(response) = reverse_http_guard_response(
        route.plan.guard.as_deref(),
        &req,
        request_method,
        proxy_name,
        &audit_ctx,
    )? {
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
            reverse_rate_limit_response(
                request_method,
                req.version(),
                proxy_name,
                Some(retry_after),
                &audit_ctx,
            ),
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
            reverse_rate_limit_response(
                request_method,
                req.version(),
                proxy_name,
                Some(retry_after),
                &audit_ctx,
            ),
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

fn reverse_http_guard_response(
    route_http_guard: Option<&crate::http::guard::CompiledHttpGuardProfile>,
    req: &Request<Body>,
    request_method: &Method,
    proxy_name: &str,
    audit_ctx: &ReverseAuditContext<'_>,
) -> Result<Option<Response<Body>>> {
    let Some(profile) = route_http_guard else {
        return Ok(None);
    };
    let Some(reject) = profile.evaluate_request(req)? else {
        return Ok(None);
    };
    let mut response = finalize_response_for_request(
        request_method,
        req.version(),
        proxy_name,
        Response::builder()
            .status(reject.status)
            .body(Body::from(reject.body))?,
        false,
    );
    annotate_reverse_response(audit_ctx, &mut response, "http_guard_reject", &[]);
    Ok(Some(response))
}

fn resolve_reverse_ext_authz(
    ext_authz: ExtAuthzEnforcement,
    mut route_headers: Option<Arc<CompiledHeaderControl>>,
    req: &Request<Body>,
    request_method: &Method,
    proxy_name: &str,
    state: &runtime::RuntimeState,
    audit_ctx: &ReverseAuditContext<'_>,
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
            let merged_headers = merge_header_controls(route_headers, deny.headers);
            let mut response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    request_method,
                    req.version(),
                    proxy_name,
                    build_local_response(local)?,
                    merged_headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    request_method,
                    req.version(),
                    proxy_name,
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from(state.messages.reverse_error.clone()))?,
                    merged_headers.as_deref(),
                    false,
                )
            };
            annotate_reverse_response(
                audit_ctx,
                &mut response,
                if deny.local_response.is_some() {
                    "ext_authz_local_response"
                } else {
                    "ext_authz_deny"
                },
                &[],
            );
            Ok(Err(response))
        }
    }
}

fn reverse_rate_limit_response(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    retry_after: Option<Duration>,
    audit_ctx: &ReverseAuditContext<'_>,
) -> Response<Body> {
    let mut response = finalize_response_for_request(
        request_method,
        request_version,
        proxy_name,
        too_many_requests(retry_after),
        false,
    );
    annotate_reverse_response(audit_ctx, &mut response, "rate_limited", &[]);
    response
}

fn reverse_local_route_response(
    route: &HttpRoute,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    route_headers: Option<&CompiledHeaderControl>,
    audit_ctx: &ReverseAuditContext<'_>,
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
    annotate_reverse_response(audit_ctx, &mut response, "respond", &[]);
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
            proxy_kind: "reverse",
            proxy_name: proxy_name.to_string(),
            scope_name: reverse_name.to_string(),
            route_name: route.name.as_deref().map(str::to_string),
            remote_ip: conn.remote_addr.ip(),
            sni: conn.tls_sni.as_deref().map(str::to_string),
            identity_user: identity.user.clone(),
            cache_policy: request_cache_policy.clone(),
            cache_default_scheme: Some(
                if conn.tls_terminated { "https" } else { "http" }.to_string(),
            ),
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
                audit_ctx.request_method,
                response_version,
                proxy_name,
                &mut response,
                route_headers,
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_reverse_response(audit_ctx, &mut response, "http_module_local_response", &[]);
            Ok(ReverseModuleOutcome::Response(Box::new(response)))
        }
    }
}

async fn prepare_reverse_cache(input: ReverseCacheInput<'_>) -> Result<ReverseCacheOutcome> {
    let ReverseCacheInput {
        mut req,
        runtime,
        state,
        route,
        conn,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        request_cache_policy,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        http_modules,
        audit_ctx,
    } = input;
    let cache_default_scheme = if conn.tls_terminated { "https" } else { "http" };
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) =
        reverse_cache_keys(&req, request_cache_policy, cache_default_scheme)?;
    let mut revalidation_state = None;
    if let (Some(snapshot), Some(policy)) =
        (request_headers_snapshot.as_ref(), request_cache_policy)
    {
        let outcome = reverse_cache_lookup(
            req,
            ReverseCacheLookupInput {
                runtime,
                state,
                route,
                request_method,
                request_version,
                proxy_name,
                route_headers,
                policy,
                snapshot,
                cache_lookup_key: cache_lookup_key.as_ref(),
                cache_target_key: cache_target_key.as_ref(),
                override_upstream,
                seed,
                sticky_seed,
                route_timeout,
                http_modules,
                audit_ctx,
            },
        )
        .await?;
        match outcome {
            ReverseCacheLookupResult::Response(response) => {
                return Ok(ReverseCacheOutcome::Response(response));
            }
            ReverseCacheLookupResult::Continue {
                req: continued_req,
                revalidation_state: state,
            } => {
                req = *continued_req;
                revalidation_state = state;
            }
        }
    }
    let collapse = reverse_cache_collapse(
        req,
        ReverseCacheCollapseInput {
            runtime,
            state,
            request_method,
            request_version,
            proxy_name,
            route_headers,
            request_cache_policy,
            request_headers_snapshot: request_headers_snapshot.as_ref(),
            cache_lookup_key: cache_lookup_key.as_ref(),
            route_timeout,
            http_modules,
            audit_ctx,
            revalidation_state,
        },
    )
    .await?;
    let (revalidation_state, guard) = match collapse {
        ReverseCacheCollapseResult::Response(response) => {
            return Ok(ReverseCacheOutcome::Response(response));
        }
        ReverseCacheCollapseResult::Continue(continued) => {
            let ReverseCacheCollapseContinue {
                req: continued_req,
                revalidation_state,
                guard,
            } = *continued;
            req = *continued_req;
            (revalidation_state, guard)
        }
    };
    Ok(ReverseCacheOutcome::Continue(Box::new(ReverseCacheState {
        req,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        _cache_collapse_guard: guard,
    })))
}

fn reverse_cache_keys(
    req: &Request<Body>,
    cache_policy: Option<&qpx_core::config::CachePolicyConfig>,
    cache_default_scheme: &str,
) -> Result<(
    Option<http::HeaderMap>,
    Option<CacheRequestKey>,
    Option<CacheRequestKey>,
)> {
    if cache_policy.is_none() {
        return Ok((None, None, None));
    }
    let cache_lookup_key = CacheRequestKey::for_lookup(req, cache_default_scheme)?;
    let cache_target_key = CacheRequestKey::for_target(req, cache_default_scheme)?;
    let snapshot = cache_lookup_key.as_ref().map(|_| req.headers().clone());
    Ok((snapshot, cache_lookup_key, cache_target_key))
}

enum ReverseCacheLookupResult {
    Response(Box<Response<Body>>),
    Continue {
        req: Box<Request<Body>>,
        revalidation_state: Option<crate::cache::RevalidationState>,
    },
}

struct ReverseCacheLookupInput<'a> {
    runtime: &'a Runtime,
    state: &'a Arc<runtime::RuntimeState>,
    route: &'a HttpRoute,
    request_method: &'a Method,
    request_version: http::Version,
    proxy_name: &'a str,
    route_headers: Option<&'a CompiledHeaderControl>,
    policy: &'a qpx_core::config::CachePolicyConfig,
    snapshot: &'a http::HeaderMap,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    cache_target_key: Option<&'a CacheRequestKey>,
    override_upstream: Option<&'a str>,
    seed: u64,
    sticky_seed: u64,
    route_timeout: Duration,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a ReverseAuditContext<'a>,
}

async fn reverse_cache_lookup(
    mut req: Request<Body>,
    input: ReverseCacheLookupInput<'_>,
) -> Result<ReverseCacheLookupResult> {
    let ReverseCacheLookupInput {
        runtime,
        state,
        route,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        policy,
        snapshot,
        cache_lookup_key,
        cache_target_key,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        http_modules,
        audit_ctx,
    } = input;
    let (lookup_decision, revalidation_state) = lookup_with_revalidation(
        &mut req,
        snapshot,
        cache_lookup_key,
        Some(policy),
        &runtime.state().cache.backends,
        state.messages.cache_miss.as_str(),
    )
    .await?;
    let cache_hit = matches!(
        lookup_decision,
        CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
    );
    http_modules.on_cache_lookup(cache_hit).await?;
    match lookup_decision {
        CacheLookupDecision::Hit(hit) => Ok(ReverseCacheLookupResult::Response(Box::new(
            finalize_reverse_cached_response(ReverseCachedResponseInput {
                response: hit,
                outcome: "cache_hit",
                request_method,
                request_version,
                proxy_name,
                route_headers,
                http_modules,
                audit_ctx,
            })
            .await?,
        ))),
        CacheLookupDecision::StaleWhileRevalidate(hit, state) => {
            maybe_spawn_reverse_revalidation(
                &req,
                ReverseRevalidationInput {
                    runtime,
                    route,
                    request_method,
                    policy,
                    snapshot,
                    lookup_key: cache_lookup_key,
                    target_key: cache_target_key,
                    override_upstream,
                    seed,
                    sticky_seed,
                    route_timeout,
                    proxy_name,
                    state,
                },
            );
            Ok(ReverseCacheLookupResult::Response(Box::new(
                finalize_reverse_cached_response(ReverseCachedResponseInput {
                    response: hit,
                    outcome: "cache_stale",
                    request_method,
                    request_version,
                    proxy_name,
                    route_headers,
                    http_modules,
                    audit_ctx,
                })
                .await?,
            )))
        }
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            Ok(ReverseCacheLookupResult::Response(Box::new(
                finalize_reverse_cached_response(ReverseCachedResponseInput {
                    response,
                    outcome: "cache_only_if_cached_miss",
                    request_method,
                    request_version,
                    proxy_name,
                    route_headers,
                    http_modules,
                    audit_ctx,
                })
                .await?,
            )))
        }
        CacheLookupDecision::Miss => Ok(ReverseCacheLookupResult::Continue {
            req: Box::new(req),
            revalidation_state,
        }),
    }
}

struct ReverseRevalidationInput<'a> {
    runtime: &'a Runtime,
    route: &'a HttpRoute,
    request_method: &'a Method,
    policy: &'a qpx_core::config::CachePolicyConfig,
    snapshot: &'a http::HeaderMap,
    lookup_key: Option<&'a CacheRequestKey>,
    target_key: Option<&'a CacheRequestKey>,
    override_upstream: Option<&'a str>,
    seed: u64,
    sticky_seed: u64,
    route_timeout: Duration,
    proxy_name: &'a str,
    state: crate::cache::RevalidationState,
}

fn maybe_spawn_reverse_revalidation(req: &Request<Body>, input: ReverseRevalidationInput<'_>) {
    let ReverseRevalidationInput {
        runtime,
        route,
        request_method,
        policy,
        snapshot,
        lookup_key,
        target_key,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        state,
    } = input;
    if *request_method != Method::GET || route.ipc.is_some() {
        return;
    }
    let Some(lookup_key) = lookup_key else {
        return;
    };
    let Some(target_key) = target_key else {
        return;
    };
    let Some(target) = override_upstream.map(OriginEndpoint::direct).or_else(|| {
        route
            .select_upstream(seed, sticky_seed)
            .map(|u| u.origin.clone())
    }) else {
        return;
    };
    if target.upstream.starts_with("ipc://") || target.upstream.starts_with("ipc+unix://") {
        return;
    }
    let Some(guard) = crate::cache::try_begin_background_revalidation(&state) else {
        return;
    };
    let runtime = runtime.clone();
    let proxy_name = proxy_name.to_string();
    let policy = policy.clone();
    let snapshot = snapshot.clone();
    let lookup_key = lookup_key.clone();
    let target_key = target_key.clone();
    let upstream_trust = route.upstream_trust.clone();
    let bg_req = clone_request_head_for_revalidation(req);
    tokio::spawn(async move {
        let _guard = guard;
        let started = Instant::now();
        let resp = timeout(
            route_timeout,
            proxy_http(
                bg_req,
                &target,
                proxy_name.as_str(),
                upstream_trust.as_deref(),
            ),
        )
        .await;
        let Ok(Ok(resp)) = resp else {
            return;
        };
        let response_delay_secs = started.elapsed().as_secs();
        let state_ref = runtime.state();
        let method = Method::GET;
        let _ = process_upstream_response_for_cache(
            resp,
            CacheWritebackContext {
                request_method: &method,
                response_delay_secs,
                cache_target_key: Some(&target_key),
                cache_lookup_key: Some(&lookup_key),
                cache_policy: Some(&policy),
                request_headers_snapshot: &snapshot,
                revalidation_state: Some(state),
                body_read_timeout: Duration::from_millis(
                    state_ref.plan.limits.upstream_http_timeout_ms.max(1),
                ),
                backends: &state_ref.cache.backends,
            },
        )
        .await;
    });
}

async fn finalize_reverse_cached_response(
    input: ReverseCachedResponseInput<'_>,
) -> Result<Response<Body>> {
    let ReverseCachedResponseInput {
        response,
        outcome,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        http_modules,
        audit_ctx,
    } = input;
    let response = http_modules.prepare_downstream_response(response).await?;
    let mut response = finalize_response_with_headers(
        request_method,
        request_version,
        proxy_name,
        response,
        route_headers,
        false,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_reverse_response(audit_ctx, &mut response, outcome, &[]);
    Ok(response)
}

async fn reverse_stale_if_error_response(
    revalidation_state: Option<&crate::cache::RevalidationState>,
    request_method: &Method,
    proxy_name: &str,
    route_headers: Option<&CompiledHeaderControl>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &ReverseAuditContext<'_>,
) -> Result<Option<Response<Body>>> {
    let Some(stale) =
        revalidation_state.and_then(crate::cache::maybe_build_stale_if_error_response)
    else {
        return Ok(None);
    };
    let stale = http_modules.prepare_downstream_response(stale).await?;
    let mut stale = stale;
    let stale_version = stale.version();
    finalize_response_with_headers_in_place(
        request_method,
        stale_version,
        proxy_name,
        &mut stale,
        route_headers,
        false,
    );
    http_modules.on_logging(Some(stale.status()), None).await;
    annotate_reverse_response(audit_ctx, &mut stale, "stale_if_error", &[]);
    Ok(Some(stale))
}

struct ReverseCacheCollapseInput<'a> {
    runtime: &'a Runtime,
    state: &'a Arc<runtime::RuntimeState>,
    request_method: &'a Method,
    request_version: http::Version,
    proxy_name: &'a str,
    route_headers: Option<&'a CompiledHeaderControl>,
    request_cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    route_timeout: Duration,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a ReverseAuditContext<'a>,
    revalidation_state: Option<crate::cache::RevalidationState>,
}

enum ReverseCacheCollapseResult {
    Response(Box<Response<Body>>),
    Continue(Box<ReverseCacheCollapseContinue>),
}

struct ReverseCacheCollapseContinue {
    req: Box<Request<Body>>,
    revalidation_state: Option<crate::cache::RevalidationState>,
    guard: Option<crate::cache::RequestCollapseGuard>,
}

async fn reverse_cache_collapse(
    mut req: Request<Body>,
    input: ReverseCacheCollapseInput<'_>,
) -> Result<ReverseCacheCollapseResult> {
    let ReverseCacheCollapseInput {
        runtime,
        state,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        request_cache_policy,
        request_headers_snapshot,
        cache_lookup_key,
        route_timeout,
        http_modules,
        audit_ctx,
        mut revalidation_state,
    } = input;
    if *request_method != Method::GET {
        return Ok(ReverseCacheCollapseResult::Continue(Box::new(
            ReverseCacheCollapseContinue {
                req: Box::new(req),
                revalidation_state,
                guard: None,
            },
        )));
    }
    let (Some(snapshot), Some(policy), Some(lookup_key)) = (
        request_headers_snapshot,
        request_cache_policy,
        cache_lookup_key,
    ) else {
        return Ok(ReverseCacheCollapseResult::Continue(Box::new(
            ReverseCacheCollapseContinue {
                req: Box::new(req),
                revalidation_state,
                guard: None,
            },
        )));
    };
    match crate::cache::begin_request_collapse(lookup_key) {
        crate::cache::RequestCollapseJoin::Leader(guard) => Ok(
            ReverseCacheCollapseResult::Continue(Box::new(ReverseCacheCollapseContinue {
                req: Box::new(req),
                revalidation_state,
                guard: Some(guard),
            })),
        ),
        crate::cache::RequestCollapseJoin::Follower(waiter) => {
            if !waiter.wait(route_timeout).await {
                return Ok(ReverseCacheCollapseResult::Continue(Box::new(
                    ReverseCacheCollapseContinue {
                        req: Box::new(req),
                        revalidation_state,
                        guard: None,
                    },
                )));
            }
            let (decision, state_update) = lookup_with_revalidation(
                &mut req,
                snapshot,
                Some(lookup_key),
                Some(policy),
                &runtime.state().cache.backends,
                state.messages.cache_miss.as_str(),
            )
            .await?;
            revalidation_state = state_update;
            let cache_hit = matches!(
                decision,
                CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
            );
            http_modules.on_cache_lookup(cache_hit).await?;
            match reverse_cache_collapse_response(
                decision,
                request_method,
                request_version,
                proxy_name,
                route_headers,
                http_modules,
                audit_ctx,
            )
            .await?
            {
                Some(response) => Ok(ReverseCacheCollapseResult::Response(Box::new(response))),
                None => Ok(ReverseCacheCollapseResult::Continue(Box::new(
                    ReverseCacheCollapseContinue {
                        req: Box::new(req),
                        revalidation_state,
                        guard: None,
                    },
                ))),
            }
        }
    }
}

async fn reverse_cache_collapse_response(
    decision: CacheLookupDecision,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    route_headers: Option<&CompiledHeaderControl>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &ReverseAuditContext<'_>,
) -> Result<Option<Response<Body>>> {
    match decision {
        CacheLookupDecision::Hit(hit) => {
            let response = finalize_reverse_cached_response(ReverseCachedResponseInput {
                response: hit,
                outcome: "cache_collapsed_hit",
                request_method,
                request_version,
                proxy_name,
                route_headers,
                http_modules,
                audit_ctx,
            })
            .await?;
            Ok(Some(response))
        }
        CacheLookupDecision::StaleWhileRevalidate(hit, _) => {
            let response = finalize_reverse_cached_response(ReverseCachedResponseInput {
                response: hit,
                outcome: "cache_collapsed_stale",
                request_method,
                request_version,
                proxy_name,
                route_headers,
                http_modules,
                audit_ctx,
            })
            .await?;
            Ok(Some(response))
        }
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            let response = finalize_reverse_cached_response(ReverseCachedResponseInput {
                response,
                outcome: "cache_only_if_cached_miss",
                request_method,
                request_version,
                proxy_name,
                route_headers,
                http_modules,
                audit_ctx,
            })
            .await?;
            Ok(Some(response))
        }
        CacheLookupDecision::Miss => Ok(None),
    }
}

fn annotate_reverse_response(
    ctx: &ReverseAuditContext<'_>,
    response: &mut Response<Body>,
    outcome: &'static str,
    extra_policy_tags: &[String],
) {
    let mut annotated_context = ctx.log_context.clone();
    merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
    attach_log_context(response, &annotated_context);
    emit_audit_log(
        ctx.state,
        AuditRecord {
            kind: "reverse",
            name: ctx.reverse_name,
            remote_ip: ctx.conn.remote_addr.ip(),
            host: (!ctx.host.is_empty()).then_some(ctx.host),
            sni: ctx.conn.tls_sni.as_deref(),
            method: Some(ctx.request_method.as_str()),
            path: ctx.path,
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule: None,
            matched_route: ctx.route.name.as_deref(),
            ext_authz_policy_id: ctx.ext_authz_policy_id,
        },
        &annotated_context,
    );
}

async fn handle_reverse_websocket_upgrade(
    ctx: ReverseWebsocketDispatch<'_>,
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let ReverseWebsocketDispatch {
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
        route_headers,
        request_method,
        http_modules,
        audit_ctx,
    } = ctx;
    let upgrade_wait_timeout = Duration::from_millis(state.plan.limits.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout = Duration::from_millis(state.plan.limits.tunnel_idle_timeout_ms);
    let selected_upstream = if override_upstream.is_none() {
        Some(
            route
                .select_upstream(seed, sticky_seed)
                .ok_or_else(|| anyhow!("no healthy upstream"))?,
        )
    } else {
        None
    };
    let override_origin = override_upstream.map(OriginEndpoint::direct);
    let upstream_origin = override_origin
        .as_ref()
        .or_else(|| selected_upstream.as_ref().map(|upstream| &upstream.origin))
        .ok_or_else(|| anyhow!("no healthy upstream"))?;
    let export_session = state.export_session_for_plan(
        &route.plan,
        conn.remote_addr,
        upstream_origin.upstream.as_str(),
    );
    let mut concurrency_ctx = request_limit_ctx.clone();
    if concurrency_ctx.upstream.is_none() {
        concurrency_ctx.upstream = selected_upstream
            .as_ref()
            .map(|upstream| upstream.target.clone());
    }
    let _concurrency_permits = match request_limits.acquire_concurrency(&concurrency_ctx) {
        Some(permits) => permits,
        None => {
            let mut response = finalize_response_for_request(
                request_method,
                req.version(),
                proxy_name,
                too_many_requests(None),
                false,
            );
            annotate_reverse_response(audit_ctx, &mut response, "concurrency_limited", &[]);
            return Ok(empty_interim_response(response));
        }
    };
    if let Some(upstream) = selected_upstream.as_ref() {
        upstream.inflight.fetch_add(1, Ordering::Relaxed);
    }
    let started = Instant::now();
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let response = timeout(
        route_timeout,
        proxy_websocket(
            req,
            upstream_origin,
            proxy_name,
            route_timeout,
            upgrade_wait_timeout,
            tunnel_idle_timeout,
            route.upstream_trust.as_deref(),
        ),
    )
    .await;
    if let Some(upstream) = selected_upstream.as_ref() {
        upstream.inflight.fetch_sub(1, Ordering::Relaxed);
    }
    match response {
        Ok(Ok(mut resp)) => {
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_status(
                    upstream,
                    &route.policy,
                    resp.status(),
                    started.elapsed(),
                );
            }
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
            resp = http_modules.on_upstream_response(resp).await?;
            resp = http_modules.prepare_downstream_response(resp).await?;
            if let Some(session) = export_session.as_ref() {
                let preview = crate::exporter::serialize_response_preview(&resp);
                session.emit_plaintext(false, &preview);
            }
            let keep_upgrade = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
            let resp_version = resp.version();
            finalize_response_with_headers_in_place(
                request_method,
                resp_version,
                proxy_name,
                &mut resp,
                route_headers,
                keep_upgrade,
            );
            http_modules.on_logging(Some(resp.status()), None).await;
            annotate_reverse_response(audit_ctx, &mut resp, "allow", &[]);
            Ok(empty_interim_response(resp))
        }
        Ok(Err(err)) => {
            http_modules.on_error(&err).await;
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_error(upstream, &route.policy, &err);
            }
            counter!(
                state.observability.metric_names.reverse_requests_total.clone(),
                "result" => "error"
            )
            .increment(1);
            Err(err)
        }
        Err(_) => {
            let err = anyhow!("upstream timeout");
            http_modules.on_error(&err).await;
            if let Some(upstream) = selected_upstream.as_ref() {
                record_reverse_upstream_timeout(upstream, &route.policy);
            }
            counter!(
                state.observability.metric_names.reverse_requests_total.clone(),
                "result" => "timeout"
            )
            .increment(1);
            Err(err)
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
        let sanitized_headers = sanitize_headers_for_policy(
            &state,
            &effective_policy,
            conn.remote_addr.ip(),
            req.headers(),
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
