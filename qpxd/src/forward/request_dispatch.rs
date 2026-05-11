use super::*;
use crate::http::observation::RequestObservationPlan;
use crate::http::rule_context::{
    RequestRuleContextInput, ResponseRuleContextInput, attach_destination_trace,
    build_request_rule_match_context, build_response_rule_match_context,
};
use crate::runtime::PlanFlags;

enum ForwardPrepareOutcome {
    Response(Box<Response<Body>>),
    Prepared(Box<ForwardPreparedRequest>),
}

struct ForwardPreparedRequest {
    req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    state: Arc<crate::runtime::RuntimeState>,
    proxy_name: String,
    listener_name: String,
    listener_cfg: crate::runtime::CompiledListenerSettings,
    remote_addr: std::net::SocketAddr,
    host: HostPort,
    effective_policy: crate::policy_context::EffectivePolicyContext,
    destination: crate::destination::DestinationMetadata,
    identity: crate::policy_context::ResolvedIdentity,
    sanitized_headers: http::HeaderMap,
    response_engine: Option<Arc<crate::http::response_policy::HttpResponseRuleEngine>>,
    selected_plan: crate::runtime::ExecutionPlan,
    action: qpx_core::config::ActionConfig,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    matched_rule: Option<String>,
    cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    request_limits: crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: RateLimitContext,
    request_rpc: Option<crate::http::rpc::RpcMatchContext>,
    is_ftp_request: bool,
}

enum ForwardPolicyOutcome {
    #[cfg(feature = "auth-basic")]
    Response(Box<Response<Body>>),
    Allow(Box<ForwardAllowedPolicy>),
}

struct ForwardAllowedPolicy {
    action: qpx_core::config::ActionConfig,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    matched_rule: Option<String>,
    identity: crate::policy_context::ResolvedIdentity,
}

enum ForwardAccessOutcome {
    Response(Box<Response<Body>>),
    Continue(Box<ForwardAccess>),
}

struct ForwardAccess {
    action: qpx_core::config::ActionConfig,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    timeout_override: Option<Duration>,
    audit: ForwardAuditContext,
}

struct ForwardAuditContext {
    state: Arc<crate::runtime::RuntimeState>,
    listener_name: String,
    remote_addr: std::net::SocketAddr,
    host: String,
    request_method: Method,
    path: Option<String>,
    matched_rule: Option<String>,
    ext_authz_policy_id: Option<String>,
    log_context: qpx_observability::access_log::RequestLogContext,
}

enum ForwardCacheLookupOutcome {
    Response(Response<Body>),
    Continue(Option<crate::cache::RevalidationState>),
}

enum ForwardCacheCollapseOutcome {
    Response(Response<Body>),
    Continue {
        revalidation_state: Option<crate::cache::RevalidationState>,
        guard: Option<crate::cache::RequestCollapseGuard>,
    },
}

enum ForwardResponsePolicyOutcome {
    Response(Response<Body>),
    Continue {
        response: Response<Body>,
        headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
        cache_policy: Option<qpx_core::config::CachePolicyConfig>,
        policy_tags: Vec<String>,
    },
}

enum ForwardDispatchPrepareOutcome {
    Response(Box<Response<Body>>),
    Ready(Box<ForwardDispatchReady>),
}

struct ForwardDispatchReady {
    req: Request<Body>,
    http_modules: crate::http::modules::HttpModuleExecution,
    request_headers_snapshot: Option<http::HeaderMap>,
    cache_lookup_key: Option<CacheRequestKey>,
    cache_target_key: Option<CacheRequestKey>,
    upstream: Option<crate::upstream::pool::ResolvedUpstreamProxy>,
    upstream_timeout: Duration,
    http_authority: String,
    export_session: Option<crate::exporter::ExportSession>,
    _concurrency_permits: crate::rate_limit::ConcurrencyPermits,
}

struct ForwardGuardInput<'a> {
    state: &'a crate::runtime::RuntimeState,
    http_guard: Option<&'a crate::http::guard::CompiledHttpGuardProfile>,
    req: &'a Request<Body>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    destination: &'a crate::destination::DestinationMetadata,
    proxy_name: &'a str,
    listener_name: &'a str,
    remote_addr: std::net::SocketAddr,
    host: &'a str,
    path: Option<&'a str>,
}

struct ForwardPolicyOutcomeInput<'a> {
    runtime: &'a Runtime,
    listener_name: &'a str,
    ctx: qpx_core::rules::RuleMatchContext<'a>,
    sanitized_headers: &'a http::HeaderMap,
    response: ForwardPolicyResponseInput<'a>,
    auth_method: &'a str,
    auth_uri: &'a str,
}

#[derive(Clone, Copy)]
struct ForwardPolicyResponseInput<'a> {
    state: &'a crate::runtime::RuntimeState,
    identity: &'a crate::policy_context::ResolvedIdentity,
    destination: &'a crate::destination::DestinationMetadata,
    proxy_name: &'a str,
    listener_name: &'a str,
    remote_addr: std::net::SocketAddr,
    host: &'a str,
    #[cfg(feature = "auth-basic")]
    request_method: &'a Method,
    #[cfg(feature = "auth-basic")]
    request_version: http::Version,
    path: Option<&'a str>,
}

struct ForwardRateLimitResponseInput<'a> {
    policy: ForwardPolicyResponseInput<'a>,
    req: &'a Request<Body>,
    matched_rule: Option<&'a str>,
    retry_after: Duration,
}

struct ForwardWebsocketInput<'a> {
    req: Request<Body>,
    upstream: Option<&'a crate::upstream::pool::ResolvedUpstreamProxy>,
    connect_authority: &'a str,
    host_header: &'a str,
    upstream_timeout: Duration,
    upgrade_wait_timeout: Duration,
    tunnel_idle_timeout: Duration,
    export_session: Option<&'a crate::exporter::ExportSession>,
    request_method: &'a Method,
    proxy_name: &'a str,
    headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    audit: &'a ForwardAuditContext,
}

pub(super) async fn dispatch_forward_request(
    req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> Result<Response<Body>> {
    execute_forward_request(req, base, runtime, listener_name, remote_addr).await
}

async fn execute_forward_request(
    req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> Result<Response<Body>> {
    match prepare_forward_request(req, base, runtime, listener_name, remote_addr).await? {
        ForwardPrepareOutcome::Response(response) => Ok(*response),
        ForwardPrepareOutcome::Prepared(prepared) => complete_forward_request(*prepared).await,
    }
}

async fn prepare_forward_request(
    mut req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> Result<ForwardPrepareOutcome> {
    let state = runtime.state();
    let proxy_name_owned = state.plan.identity.proxy_name.to_string();
    let proxy_name = proxy_name_owned.as_str();
    let compiled_edge = state
        .plan
        .forward_edge(listener_name)
        .ok_or_else(|| anyhow!("compiled forward edge not found"))?;
    let listener_cfg = compiled_edge.listener.clone();
    let effective_policy = compiled_edge.default_plan.policy_context.clone();
    let http_guard = compiled_edge.default_plan.guard.as_deref();
    let is_ftp_request = base
        .scheme
        .as_deref()
        .map(|scheme| scheme.eq_ignore_ascii_case("ftp"))
        .unwrap_or(false);
    let host = match resolve_forward_target_or_response(
        &req,
        &base,
        &state,
        &listener_cfg,
        proxy_name,
        is_ftp_request,
    )? {
        Ok(host) => host,
        Err(response) => return Ok(ForwardPrepareOutcome::Response(Box::new(response))),
    };
    let engine = state
        .policy
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let prefilter_ctx = forward_prefilter_context(&base, &host);
    let response_engine = compiled_edge.default_plan.response_rules.clone();
    let capture_body = compiled_edge.flags.contains(PlanFlags::CAPTURE_BODY);
    let (observation_plan, max_observed_request_body_bytes) = plan_forward_request_observation(
        engine,
        response_engine.as_deref(),
        &prefilter_ctx,
        http_guard,
        &req,
        capture_body,
        state.plan.limits.max_observed_request_body_bytes,
    );
    let max_observed_request_body_bytes =
        compiled_edge.body_observation_limit(max_observed_request_body_bytes);
    req = match observe_forward_request(
        req,
        observation_plan,
        max_observed_request_body_bytes,
        Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
        &base.method,
        proxy_name,
    )
    .await?
    {
        Ok(req) => req,
        Err(response) => return Ok(ForwardPrepareOutcome::Response(Box::new(response))),
    };
    let path = base.path.as_deref();
    let sanitized_headers =
        sanitize_headers_for_policy(&state, &effective_policy, remote_addr.ip(), req.headers())?;
    let identity = resolve_identity(
        &state,
        &effective_policy,
        remote_addr.ip(),
        Some(&sanitized_headers),
        None,
    )?;
    let destination = forward_destination_metadata(
        &state,
        &base,
        &host,
        compiled_edge.default_plan.destination_resolution.as_ref(),
    );
    if let Some(response) = forward_http_guard_response(ForwardGuardInput {
        state: &state,
        http_guard,
        req: &req,
        identity: &identity,
        destination: &destination,
        proxy_name,
        listener_name,
        remote_addr,
        host: host.host.as_str(),
        path,
    })? {
        return Ok(ForwardPrepareOutcome::Response(Box::new(response)));
    }
    let request_rpc = observation_plan
        .needs_rpc
        .then(|| crate::http::rpc::inspect_request(&req));
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base: &base,
        headers: &sanitized_headers,
        destination: &destination,
        identity: &identity,
        request_size: observed_request_size(&req),
        rpc: request_rpc.as_ref(),
        client_cert: None,
        upstream_cert: None,
    });
    let policy_response = ForwardPolicyResponseInput {
        state: &state,
        identity: &identity,
        destination: &destination,
        proxy_name,
        listener_name,
        remote_addr,
        host: host.host.as_str(),
        #[cfg(feature = "auth-basic")]
        request_method: req.method(),
        #[cfg(feature = "auth-basic")]
        request_version: req.version(),
        path,
    };
    let policy_outcome = evaluate_forward_policy_outcome(ForwardPolicyOutcomeInput {
        runtime: &runtime,
        listener_name,
        ctx,
        sanitized_headers: &sanitized_headers,
        response: policy_response,
        auth_method: req.method().as_str(),
        auth_uri: base.request_uri.as_str(),
    })
    .await?;
    let ForwardAllowedPolicy {
        action,
        headers,
        matched_rule,
        identity,
    } = match policy_outcome {
        #[cfg(feature = "auth-basic")]
        ForwardPolicyOutcome::Response(response) => {
            return Ok(ForwardPrepareOutcome::Response(response));
        }
        ForwardPolicyOutcome::Allow(allowed) => *allowed,
    };
    let selected_plan = compiled_edge
        .execution_plan_for_rule(matched_rule.as_deref())
        .clone();
    let cache_policy = selected_plan.cache.clone();
    let request_limit_ctx =
        RateLimitContext::from_identity(remote_addr.ip(), &identity, matched_rule.as_deref(), None);
    let crate::rate_limit::RequestLimitAcquire {
        limits: request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        crate::rate_limit::TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        return Ok(ForwardPrepareOutcome::Response(Box::new(
            forward_rate_limit_response(ForwardRateLimitResponseInput {
                policy: policy_response,
                req: &req,
                matched_rule: matched_rule.as_deref(),
                retry_after,
            }),
        )));
    }
    Ok(ForwardPrepareOutcome::Prepared(Box::new(
        ForwardPreparedRequest {
            req,
            base,
            runtime,
            state,
            proxy_name: proxy_name_owned,
            listener_name: listener_name.to_string(),
            listener_cfg,
            remote_addr,
            host,
            effective_policy,
            destination,
            identity,
            sanitized_headers,
            response_engine,
            selected_plan,
            action,
            headers,
            matched_rule: matched_rule.map(|rule| rule.to_string()),
            cache_policy,
            request_limits,
            request_limit_ctx,
            request_rpc,
            is_ftp_request,
        },
    )))
}

fn resolve_forward_target_or_response(
    req: &Request<Body>,
    base: &BaseRequestFields,
    state: &crate::runtime::RuntimeState,
    listener_cfg: &crate::runtime::CompiledListenerSettings,
    proxy_name: &str,
    is_ftp_request: bool,
) -> Result<std::result::Result<HostPort, Response<Body>>> {
    if is_ftp_request && !listener_cfg.ftp.enabled {
        return Ok(Err(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(Body::from(state.messages.ftp_disabled.clone()))?,
            false,
        )));
    }
    let Some(host) = base.host.as_deref() else {
        return Ok(Err(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("missing Host/authority"))
                .unwrap_or_else(|_| bad_request("missing Host/authority")),
            false,
        )));
    };
    Ok(Ok(HostPort {
        host: host.to_string(),
        port: base.dst_port,
    }))
}

fn forward_prefilter_context<'a>(
    base: &'a BaseRequestFields,
    host: &'a HostPort,
) -> MatchPrefilterContext<'a> {
    MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: host.port,
        src_ip: base.peer_ip,
        host: Some(host.host.as_str()),
        sni: base.sni.as_deref(),
        path: base.path.as_deref(),
    }
}

fn plan_forward_request_observation(
    engine: &qpx_core::rules::RuleEngine,
    response_engine: Option<&crate::http::response_policy::HttpResponseRuleEngine>,
    prefilter_ctx: &MatchPrefilterContext<'_>,
    http_guard: Option<&crate::http::guard::CompiledHttpGuardProfile>,
    req: &Request<Body>,
    capture_body: bool,
    default_max_observed_request_body_bytes: usize,
) -> (RequestObservationPlan, usize) {
    let response_candidates_for_request = response_engine
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let mut observation_plan = RequestObservationPlan::from_policy_candidates(
        engine,
        &response_candidates_for_request,
        prefilter_ctx.clone(),
    );
    observation_plan.include_body(capture_body);
    observation_plan.include_body(
        http_guard.is_some_and(|profile| profile.requires_request_body_buffering(req)),
    );
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(default_max_observed_request_body_bytes))
        .unwrap_or(default_max_observed_request_body_bytes);
    (observation_plan, max_observed_request_body_bytes)
}

fn forward_destination_metadata(
    state: &crate::runtime::RuntimeState,
    base: &BaseRequestFields,
    host: &HostPort,
    destination_resolution: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
) -> crate::destination::DestinationMetadata {
    state.classify_destination(
        &DestinationInputs {
            host: Some(host.host.as_str()),
            ip: host.host.parse().ok(),
            scheme: base.scheme.as_deref(),
            port: host.port,
            ..Default::default()
        },
        destination_resolution,
    )
}

async fn observe_forward_request(
    req: Request<Body>,
    observation_plan: RequestObservationPlan,
    max_observed_request_body_bytes: usize,
    read_timeout: Duration,
    method: &Method,
    proxy_name: &str,
) -> Result<std::result::Result<Request<Body>, Response<Body>>> {
    let request_version = req.version();
    match observation_plan
        .observe_request(req, max_observed_request_body_bytes, read_timeout)
        .await
    {
        Ok(req) => Ok(Ok(req)),
        Err(err) if crate::http::body_size::is_observed_body_limit_exceeded(&err) => {
            Ok(Err(finalize_response_for_request(
                method,
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

fn forward_http_guard_response(input: ForwardGuardInput<'_>) -> Result<Option<Response<Body>>> {
    let ForwardGuardInput {
        state,
        http_guard,
        req,
        identity,
        destination,
        proxy_name,
        listener_name,
        remote_addr,
        host,
        path,
    } = input;
    let Some(profile) = http_guard else {
        return Ok(None);
    };
    let Some(reject) = profile.evaluate_request(req)? else {
        return Ok(None);
    };
    let mut log_context = identity.to_log_context(None, None, None);
    attach_destination_trace(&mut log_context, destination);
    let mut response = finalize_response_for_request(
        req.method(),
        req.version(),
        proxy_name,
        Response::builder()
            .status(reject.status)
            .body(Body::from(reject.body))?,
        false,
    );
    attach_log_context(&mut response, &log_context);
    emit_audit_log(
        state,
        AuditRecord {
            kind: "forward",
            name: listener_name,
            remote_ip: remote_addr.ip(),
            host: Some(host),
            sni: None,
            method: Some(req.method().as_str()),
            path,
            outcome: "http_guard_reject",
            status: Some(response.status().as_u16()),
            matched_rule: None,
            matched_route: None,
            ext_authz_policy_id: None,
        },
        &log_context,
    );
    Ok(Some(response))
}

async fn evaluate_forward_policy_outcome(
    input: ForwardPolicyOutcomeInput<'_>,
) -> Result<ForwardPolicyOutcome> {
    let ForwardPolicyOutcomeInput {
        runtime,
        listener_name,
        ctx,
        sanitized_headers,
        response: response_input,
        auth_method,
        auth_uri,
    } = input;
    let policy = evaluate_forward_policy(
        runtime,
        listener_name,
        ctx,
        sanitized_headers,
        auth_method,
        auth_uri,
    )
    .await?;
    match policy {
        ForwardPolicyDecision::Allow(allowed) => {
            let mut identity = response_input.identity.clone();
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            Ok(ForwardPolicyOutcome::Allow(Box::new(
                ForwardAllowedPolicy {
                    action: allowed.action,
                    headers: allowed.headers,
                    matched_rule: allowed.matched_rule.map(|rule| rule.to_string()),
                    identity,
                },
            )))
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Challenge(chal) => {
            let mut response = proxy_auth_required(
                chal,
                response_input.state.messages.proxy_auth_required.as_str(),
            );
            response = finalize_forward_policy_response(response_input, response, "challenge");
            Ok(ForwardPolicyOutcome::Response(Box::new(response)))
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Forbidden => {
            let response = finalize_forward_policy_response(
                response_input,
                forbidden(response_input.state.messages.forbidden.as_str()),
                "forbidden",
            );
            Ok(ForwardPolicyOutcome::Response(Box::new(response)))
        }
    }
}

#[cfg(feature = "auth-basic")]
fn finalize_forward_policy_response(
    input: ForwardPolicyResponseInput<'_>,
    response: Response<Body>,
    outcome: &'static str,
) -> Response<Body> {
    let mut log_context = input.identity.to_log_context(None, None, None);
    attach_destination_trace(&mut log_context, input.destination);
    let mut response = finalize_response_for_request(
        input.request_method,
        input.request_version,
        input.proxy_name,
        response,
        false,
    );
    attach_log_context(&mut response, &log_context);
    emit_audit_log(
        input.state,
        AuditRecord {
            kind: "forward",
            name: input.listener_name,
            remote_ip: input.remote_addr.ip(),
            host: Some(input.host),
            sni: None,
            method: Some(input.request_method.as_str()),
            path: input.path,
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule: None,
            matched_route: None,
            ext_authz_policy_id: None,
        },
        &log_context,
    );
    response
}

fn forward_rate_limit_response(input: ForwardRateLimitResponseInput<'_>) -> Response<Body> {
    let ForwardRateLimitResponseInput {
        policy,
        req,
        matched_rule,
        retry_after,
    } = input;
    let mut log_context = policy.identity.to_log_context(matched_rule, None, None);
    attach_destination_trace(&mut log_context, policy.destination);
    let mut response = finalize_response_for_request(
        req.method(),
        req.version(),
        policy.proxy_name,
        too_many_requests(Some(retry_after)),
        false,
    );
    attach_log_context(&mut response, &log_context);
    emit_audit_log(
        policy.state,
        AuditRecord {
            kind: "forward",
            name: policy.listener_name,
            remote_ip: policy.remote_addr.ip(),
            host: Some(policy.host),
            sni: None,
            method: Some(req.method().as_str()),
            path: policy.path,
            outcome: "rate_limited",
            status: Some(response.status().as_u16()),
            matched_rule,
            matched_route: None,
            ext_authz_policy_id: None,
        },
        &log_context,
    );
    response
}

struct ForwardAccessInput<'a> {
    state: Arc<crate::runtime::RuntimeState>,
    effective_policy: &'a crate::policy_context::EffectivePolicyContext,
    proxy_name: &'a str,
    listener_name: &'a str,
    remote_addr: std::net::SocketAddr,
    host: &'a HostPort,
    base: &'a BaseRequestFields,
    destination: &'a crate::destination::DestinationMetadata,
    identity: &'a crate::policy_context::ResolvedIdentity,
    sanitized_headers: &'a http::HeaderMap,
    request_method: Method,
    request_version: http::Version,
    action: qpx_core::config::ActionConfig,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    matched_rule: Option<String>,
    cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: &'a RateLimitContext,
}

async fn enforce_forward_access_control(
    input: ForwardAccessInput<'_>,
) -> Result<ForwardAccessOutcome> {
    let ext_authz = enforce_ext_authz(
        &input.state,
        input.effective_policy,
        ExtAuthzInput {
            proxy_kind: "forward",
            proxy_name: input.proxy_name,
            scope_name: input.listener_name,
            remote_ip: input.remote_addr.ip(),
            dst_port: input.host.port,
            host: Some(input.host.host.as_str()),
            sni: None,
            method: Some(input.request_method.as_str()),
            path: input.base.path.as_deref(),
            uri: Some(input.base.request_uri.as_str()),
            matched_rule: input.matched_rule.as_deref(),
            matched_route: None,
            action: Some(&input.action),
            headers: Some(input.sanitized_headers),
            identity: input.identity,
        },
    )
    .await?;
    let audit = build_forward_audit_context(&input, &ext_authz);
    let mut action = input.action;
    let mut headers = input.headers;
    let mut cache_policy = input.cache_policy;
    match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardHttp)?;
            headers = merge_header_controls(headers, allow.headers.clone());
            if allow.cache_bypass {
                cache_policy = None;
            }
            if let Some(retry_after) = input.request_limits.merge_profile_and_check(
                &input.state.policy.rate_limiters,
                allow.rate_limit_profile.as_deref(),
                crate::rate_limit::TransportScope::Request,
                input.request_limit_ctx,
                1,
            )? {
                let mut response = finalize_response_for_request(
                    &input.request_method,
                    input.request_version,
                    input.proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                );
                annotate_forward_response(&mut response, &audit, "rate_limited", &[]);
                return Ok(ForwardAccessOutcome::Response(Box::new(response)));
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            Ok(ForwardAccessOutcome::Continue(Box::new(ForwardAccess {
                action,
                headers,
                cache_policy,
                timeout_override: allow.timeout_override,
                audit,
            })))
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let merged_headers = merge_header_controls(headers, deny.headers);
            let mut response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    &input.request_method,
                    input.request_version,
                    input.proxy_name,
                    build_local_response(local)?,
                    merged_headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    &input.request_method,
                    input.request_version,
                    input.proxy_name,
                    forbidden(input.state.messages.forbidden.as_str()),
                    merged_headers.as_deref(),
                    false,
                )
            };
            annotate_forward_response(
                &mut response,
                &audit,
                if deny.local_response.is_some() {
                    "ext_authz_local_response"
                } else {
                    "ext_authz_deny"
                },
                &[],
            );
            Ok(ForwardAccessOutcome::Response(Box::new(response)))
        }
    }
}

fn build_forward_audit_context(
    input: &ForwardAccessInput<'_>,
    ext_authz: &ExtAuthzEnforcement,
) -> ForwardAuditContext {
    let ext_authz_policy_id = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    };
    let ext_authz_policy_tags = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
    };
    let mut log_context = input.identity.to_log_context(
        input.matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    attach_destination_trace(&mut log_context, input.destination);
    log_context.policy_tags = ext_authz_policy_tags;
    ForwardAuditContext {
        state: input.state.clone(),
        listener_name: input.listener_name.to_string(),
        remote_addr: input.remote_addr,
        host: input.host.host.clone(),
        request_method: input.request_method.clone(),
        path: input.base.path.clone(),
        matched_rule: input.matched_rule.clone(),
        ext_authz_policy_id,
        log_context,
    }
}

fn annotate_forward_response(
    response: &mut Response<Body>,
    audit: &ForwardAuditContext,
    outcome: &'static str,
    extra_policy_tags: &[String],
) {
    let mut annotated_context = audit.log_context.clone();
    merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
    attach_log_context(response, &annotated_context);
    emit_audit_log(
        &audit.state,
        AuditRecord {
            kind: "forward",
            name: audit.listener_name.as_str(),
            remote_ip: audit.remote_addr.ip(),
            host: Some(audit.host.as_str()),
            sni: None,
            method: Some(audit.request_method.as_str()),
            path: audit.path.as_deref(),
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule: audit.matched_rule.as_deref(),
            matched_route: None,
            ext_authz_policy_id: audit.ext_authz_policy_id.as_deref(),
        },
        &annotated_context,
    );
}

fn handle_forward_local_action(
    req: &Request<Body>,
    state: &crate::runtime::RuntimeState,
    proxy_name: &str,
    action: &qpx_core::config::ActionConfig,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    audit: &ForwardAuditContext,
) -> Result<Option<Response<Body>>> {
    if matches!(action.kind, ActionKind::Block) {
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            blocked(state.messages.blocked.as_str()),
            false,
        );
        annotate_forward_response(&mut response, audit, "block", &[]);
        return Ok(Some(response));
    }
    if matches!(action.kind, ActionKind::Respond) {
        let local = action
            .local_response
            .as_ref()
            .ok_or_else(|| anyhow!("respond action requires local_response"))?;
        let mut response = finalize_response_with_headers(
            req.method(),
            req.version(),
            proxy_name,
            build_local_response(local)?,
            headers,
            false,
        );
        annotate_forward_response(&mut response, audit, "respond", &[]);
        return Ok(Some(response));
    }
    Ok(None)
}

async fn handle_forward_ftp(
    req: Request<Body>,
    listener_cfg: &crate::runtime::CompiledListenerSettings,
    state: &crate::runtime::RuntimeState,
    request_method: &Method,
    proxy_name: &str,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    audit: &ForwardAuditContext,
) -> Result<Response<Body>> {
    let mut response = ftp::handle_ftp(
        req,
        listener_cfg.ftp.clone(),
        Arc::<str>::from(state.messages.unsupported_ftp_method.as_str()),
        state.ftp_semaphore.clone(),
    )
    .await?;
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        request_method,
        response_version,
        proxy_name,
        &mut response,
        headers,
        false,
    );
    annotate_forward_response(&mut response, audit, "allow", &[]);
    Ok(response)
}

async fn handle_forward_max_forwards(
    req: &mut Request<Body>,
    state: &crate::runtime::RuntimeState,
    proxy_name: &str,
    audit: &ForwardAuditContext,
) -> Option<Response<Body>> {
    let mut response = handle_max_forwards_in_place(
        req,
        proxy_name,
        state.plan.limits.trace_reflect_all_headers,
        state.plan.limits.max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
    )
    .await?;
    annotate_forward_response(&mut response, audit, "max_forwards", &[]);
    Some(response)
}

fn ensure_forward_host_header(req: &mut Request<Body>, host: &HostPort) -> Result<()> {
    if req.headers().contains_key("host") {
        return Ok(());
    }
    let default_port = match req.uri().scheme_str() {
        Some(s) if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("wss") => 443,
        Some(s) if s.eq_ignore_ascii_case("ftp") => 21,
        _ => 80,
    };
    let host_value = match host.port {
        Some(port) if port != default_port => format_authority_host_port(host.host.as_str(), port),
        _ => host.host.clone(),
    };
    req.headers_mut()
        .insert("host", http::HeaderValue::from_str(&host_value)?);
    Ok(())
}

async fn proxy_forward_websocket(input: ForwardWebsocketInput<'_>) -> Result<Response<Body>> {
    let ForwardWebsocketInput {
        req,
        upstream,
        connect_authority,
        host_header,
        upstream_timeout,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        export_session,
        request_method,
        proxy_name,
        headers,
        audit,
    } = input;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let mut response = proxy_websocket_http1(
        req,
        WebsocketProxyConfig {
            upstream_proxy: upstream,
            direct_connect_authority: connect_authority,
            direct_host_header: host_header,
            timeout_dur: upstream_timeout,
            upgrade_wait_timeout,
            tunnel_idle_timeout,
            tunnel_label: "forward",
            upstream_context: "forward websocket upstream proxy",
            direct_context: "forward websocket direct",
        },
    )
    .await?;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let keep_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        request_method,
        response_version,
        proxy_name,
        &mut response,
        headers,
        keep_upgrade,
    );
    annotate_forward_response(&mut response, audit, "allow", &[]);
    Ok(response)
}

struct ForwardCacheLookupInput<'a> {
    req: &'a mut Request<Body>,
    runtime: &'a Runtime,
    action: &'a qpx_core::config::ActionConfig,
    listener_name: &'a str,
    http_authority: &'a str,
    upstream_timeout: Duration,
    request_method: &'a Method,
    client_version: http::Version,
    proxy_name: &'a str,
    headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    cache_target_key: Option<&'a CacheRequestKey>,
    state: &'a crate::runtime::RuntimeState,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit: &'a ForwardAuditContext,
}

async fn try_forward_cache_lookup(
    input: ForwardCacheLookupInput<'_>,
) -> Result<ForwardCacheLookupOutcome> {
    let Some(snapshot) = input.request_headers_snapshot else {
        return Ok(ForwardCacheLookupOutcome::Continue(None));
    };
    if input.cache_policy.is_none() {
        return Ok(ForwardCacheLookupOutcome::Continue(None));
    }
    let (lookup_decision, lookup_revalidation_state) = lookup_with_revalidation(
        input.req,
        snapshot,
        input.cache_lookup_key,
        input.cache_policy,
        &input.state.cache.backends,
        input.state.messages.cache_miss.as_str(),
    )
    .await?;
    let cache_hit = matches!(
        lookup_decision,
        CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
    );
    input.http_modules.on_cache_lookup(cache_hit).await?;
    match lookup_decision {
        CacheLookupDecision::Hit(hit) => {
            let response = finalize_forward_cache_hit(
                hit,
                input.http_modules,
                input.request_method,
                input.proxy_name,
                input.headers,
                input.audit,
                "cache_hit",
            )
            .await?;
            Ok(ForwardCacheLookupOutcome::Response(response))
        }
        CacheLookupDecision::StaleWhileRevalidate(hit, state) => {
            maybe_spawn_forward_background_revalidation(&input, &state);
            let response = finalize_forward_cache_hit(
                hit,
                input.http_modules,
                input.request_method,
                input.proxy_name,
                input.headers,
                input.audit,
                "cache_stale",
            )
            .await?;
            Ok(ForwardCacheLookupOutcome::Response(response))
        }
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            let response = input
                .http_modules
                .prepare_downstream_response(response)
                .await?;
            let mut response = finalize_response_with_headers(
                input.request_method,
                input.client_version,
                input.proxy_name,
                response,
                input.headers,
                false,
            );
            input
                .http_modules
                .on_logging(Some(response.status()), None)
                .await;
            annotate_forward_response(&mut response, input.audit, "cache_only_if_cached_miss", &[]);
            Ok(ForwardCacheLookupOutcome::Response(response))
        }
        CacheLookupDecision::Miss => Ok(ForwardCacheLookupOutcome::Continue(
            lookup_revalidation_state,
        )),
    }
}

async fn finalize_forward_cache_hit(
    mut response: Response<Body>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    request_method: &Method,
    proxy_name: &str,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    audit: &ForwardAuditContext,
    outcome: &'static str,
) -> Result<Response<Body>> {
    response = http_modules.prepare_downstream_response(response).await?;
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        request_method,
        response_version,
        proxy_name,
        &mut response,
        headers,
        false,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_forward_response(&mut response, audit, outcome, &[]);
    Ok(response)
}

fn maybe_spawn_forward_background_revalidation(
    input: &ForwardCacheLookupInput<'_>,
    state: &crate::cache::RevalidationState,
) {
    if *input.request_method != Method::GET {
        return;
    }
    let (Some(policy), Some(snapshot), Some(lookup_key), Some(target_key)) = (
        input.cache_policy,
        input.request_headers_snapshot,
        input.cache_lookup_key,
        input.cache_target_key,
    ) else {
        return;
    };
    let Some(guard) = crate::cache::try_begin_background_revalidation(state) else {
        return;
    };
    let runtime = input.runtime.clone();
    let action = input.action.clone();
    let listener_name = input.listener_name.to_string();
    let http_authority = input.http_authority.to_string();
    let policy = policy.clone();
    let snapshot = snapshot.clone();
    let lookup_key = lookup_key.clone();
    let target_key = target_key.clone();
    let bg_req = clone_request_head_for_revalidation(input.req);
    let upstream_timeout = input.upstream_timeout;
    let state = state.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let started = std::time::Instant::now();
        let runtime_state = runtime.state();
        let upstream = resolve_upstream(&action, &runtime_state, listener_name.as_str())
            .ok()
            .flatten();
        let Ok(resp) = proxy_http1_request(
            bg_req,
            upstream.as_ref(),
            http_authority.as_str(),
            upstream_timeout,
        )
        .await
        else {
            return;
        };
        let response_delay_secs = started.elapsed().as_secs();
        let state_ref = runtime.state();
        let backends = &state_ref.cache.backends;
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
                body_read_timeout: std::time::Duration::from_millis(
                    state_ref.plan.limits.upstream_http_timeout_ms.max(1),
                ),
                backends,
            },
        )
        .await;
    });
}

struct ForwardCacheCollapseInput<'a> {
    req: &'a mut Request<Body>,
    request_method: &'a Method,
    client_version: http::Version,
    proxy_name: &'a str,
    headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    state: &'a crate::runtime::RuntimeState,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    upstream_timeout: Duration,
    audit: &'a ForwardAuditContext,
    revalidation_state: Option<crate::cache::RevalidationState>,
}

async fn try_forward_cache_collapse(
    input: ForwardCacheCollapseInput<'_>,
) -> Result<ForwardCacheCollapseOutcome> {
    let mut revalidation_state = input.revalidation_state.clone();
    let mut guard = None;
    if input.request_method != Method::GET {
        return Ok(ForwardCacheCollapseOutcome::Continue {
            revalidation_state,
            guard,
        });
    }
    let (Some(snapshot), Some(policy), Some(lookup_key)) = (
        input.request_headers_snapshot,
        input.cache_policy,
        input.cache_lookup_key,
    ) else {
        return Ok(ForwardCacheCollapseOutcome::Continue {
            revalidation_state,
            guard,
        });
    };
    match crate::cache::begin_request_collapse(lookup_key) {
        crate::cache::RequestCollapseJoin::Leader(leader) => guard = Some(leader),
        crate::cache::RequestCollapseJoin::Follower(waiter) => {
            if waiter.wait(input.upstream_timeout).await {
                let (lookup_decision, next_revalidation_state) = lookup_with_revalidation(
                    input.req,
                    snapshot,
                    input.cache_lookup_key,
                    Some(policy),
                    &input.state.cache.backends,
                    input.state.messages.cache_miss.as_str(),
                )
                .await?;
                revalidation_state = next_revalidation_state;
                let cache_hit = matches!(
                    lookup_decision,
                    CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
                );
                input.http_modules.on_cache_lookup(cache_hit).await?;
                if let Some(response) =
                    finalize_forward_collapsed_cache_decision(input, lookup_decision).await?
                {
                    return Ok(ForwardCacheCollapseOutcome::Response(response));
                }
            }
        }
    }
    Ok(ForwardCacheCollapseOutcome::Continue {
        revalidation_state,
        guard,
    })
}

async fn finalize_forward_collapsed_cache_decision(
    input: ForwardCacheCollapseInput<'_>,
    lookup_decision: CacheLookupDecision,
) -> Result<Option<Response<Body>>> {
    match lookup_decision {
        CacheLookupDecision::Hit(hit) => Ok(Some(
            finalize_forward_cache_hit(
                hit,
                input.http_modules,
                input.request_method,
                input.proxy_name,
                input.headers,
                input.audit,
                "cache_collapsed_hit",
            )
            .await?,
        )),
        CacheLookupDecision::StaleWhileRevalidate(hit, _) => Ok(Some(
            finalize_forward_cache_hit(
                hit,
                input.http_modules,
                input.request_method,
                input.proxy_name,
                input.headers,
                input.audit,
                "cache_collapsed_stale",
            )
            .await?,
        )),
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            let response = input
                .http_modules
                .prepare_downstream_response(response)
                .await?;
            let mut response = finalize_response_with_headers(
                input.request_method,
                input.client_version,
                input.proxy_name,
                response,
                input.headers,
                false,
            );
            input
                .http_modules
                .on_logging(Some(response.status()), None)
                .await;
            annotate_forward_response(&mut response, input.audit, "cache_only_if_cached_miss", &[]);
            Ok(Some(response))
        }
        CacheLookupDecision::Miss => Ok(None),
    }
}

struct ForwardUpstreamInput<'a> {
    req: Request<Body>,
    upstream: Option<&'a crate::upstream::pool::ResolvedUpstreamProxy>,
    http_authority: &'a str,
    upstream_timeout: Duration,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    export_session: Option<&'a crate::exporter::ExportSession>,
    request_method: &'a Method,
    client_version: http::Version,
    proxy_name: &'a str,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    cache_target_key: Option<&'a CacheRequestKey>,
    revalidation_state: Option<crate::cache::RevalidationState>,
    response_engine: Option<&'a crate::http::response_policy::HttpResponseRuleEngine>,
    selected_plan: &'a crate::runtime::ExecutionPlan,
    base: &'a BaseRequestFields,
    destination: &'a crate::destination::DestinationMetadata,
    identity: &'a crate::policy_context::ResolvedIdentity,
    host: &'a HostPort,
    remote_addr: std::net::SocketAddr,
    state: &'a crate::runtime::RuntimeState,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    audit: &'a ForwardAuditContext,
}

async fn execute_forward_upstream(input: ForwardUpstreamInput<'_>) -> Result<Response<Body>> {
    let ForwardUpstreamInput {
        mut req,
        upstream,
        http_authority,
        upstream_timeout,
        http_modules,
        export_session,
        request_method,
        client_version,
        proxy_name,
        mut headers,
        mut cache_policy,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        response_engine,
        selected_plan,
        base,
        destination,
        identity,
        host,
        remote_addr,
        state,
        request_rpc,
        audit,
    } = input;
    let upstream_started = std::time::Instant::now();
    http_modules.on_upstream_request(&mut req).await?;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let proxied =
        match proxy_http1_request_with_interim(req, upstream, http_authority, upstream_timeout)
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                http_modules.on_error(&err).await;
                if let Some(stale) = finalize_forward_stale_if_error(
                    None,
                    &revalidation_state,
                    http_modules,
                    request_method,
                    proxy_name,
                    headers.as_deref(),
                    audit,
                )
                .await?
                {
                    return Ok(stale);
                }
                return Err(err);
            }
        };
    let mut response = proxied.response;
    if !proxied.interim.is_empty() {
        response.extensions_mut().insert(proxied.interim);
    }
    response = http_modules.on_upstream_response(response).await?;
    let response_policy_tags = match apply_forward_response_policy(ForwardResponsePolicyInput {
        response,
        response_engine,
        selected_plan,
        base,
        destination,
        identity,
        host,
        remote_addr,
        state,
        request_method,
        client_version,
        proxy_name,
        headers,
        cache_policy,
        request_rpc,
        http_modules,
        audit,
    })
    .await?
    {
        ForwardResponsePolicyOutcome::Response(response) => return Ok(response),
        ForwardResponsePolicyOutcome::Continue {
            response: updated,
            headers: updated_headers,
            cache_policy: updated_cache_policy,
            policy_tags,
        } => {
            response = updated;
            headers = updated_headers;
            cache_policy = updated_cache_policy;
            policy_tags
        }
    };
    let response_delay_secs = upstream_started.elapsed().as_secs();
    if response.status().is_server_error()
        && let Some(stale) = finalize_forward_stale_if_error(
            Some(response.status()),
            &revalidation_state,
            http_modules,
            request_method,
            proxy_name,
            headers.as_deref(),
            audit,
        )
        .await?
    {
        return Ok(stale);
    }
    response = write_forward_cache_result(ForwardCacheWriteInput {
        response,
        cache_policy: cache_policy.as_ref(),
        request_headers_snapshot,
        cache_target_key,
        cache_lookup_key,
        revalidation_state,
        request_method,
        response_delay_secs,
        state,
    })
    .await?;
    response = http_modules.prepare_downstream_response(response).await?;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        request_method,
        response_version,
        proxy_name,
        &mut response,
        headers.as_deref(),
        false,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_forward_response(&mut response, audit, "allow", &response_policy_tags);
    Ok(response)
}

struct ForwardResponsePolicyInput<'a> {
    response: Response<Body>,
    response_engine: Option<&'a crate::http::response_policy::HttpResponseRuleEngine>,
    selected_plan: &'a crate::runtime::ExecutionPlan,
    base: &'a BaseRequestFields,
    destination: &'a crate::destination::DestinationMetadata,
    identity: &'a crate::policy_context::ResolvedIdentity,
    host: &'a HostPort,
    remote_addr: std::net::SocketAddr,
    state: &'a crate::runtime::RuntimeState,
    request_method: &'a Method,
    client_version: http::Version,
    proxy_name: &'a str,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit: &'a ForwardAuditContext,
}

async fn apply_forward_response_policy(
    input: ForwardResponsePolicyInput<'_>,
) -> Result<ForwardResponsePolicyOutcome> {
    let response_prefilter_ctx = MatchPrefilterContext {
        method: Some(input.request_method.as_str()),
        dst_port: input.host.port,
        src_ip: Some(input.remote_addr.ip()),
        host: Some(input.host.host.as_str()),
        sni: None,
        path: input.base.path.as_deref(),
    };
    let response_candidates = input
        .response_engine
        .map(|engine| engine.candidate_profile(response_prefilter_ctx))
        .unwrap_or_default();
    let response_status = input.response.status().as_u16();
    let response_headers = input.response.headers().clone();
    let decision = apply_listener_response_policy(
        input.response_engine,
        response_candidates,
        build_response_rule_match_context(ResponseRuleContextInput {
            base: input.base,
            headers: &response_headers,
            destination: input.destination,
            identity: input.identity,
            response_status,
            response_size: None,
            rpc: None,
            client_cert: None,
            upstream_cert: None,
        }),
        input.response,
        input.headers.clone(),
        input.request_rpc,
        ResponseBodyObservationLimits {
            max_body_bytes: input
                .selected_plan
                .body_observation_limit(input.state.plan.limits.max_observed_response_body_bytes),
            read_timeout: std::time::Duration::from_millis(
                input.state.plan.limits.upstream_http_timeout_ms.max(1),
            ),
            force_body: input.selected_plan.flags.contains(PlanFlags::CAPTURE_BODY),
        },
    )
    .await?;
    match decision {
        ListenerResponsePolicyDecision::Continue {
            response,
            headers,
            cache_bypass,
            suppress_retry: _suppress_retry,
            mirror: _mirror,
            policy_tags,
        } => Ok(ForwardResponsePolicyOutcome::Continue {
            response,
            headers,
            cache_policy: if cache_bypass {
                None
            } else {
                input.cache_policy
            },
            policy_tags,
        }),
        ListenerResponsePolicyDecision::LocalResponse {
            response,
            headers,
            policy_tags,
        } => {
            let response = input
                .http_modules
                .prepare_downstream_response(response)
                .await?;
            let mut response = finalize_response_with_headers(
                input.request_method,
                input.client_version,
                input.proxy_name,
                response,
                headers.as_deref(),
                false,
            );
            input
                .http_modules
                .on_logging(Some(response.status()), None)
                .await;
            annotate_forward_response(
                &mut response,
                input.audit,
                "response_local_response",
                &policy_tags,
            );
            Ok(ForwardResponsePolicyOutcome::Response(response))
        }
    }
}

async fn finalize_forward_stale_if_error(
    _status: Option<StatusCode>,
    revalidation_state: &Option<crate::cache::RevalidationState>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    request_method: &Method,
    proxy_name: &str,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    audit: &ForwardAuditContext,
) -> Result<Option<Response<Body>>> {
    let Some(stale) = revalidation_state
        .as_ref()
        .and_then(crate::cache::maybe_build_stale_if_error_response)
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
        headers,
        false,
    );
    http_modules.on_logging(Some(stale.status()), None).await;
    annotate_forward_response(&mut stale, audit, "stale_if_error", &[]);
    Ok(Some(stale))
}

struct ForwardCacheWriteInput<'a> {
    response: Response<Body>,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_target_key: Option<&'a CacheRequestKey>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    revalidation_state: Option<crate::cache::RevalidationState>,
    request_method: &'a Method,
    response_delay_secs: u64,
    state: &'a crate::runtime::RuntimeState,
}

async fn write_forward_cache_result(input: ForwardCacheWriteInput<'_>) -> Result<Response<Body>> {
    let Some(policy) = input.cache_policy else {
        return Ok(input.response);
    };
    if let Some(snapshot) = input.request_headers_snapshot {
        process_upstream_response_for_cache(
            input.response,
            CacheWritebackContext {
                request_method: input.request_method,
                response_delay_secs: input.response_delay_secs,
                cache_target_key: input.cache_target_key,
                cache_lookup_key: input.cache_lookup_key,
                cache_policy: Some(policy),
                request_headers_snapshot: snapshot,
                revalidation_state: input.revalidation_state,
                body_read_timeout: std::time::Duration::from_millis(
                    input.state.plan.limits.upstream_http_timeout_ms.max(1),
                ),
                backends: &input.state.cache.backends,
            },
        )
        .await
    } else {
        crate::cache::maybe_invalidate(
            input.request_method,
            input.response.status(),
            input.response.headers(),
            input.cache_target_key,
            policy,
            &input.state.cache.backends,
        )
        .await?;
        Ok(input.response)
    }
}

struct ForwardPreparedHttpInput<'a> {
    ready: ForwardDispatchReady,
    runtime: &'a Runtime,
    action: &'a qpx_core::config::ActionConfig,
    listener_name: &'a str,
    request_method: &'a Method,
    client_version: http::Version,
    proxy_name: &'a str,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    state: &'a crate::runtime::RuntimeState,
    audit: &'a ForwardAuditContext,
    response_engine: Option<&'a crate::http::response_policy::HttpResponseRuleEngine>,
    selected_plan: &'a crate::runtime::ExecutionPlan,
    base: &'a BaseRequestFields,
    destination: &'a crate::destination::DestinationMetadata,
    identity: &'a crate::policy_context::ResolvedIdentity,
    host: &'a HostPort,
    remote_addr: std::net::SocketAddr,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
}

async fn execute_forward_http_after_prepare(
    input: ForwardPreparedHttpInput<'_>,
) -> Result<Response<Body>> {
    let ForwardDispatchReady {
        mut req,
        mut http_modules,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        upstream,
        upstream_timeout,
        http_authority,
        export_session,
        _concurrency_permits,
    } = input.ready;
    let mut revalidation_state;
    match try_forward_cache_lookup(ForwardCacheLookupInput {
        req: &mut req,
        runtime: input.runtime,
        action: input.action,
        listener_name: input.listener_name,
        http_authority: http_authority.as_str(),
        upstream_timeout,
        request_method: input.request_method,
        client_version: input.client_version,
        proxy_name: input.proxy_name,
        headers: input.headers.as_deref(),
        cache_policy: input.cache_policy,
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        cache_target_key: cache_target_key.as_ref(),
        state: input.state,
        http_modules: &mut http_modules,
        audit: input.audit,
    })
    .await?
    {
        ForwardCacheLookupOutcome::Response(response) => return Ok(response),
        ForwardCacheLookupOutcome::Continue(state) => revalidation_state = state,
    }
    let _cache_collapse_guard = match try_forward_cache_collapse(ForwardCacheCollapseInput {
        req: &mut req,
        request_method: input.request_method,
        client_version: input.client_version,
        proxy_name: input.proxy_name,
        headers: input.headers.as_deref(),
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_policy: input.cache_policy,
        cache_lookup_key: cache_lookup_key.as_ref(),
        state: input.state,
        http_modules: &mut http_modules,
        upstream_timeout,
        audit: input.audit,
        revalidation_state,
    })
    .await?
    {
        ForwardCacheCollapseOutcome::Response(response) => return Ok(response),
        ForwardCacheCollapseOutcome::Continue {
            revalidation_state: state,
            guard,
        } => {
            revalidation_state = state;
            guard
        }
    };
    execute_forward_upstream(ForwardUpstreamInput {
        req,
        upstream: upstream.as_ref(),
        http_authority: http_authority.as_str(),
        upstream_timeout,
        http_modules: &mut http_modules,
        export_session: export_session.as_ref(),
        request_method: input.request_method,
        client_version: input.client_version,
        proxy_name: input.proxy_name,
        headers: input.headers,
        cache_policy: input.cache_policy.cloned(),
        request_headers_snapshot: request_headers_snapshot.as_ref(),
        cache_lookup_key: cache_lookup_key.as_ref(),
        cache_target_key: cache_target_key.as_ref(),
        revalidation_state,
        response_engine: input.response_engine,
        selected_plan: input.selected_plan,
        base: input.base,
        destination: input.destination,
        identity: input.identity,
        host: input.host,
        remote_addr: input.remote_addr,
        state: input.state,
        request_rpc: input.request_rpc,
        audit: input.audit,
    })
    .await
}

struct ForwardDispatchPrepareInput<'a> {
    req: Request<Body>,
    state: Arc<crate::runtime::RuntimeState>,
    effective_policy: &'a crate::policy_context::EffectivePolicyContext,
    remote_addr: std::net::SocketAddr,
    proxy_name: &'a str,
    listener_name: &'a str,
    selected_plan: &'a crate::runtime::ExecutionPlan,
    action: &'a qpx_core::config::ActionConfig,
    headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    matched_rule: Option<&'a str>,
    request_limits: crate::rate_limit::AppliedRateLimits,
    timeout_override: Option<Duration>,
    host: &'a HostPort,
    request_method: &'a Method,
    audit: &'a ForwardAuditContext,
}

async fn prepare_forward_dispatch(
    input: ForwardDispatchPrepareInput<'_>,
) -> Result<ForwardDispatchPrepareOutcome> {
    let ForwardDispatchPrepareInput {
        mut req,
        state,
        effective_policy,
        remote_addr,
        proxy_name,
        listener_name,
        selected_plan,
        action,
        headers,
        cache_policy,
        identity,
        matched_rule,
        request_limits,
        timeout_override,
        host,
        request_method,
        audit,
    } = input;
    strip_untrusted_identity_headers(
        &state,
        effective_policy,
        remote_addr.ip(),
        req.headers_mut(),
    )?;
    let websocket = is_websocket_upgrade(req.headers());
    prepare_request_with_headers_in_place(&mut req, proxy_name, headers, websocket);
    ensure_forward_host_header(&mut req, host)?;
    let mut http_modules = selected_plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: "forward",
            proxy_name: proxy_name.to_string(),
            scope_name: listener_name.to_string(),
            route_name: None,
            remote_ip: remote_addr.ip(),
            sni: None,
            identity_user: identity.user.clone(),
            cache_policy: cache_policy.cloned(),
            cache_default_scheme: Some(req.uri().scheme_str().unwrap_or("http").to_string()),
        },
    );
    if let crate::http::modules::RequestHeadersOutcome::Respond(response) =
        http_modules.on_request_headers(&mut req).await?
    {
        let mut response = http_modules.prepare_downstream_response(*response).await?;
        let response_version = response.version();
        finalize_response_with_headers_in_place(
            request_method,
            response_version,
            proxy_name,
            &mut response,
            headers,
            false,
        );
        http_modules.on_logging(Some(response.status()), None).await;
        annotate_forward_response(&mut response, audit, "http_module_local_response", &[]);
        return Ok(ForwardDispatchPrepareOutcome::Response(Box::new(response)));
    }
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) =
        prepare_forward_cache_keys(&req, action, cache_policy)?;
    let upstream = resolve_upstream(action, &state, listener_name)?;
    let rate_limit_ctx = RateLimitContext::from_identity(
        remote_addr.ip(),
        identity,
        matched_rule,
        upstream.as_ref().map(|upstream| upstream.key()),
    );
    let Some(_concurrency_permits) = request_limits.acquire_concurrency(&rate_limit_ctx) else {
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            too_many_requests(None),
            false,
        );
        annotate_forward_response(&mut response, audit, "concurrency_limited", &[]);
        return Ok(ForwardDispatchPrepareOutcome::Response(Box::new(response)));
    };
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.plan.limits.upstream_http_timeout_ms));
    let http_authority = forward_http_authority(host);
    let export_session = state.export_session_for_plan(selected_plan, remote_addr, &http_authority);
    if websocket {
        let connect_authority = forward_websocket_connect_authority(host);
        let host_header = forward_websocket_host_header(host);
        let response = proxy_forward_websocket(ForwardWebsocketInput {
            req,
            upstream: upstream.as_ref(),
            connect_authority: connect_authority.as_str(),
            host_header: host_header.as_str(),
            upstream_timeout,
            upgrade_wait_timeout: Duration::from_millis(state.plan.limits.upgrade_wait_timeout_ms),
            tunnel_idle_timeout: Duration::from_millis(state.plan.limits.tunnel_idle_timeout_ms),
            export_session: export_session.as_ref(),
            request_method,
            proxy_name,
            headers,
            audit,
        })
        .await?;
        return Ok(ForwardDispatchPrepareOutcome::Response(Box::new(response)));
    }
    Ok(ForwardDispatchPrepareOutcome::Ready(Box::new(
        ForwardDispatchReady {
            req,
            http_modules,
            request_headers_snapshot,
            cache_lookup_key,
            cache_target_key,
            upstream,
            upstream_timeout,
            http_authority,
            export_session,
            _concurrency_permits,
        },
    )))
}

fn prepare_forward_cache_keys(
    req: &Request<Body>,
    action: &qpx_core::config::ActionConfig,
    cache_policy: Option<&qpx_core::config::CachePolicyConfig>,
) -> Result<(
    Option<http::HeaderMap>,
    Option<CacheRequestKey>,
    Option<CacheRequestKey>,
)> {
    let cache_applicable = cache_policy.is_some()
        && matches!(
            action.kind,
            ActionKind::Direct | ActionKind::Proxy | ActionKind::Tunnel | ActionKind::Inspect
        );
    if !cache_applicable {
        return Ok((None, None, None));
    }
    let cache_default_scheme = req.uri().scheme_str().unwrap_or("http");
    let cache_lookup_key = CacheRequestKey::for_lookup(req, cache_default_scheme)?;
    let cache_target_key = CacheRequestKey::for_target(req, cache_default_scheme)?;
    let snapshot = cache_lookup_key.as_ref().map(|_| req.headers().clone());
    Ok((snapshot, cache_lookup_key, cache_target_key))
}

fn forward_http_authority(host: &HostPort) -> String {
    match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => host.host.clone(),
    }
}

fn forward_websocket_connect_authority(host: &HostPort) -> String {
    match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => format_authority_host_port(host.host.as_str(), 80),
    }
}

fn forward_websocket_host_header(host: &HostPort) -> String {
    match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => host.host.clone(),
    }
}

async fn complete_forward_request(prepared: ForwardPreparedRequest) -> Result<Response<Body>> {
    let ForwardPreparedRequest {
        mut req,
        base,
        runtime,
        state,
        proxy_name,
        listener_name,
        listener_cfg,
        remote_addr,
        host,
        effective_policy,
        destination,
        identity,
        sanitized_headers,
        response_engine,
        selected_plan,
        action,
        headers,
        matched_rule,
        cache_policy,
        mut request_limits,
        request_limit_ctx,
        request_rpc,
        is_ftp_request,
    } = prepared;
    let proxy_name = proxy_name.as_str();
    let listener_name = listener_name.as_str();
    let request_method = req.method().clone();
    let client_version = req.version();
    let access = match enforce_forward_access_control(ForwardAccessInput {
        state: state.clone(),
        effective_policy: &effective_policy,
        proxy_name,
        listener_name,
        remote_addr,
        host: &host,
        base: &base,
        destination: &destination,
        identity: &identity,
        sanitized_headers: &sanitized_headers,
        request_method: request_method.clone(),
        request_version: client_version,
        action,
        headers,
        matched_rule: matched_rule.clone(),
        cache_policy,
        request_limits: &mut request_limits,
        request_limit_ctx: &request_limit_ctx,
    })
    .await?
    {
        ForwardAccessOutcome::Response(response) => return Ok(*response),
        ForwardAccessOutcome::Continue(access) => *access,
    };
    let action = access.action;
    let headers = access.headers;
    let cache_policy = access.cache_policy;
    let timeout_override = access.timeout_override;
    let audit = access.audit;

    if let Some(response) = handle_forward_local_action(
        &req,
        &state,
        proxy_name,
        &action,
        headers.as_deref(),
        &audit,
    )? {
        return Ok(response);
    }

    if is_ftp_request {
        let response = handle_forward_ftp(
            req,
            &listener_cfg,
            &state,
            &request_method,
            proxy_name,
            headers.as_deref(),
            &audit,
        )
        .await?;
        return Ok(response);
    }
    if let Some(response) = handle_forward_max_forwards(&mut req, &state, proxy_name, &audit).await
    {
        return Ok(response);
    }
    let ready = match prepare_forward_dispatch(ForwardDispatchPrepareInput {
        req,
        state: state.clone(),
        effective_policy: &effective_policy,
        remote_addr,
        proxy_name,
        listener_name,
        selected_plan: &selected_plan,
        action: &action,
        headers: headers.as_deref(),
        cache_policy: cache_policy.as_ref(),
        identity: &identity,
        matched_rule: matched_rule.as_deref(),
        request_limits,
        timeout_override,
        host: &host,
        request_method: &request_method,
        audit: &audit,
    })
    .await?
    {
        ForwardDispatchPrepareOutcome::Response(response) => return Ok(*response),
        ForwardDispatchPrepareOutcome::Ready(ready) => *ready,
    };
    execute_forward_http_after_prepare(ForwardPreparedHttpInput {
        ready,
        runtime: &runtime,
        action: &action,
        listener_name,
        request_method: &request_method,
        client_version,
        proxy_name,
        cache_policy: cache_policy.as_ref(),
        headers,
        state: &state,
        audit: &audit,
        response_engine: response_engine.as_deref(),
        selected_plan: &selected_plan,
        base: &base,
        destination: &destination,
        identity: &identity,
        host: &host,
        remote_addr,
        request_rpc: request_rpc.as_ref(),
    })
    .await
}
