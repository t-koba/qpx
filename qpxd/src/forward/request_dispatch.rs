use super::*;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchCacheCollapseOutcome, DispatchCacheLookupOutcome,
    DispatchCacheWriteInput, DispatchCachedResponseInput, DispatchError, DispatchGuardInput,
    DispatchRateLimitInput, DispatchRequestPrepareInput, DispatchResponsePolicyInput,
    DispatchResponsePolicyOutcome, DispatchWebsocketProxyInput, ExtAuthzDenyResponseInput,
    PreparedDispatchRequest, annotate_dispatch_response, apply_dispatch_response_policy,
    emit_dispatch_websocket_response_preview, evaluate_http_guard, ext_authz_deny_response,
    finalize_dispatch_cached_response, finalize_dispatch_stale_if_error_response,
    prepare_dispatch_cache_keys, prepare_dispatch_request, proxy_dispatch_websocket_http1,
    rate_limit_response, record_cache_lookup_duration, record_cache_lookup_result,
    record_upstream_request_duration, write_dispatch_cache_result,
};
use crate::http::rule_context::{
    RequestRuleContextInput, ResponseRuleContextInput, attach_destination_trace,
    build_request_rule_match_context, build_response_rule_match_context,
};
use crate::runtime::PlanFlags;

#[path = "request_dispatch_cache.rs"]
mod request_dispatch_cache;
#[path = "request_dispatch_upstream.rs"]
mod request_dispatch_upstream;

use self::request_dispatch_cache::{
    ForwardCacheCollapseInput, ForwardCacheLookupInput, prepare_forward_cache_keys,
    try_forward_cache_collapse, try_forward_cache_lookup,
};
use self::request_dispatch_upstream::{ForwardUpstreamInput, execute_forward_upstream};

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
    Rejected(DispatchError),
    Allow(Box<ForwardAllowedPolicy>),
}

struct ForwardAllowedPolicy {
    action: qpx_core::config::ActionConfig,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    matched_rule: Option<String>,
    identity: crate::policy_context::ResolvedIdentity,
}

enum ForwardAccessOutcome {
    Continue(Box<ForwardAccess>),
}

struct ForwardAccess {
    action: qpx_core::config::ActionConfig,
    headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    timeout_override: Option<Duration>,
    audit: DispatchAuditContext,
}

pub(super) enum ForwardResponsePolicyOutcome {
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

pub(super) struct ForwardDispatchReady {
    pub(super) req: Request<Body>,
    pub(super) http_modules: crate::http::modules::HttpModuleExecution,
    pub(super) request_headers_snapshot: Option<http::HeaderMap>,
    pub(super) cache_lookup_key: Option<CacheRequestKey>,
    pub(super) cache_target_key: Option<CacheRequestKey>,
    pub(super) upstream: Option<crate::upstream::pool::ResolvedUpstreamProxy>,
    pub(super) upstream_timeout: Duration,
    pub(super) http_authority: String,
    pub(super) export_session: Option<crate::exporter::ExportSession>,
    pub(super) _concurrency_permits: crate::rate_limit::ConcurrencyPermits,
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
    #[cfg(feature = "auth-basic")]
    state: &'a crate::runtime::RuntimeState,
    identity: &'a crate::policy_context::ResolvedIdentity,
    destination: &'a crate::destination::DestinationMetadata,
    #[cfg(feature = "auth-basic")]
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
    audit: &'a DispatchAuditContext,
}

#[tracing::instrument(
    skip_all,
    fields(kind = "forward", host = %base.host.as_deref().unwrap_or(""), method = %base.method)
)]
pub(super) async fn dispatch_forward_request(
    req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> std::result::Result<Response<Body>, DispatchError> {
    execute_forward_request(req, base, runtime, listener_name, remote_addr).await
}

async fn execute_forward_request(
    req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> std::result::Result<Response<Body>, DispatchError> {
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
) -> std::result::Result<ForwardPrepareOutcome, DispatchError> {
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
    let response_candidates_for_request = response_engine
        .as_deref()
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.plan.limits.max_observed_request_body_bytes))
        .unwrap_or(state.plan.limits.max_observed_request_body_bytes);
    let max_observed_request_body_bytes =
        compiled_edge.body_observation_limit(max_observed_request_body_bytes);
    let request_version_for_observation = req.version();
    let PreparedDispatchRequest {
        req: prepared_req,
        observation_plan: _observation_plan,
        sanitized_headers,
        identity,
        request_rpc,
    } = match prepare_dispatch_request(DispatchRequestPrepareInput {
        req,
        rule_engine: engine,
        response_candidates: &response_candidates_for_request,
        prefilter_ctx,
        http_guard,
        capture_body: compiled_edge.flags.contains(PlanFlags::CAPTURE_BODY),
        max_observed_request_body_bytes,
        read_timeout: Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
        request_method: &base.method,
        request_version: request_version_for_observation,
        proxy_name,
        state: &state,
        effective_policy: &effective_policy,
        remote_ip: remote_addr.ip(),
    })
    .await?
    {
        Ok(prepared) => prepared,
        Err(response) => return Ok(ForwardPrepareOutcome::Response(Box::new(response))),
    };
    req = prepared_req;
    let path = base.path.as_deref();
    let destination = forward_destination_metadata(
        &state,
        &base,
        &host,
        compiled_edge.default_plan.destination_resolution.as_ref(),
    );
    if let Some(response) = evaluate_http_guard(DispatchGuardInput {
        profile: http_guard,
        req: &req,
        destination: &destination,
        proxy_name,
        audit: DispatchAuditContext::new(
            state.clone(),
            crate::http::dispatch::ProxyKind::Forward,
            listener_name,
            remote_addr,
            req.method().clone(),
            path.map(str::to_string),
            identity.to_log_context(None, None, None),
        )
        .with_host(Some(host.host.clone())),
    })? {
        return Ok(ForwardPrepareOutcome::Response(Box::new(response)));
    }
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
        #[cfg(feature = "auth-basic")]
        state: &state,
        identity: &identity,
        destination: &destination,
        #[cfg(feature = "auth-basic")]
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
        ForwardPolicyOutcome::Rejected(err) => {
            return Err(err);
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
        return Err(DispatchError::RateLimited {
            response: Box::new(rate_limit_response(DispatchRateLimitInput {
                req: &req,
                proxy_name,
                retry_after: Some(retry_after),
                audit: build_forward_rate_limit_audit_context(
                    state.clone(),
                    policy_response,
                    req.method(),
                    matched_rule.as_deref(),
                ),
            })),
        });
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

async fn evaluate_forward_policy_outcome(
    input: ForwardPolicyOutcomeInput<'_>,
) -> std::result::Result<ForwardPolicyOutcome, DispatchError> {
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
            response = finalize_forward_policy_response(
                response_input,
                response,
                crate::http::dispatch::DispatchOutcome::Challenge,
            );
            Ok(ForwardPolicyOutcome::Rejected(
                DispatchError::AuthRequired {
                    method: "proxy".to_string(),
                    response: Box::new(response),
                },
            ))
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Forbidden => {
            let response = finalize_forward_policy_response(
                response_input,
                forbidden(response_input.state.messages.forbidden.as_str()),
                crate::http::dispatch::DispatchOutcome::Forbidden,
            );
            Ok(ForwardPolicyOutcome::Rejected(
                DispatchError::PolicyDenied {
                    reason: "authentication denied".to_string(),
                    response: Box::new(response),
                },
            ))
        }
    }
}

#[cfg(feature = "auth-basic")]
fn finalize_forward_policy_response(
    input: ForwardPolicyResponseInput<'_>,
    response: Response<Body>,
    outcome: crate::http::dispatch::DispatchOutcome,
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
            kind: crate::http::dispatch::ProxyKind::Forward,
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

fn build_forward_rate_limit_audit_context(
    state: Arc<crate::runtime::RuntimeState>,
    policy: ForwardPolicyResponseInput<'_>,
    request_method: &Method,
    matched_rule: Option<&str>,
) -> DispatchAuditContext {
    let mut log_context = policy.identity.to_log_context(matched_rule, None, None);
    attach_destination_trace(&mut log_context, policy.destination);
    DispatchAuditContext::new(
        state,
        crate::http::dispatch::ProxyKind::Forward,
        policy.listener_name,
        policy.remote_addr,
        request_method.clone(),
        policy.path.map(str::to_string),
        log_context,
    )
    .with_host(Some(policy.host.to_string()))
    .with_matched_rule(matched_rule.map(str::to_string))
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
) -> std::result::Result<ForwardAccessOutcome, DispatchError> {
    let ext_authz = enforce_ext_authz(
        &input.state,
        input.effective_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
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
                annotate_dispatch_response(
                    &mut response,
                    &audit,
                    crate::http::dispatch::DispatchOutcome::RateLimited,
                    &[],
                );
                return Err(DispatchError::RateLimited {
                    response: Box::new(response),
                });
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
            let response = ext_authz_deny_response(ExtAuthzDenyResponseInput {
                ext_authz: ExtAuthzEnforcement::Deny(deny),
                base_headers: headers,
                request_method: &input.request_method,
                request_version: input.request_version,
                proxy_name: input.proxy_name,
                default_response: forbidden(input.state.messages.forbidden.as_str()),
                audit: &audit,
            })?;
            Err(DispatchError::ExtAuthzDenied {
                response: Box::new(response),
            })
        }
    }
}

fn build_forward_audit_context(
    input: &ForwardAccessInput<'_>,
    ext_authz: &ExtAuthzEnforcement,
) -> DispatchAuditContext {
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
    DispatchAuditContext::new(
        input.state.clone(),
        crate::http::dispatch::ProxyKind::Forward,
        input.listener_name,
        input.remote_addr,
        input.request_method.clone(),
        input.base.path.clone(),
        log_context,
    )
    .with_host(Some(input.host.host.clone()))
    .with_matched_rule(input.matched_rule.clone())
    .with_ext_authz_policy_id(ext_authz_policy_id)
}

fn handle_forward_local_action(
    req: &Request<Body>,
    state: &crate::runtime::RuntimeState,
    proxy_name: &str,
    action: &qpx_core::config::ActionConfig,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    audit: &DispatchAuditContext,
) -> Result<Option<Response<Body>>> {
    if matches!(action.kind, ActionKind::Block) {
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            blocked(state.messages.blocked.as_str()),
            false,
        );
        annotate_dispatch_response(
            &mut response,
            audit,
            crate::http::dispatch::DispatchOutcome::Block,
            &[],
        );
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
        annotate_dispatch_response(
            &mut response,
            audit,
            crate::http::dispatch::DispatchOutcome::Respond,
            &[],
        );
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
    audit: &DispatchAuditContext,
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
    annotate_dispatch_response(
        &mut response,
        audit,
        crate::http::dispatch::DispatchOutcome::Allow,
        &[],
    );
    Ok(response)
}

async fn handle_forward_max_forwards(
    req: &mut Request<Body>,
    state: &crate::runtime::RuntimeState,
    proxy_name: &str,
    audit: &DispatchAuditContext,
) -> Option<Response<Body>> {
    let mut response = handle_max_forwards_in_place(
        req,
        proxy_name,
        state.plan.limits.trace_reflect_all_headers,
        state.plan.limits.max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
    )
    .await?;
    annotate_dispatch_response(
        &mut response,
        audit,
        crate::http::dispatch::DispatchOutcome::MaxForwards,
        &[],
    );
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
    let mut response = proxy_dispatch_websocket_http1(DispatchWebsocketProxyInput {
        req,
        upstream_proxy: upstream,
        direct_connect_authority: connect_authority,
        direct_host_header: host_header,
        timeout_dur: upstream_timeout,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        tunnel_label: "forward",
        upstream_context: "forward websocket upstream proxy",
        direct_context: "forward websocket direct",
        export_session,
    })
    .await?;
    emit_dispatch_websocket_response_preview(export_session, &response);
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
    annotate_dispatch_response(
        &mut response,
        audit,
        crate::http::dispatch::DispatchOutcome::Allow,
        &[],
    );
    Ok(response)
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
    audit: &'a DispatchAuditContext,
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
        DispatchCacheLookupOutcome::Response(response) => return Ok(response),
        DispatchCacheLookupOutcome::Continue(state) => revalidation_state = state,
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
        DispatchCacheCollapseOutcome::Response(response) => return Ok(response),
        DispatchCacheCollapseOutcome::Continue {
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
    request_limits: crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: RateLimitContext,
    timeout_override: Option<Duration>,
    host: &'a HostPort,
    request_method: &'a Method,
    audit: &'a DispatchAuditContext,
}

async fn prepare_forward_dispatch(
    input: ForwardDispatchPrepareInput<'_>,
) -> std::result::Result<ForwardDispatchPrepareOutcome, DispatchError> {
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
        request_limits,
        mut request_limit_ctx,
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
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name,
            scope_name: listener_name,
            route_name: None,
            remote_ip: remote_addr.ip(),
            sni: None,
            identity_user: identity.user.as_deref(),
            cache_policy: cache_policy.cloned(),
            cache_default_scheme: Some(req.uri().scheme_str().unwrap_or("http")),
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
        annotate_dispatch_response(
            &mut response,
            audit,
            crate::http::dispatch::DispatchOutcome::HttpModuleLocalResponse,
            &[],
        );
        return Ok(ForwardDispatchPrepareOutcome::Response(Box::new(response)));
    }
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) =
        prepare_forward_cache_keys(&req, action, cache_policy)?;
    let upstream = resolve_upstream(action, &state, listener_name)
        .map_err(|err| DispatchError::UpstreamUnavailable(err.to_string()))?;
    request_limit_ctx.upstream = upstream.as_ref().map(|upstream| upstream.key().to_string());
    let Some(_concurrency_permits) = request_limits.acquire_concurrency(&request_limit_ctx) else {
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            too_many_requests(None),
            false,
        );
        annotate_dispatch_response(
            &mut response,
            audit,
            crate::http::dispatch::DispatchOutcome::ConcurrencyLimited,
            &[],
        );
        return Err(DispatchError::RateLimited {
            response: Box::new(response),
        });
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

async fn complete_forward_request(
    prepared: ForwardPreparedRequest,
) -> std::result::Result<Response<Body>, DispatchError> {
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
        request_limits,
        request_limit_ctx,
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
    .map_err(DispatchError::from)
}
