use super::*;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchGuardInput, DispatchRateLimitInput, DispatchRequestPrepareInput,
    DispatchResponsePolicyInput, DispatchResponsePolicyOutcome, DispatchWebsocketProxyInput,
    ExtAuthzDenyResponseInput, PreparedDispatchRequest, annotate_dispatch_response,
    apply_dispatch_response_policy, emit_dispatch_websocket_response_preview, evaluate_http_guard,
    ext_authz_deny_response, prepare_dispatch_request, proxy_dispatch_websocket_http1,
    rate_limit_response, record_upstream_request_duration,
};
use crate::http::policy::EvaluatedAction;
use crate::http::rule_context::{
    RequestRuleContextInput, ResponseRuleContextInput, attach_destination_trace,
    build_request_rule_match_context, build_response_rule_match_context,
};

enum TransparentPrepareOutcome {
    Response(Box<hyper::Response<Body>>),
    Prepared(Box<TransparentPreparedRequest>),
}

struct TransparentPreparedRequest {
    req: Request<Body>,
    state: Arc<crate::runtime::RuntimeState>,
    proxy_name: String,
    listener_name: String,
    listener_cfg: crate::runtime::CompiledListenerSettings,
    remote_addr: SocketAddr,
    connect_target: ConnectTarget,
    host_for_match: Option<String>,
    base: crate::http::base_fields::BaseRequestFields,
    effective_policy: crate::policy_context::EffectivePolicyContext,
    destination: crate::destination::DestinationMetadata,
    identity: crate::policy_context::ResolvedIdentity,
    sanitized_headers: http::HeaderMap,
    response_engine: Option<Arc<crate::http::response_policy::HttpResponseRuleEngine>>,
    selected_plan: crate::runtime::ExecutionPlan,
    policy: Option<Box<EvaluatedAction>>,
    early_response: Option<Box<hyper::Response<Body>>>,
    matched_rule: Option<String>,
    request_limits: crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: RateLimitContext,
    request_rpc: Option<crate::http::rpc::RpcMatchContext>,
}

struct TransparentPolicyEvaluation {
    policy: Option<Box<EvaluatedAction>>,
    early_response: Option<Box<hyper::Response<Body>>>,
    matched_rule: Option<String>,
    request_rpc: Option<crate::http::rpc::RpcMatchContext>,
}

enum TransparentAccessOutcome {
    Response(Box<hyper::Response<Body>>),
    Continue(Box<TransparentAccess>),
}

struct TransparentAccess {
    policy: Box<EvaluatedAction>,
    timeout_override: Option<Duration>,
    audit: DispatchAuditContext,
}

struct TransparentPolicyInput<'a> {
    engine: &'a qpx_core::rules::RuleEngine,
    req: &'a Request<Body>,
    base: &'a crate::http::base_fields::BaseRequestFields,
    sanitized_headers: &'a http::HeaderMap,
    destination: &'a crate::destination::DestinationMetadata,
    identity: &'a crate::policy_context::ResolvedIdentity,
    needs_rpc: bool,
    proxy_name: &'a str,
    forbidden_message: &'a str,
}

struct TransparentWebsocketInput<'a> {
    req: Request<Body>,
    upstream: Option<&'a crate::upstream::pool::ResolvedUpstreamProxy>,
    authority: &'a str,
    upstream_timeout: Duration,
    upgrade_wait_timeout: Duration,
    tunnel_idle_timeout: Duration,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    export_session: Option<&'a crate::exporter::ExportSession>,
    request_method: &'a hyper::Method,
    proxy_name: &'a str,
    policy_headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    audit: &'a DispatchAuditContext,
}

#[tracing::instrument(
    skip_all,
    fields(kind = "transparent", host = tracing::field::Empty, method = %req.method())
)]
pub(super) async fn dispatch_transparent_request(
    req: Request<Body>,
    runtime: Runtime,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
) -> Result<hyper::Response<Body>> {
    execute_transparent_request(req, runtime, remote_addr, original_target, listener_name).await
}

async fn execute_transparent_request(
    req: Request<Body>,
    runtime: Runtime,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
) -> Result<hyper::Response<Body>> {
    match prepare_transparent_request(req, runtime, remote_addr, original_target, listener_name)
        .await?
    {
        TransparentPrepareOutcome::Response(response) => Ok(*response),
        TransparentPrepareOutcome::Prepared(prepared) => {
            complete_transparent_request(*prepared).await
        }
    }
}

async fn prepare_transparent_request(
    mut req: Request<Body>,
    runtime: Runtime,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
) -> Result<TransparentPrepareOutcome> {
    let state = runtime.state();
    let proxy_name_owned = state.plan.identity.proxy_name.to_string();
    let proxy_name = proxy_name_owned.as_str();
    if let PreflightOutcome::Reject(response) = preflight_validate(
        &req,
        proxy_name,
        PreflightOptions::reject_connect(
            state.plan.limits.trace_enabled,
            state.messages.trace_disabled.as_str(),
            StatusCode::METHOD_NOT_ALLOWED,
            "transparent HTTP forward_edges do not support CONNECT",
        ),
    ) {
        return Ok(TransparentPrepareOutcome::Response(response));
    }
    let engine = state
        .policy
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let listener_cfg = state
        .ingress_edge_settings(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?
        .clone();
    let compiled_edge = state
        .plan
        .transparent_edge(listener_name)
        .ok_or_else(|| anyhow!("compiled transparent edge not found"))?;
    let effective_policy = compiled_edge.default_plan.policy_context.clone();
    let http_guard = compiled_edge.default_plan.guard.as_deref();

    let (connect_target, host_for_match) = resolve_http_target(&req, original_target.as_ref())?;
    let base = extract_base_request_fields(
        &req,
        BaseRequestContext {
            peer_ip: Some(remote_addr.ip()),
            dst_port: Some(connect_target.port()),
            host: host_for_match.as_deref(),
            scheme: Some("http"),
            ..Default::default()
        },
    );
    let prefilter_ctx =
        transparent_prefilter_context(&base, &connect_target, remote_addr, &host_for_match);
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
        capture_body: compiled_edge
            .flags
            .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
        max_observed_request_body_bytes,
        read_timeout: std::time::Duration::from_millis(
            state.plan.limits.http_header_read_timeout_ms.max(1),
        ),
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
        Err(response) => return Ok(TransparentPrepareOutcome::Response(Box::new(response))),
    };
    req = prepared_req;
    let path = base.path.as_deref();
    let destination = state.classify_destination(
        &DestinationInputs {
            host: host_for_match.as_deref(),
            ip: host_for_match
                .as_deref()
                .and_then(|value| value.parse().ok()),
            scheme: base.scheme.as_deref(),
            port: Some(connect_target.port()),
            ..Default::default()
        },
        compiled_edge.default_plan.destination_resolution.as_ref(),
    );
    if let Some(response) = evaluate_http_guard(DispatchGuardInput {
        profile: http_guard,
        req: &req,
        destination: &destination,
        proxy_name,
        audit: DispatchAuditContext::new(
            state.clone(),
            crate::http::dispatch::ProxyKind::Transparent,
            listener_name,
            remote_addr,
            req.method().clone(),
            path.map(str::to_string),
            identity.to_log_context(None, None, None),
        )
        .with_host(host_for_match.clone()),
    })? {
        return Ok(TransparentPrepareOutcome::Response(Box::new(response)));
    }
    let policy_evaluation = evaluate_transparent_policy(TransparentPolicyInput {
        engine,
        req: &req,
        base: &base,
        sanitized_headers: &sanitized_headers,
        destination: &destination,
        identity: &identity,
        needs_rpc: request_rpc.is_some(),
        proxy_name,
        forbidden_message: state.messages.forbidden.as_str(),
    })?;
    let TransparentPolicyEvaluation {
        policy,
        early_response,
        matched_rule,
        request_rpc,
    } = policy_evaluation;
    let selected_plan = compiled_edge
        .execution_plan_for_rule(matched_rule.as_deref())
        .clone();
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
        return Ok(TransparentPrepareOutcome::Response(Box::new(
            rate_limit_response(DispatchRateLimitInput {
                req: &req,
                proxy_name,
                retry_after: Some(retry_after),
                audit: build_transparent_prepare_audit_context(TransparentPrepareAuditInput {
                    state: &state,
                    identity: &identity,
                    destination: &destination,
                    listener_name,
                    remote_addr,
                    host: host_for_match.clone(),
                    request_method: req.method(),
                    path,
                    matched_rule: matched_rule.as_deref(),
                }),
            }),
        )));
    }
    Ok(TransparentPrepareOutcome::Prepared(Box::new(
        TransparentPreparedRequest {
            req,
            state,
            proxy_name: proxy_name_owned,
            listener_name: listener_name.to_string(),
            listener_cfg,
            remote_addr,
            connect_target,
            host_for_match,
            base,
            effective_policy,
            destination,
            identity,
            sanitized_headers,
            response_engine,
            selected_plan,
            policy,
            early_response,
            matched_rule,
            request_limits,
            request_limit_ctx,
            request_rpc,
        },
    )))
}

fn transparent_prefilter_context<'a>(
    base: &'a crate::http::base_fields::BaseRequestFields,
    connect_target: &ConnectTarget,
    remote_addr: SocketAddr,
    host_for_match: &'a Option<String>,
) -> MatchPrefilterContext<'a> {
    MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: Some(connect_target.port()),
        src_ip: Some(remote_addr.ip()),
        host: host_for_match.as_deref(),
        sni: None,
        path: base.path.as_deref(),
    }
}

fn evaluate_transparent_policy(
    input: TransparentPolicyInput<'_>,
) -> Result<TransparentPolicyEvaluation> {
    let TransparentPolicyInput {
        engine,
        req,
        base,
        sanitized_headers,
        destination,
        identity,
        needs_rpc,
        proxy_name,
        forbidden_message,
    } = input;
    let request_rpc = needs_rpc.then(|| crate::http::rpc::inspect_request(req));
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base,
        headers: sanitized_headers,
        destination,
        identity,
        request_size: observed_request_size(req),
        rpc: request_rpc.as_ref(),
        client_cert: None,
        upstream_cert: None,
    });
    let decision = evaluate_listener_policy(
        engine,
        &ctx,
        req.method(),
        req.version(),
        proxy_name,
        forbidden,
        forbidden_message,
    )?;
    let (policy, early_response, matched_rule) = match decision {
        ListenerPolicyDecision::Proceed(mut policy) => {
            let matched_rule = policy.matched_rule.take();
            (Some(policy), None, matched_rule)
        }
        ListenerPolicyDecision::Early(response, matched_rule) => {
            (None, Some(response), matched_rule)
        }
    };
    Ok(TransparentPolicyEvaluation {
        policy,
        early_response,
        matched_rule,
        request_rpc,
    })
}

struct TransparentPrepareAuditInput<'a> {
    state: &'a Arc<crate::runtime::RuntimeState>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    destination: &'a crate::destination::DestinationMetadata,
    listener_name: &'a str,
    remote_addr: SocketAddr,
    host: Option<String>,
    request_method: &'a hyper::Method,
    path: Option<&'a str>,
    matched_rule: Option<&'a str>,
}

fn build_transparent_prepare_audit_context(
    input: TransparentPrepareAuditInput<'_>,
) -> DispatchAuditContext {
    let mut log_context = input
        .identity
        .to_log_context(input.matched_rule, None, None);
    attach_destination_trace(&mut log_context, input.destination);
    DispatchAuditContext::new(
        input.state.clone(),
        crate::http::dispatch::ProxyKind::Transparent,
        input.listener_name,
        input.remote_addr,
        input.request_method.clone(),
        input.path.map(str::to_string),
        log_context,
    )
    .with_host(input.host)
    .with_matched_rule(input.matched_rule.map(str::to_string))
}

struct TransparentAccessInput<'a> {
    state: Arc<crate::runtime::RuntimeState>,
    proxy_name: &'a str,
    listener_name: &'a str,
    remote_addr: SocketAddr,
    connect_target: &'a ConnectTarget,
    host_for_match: &'a Option<String>,
    base: &'a crate::http::base_fields::BaseRequestFields,
    effective_policy: &'a crate::policy_context::EffectivePolicyContext,
    destination: &'a crate::destination::DestinationMetadata,
    identity: &'a crate::policy_context::ResolvedIdentity,
    sanitized_headers: &'a http::HeaderMap,
    request_method: hyper::Method,
    request_version: hyper::Version,
    request_uri: String,
    policy: Option<Box<EvaluatedAction>>,
    early_response: Option<Box<hyper::Response<Body>>>,
    matched_rule: Option<String>,
    request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    request_limit_ctx: &'a RateLimitContext,
}

async fn enforce_transparent_access_control(
    input: TransparentAccessInput<'_>,
) -> Result<TransparentAccessOutcome> {
    let ext_authz = if let Some(policy) = input.policy.as_ref() {
        Some(
            enforce_ext_authz(
                &input.state,
                input.effective_policy,
                ExtAuthzInput {
                    proxy_kind: crate::http::dispatch::ProxyKind::Transparent,
                    proxy_name: input.proxy_name,
                    scope_name: input.listener_name,
                    remote_ip: input.remote_addr.ip(),
                    dst_port: Some(input.connect_target.port()),
                    host: input.host_for_match.as_deref(),
                    sni: None,
                    method: Some(input.request_method.as_str()),
                    path: input.base.path.as_deref(),
                    uri: Some(input.request_uri.as_str()),
                    matched_rule: input.matched_rule.as_deref(),
                    matched_route: None,
                    action: Some(&policy.action),
                    headers: Some(input.sanitized_headers),
                    identity: input.identity,
                },
            )
            .await?,
        )
    } else {
        None
    };
    let audit = build_transparent_audit_context(&input, ext_authz.as_ref());
    if let Some(mut response) = input.early_response {
        annotate_dispatch_response(
            &mut response,
            &audit,
            crate::http::dispatch::DispatchOutcome::EarlyResponse,
            &[],
        );
        return Ok(TransparentAccessOutcome::Response(response));
    }
    let Some(mut policy) = input.policy else {
        return Err(anyhow!(
            "transparent policy missing after early response handling"
        ));
    };
    if let Some(ext_authz) = ext_authz {
        match ext_authz {
            ExtAuthzEnforcement::Continue(allow) => {
                validate_ext_authz_allow_mode(&allow, ExtAuthzMode::TransparentHttp)?;
                policy.headers = merge_header_controls(policy.headers, allow.headers.clone());
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
                    return Ok(TransparentAccessOutcome::Response(Box::new(response)));
                }
                apply_ext_authz_action_overrides(&mut policy.action, &allow);
                return Ok(TransparentAccessOutcome::Continue(Box::new(
                    TransparentAccess {
                        policy,
                        timeout_override: allow.timeout_override,
                        audit,
                    },
                )));
            }
            ExtAuthzEnforcement::Deny(deny) => {
                let response = ext_authz_deny_response(ExtAuthzDenyResponseInput {
                    ext_authz: ExtAuthzEnforcement::Deny(deny),
                    base_headers: policy.headers.clone(),
                    request_method: &input.request_method,
                    request_version: input.request_version,
                    proxy_name: input.proxy_name,
                    default_response: forbidden(input.state.messages.forbidden.as_str()),
                    audit: &audit,
                })?;
                return Ok(TransparentAccessOutcome::Response(Box::new(response)));
            }
        }
    }
    Ok(TransparentAccessOutcome::Continue(Box::new(
        TransparentAccess {
            policy,
            timeout_override: None,
            audit,
        },
    )))
}

fn build_transparent_audit_context(
    input: &TransparentAccessInput<'_>,
    ext_authz: Option<&ExtAuthzEnforcement>,
) -> DispatchAuditContext {
    let ext_authz_policy_id = ext_authz.and_then(|decision| match decision {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    });
    let ext_authz_policy_tags = ext_authz
        .map(|decision| match decision {
            ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
            ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
        })
        .unwrap_or_default();
    let mut log_context = input.identity.to_log_context(
        input.matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    attach_destination_trace(&mut log_context, input.destination);
    log_context.policy_tags = ext_authz_policy_tags;
    DispatchAuditContext::new(
        input.state.clone(),
        crate::http::dispatch::ProxyKind::Transparent,
        input.listener_name,
        input.remote_addr,
        input.request_method.clone(),
        input.base.path.clone(),
        log_context,
    )
    .with_host(input.host_for_match.clone())
    .with_matched_rule(input.matched_rule.clone())
    .with_ext_authz_policy_id(ext_authz_policy_id)
}

async fn complete_transparent_request(
    prepared: TransparentPreparedRequest,
) -> Result<hyper::Response<Body>> {
    let TransparentPreparedRequest {
        mut req,
        state,
        proxy_name,
        listener_name,
        listener_cfg,
        remote_addr,
        connect_target,
        host_for_match,
        base,
        effective_policy,
        destination,
        identity,
        sanitized_headers,
        response_engine,
        selected_plan,
        policy,
        early_response,
        matched_rule,
        mut request_limits,
        request_limit_ctx,
        request_rpc,
    } = prepared;
    let proxy_name = proxy_name.as_str();
    let listener_name = listener_name.as_str();
    let request_method = req.method().clone();
    let request_version = req.version();
    let access = match enforce_transparent_access_control(TransparentAccessInput {
        state: state.clone(),
        proxy_name,
        listener_name,
        remote_addr,
        connect_target: &connect_target,
        host_for_match: &host_for_match,
        base: &base,
        effective_policy: &effective_policy,
        destination: &destination,
        identity: &identity,
        sanitized_headers: &sanitized_headers,
        request_method: request_method.clone(),
        request_version,
        request_uri: base.request_uri.clone(),
        policy,
        early_response,
        matched_rule: matched_rule.clone(),
        request_limits: &mut request_limits,
        request_limit_ctx: &request_limit_ctx,
    })
    .await?
    {
        TransparentAccessOutcome::Response(response) => return Ok(*response),
        TransparentAccessOutcome::Continue(access) => *access,
    };
    let mut policy = access.policy;
    let timeout_override = access.timeout_override;
    let audit = access.audit;

    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name,
        state.plan.limits.trace_reflect_all_headers,
        state.plan.limits.max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
    )
    .await
    {
        let mut response = response;
        annotate_dispatch_response(
            &mut response,
            &audit,
            crate::http::dispatch::DispatchOutcome::MaxForwards,
            &[],
        );
        return Ok(response);
    }
    strip_untrusted_identity_headers(
        &state,
        &effective_policy,
        remote_addr.ip(),
        req.headers_mut(),
    )?;
    let websocket = is_websocket_upgrade(req.headers());
    prepare_request_with_headers_in_place(
        &mut req,
        proxy_name,
        policy.headers.as_deref(),
        websocket,
    );
    let mut http_modules = selected_plan.modules.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: crate::http::dispatch::ProxyKind::Transparent,
            proxy_name,
            scope_name: listener_name,
            route_name: None,
            remote_ip: remote_addr.ip(),
            sni: None,
            identity_user: identity.user.as_deref(),
            cache_policy: None,
            cache_default_scheme: None,
        },
    );
    match http_modules.on_request_headers(&mut req).await? {
        crate::http::modules::RequestHeadersOutcome::Continue => {}
        crate::http::modules::RequestHeadersOutcome::Respond(response) => {
            let mut response = http_modules.prepare_downstream_response(*response).await?;
            let response_version = response.version();
            finalize_response_with_headers_in_place(
                &request_method,
                response_version,
                proxy_name,
                &mut response,
                policy.headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_dispatch_response(
                &mut response,
                &audit,
                crate::http::dispatch::DispatchOutcome::HttpModuleLocalResponse,
                &[],
            );
            return Ok(response);
        }
    }

    let upstream = resolve_upstream(&policy.action, &state, &listener_cfg)?;
    let rate_limit_ctx = RateLimitContext::from_identity(
        remote_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        upstream.as_ref().map(|upstream| upstream.key()),
    );
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
        Some(permits) => permits,
        None => {
            let mut response = finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                too_many_requests(None),
                false,
            );
            annotate_dispatch_response(
                &mut response,
                &audit,
                crate::http::dispatch::DispatchOutcome::ConcurrencyLimited,
                &[],
            );
            return Ok(response);
        }
    };
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.plan.limits.upstream_http_timeout_ms));
    let upgrade_wait_timeout = Duration::from_millis(state.plan.limits.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout = Duration::from_millis(state.plan.limits.tunnel_idle_timeout_ms);
    let authority = connect_target.authority();
    let export_session =
        state.export_session_for_plan(&selected_plan, remote_addr, authority.as_str());
    if websocket {
        return proxy_transparent_websocket(TransparentWebsocketInput {
            req,
            upstream: upstream.as_ref(),
            authority: authority.as_str(),
            upstream_timeout,
            upgrade_wait_timeout,
            tunnel_idle_timeout,
            http_modules: &mut http_modules,
            export_session: export_session.as_ref(),
            request_method: &request_method,
            proxy_name,
            policy_headers: policy.headers.as_deref(),
            audit: &audit,
        })
        .await;
    }

    proxy_transparent_http1(
        req,
        upstream.as_ref(),
        authority.as_str(),
        upstream_timeout,
        &mut http_modules,
        export_session.as_ref(),
        TransparentResponsePolicyInput {
            state: &state,
            response_engine: response_engine.as_deref(),
            selected_plan: &selected_plan,
            base: &base,
            destination: &destination,
            identity: &identity,
            connect_target: &connect_target,
            host_for_match: &host_for_match,
            request_method: &request_method,
            request_version,
            proxy_name,
            request_rpc: request_rpc.as_ref(),
            headers: &mut policy.headers,
            audit: &audit,
        },
    )
    .await
}

async fn proxy_transparent_websocket(
    input: TransparentWebsocketInput<'_>,
) -> Result<hyper::Response<Body>> {
    let TransparentWebsocketInput {
        req,
        upstream,
        authority,
        upstream_timeout,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        http_modules,
        export_session,
        request_method,
        proxy_name,
        policy_headers,
        audit,
    } = input;
    let mut response = proxy_dispatch_websocket_http1(DispatchWebsocketProxyInput {
        req,
        upstream_proxy: upstream,
        direct_connect_authority: authority,
        direct_host_header: authority,
        timeout_dur: upstream_timeout,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        tunnel_label: "transparent",
        upstream_context: "transparent websocket upstream proxy",
        direct_context: "transparent websocket direct",
        export_session,
    })
    .await?;
    response = http_modules.on_upstream_response(response).await?;
    response = http_modules.prepare_downstream_response(response).await?;
    emit_dispatch_websocket_response_preview(export_session, &response);
    let keep_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        request_method,
        response_version,
        proxy_name,
        &mut response,
        policy_headers,
        keep_upgrade,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(
        &mut response,
        audit,
        crate::http::dispatch::DispatchOutcome::Allow,
        &[],
    );
    Ok(response)
}

struct TransparentResponsePolicyInput<'a> {
    state: &'a Arc<crate::runtime::RuntimeState>,
    response_engine: Option<&'a crate::http::response_policy::HttpResponseRuleEngine>,
    selected_plan: &'a crate::runtime::ExecutionPlan,
    base: &'a crate::http::base_fields::BaseRequestFields,
    destination: &'a crate::destination::DestinationMetadata,
    identity: &'a crate::policy_context::ResolvedIdentity,
    connect_target: &'a ConnectTarget,
    host_for_match: &'a Option<String>,
    request_method: &'a hyper::Method,
    request_version: hyper::Version,
    proxy_name: &'a str,
    request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    headers: &'a mut Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    audit: &'a DispatchAuditContext,
}

async fn proxy_transparent_http1(
    mut req: Request<Body>,
    upstream: Option<&crate::upstream::pool::ResolvedUpstreamProxy>,
    authority: &str,
    upstream_timeout: Duration,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    export_session: Option<&crate::exporter::ExportSession>,
    input: TransparentResponsePolicyInput<'_>,
) -> Result<hyper::Response<Body>> {
    let upstream_started = std::time::Instant::now();
    http_modules.on_upstream_request(&mut req).await?;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let proxied_result =
        proxy_http1_request_with_interim(req, upstream, authority, upstream_timeout).await;
    record_upstream_request_duration(input.audit.kind, upstream_started.elapsed());
    let proxied = match proxied_result {
        Ok(proxied) => proxied,
        Err(err) => {
            http_modules.on_error(&err).await;
            return Err(err);
        }
    };
    let mut response = proxied.response;
    if !proxied.interim.is_empty() {
        response.extensions_mut().insert(proxied.interim);
    }
    response = http_modules.on_upstream_response(response).await?;
    let response_candidates = input
        .response_engine
        .map(|engine| {
            engine.candidate_profile(MatchPrefilterContext {
                method: Some(input.request_method.as_str()),
                dst_port: Some(input.connect_target.port()),
                src_ip: Some(input.audit.remote_addr.ip()),
                host: input.host_for_match.as_deref(),
                sni: None,
                path: input.base.path.as_deref(),
            })
        })
        .unwrap_or_default();
    let response_status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let response_policy_tags = match apply_dispatch_response_policy(DispatchResponsePolicyInput {
        response,
        engine: input.response_engine,
        candidates: response_candidates,
        rule_context: build_response_rule_match_context(ResponseRuleContextInput {
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
        headers: input.headers.as_ref().cloned(),
        request_rpc: input.request_rpc,
        body_observation: ResponseBodyObservationLimits {
            max_body_bytes: input
                .selected_plan
                .body_observation_limit(input.state.plan.limits.max_observed_response_body_bytes),
            read_timeout: std::time::Duration::from_millis(
                input.state.plan.limits.upstream_http_timeout_ms.max(1),
            ),
            force_body: input
                .selected_plan
                .flags
                .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
        },
        http_modules,
        audit: input.audit,
        request_method: input.request_method,
        request_version: input.request_version,
        proxy_name: input.proxy_name,
        pre_finalize_local_response: true,
    })
    .await?
    {
        DispatchResponsePolicyOutcome::Continue {
            response: updated,
            headers: updated_headers,
            cache_bypass: _cache_bypass,
            suppress_retry: _suppress_retry,
            mirror: _mirror,
            policy_tags,
        } => {
            response = updated;
            *input.headers = updated_headers;
            policy_tags
        }
        DispatchResponsePolicyOutcome::Response(response) => return Ok(response),
    };
    response = http_modules.prepare_downstream_response(response).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        input.request_method,
        response_version,
        input.proxy_name,
        &mut response,
        input.headers.as_ref().map(|headers| headers.as_ref()),
        false,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_dispatch_response(
        &mut response,
        input.audit,
        crate::http::dispatch::DispatchOutcome::Allow,
        &response_policy_tags,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use crate::test_util::{decode_gzip, spawn_static_http_server};
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
        IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn transparent_http_modules_can_compress_responses() {
        let upstream_addr = spawn_static_http_server(
            "200 OK",
            vec![("Content-Type", "text/plain".to_string())],
            "transparent compression".to_string(),
            1,
        )
        .await;
        let runtime = Runtime::new(Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            telemetry: qpx_core::config::TelemetryConfig {
                system_log: SystemLogConfig::default(),
                access_log: AccessLogConfig::default(),
                audit_log: AuditLogConfig::default(),
                metrics: None,
                otel: None,
                exporter: None,
            },
            security: qpx_core::config::SecurityConfig {
                auth: AuthConfig::default(),
                identity_sources: Vec::new(),
                decisions: qpx_core::config::DecisionConfig {
                    ext_authz: Vec::new(),
                },
                destination: Default::default(),
                named_sets: Vec::new(),
                upstream_trust_profiles: Vec::new(),
            },
            http: qpx_core::config::HttpGlobalConfig::default(),
            traffic: qpx_core::config::TrafficConfig::default(),
            acme: None,
            edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
                name: "transparent".to_string(),
                mode: IngressEdgeMode::Transparent,
                listen: "127.0.0.1:0".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Direct,
                    upstream: None,
                    local_response: None,
                },
                original_dst: None,
                tls_inspection: None,
                rules: Vec::new(),
                connection_filter: Vec::new(),
                upstream_proxy: None,
                http3: None,
                ftp: Default::default(),
                xdp: None,
                cache: None,
                capture: None,
                rate_limit: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                http_modules: vec![
                    serde_yaml::from_str(
                        r#"type: response_compression
settings:
  min_body_bytes: 1
  max_body_bytes: 65536
  content_types:
    - text/plain
  gzip: true
  brotli: false
  zstd: false
  gzip_level: 6
  brotli_level: 5
  zstd_level: 3"#,
                    )
                    .expect("http module config"),
                ],
            })],
            upstreams: Vec::new(),
            caches: Vec::new(),
        })
        .expect("runtime");
        let request = Request::builder()
            .method(http::Method::GET)
            .uri(format!("http://{upstream_addr}/asset"))
            .header("host", upstream_addr.to_string())
            .header("accept-encoding", "gzip")
            .version(http::Version::HTTP_11)
            .body(Body::empty())
            .expect("request");

        let response = dispatch_transparent_request(
            request,
            runtime,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            None,
            "transparent",
        )
        .await
        .expect("response");

        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_ENCODING)
                .and_then(|value| value.to_str().ok()),
            Some("gzip")
        );
        let body = to_bytes(response.into_body()).await.expect("body");
        assert_eq!(decode_gzip(body.as_ref()), "transparent compression");
    }
}
