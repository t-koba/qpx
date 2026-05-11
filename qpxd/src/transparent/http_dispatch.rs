use super::*;
use crate::http::observation::RequestObservationPlan;
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
    audit: TransparentAuditContext,
}

struct TransparentAuditContext {
    state: Arc<crate::runtime::RuntimeState>,
    listener_name: String,
    remote_addr: SocketAddr,
    host_for_match: Option<String>,
    request_method: hyper::Method,
    path: Option<String>,
    matched_rule: Option<String>,
    ext_authz_policy_id: Option<String>,
    log_context: qpx_observability::access_log::RequestLogContext,
}

struct TransparentGuardInput<'a> {
    state: &'a crate::runtime::RuntimeState,
    http_guard: Option<&'a crate::http::guard::CompiledHttpGuardProfile>,
    req: &'a Request<Body>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    destination: &'a crate::destination::DestinationMetadata,
    proxy_name: &'a str,
    listener_name: &'a str,
    remote_addr: SocketAddr,
    host: Option<&'a str>,
    path: Option<&'a str>,
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

struct TransparentRateLimitResponseInput<'a> {
    state: &'a crate::runtime::RuntimeState,
    req: &'a Request<Body>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    destination: &'a crate::destination::DestinationMetadata,
    proxy_name: &'a str,
    listener_name: &'a str,
    remote_addr: SocketAddr,
    host: Option<&'a str>,
    path: Option<&'a str>,
    matched_rule: Option<&'a str>,
    retry_after: Duration,
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
    audit: &'a TransparentAuditContext,
}

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
    let mut observation_plan = RequestObservationPlan::from_policy_candidates(
        engine,
        &response_candidates_for_request,
        prefilter_ctx.clone(),
    );
    observation_plan.include_body(
        compiled_edge
            .flags
            .contains(crate::runtime::PlanFlags::CAPTURE_BODY),
    );
    let guard_requires_buffering =
        http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req));
    observation_plan.include_body(guard_requires_buffering);
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.plan.limits.max_observed_request_body_bytes))
        .unwrap_or(state.plan.limits.max_observed_request_body_bytes);
    let max_observed_request_body_bytes =
        compiled_edge.body_observation_limit(max_observed_request_body_bytes);
    req = match observe_transparent_request(
        req,
        observation_plan,
        max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.plan.limits.http_header_read_timeout_ms.max(1)),
        &base.method,
        proxy_name,
    )
    .await?
    {
        Ok(req) => req,
        Err(response) => return Ok(TransparentPrepareOutcome::Response(Box::new(response))),
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
    if let Some(response) = transparent_http_guard_response(TransparentGuardInput {
        state: &state,
        http_guard,
        req: &req,
        identity: &identity,
        destination: &destination,
        proxy_name,
        listener_name,
        remote_addr,
        host: host_for_match.as_deref(),
        path,
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
        needs_rpc: observation_plan.needs_rpc,
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
            transparent_rate_limit_response(TransparentRateLimitResponseInput {
                state: &state,
                req: &req,
                identity: &identity,
                destination: &destination,
                proxy_name,
                listener_name,
                remote_addr,
                host: host_for_match.as_deref(),
                path,
                matched_rule: matched_rule.as_deref(),
                retry_after,
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

fn transparent_http_guard_response(
    input: TransparentGuardInput<'_>,
) -> Result<Option<hyper::Response<Body>>> {
    let TransparentGuardInput {
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
        hyper::Response::builder()
            .status(reject.status)
            .body(Body::from(reject.body))?,
        false,
    );
    attach_log_context(&mut response, &log_context);
    emit_audit_log(
        state,
        AuditRecord {
            kind: "transparent",
            name: listener_name,
            remote_ip: remote_addr.ip(),
            host,
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

async fn observe_transparent_request(
    req: Request<Body>,
    observation_plan: RequestObservationPlan,
    max_observed_request_body_bytes: usize,
    read_timeout: Duration,
    method: &hyper::Method,
    proxy_name: &str,
) -> Result<std::result::Result<Request<Body>, hyper::Response<Body>>> {
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
                hyper::Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request body too large"))?,
                false,
            )))
        }
        Err(err) => Err(err),
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

fn transparent_rate_limit_response(
    input: TransparentRateLimitResponseInput<'_>,
) -> hyper::Response<Body> {
    let TransparentRateLimitResponseInput {
        state,
        req,
        identity,
        destination,
        proxy_name,
        listener_name,
        remote_addr,
        host,
        path,
        matched_rule,
        retry_after,
    } = input;
    let mut log_context = identity.to_log_context(matched_rule, None, None);
    attach_destination_trace(&mut log_context, destination);
    let mut response = finalize_response_for_request(
        req.method(),
        req.version(),
        proxy_name,
        too_many_requests(Some(retry_after)),
        false,
    );
    attach_log_context(&mut response, &log_context);
    emit_audit_log(
        state,
        AuditRecord {
            kind: "transparent",
            name: listener_name,
            remote_ip: remote_addr.ip(),
            host,
            sni: None,
            method: Some(req.method().as_str()),
            path,
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
                    proxy_kind: "transparent",
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
        annotate_transparent_response(&mut response, &audit, "early_response", &[]);
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
                    annotate_transparent_response(&mut response, &audit, "rate_limited", &[]);
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
                let merged_headers = merge_header_controls(policy.headers.clone(), deny.headers);
                let mut response = if let Some(local) = deny.local_response.as_ref() {
                    crate::http::l7::finalize_response_with_headers(
                        &input.request_method,
                        input.request_version,
                        input.proxy_name,
                        crate::http::local_response::build_local_response(local)?,
                        merged_headers.as_deref(),
                        false,
                    )
                } else {
                    crate::http::l7::finalize_response_with_headers(
                        &input.request_method,
                        input.request_version,
                        input.proxy_name,
                        forbidden(input.state.messages.forbidden.as_str()),
                        merged_headers.as_deref(),
                        false,
                    )
                };
                annotate_transparent_response(
                    &mut response,
                    &audit,
                    if deny.local_response.is_some() {
                        "ext_authz_local_response"
                    } else {
                        "ext_authz_deny"
                    },
                    &[],
                );
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
) -> TransparentAuditContext {
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
    TransparentAuditContext {
        state: input.state.clone(),
        listener_name: input.listener_name.to_string(),
        remote_addr: input.remote_addr,
        host_for_match: input.host_for_match.clone(),
        request_method: input.request_method.clone(),
        path: input.base.path.clone(),
        matched_rule: input.matched_rule.clone(),
        ext_authz_policy_id,
        log_context,
    }
}

fn annotate_transparent_response(
    response: &mut hyper::Response<Body>,
    audit: &TransparentAuditContext,
    outcome: &'static str,
    extra_policy_tags: &[String],
) {
    let mut annotated_context = audit.log_context.clone();
    merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
    attach_log_context(response, &annotated_context);
    emit_audit_log(
        &audit.state,
        AuditRecord {
            kind: "transparent",
            name: audit.listener_name.as_str(),
            remote_ip: audit.remote_addr.ip(),
            host: audit.host_for_match.as_deref(),
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
        annotate_transparent_response(&mut response, &audit, "max_forwards", &[]);
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
            proxy_kind: "transparent",
            proxy_name: proxy_name.to_string(),
            scope_name: listener_name.to_string(),
            route_name: None,
            remote_ip: remote_addr.ip(),
            sni: None,
            identity_user: identity.user.clone(),
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
            annotate_transparent_response(&mut response, &audit, "http_module_local_response", &[]);
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
            annotate_transparent_response(&mut response, &audit, "concurrency_limited", &[]);
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
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let mut response = proxy_websocket_http1(
        req,
        WebsocketProxyConfig {
            upstream_proxy: upstream,
            direct_connect_authority: authority,
            direct_host_header: authority,
            timeout_dur: upstream_timeout,
            upgrade_wait_timeout,
            tunnel_idle_timeout,
            tunnel_label: "transparent",
            upstream_context: "transparent websocket upstream proxy",
            direct_context: "transparent websocket direct",
        },
    )
    .await?;
    response = http_modules.on_upstream_response(response).await?;
    response = http_modules.prepare_downstream_response(response).await?;
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
        policy_headers,
        keep_upgrade,
    );
    http_modules.on_logging(Some(response.status()), None).await;
    annotate_transparent_response(&mut response, audit, "allow", &[]);
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
    audit: &'a TransparentAuditContext,
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
    http_modules.on_upstream_request(&mut req).await?;
    if let Some(session) = export_session {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let proxied =
        match proxy_http1_request_with_interim(req, upstream, authority, upstream_timeout).await {
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
    let response_policy_tags = match apply_listener_response_policy(
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
        response,
        input.headers.as_ref().cloned(),
        input.request_rpc,
        ResponseBodyObservationLimits {
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
    )
    .await?
    {
        ListenerResponsePolicyDecision::Continue {
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
        ListenerResponsePolicyDecision::LocalResponse {
            response: local,
            headers: updated_headers,
            policy_tags,
        } => {
            let response = http_modules.prepare_downstream_response(local).await?;
            let mut response = finalize_response_for_request(
                input.request_method,
                input.request_version,
                input.proxy_name,
                response,
                false,
            );
            finalize_response_with_headers_in_place(
                input.request_method,
                input.request_version,
                input.proxy_name,
                &mut response,
                updated_headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(response.status()), None).await;
            annotate_transparent_response(
                &mut response,
                input.audit,
                "response_local_response",
                &policy_tags,
            );
            return Ok(response);
        }
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
    annotate_transparent_response(&mut response, input.audit, "allow", &response_policy_tags);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use qpx_core::config::{
        AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, Config,
        IdentityConfig, IngressEdgeConfig, IngressEdgeMode, MessagesConfig, RuntimeConfig,
        SystemLogConfig,
    };
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn spawn_static_http_server(body: &str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let body = body.to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.expect("write");
        });
        addr
    }

    fn decode_gzip(bytes: &[u8]) -> String {
        let mut decoder = flate2::read::GzDecoder::new(bytes);
        let mut out = String::new();
        decoder.read_to_string(&mut out).expect("decode");
        out
    }

    #[tokio::test]
    async fn transparent_http_modules_can_compress_responses() {
        let upstream_addr = spawn_static_http_server("transparent compression").await;
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
