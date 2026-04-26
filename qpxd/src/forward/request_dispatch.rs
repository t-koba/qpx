use super::*;
use crate::http::observation::RequestObservationPlan;
use crate::http::rule_context::{
    attach_destination_trace, build_request_rule_match_context, build_response_rule_match_context,
    RequestRuleContextInput, ResponseRuleContextInput,
};

pub(super) async fn dispatch_forward_request(
    mut req: Request<Body>,
    base: BaseRequestFields,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    let listener_cfg = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let effective_policy =
        EffectivePolicyContext::from_single(listener_cfg.policy_context.as_ref());
    let http_guard = listener_cfg
        .http_guard_profile
        .as_deref()
        .and_then(|name| state.http_guard_profile(name));
    let mut cache_policy = listener_cfg.cache.as_ref().filter(|c| c.enabled).cloned();
    let is_ftp_request = base
        .scheme
        .as_deref()
        .map(|scheme| scheme.eq_ignore_ascii_case("ftp"))
        .unwrap_or(false);
    if is_ftp_request && !listener_cfg.ftp.enabled {
        return Ok(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(Body::from(state.messages.ftp_disabled.clone()))
                .unwrap(),
            false,
        ));
    }
    let host = match base.host.as_deref() {
        Some(host) => HostPort {
            host: host.to_string(),
            port: base.dst_port,
        },
        None => {
            return Ok(finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("missing Host/authority"))
                    .unwrap_or_else(|_| bad_request("missing Host/authority")),
                false,
            ));
        }
    };
    let engine = state
        .policy
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: host.port,
        src_ip: base.peer_ip,
        host: Some(host.host.as_str()),
        sni: base.sni.as_deref(),
        path: base.path.as_deref(),
    };
    let response_engine = state
        .policy
        .response_rules_by_listener
        .get(listener_name)
        .map(Arc::as_ref);
    let response_candidates_for_request = response_engine
        .map(|engine| engine.candidate_profile(prefilter_ctx.clone()))
        .unwrap_or_default();
    let mut observation_plan = RequestObservationPlan::from_policy_candidates(
        engine,
        &response_candidates_for_request,
        prefilter_ctx.clone(),
    );
    let guard_requires_buffering =
        http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req));
    observation_plan.include_body(guard_requires_buffering);
    let max_observed_request_body_bytes = http_guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.config.runtime.max_observed_request_body_bytes))
        .unwrap_or(state.config.runtime.max_observed_request_body_bytes);
    let request_version_for_observation = req.version();
    req = match observation_plan
        .observe_request(
            req,
            max_observed_request_body_bytes,
            std::time::Duration::from_millis(
                state.config.runtime.http_header_read_timeout_ms.max(1),
            ),
        )
        .await
    {
        Ok(req) => req,
        Err(err) if crate::http::body_size::is_observed_body_limit_exceeded(&err) => {
            return Ok(finalize_response_for_request(
                &base.method,
                request_version_for_observation,
                proxy_name,
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Body::from("request body too large"))?,
                false,
            ));
        }
        Err(err) => return Err(err),
    };
    let path = base.path.as_deref();
    let sanitized_headers =
        sanitize_headers_for_policy(&state, &effective_policy, remote_addr.ip(), req.headers())?;
    let mut identity = resolve_identity(
        &state,
        &effective_policy,
        remote_addr.ip(),
        Some(&sanitized_headers),
        None,
    )?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(host.host.as_str()),
            ip: host.host.parse().ok(),
            scheme: base.scheme.as_deref(),
            port: host.port,
            ..Default::default()
        },
        listener_cfg.destination_resolution.as_ref(),
    );
    if let Some(profile) = http_guard {
        if let Some(reject) = profile.evaluate_request(&req)? {
            let mut log_context = identity.to_log_context(None, None, None);
            attach_destination_trace(&mut log_context, &destination);
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
                &state,
                AuditRecord {
                    kind: "forward",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: Some(host.host.as_str()),
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
            return Ok(response);
        }
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
    let policy = evaluate_forward_policy(
        &runtime,
        listener_name,
        ctx,
        &sanitized_headers,
        req.method().as_str(),
        base.request_uri.as_str(),
    )
    .await?;
    let (mut action, mut headers, matched_rule) = match policy {
        ForwardPolicyDecision::Allow(allowed) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (allowed.action, allowed.headers, allowed.matched_rule)
        }
        ForwardPolicyDecision::Challenge(chal) => {
            let mut log_context = identity.to_log_context(None, None, None);
            attach_destination_trace(&mut log_context, &destination);
            let response = proxy_auth_required(chal, state.messages.proxy_auth_required.as_str());
            let mut response = finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                response,
                false,
            );
            attach_log_context(&mut response, &log_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "forward",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: Some(host.host.as_str()),
                    sni: None,
                    method: Some(req.method().as_str()),
                    path,
                    outcome: "challenge",
                    status: Some(response.status().as_u16()),
                    matched_rule: None,
                    matched_route: None,
                    ext_authz_policy_id: None,
                },
                &log_context,
            );
            return Ok(response);
        }
        ForwardPolicyDecision::Forbidden => {
            let mut log_context = identity.to_log_context(None, None, None);
            attach_destination_trace(&mut log_context, &destination);
            let mut response = finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            );
            attach_log_context(&mut response, &log_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "forward",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: Some(host.host.as_str()),
                    sni: None,
                    method: Some(req.method().as_str()),
                    path,
                    outcome: "forbidden",
                    status: Some(response.status().as_u16()),
                    matched_rule: None,
                    matched_route: None,
                    ext_authz_policy_id: None,
                },
                &log_context,
            );
            return Ok(response);
        }
    };
    let request_limit_ctx =
        RateLimitContext::from_identity(remote_addr.ip(), &identity, matched_rule.as_deref(), None);
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_request(
        crate::rate_limit::RequestLimitCollectInput {
            listener: Some(listener_name),
            rule: matched_rule.as_deref(),
            profile: None,
            scope: crate::rate_limit::TransportScope::Request,
            extra: None,
            ctx: &request_limit_ctx,
            cost: 1,
        },
    )?;
    if let Some(retry_after) = retry_after {
        let mut log_context = identity.to_log_context(matched_rule.as_deref(), None, None);
        attach_destination_trace(&mut log_context, &destination);
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            too_many_requests(Some(retry_after)),
            false,
        );
        attach_log_context(&mut response, &log_context);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: "forward",
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: Some(host.host.as_str()),
                sni: None,
                method: Some(req.method().as_str()),
                path,
                outcome: "rate_limited",
                status: Some(response.status().as_u16()),
                matched_rule: matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: None,
            },
            &log_context,
        );
        return Ok(response);
    }
    let request_method = req.method().clone();
    let client_version = req.version();
    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: "forward",
            proxy_name,
            scope_name: listener_name,
            remote_ip: remote_addr.ip(),
            dst_port: host.port,
            host: Some(host.host.as_str()),
            sni: None,
            method: Some(req.method().as_str()),
            path: base.path.as_deref(),
            uri: Some(base.request_uri.as_str()),
            matched_rule: matched_rule.as_deref(),
            matched_route: None,
            action: Some(&action),
            headers: Some(&sanitized_headers),
            identity: &identity,
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
    let mut log_context = identity.to_log_context(
        matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    attach_destination_trace(&mut log_context, &destination);
    log_context.policy_tags = ext_authz_policy_tags;
    let annotate_with_tags =
        |response: &mut Response<Body>, outcome: &'static str, extra_policy_tags: &[String]| {
            let mut annotated_context = log_context.clone();
            merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
            attach_log_context(response, &annotated_context);
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "forward",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: Some(host.host.as_str()),
                    sni: None,
                    method: Some(request_method.as_str()),
                    path: base.path.as_deref(),
                    outcome,
                    status: Some(response.status().as_u16()),
                    matched_rule: matched_rule.as_deref(),
                    matched_route: None,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &annotated_context,
            );
        };
    let annotate = |response: &mut Response<Body>, outcome: &'static str| {
        annotate_with_tags(response, outcome, &[]);
    };
    let timeout_override = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardHttp)?;
            headers = merge_header_controls(headers, allow.headers.clone());
            if allow.cache_bypass {
                cache_policy = None;
            }
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                &state.policy.rate_limiters,
                allow.rate_limit_profile.as_deref(),
                crate::rate_limit::TransportScope::Request,
                &request_limit_ctx,
                1,
            )? {
                let mut response = finalize_response_for_request(
                    req.method(),
                    req.version(),
                    proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                );
                annotate(&mut response, "rate_limited");
                return Ok(response);
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            allow.timeout_override
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let merged_headers = merge_header_controls(headers.clone(), deny.headers);
            let mut response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    req.method(),
                    req.version(),
                    proxy_name,
                    build_local_response(local)?,
                    merged_headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    req.method(),
                    req.version(),
                    proxy_name,
                    forbidden(state.messages.forbidden.as_str()),
                    merged_headers.as_deref(),
                    false,
                )
            };
            annotate(
                &mut response,
                if deny.local_response.is_some() {
                    "ext_authz_local_response"
                } else {
                    "ext_authz_deny"
                },
            );
            return Ok(response);
        }
    };

    if matches!(action.kind, ActionKind::Block) {
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            blocked(state.messages.blocked.as_str()),
            false,
        );
        annotate(&mut response, "block");
        return Ok(response);
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
            headers.as_deref(),
            false,
        );
        annotate(&mut response, "respond");
        return Ok(response);
    }

    if is_ftp_request {
        let mut response = ftp::handle_ftp(
            req,
            listener_cfg.ftp.clone(),
            Arc::<str>::from(state.messages.unsupported_ftp_method.as_str()),
            state.ftp_semaphore.clone(),
        )
        .await?;
        let response_version = response.version();
        finalize_response_with_headers_in_place(
            &request_method,
            response_version,
            proxy_name,
            &mut response,
            headers.as_deref(),
            false,
        );
        annotate(&mut response, "allow");
        return Ok(response);
    }
    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name,
        state.config.runtime.trace_reflect_all_headers,
        state.config.runtime.max_observed_request_body_bytes,
        std::time::Duration::from_millis(state.config.runtime.http_header_read_timeout_ms.max(1)),
    )
    .await
    {
        let mut response = response;
        annotate(&mut response, "max_forwards");
        return Ok(response);
    }
    strip_untrusted_identity_headers(
        &state,
        &effective_policy,
        remote_addr.ip(),
        req.headers_mut(),
    )?;
    let websocket = is_websocket_upgrade(req.headers());
    prepare_request_with_headers_in_place(&mut req, proxy_name, headers.as_deref(), websocket);
    if !req.headers().contains_key("host") {
        let default_port = match req.uri().scheme_str() {
            Some(s) if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("wss") => 443,
            Some(s) if s.eq_ignore_ascii_case("ftp") => 21,
            _ => 80,
        };
        let host_value = match host.port {
            Some(port) if port != default_port => {
                format_authority_host_port(host.host.as_str(), port)
            }
            _ => host.host.clone(),
        };
        req.headers_mut()
            .insert("host", http::HeaderValue::from_str(&host_value).unwrap());
    }
    let http_modules_chain = state
        .listener_http_modules(listener_name)
        .cloned()
        .unwrap_or_else(|| {
            std::sync::Arc::new(crate::http::modules::CompiledHttpModuleChain::default())
        });
    let mut http_modules = http_modules_chain.start(
        state.clone(),
        crate::http::modules::HttpModuleSessionInit {
            proxy_kind: "forward",
            proxy_name: proxy_name.to_string(),
            scope_name: listener_name.to_string(),
            route_name: None,
            remote_ip: remote_addr.ip(),
            cache_policy: cache_policy.clone(),
            cache_default_scheme: Some(req.uri().scheme_str().unwrap_or("http").to_string()),
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
                headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(&response), None);
            annotate(&mut response, "http_module_local_response");
            return Ok(response);
        }
    }
    let cache_applicable = cache_policy.is_some()
        && matches!(
            action.kind,
            ActionKind::Direct | ActionKind::Proxy | ActionKind::Tunnel | ActionKind::Inspect
        );
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) = if cache_applicable {
        let cache_default_scheme = req.uri().scheme_str().unwrap_or("http");
        let cache_lookup_key = CacheRequestKey::for_lookup(&req, cache_default_scheme)?;
        let cache_target_key = CacheRequestKey::for_target(&req, cache_default_scheme)?;
        let snapshot = cache_lookup_key.as_ref().map(|_| req.headers().clone());
        (snapshot, cache_lookup_key, cache_target_key)
    } else {
        (None, None, None)
    };
    let mut revalidation_state = None;

    let upstream = resolve_upstream(&action, &state, listener_name)?;
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
            annotate(&mut response, "concurrency_limited");
            return Ok(response);
        }
    };
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
    let upgrade_wait_timeout = Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout = Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
    let http_authority = match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => host.host.clone(),
    };
    let export_session = state.export_session(remote_addr, http_authority.as_str());
    let websocket_connect_authority = match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => format_authority_host_port(host.host.as_str(), 80),
    };
    let websocket_host_header = match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => host.host.clone(),
    };
    if websocket {
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_request_preview(&req);
            session.emit_plaintext(true, &preview);
        }
        let mut response = proxy_websocket_http1(
            req,
            WebsocketProxyConfig {
                upstream_proxy: upstream.as_ref(),
                direct_connect_authority: websocket_connect_authority.as_str(),
                direct_host_header: websocket_host_header.as_str(),
                timeout_dur: upstream_timeout,
                upgrade_wait_timeout,
                tunnel_idle_timeout,
                tunnel_label: "forward",
                upstream_context: "forward websocket upstream proxy",
                direct_context: "forward websocket direct",
            },
        )
        .await?;
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_response_preview(&response);
            session.emit_plaintext(false, &preview);
        }
        let keep_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
        let response_version = response.version();
        finalize_response_with_headers_in_place(
            &request_method,
            response_version,
            proxy_name,
            &mut response,
            headers.as_deref(),
            keep_upgrade,
        );
        annotate(&mut response, "allow");
        return Ok(response);
    }

    if let (Some(snapshot), Some(_)) = (request_headers_snapshot.as_ref(), cache_policy.as_ref()) {
        let (lookup_decision, lookup_revalidation_state) = lookup_with_revalidation(
            &mut req,
            snapshot,
            cache_lookup_key.as_ref(),
            cache_policy.as_ref(),
            &state.cache.backends,
            state.messages.cache_miss.as_str(),
        )
        .await?;
        revalidation_state = lookup_revalidation_state;
        let cache_hit = matches!(
            lookup_decision,
            CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
        );
        http_modules.on_cache_lookup(cache_hit).await?;
        match lookup_decision {
            CacheLookupDecision::Hit(mut hit) => {
                hit = http_modules.prepare_downstream_response(hit).await?;
                let hit_version = hit.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    hit_version,
                    proxy_name,
                    &mut hit,
                    headers.as_deref(),
                    false,
                );
                http_modules.on_logging(Some(&hit), None);
                annotate(&mut hit, "cache_hit");
                return Ok(hit);
            }
            CacheLookupDecision::StaleWhileRevalidate(mut hit, state) => {
                if request_method == Method::GET {
                    if let (Some(policy), Some(snapshot), Some(lookup_key), Some(target_key)) = (
                        cache_policy.as_ref(),
                        request_headers_snapshot.as_ref(),
                        cache_lookup_key.as_ref(),
                        cache_target_key.as_ref(),
                    ) {
                        if let Some(guard) = crate::cache::try_begin_background_revalidation(&state)
                        {
                            let runtime = runtime.clone();
                            let action = action.clone();
                            let listener_name = listener_name.to_string();
                            let http_authority = http_authority.clone();
                            let policy = (*policy).clone();
                            let snapshot = (*snapshot).clone();
                            let lookup_key = (*lookup_key).clone();
                            let target_key = (*target_key).clone();
                            let bg_req = clone_request_head_for_revalidation(&req);
                            tokio::spawn(async move {
                                let _guard = guard;
                                let started = std::time::Instant::now();
                                let runtime_state = runtime.state();
                                let upstream = resolve_upstream(
                                    &action,
                                    &runtime_state,
                                    listener_name.as_str(),
                                )
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
                                            state_ref
                                                .config
                                                .runtime
                                                .upstream_http_timeout_ms
                                                .max(1),
                                        ),
                                        backends,
                                    },
                                )
                                .await;
                            });
                        }
                    }
                }
                hit = http_modules.prepare_downstream_response(hit).await?;
                let hit_version = hit.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    hit_version,
                    proxy_name,
                    &mut hit,
                    headers.as_deref(),
                    false,
                );
                http_modules.on_logging(Some(&hit), None);
                annotate(&mut hit, "cache_stale");
                return Ok(hit);
            }
            CacheLookupDecision::OnlyIfCachedMiss(response) => {
                let response = http_modules.prepare_downstream_response(response).await?;
                let mut response = finalize_response_with_headers(
                    &request_method,
                    client_version,
                    proxy_name,
                    response,
                    headers.as_deref(),
                    false,
                );
                http_modules.on_logging(Some(&response), None);
                annotate(&mut response, "cache_only_if_cached_miss");
                return Ok(response);
            }
            CacheLookupDecision::Miss => {}
        }
    }

    let mut _cache_collapse_guard = None;
    if request_method == Method::GET {
        if let (Some(snapshot), Some(policy), Some(lookup_key)) = (
            request_headers_snapshot.as_ref(),
            cache_policy.as_ref(),
            cache_lookup_key.as_ref(),
        ) {
            match crate::cache::begin_request_collapse(lookup_key) {
                crate::cache::RequestCollapseJoin::Leader(guard) => {
                    _cache_collapse_guard = Some(guard);
                }
                crate::cache::RequestCollapseJoin::Follower(waiter) => {
                    if waiter.wait(upstream_timeout).await {
                        let (lookup_decision, lookup_revalidation_state) =
                            lookup_with_revalidation(
                                &mut req,
                                snapshot,
                                cache_lookup_key.as_ref(),
                                Some(policy),
                                &state.cache.backends,
                                state.messages.cache_miss.as_str(),
                            )
                            .await?;
                        revalidation_state = lookup_revalidation_state;
                        let cache_hit = matches!(
                            lookup_decision,
                            CacheLookupDecision::Hit(_)
                                | CacheLookupDecision::StaleWhileRevalidate(_, _)
                        );
                        http_modules.on_cache_lookup(cache_hit).await?;
                        match lookup_decision {
                            CacheLookupDecision::Hit(mut hit) => {
                                hit = http_modules.prepare_downstream_response(hit).await?;
                                let hit_version = hit.version();
                                finalize_response_with_headers_in_place(
                                    &request_method,
                                    hit_version,
                                    proxy_name,
                                    &mut hit,
                                    headers.as_deref(),
                                    false,
                                );
                                http_modules.on_logging(Some(&hit), None);
                                annotate(&mut hit, "cache_collapsed_hit");
                                return Ok(hit);
                            }
                            CacheLookupDecision::StaleWhileRevalidate(mut hit, _) => {
                                hit = http_modules.prepare_downstream_response(hit).await?;
                                let hit_version = hit.version();
                                finalize_response_with_headers_in_place(
                                    &request_method,
                                    hit_version,
                                    proxy_name,
                                    &mut hit,
                                    headers.as_deref(),
                                    false,
                                );
                                http_modules.on_logging(Some(&hit), None);
                                annotate(&mut hit, "cache_collapsed_stale");
                                return Ok(hit);
                            }
                            CacheLookupDecision::OnlyIfCachedMiss(response) => {
                                let response =
                                    http_modules.prepare_downstream_response(response).await?;
                                let mut response = finalize_response_with_headers(
                                    &request_method,
                                    client_version,
                                    proxy_name,
                                    response,
                                    headers.as_deref(),
                                    false,
                                );
                                http_modules.on_logging(Some(&response), None);
                                annotate(&mut response, "cache_only_if_cached_miss");
                                return Ok(response);
                            }
                            CacheLookupDecision::Miss => {}
                        }
                    }
                }
            }
        }
    }

    let upstream_started = std::time::Instant::now();
    http_modules.on_upstream_request(&mut req).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let proxied = match proxy_http1_request_with_interim(
        req,
        upstream.as_ref(),
        http_authority.as_str(),
        upstream_timeout,
    )
    .await
    {
        Ok(resp) => resp,
        Err(err) => {
            http_modules.on_error(&err);
            if let Some(stale) = revalidation_state
                .as_ref()
                .and_then(crate::cache::maybe_build_stale_if_error_response)
            {
                let stale = http_modules.prepare_downstream_response(stale).await?;
                let mut stale = stale;
                let stale_version = stale.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    stale_version,
                    proxy_name,
                    &mut stale,
                    headers.as_deref(),
                    false,
                );
                http_modules.on_logging(Some(&stale), None);
                annotate(&mut stale, "stale_if_error");
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
    let response_prefilter_ctx = MatchPrefilterContext {
        method: Some(request_method.as_str()),
        dst_port: host.port,
        src_ip: Some(remote_addr.ip()),
        host: Some(host.host.as_str()),
        sni: None,
        path,
    };
    let response_candidates = response_engine
        .map(|engine| engine.candidate_profile(response_prefilter_ctx.clone()))
        .unwrap_or_default();
    let response_status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let response_policy_tags = match apply_listener_response_policy(
        response_engine,
        response_candidates,
        build_response_rule_match_context(ResponseRuleContextInput {
            base: &base,
            headers: &response_headers,
            destination: &destination,
            identity: &identity,
            response_status,
            response_size: None,
            rpc: None,
            client_cert: None,
            upstream_cert: None,
        }),
        response,
        headers.clone(),
        request_rpc.as_ref(),
        ResponseBodyObservationLimits {
            max_body_bytes: state.config.runtime.max_observed_response_body_bytes,
            read_timeout: std::time::Duration::from_millis(
                state.config.runtime.upstream_http_timeout_ms.max(1),
            ),
        },
    )
    .await?
    {
        ListenerResponsePolicyDecision::Continue {
            response: updated,
            headers: updated_headers,
            cache_bypass,
            suppress_retry: _suppress_retry,
            mirror: _mirror,
            policy_tags,
        } => {
            response = updated;
            headers = updated_headers;
            if cache_bypass {
                cache_policy = None;
            }
            policy_tags
        }
        ListenerResponsePolicyDecision::LocalResponse {
            response: local,
            headers: updated_headers,
            policy_tags,
        } => {
            let response = http_modules.prepare_downstream_response(local).await?;
            let mut response = finalize_response_with_headers(
                &request_method,
                client_version,
                proxy_name,
                response,
                updated_headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(&response), None);
            annotate_with_tags(&mut response, "response_local_response", &policy_tags);
            return Ok(response);
        }
    };
    let response_delay_secs = upstream_started.elapsed().as_secs();
    if response.status().is_server_error() {
        if let Some(stale) = revalidation_state
            .as_ref()
            .and_then(crate::cache::maybe_build_stale_if_error_response)
        {
            let stale = http_modules.prepare_downstream_response(stale).await?;
            let mut stale = stale;
            let stale_version = stale.version();
            finalize_response_with_headers_in_place(
                &request_method,
                stale_version,
                proxy_name,
                &mut stale,
                headers.as_deref(),
                false,
            );
            http_modules.on_logging(Some(&stale), None);
            annotate(&mut stale, "stale_if_error");
            return Ok(stale);
        }
    }
    if let Some(policy) = cache_policy.as_ref() {
        if let Some(snapshot) = request_headers_snapshot.as_ref() {
            response = process_upstream_response_for_cache(
                response,
                CacheWritebackContext {
                    request_method: &request_method,
                    response_delay_secs,
                    cache_target_key: cache_target_key.as_ref(),
                    cache_lookup_key: cache_lookup_key.as_ref(),
                    cache_policy: Some(policy),
                    request_headers_snapshot: snapshot,
                    revalidation_state,
                    body_read_timeout: std::time::Duration::from_millis(
                        state.config.runtime.upstream_http_timeout_ms.max(1),
                    ),
                    backends: &state.cache.backends,
                },
            )
            .await?;
        } else {
            crate::cache::maybe_invalidate(
                &request_method,
                response.status(),
                response.headers(),
                cache_target_key.as_ref(),
                policy,
                &state.cache.backends,
            )
            .await?;
        }
    }
    response = http_modules.prepare_downstream_response(response).await?;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        &request_method,
        response_version,
        proxy_name,
        &mut response,
        headers.as_deref(),
        false,
    );
    http_modules.on_logging(Some(&response), None);
    annotate_with_tags(&mut response, "allow", &response_policy_tags);
    Ok(response)
}
