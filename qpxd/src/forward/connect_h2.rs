use super::*;

pub(super) async fn handle_h2_extended_connect(
    req: Request<Body>,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: SocketAddr,
) -> Result<Response<Body>> {
    let protocol = req
        .extensions()
        .get::<H2Protocol>()
        .cloned()
        .ok_or_else(|| anyhow!("missing HTTP/2 extended CONNECT protocol"))?;
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    let req_version = req.version();
    let listener_cfg = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let effective_policy =
        EffectivePolicyContext::from_single(listener_cfg.policy_context.as_ref());

    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| anyhow!("missing authority"))?
        .as_str()
        .to_string();
    let scheme = req.uri().scheme_str().unwrap_or("https").to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let (host, port) =
        parse_authority_host_port(authority.as_str(), default_port_for_scheme(&scheme))
            .ok_or_else(|| anyhow!("invalid extended CONNECT authority"))?;
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
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: Some(scheme.as_str()),
            port: Some(port),
            alpn: Some("h2"),
            ..Default::default()
        },
        listener_cfg.destination_resolution.as_ref(),
    );
    let request_uri = req.uri().to_string();
    let request_query_owned = req
        .uri()
        .path_and_query()
        .and_then(|pq| pq.query())
        .map(str::to_string);
    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: Some(port),
        host: Some(host.as_str()),
        sni: Some(host.as_str()),
        method: Some("CONNECT"),
        path: Some(path.as_str()),
        query: request_query_owned.as_deref(),
        authority: Some(authority.as_str()),
        scheme: Some(scheme.as_str()),
        http_version: Some(http_version_label(req_version)),
        alpn: Some("h2"),
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        headers: Some(&sanitized_headers),
        user: identity.user.as_deref(),
        user_groups: &identity.groups,
        device_id: identity.device_id.as_deref(),
        posture: &identity.posture,
        tenant: identity.tenant.as_deref(),
        auth_strength: identity.auth_strength.as_deref(),
        idp: identity.idp.as_deref(),
        ..Default::default()
    };
    let (mut action, matched_rule) = match evaluate_forward_policy(
        &runtime,
        listener_name,
        ctx,
        &sanitized_headers,
        "CONNECT",
        request_uri.as_str(),
    )
    .await?
    {
        ForwardPolicyDecision::Allow(allowed) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (allowed.action, allowed.matched_rule)
        }
        ForwardPolicyDecision::Challenge(chal) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = proxy_auth_required(chal, state.messages.proxy_auth_required.as_str());
            let mut response = finalize_response_for_request(
                &Method::CONNECT,
                req_version,
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
                    host: Some(host.as_str()),
                    sni: Some(host.as_str()),
                    method: Some("CONNECT"),
                    path: Some(path.as_str()),
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
            let log_context = identity.to_log_context(None, None, None);
            let mut response = finalize_response_for_request(
                &Method::CONNECT,
                req_version,
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
                    host: Some(host.as_str()),
                    sni: Some(host.as_str()),
                    method: Some("CONNECT"),
                    path: Some(path.as_str()),
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
            scope: crate::rate_limit::TransportScope::Connect,
            extra: None,
            ctx: &request_limit_ctx,
            cost: 1,
        },
    )?;
    if let Some(retry_after) = retry_after {
        return Ok(finalize_response_for_request(
            &Method::CONNECT,
            req_version,
            proxy_name,
            too_many_requests(Some(retry_after)),
            false,
        ));
    }
    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: "forward",
            proxy_name,
            scope_name: listener_name,
            remote_ip: remote_addr.ip(),
            dst_port: Some(port),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: Some(path.as_str()),
            uri: Some(request_uri.as_str()),
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
    log_context.policy_tags = ext_authz_policy_tags;
    let annotate = |response: &mut Response<Body>, outcome: &'static str| {
        attach_log_context(response, &log_context);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: "forward",
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: Some(host.as_str()),
                sni: Some(host.as_str()),
                method: Some("CONNECT"),
                path: Some(path.as_str()),
                outcome,
                status: Some(response.status().as_u16()),
                matched_rule: matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &log_context,
        );
    };
    let (response_headers, timeout_override) = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardConnect)?;
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                &state.policy.rate_limiters,
                allow.rate_limit_profile.as_deref(),
                crate::rate_limit::TransportScope::Connect,
                &request_limit_ctx,
                1,
            )? {
                return Ok(finalize_response_for_request(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                ));
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            (allow.headers, allow.timeout_override)
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let mut response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    build_local_response(local)?,
                    deny.headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    forbidden(state.messages.forbidden.as_str()),
                    deny.headers.as_deref(),
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

    match action.kind {
        ActionKind::Block => {
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            annotate(&mut response, "block");
            return Ok(response);
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                build_local_response(local)?,
                response_headers.as_deref(),
                false,
            );
            annotate(&mut response, "respond");
            return Ok(response);
        }
        ActionKind::Inspect => {
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            annotate(&mut response, "block");
            return Ok(response);
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }

    let upstream_url = resolve_upstream_url(&action, &state, listener_name)?;
    let rate_limit_ctx = RateLimitContext::from_identity(
        remote_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        upstream_url.as_deref(),
    );
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
        Some(permits) => permits,
        None => {
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                too_many_requests(None),
                response_headers.as_deref(),
                false,
            );
            annotate(&mut response, "concurrency_limited");
            return Ok(response);
        }
    };
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
    let tunnel_idle_timeout =
        Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms.max(1));
    let declared_request_length = parse_h2_content_length(req.headers())?;
    let upstream = match open_upstream_h2_extended_connect_stream(
        req.uri(),
        &sanitized_headers,
        protocol,
        proxy_name,
        upstream_url.as_deref(),
        upstream_timeout,
        listener_upstream_trust(listener_cfg)?.as_deref(),
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/2 extended CONNECT establish failed");
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(state.messages.proxy_error.clone()))?,
                response_headers.as_deref(),
                false,
            );
            annotate(&mut response, "error");
            return Ok(response);
        }
    };

    let H2ExtendedConnectUpstream {
        interim,
        response,
        send_stream,
    } = upstream;
    let downstream_body = req.into_body();
    if !response.status().is_success() {
        let mut response = finalize_response_with_headers(
            &Method::CONNECT,
            req_version,
            proxy_name,
            h2_response_to_hyper(response)?,
            response_headers.as_deref(),
            false,
        );
        if !interim.is_empty() {
            response.extensions_mut().insert(interim);
        }
        annotate(&mut response, "allow");
        return Ok(response);
    }

    let (parts, upstream_body) = response.into_parts();
    let mut response = Response::builder()
        .status(StatusCode::from_u16(parts.status.as_u16())?)
        .body(spawn_h2_extended_connect_relay(
            downstream_body,
            declared_request_length,
            send_stream,
            upstream_body,
            tunnel_idle_timeout,
        ))?;
    *response.headers_mut() = h1_headers_to_http(&parts.headers)?;
    *response.version_mut() = http::Version::HTTP_2;
    let mut response = finalize_extended_connect_response_with_headers(
        req_version,
        proxy_name,
        response,
        response_headers.as_deref(),
        false,
    );
    if !interim.is_empty() {
        response.extensions_mut().insert(interim);
    }
    annotate(&mut response, "allow");
    Ok(response)
}
