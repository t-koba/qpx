use super::*;

pub(crate) async fn prepare_h3_connect_request(
    req_head: &::http::Request<()>,
    req_stream: &mut H3ServerRequestStream,
    handler: &ForwardH3Handler,
    conn: &H3ConnInfo,
    connect_udp_cfg: Option<&ConnectUdpConfig>,
) -> Result<H3ConnectPreparation> {
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let max_h3_response_body_bytes = state.plan.limits.max_h3_response_body_bytes;
    let protocol = req_head.extensions().get::<::h3::ext::Protocol>().copied();
    let is_connect_udp = protocol == Some(::h3::ext::Protocol::CONNECT_UDP);
    let is_extended_connect = protocol.is_some();

    if is_connect_udp {
        let Some(cfg) = connect_udp_cfg else {
            send_h3_static_response(
                req_stream,
                ::http::StatusCode::NOT_IMPLEMENTED,
                state.messages.connect_udp_disabled.as_bytes(),
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        };
        if !cfg.enabled {
            send_h3_static_response(
                req_stream,
                ::http::StatusCode::NOT_IMPLEMENTED,
                state.messages.connect_udp_disabled.as_bytes(),
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
    }

    let req_authority = match req_head.uri().authority().map(|a| a.as_str().to_string()) {
        Some(authority) => authority,
        None => {
            let message = if is_connect_udp {
                b"missing CONNECT-UDP authority".as_slice()
            } else {
                b"missing CONNECT authority".as_slice()
            };
            send_h3_static_response(
                req_stream,
                ::http::StatusCode::BAD_REQUEST,
                message,
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
    };

    let (host, port, authority_host_for_validation, authority_port_for_validation, auth_uri) =
        if is_connect_udp {
            let uri_template = connect_udp_cfg.and_then(|cfg| cfg.uri_template.as_deref());
            let (host, port) = match parse_connect_udp_target(req_head.uri(), uri_template) {
                Ok(parsed) => parsed,
                Err(_) => {
                    send_h3_static_response(
                        req_stream,
                        ::http::StatusCode::BAD_REQUEST,
                        b"invalid CONNECT-UDP target",
                        &http::Method::CONNECT,
                        proxy_name,
                        max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(H3ConnectPreparation::Responded);
                }
            };
            let scheme = match req_head.uri().scheme_str() {
                Some(scheme) => scheme,
                None => {
                    send_h3_static_response(
                        req_stream,
                        ::http::StatusCode::BAD_REQUEST,
                        b"missing CONNECT-UDP :scheme",
                        &http::Method::CONNECT,
                        proxy_name,
                        max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(H3ConnectPreparation::Responded);
                }
            };
            let default_port = default_port_for_scheme(scheme);
            let authority = req_head
                .uri()
                .authority()
                .ok_or_else(|| anyhow!("CONNECT target authority missing"))?;
            let authority_host = authority.host().to_string();
            let authority_port = authority.port_u16().unwrap_or(default_port);
            let path = match req_head.uri().path_and_query().map(|pq| pq.as_str()) {
                Some(path) => path,
                None => {
                    send_h3_static_response(
                        req_stream,
                        ::http::StatusCode::BAD_REQUEST,
                        b"missing CONNECT-UDP :path",
                        &http::Method::CONNECT,
                        proxy_name,
                        max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(H3ConnectPreparation::Responded);
                }
            };
            let auth_uri = format!("{scheme}://{req_authority}{path}");
            (host, port, authority_host, authority_port, auth_uri)
        } else {
            let (host, port) = match parse_connect_authority_required(&req_authority) {
                Ok(parsed) => parsed,
                Err(_) => {
                    send_h3_static_response(
                        req_stream,
                        ::http::StatusCode::BAD_REQUEST,
                        b"invalid CONNECT authority",
                        &http::Method::CONNECT,
                        proxy_name,
                        max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(H3ConnectPreparation::Responded);
                }
            };
            let auth_uri = if is_extended_connect {
                let scheme = req_head.uri().scheme_str().unwrap_or("https");
                let path = req_head
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                format!("{scheme}://{req_authority}{path}")
            } else {
                req_authority.clone()
            };
            (host.clone(), port, host, port, auth_uri)
        };

    let headers = match h1_headers_to_http(req_head.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            let message = if is_connect_udp {
                b"invalid CONNECT-UDP headers".as_slice()
            } else {
                b"invalid CONNECT headers".as_slice()
            };
            send_h3_static_response(
                req_stream,
                ::http::StatusCode::BAD_REQUEST,
                message,
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
    };

    if let Err(err) = validate_h3_connect_head(
        req_head,
        &headers,
        authority_host_for_validation.as_str(),
        authority_port_for_validation,
        is_extended_connect,
    ) {
        if is_connect_udp {
            warn!(error = ?err, "invalid forward HTTP/3 CONNECT-UDP request");
        } else {
            warn!(error = ?err, "invalid forward HTTP/3 CONNECT request");
        }
        let message = if is_connect_udp {
            b"bad CONNECT-UDP request".as_slice()
        } else {
            b"bad CONNECT request".as_slice()
        };
        send_h3_static_response(
            req_stream,
            ::http::StatusCode::BAD_REQUEST,
            message,
            &http::Method::CONNECT,
            proxy_name,
            max_h3_response_body_bytes,
        )
        .await?;
        return Ok(H3ConnectPreparation::Responded);
    }

    let base_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), None)
        .ok_or_else(|| anyhow!("listener plan not found"))?;
    let effective_policy = base_plan.policy_context.clone();
    let mut sanitized_headers = headers;
    sanitize_headers_for_policy(
        &state,
        &effective_policy,
        conn.remote_addr.ip(),
        &mut sanitized_headers,
    )?;
    let mut identity = resolve_identity(
        &state,
        &effective_policy,
        conn.remote_addr.ip(),
        Some(&sanitized_headers),
        conn.peer_certificates
            .as_deref()
            .map(|certs| certs.as_slice()),
    )?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: if is_connect_udp {
                req_head.uri().scheme_str()
            } else {
                Some("https")
            },
            port: Some(port),
            alpn: Some("h3"),
            ..Default::default()
        },
        base_plan.destination_resolution.as_ref(),
    );
    let audit_path = req_head
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string());
    macro_rules! send_policy {
        ($response:expr, $outcome:expr, $matched_rule:expr, $ext_authz_policy_id:expr, $log_context:expr) => {
            send_h3_policy_response(
                req_stream,
                $response,
                H3PolicyResponseContext {
                    request_method: &http::Method::CONNECT,
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: $outcome,
                    matched_rule: $matched_rule,
                    ext_authz_policy_id: $ext_authz_policy_id,
                    log_context: $log_context,
                },
            )
        };
    }
    let ctx = build_dispatch_connect_rule_context(DispatchConnectRuleContextInput {
        remote_ip: conn.remote_addr.ip(),
        port,
        host: host.as_str(),
        path: audit_path.as_deref(),
        authority: req_authority.as_str(),
        http_version: http_version_label(http::Version::HTTP_3),
        alpn: Some("h3"),
        destination: &destination,
        headers: &sanitized_headers,
        identity: &identity,
    });

    let (mut action, matched_rule) = match crate::forward::evaluate_forward_policy(
        &handler.runtime,
        handler.listener_name.as_ref(),
        ctx,
        &sanitized_headers,
        "CONNECT",
        auth_uri.as_str(),
    )
    .await
    {
        Ok(crate::forward::ForwardPolicyDecision::Allow(allowed)) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (
                allowed.action,
                allowed.matched_rule.map(|rule| rule.to_string()),
            )
        }
        #[cfg(feature = "auth-basic")]
        Ok(crate::forward::ForwardPolicyDecision::Challenge(challenge)) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                proxy_auth_required(challenge, state.messages.proxy_auth_required.as_str()),
                false,
            );
            send_policy!(
                response,
                crate::http::dispatch::DispatchOutcome::Challenge,
                None,
                None,
                &log_context
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        #[cfg(feature = "auth-basic")]
        Ok(crate::forward::ForwardPolicyDecision::Forbidden) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            );
            send_policy!(
                response,
                crate::http::dispatch::DispatchOutcome::Forbidden,
                None,
                None,
                &log_context
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        Err(err) => {
            if is_connect_udp {
                warn!(
                    error = ?err,
                    "forward HTTP/3 CONNECT-UDP policy evaluation failed"
                );
            } else {
                warn!(error = ?err, "forward HTTP/3 CONNECT policy evaluation failed");
            }
            send_h3_static_response(
                req_stream,
                ::http::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
    };
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled HTTP/3 CONNECT listener execution plan not found"))?;

    let request_limit_ctx = RateLimitContext::from_identity(
        conn.remote_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        None,
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        crate::rate_limit::TransportScope::Connect,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        let log_context = identity.to_log_context(matched_rule.as_deref(), None, None);
        let response = finalize_response_for_request(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            proxy_name,
            too_many_requests(Some(retry_after)),
            false,
        );
        send_policy!(
            response,
            crate::http::dispatch::DispatchOutcome::RateLimited,
            matched_rule.as_deref(),
            None,
            &log_context
        )
        .await?;
        return Ok(H3ConnectPreparation::Responded);
    }

    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name,
            scope_name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            dst_port: Some(port),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            uri: Some(auth_uri.as_str()),
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
    let (response_headers, timeout_override, rate_limit_profile) = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardConnect)?;
            let rate_limit_profile = allow.rate_limit_profile.clone();
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                &state.policy.rate_limiters,
                rate_limit_profile.as_deref(),
                crate::rate_limit::TransportScope::Connect,
                &request_limit_ctx,
                1,
            )? {
                let response = finalize_response_for_request(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                );
                send_policy!(
                    response,
                    crate::http::dispatch::DispatchOutcome::RateLimited,
                    matched_rule.as_deref(),
                    ext_authz_policy_id.as_deref(),
                    &log_context
                )
                .await?;
                return Ok(H3ConnectPreparation::Responded);
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            (allow.headers, allow.timeout_override, rate_limit_profile)
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    build_local_response(local)?,
                    deny.headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    forbidden(state.messages.forbidden.as_str()),
                    deny.headers.as_deref(),
                    false,
                )
            };
            send_policy!(
                response,
                if deny.local_response.is_some() {
                    crate::http::dispatch::DispatchOutcome::ExtAuthzLocalResponse
                } else {
                    crate::http::dispatch::DispatchOutcome::ExtAuthzDeny
                },
                matched_rule.as_deref(),
                ext_authz_policy_id.as_deref(),
                &log_context
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
    };

    match action.kind {
        ActionKind::Block => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            send_policy!(
                response,
                crate::http::dispatch::DispatchOutcome::Block,
                matched_rule.as_deref(),
                ext_authz_policy_id.as_deref(),
                &log_context
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                build_local_response(local)?,
                response_headers.as_deref(),
                false,
            );
            send_policy!(
                response,
                crate::http::dispatch::DispatchOutcome::Respond,
                matched_rule.as_deref(),
                ext_authz_policy_id.as_deref(),
                &log_context
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        ActionKind::Inspect => {}
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }

    Ok(H3ConnectPreparation::Continue(Box::new(
        PreparedH3Connect {
            authority: format_authority(&host, port),
            host,
            port,
            action,
            response_headers,
            log_context,
            matched_rule,
            ext_authz_policy_id,
            audit_path,
            timeout_override,
            rate_limit_profile,
            rate_limit_context: request_limit_ctx,
            sanitized_headers,
            identity,
        },
    )))
}
