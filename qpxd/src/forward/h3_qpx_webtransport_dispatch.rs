use super::h3_qpx_webtransport::{
    QpxWebTransportRelayContext, WebTransportFlowLimits, relay_qpx_webtransport_session,
};
use super::*;
use crate::rate_limit::RateLimitContext;

pub(super) async fn handle_qpx_webtransport_connect(
    handler: &ForwardQpxHandler,
    req_head: http::Request<()>,
    mut req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
    session: qpx_h3::WebTransportSession,
) -> Result<()> {
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.to_string();
    let max_h3_response_body_bytes = state.plan.limits.max_h3_response_body_bytes;
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.tunnel_idle_timeout_ms.max(1));

    let req_authority = match req_head.uri().authority().map(|a| a.as_str().to_string()) {
        Some(authority) => authority,
        None => {
            send_qpx_static_response(
                &mut req_stream,
                StatusCode::BAD_REQUEST,
                b"missing CONNECT authority",
            )
            .await?;
            return Ok(());
        }
    };
    let (host, port) = match parse_connect_authority_required(&req_authority) {
        Ok(parsed) => parsed,
        Err(_) => {
            send_qpx_static_response(
                &mut req_stream,
                StatusCode::BAD_REQUEST,
                b"invalid CONNECT authority",
            )
            .await?;
            return Ok(());
        }
    };
    let headers = match h1_headers_to_http(req_head.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            send_qpx_static_response(
                &mut req_stream,
                StatusCode::BAD_REQUEST,
                b"invalid CONNECT headers",
            )
            .await?;
            return Ok(());
        }
    };
    if let Err(err) = validate_qpx_connect_head(
        &req_head,
        &headers,
        host.as_str(),
        port,
        Some(&qpx_h3::Protocol::WebTransport),
    ) {
        warn!(error = ?err, "invalid forward HTTP/3 WebTransport request");
        send_qpx_static_response(
            &mut req_stream,
            StatusCode::BAD_REQUEST,
            b"bad CONNECT request",
        )
        .await?;
        return Ok(());
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
        &crate::destination::DestinationInputs {
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: req_head.uri().scheme_str(),
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
    let auth_uri = format!(
        "{}://{}{}",
        req_head.uri().scheme_str().unwrap_or("https"),
        req_authority,
        req_head
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );
    let ctx = RuleMatchContext {
        src_ip: Some(conn.remote_addr.ip()),
        dst_port: Some(port),
        host: Some(host.as_str()),
        sni: Some(host.as_str()),
        method: Some("CONNECT"),
        path: audit_path.as_deref(),
        authority: Some(req_authority.as_str()),
        http_version: Some(http_version_label(http::Version::HTTP_3)),
        alpn: Some("h3"),
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
        &handler.runtime,
        handler.listener_name.as_ref(),
        ctx,
        &sanitized_headers,
        "CONNECT",
        auth_uri.as_str(),
    )
    .await
    {
        Ok(ForwardPolicyDecision::Allow(allowed)) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (
                allowed.action,
                allowed.matched_rule.map(|rule: Arc<str>| rule.to_string()),
            )
        }
        #[cfg(feature = "auth-basic")]
        Ok(ForwardPolicyDecision::Challenge(challenge)) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                proxy_auth_required(challenge, state.messages.proxy_auth_required.as_str()),
                false,
            );
            send_qpx_policy_response(
                &mut req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: crate::http::dispatch::DispatchOutcome::Challenge,
                    matched_rule: None,
                    ext_authz_policy_id: None,
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(());
        }
        #[cfg(feature = "auth-basic")]
        Ok(ForwardPolicyDecision::Forbidden) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                forbidden(state.messages.forbidden.as_str()),
                false,
            );
            send_qpx_policy_response(
                &mut req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: crate::http::dispatch::DispatchOutcome::Forbidden,
                    matched_rule: None,
                    ext_authz_policy_id: None,
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(());
        }
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 WebTransport policy evaluation failed");
            send_qpx_static_response(
                &mut req_stream,
                StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
            )
            .await?;
            return Ok(());
        }
    };
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled WebTransport listener execution plan not found"))?;

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
        crate::rate_limit::TransportScope::Webtransport,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        let log_context = identity.to_log_context(matched_rule.as_deref(), None, None);
        let response = finalize_response_for_request(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            proxy_name.as_str(),
            too_many_requests(Some(retry_after)),
            false,
        );
        send_qpx_policy_response(
            &mut req_stream,
            response,
            QpxPolicyResponseContext {
                state: &state,
                listener_name: handler.listener_name.as_ref(),
                conn: &conn,
                host: host.as_str(),
                path: audit_path.as_deref(),
                outcome: crate::http::dispatch::DispatchOutcome::RateLimited,
                matched_rule: matched_rule.as_deref(),
                ext_authz_policy_id: None,
                log_context: &log_context,
            },
        )
        .await?;
        return Ok(());
    }

    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name: proxy_name.as_str(),
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
                crate::rate_limit::TransportScope::Webtransport,
                &request_limit_ctx,
                1,
            )? {
                let response = finalize_response_for_request(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    too_many_requests(Some(retry_after)),
                    false,
                );
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: handler.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: crate::http::dispatch::DispatchOutcome::RateLimited,
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
                )
                .await?;
                return Ok(());
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            (allow.headers, allow.timeout_override, rate_limit_profile)
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    build_local_response(local)?,
                    deny.headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    forbidden(state.messages.forbidden.as_str()),
                    deny.headers.as_deref(),
                    false,
                )
            };
            send_qpx_policy_response(
                &mut req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: if deny.local_response.is_some() {
                        crate::http::dispatch::DispatchOutcome::ExtAuthzLocalResponse
                    } else {
                        crate::http::dispatch::DispatchOutcome::ExtAuthzDeny
                    },
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(());
        }
    };

    match action.kind {
        ActionKind::Block => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            send_qpx_policy_response(
                &mut req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: crate::http::dispatch::DispatchOutcome::Block,
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(());
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                build_local_response(local)?,
                response_headers.as_deref(),
                false,
            );
            send_qpx_policy_response(
                &mut req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: crate::http::dispatch::DispatchOutcome::Respond,
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(());
        }
        ActionKind::Inspect => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            send_qpx_policy_response(
                &mut req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: crate::http::dispatch::DispatchOutcome::Block,
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(());
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }

    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.plan.limits.upstream_http_timeout_ms));
    let _concurrency_permits = match request_limits.acquire_concurrency(&request_limit_ctx) {
        Some(permits) => Some(permits),
        None => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                too_many_requests(None),
                response_headers.as_deref(),
                false,
            );
            send_qpx_policy_response(
                &mut req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: crate::http::dispatch::DispatchOutcome::RateLimited,
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(());
        }
    };
    let upstream =
        match open_upstream_qpx_extended_connect_stream(OpenUpstreamQpxExtendedConnectInput {
            req_head: &req_head,
            sanitized_headers: &sanitized_headers,
            proxy_name: proxy_name.as_str(),
            upstream: action.upstream.as_deref(),
            verify_upstream: state
                .ingress_edge_settings(handler.listener_name.as_ref())
                .and_then(|listener| listener.tls_inspection.as_ref())
                .map(|cfg| {
                    cfg.verify_upstream
                        && !state.tls_verify_exception_matches(
                            handler.listener_name.as_ref(),
                            host.as_str(),
                        )
                })
                .unwrap_or(true),
            protocol: qpx_h3::Protocol::WebTransport,
            enable_datagram: session.datagrams.is_some(),
            timeout_dur: upstream_timeout,
        })
        .await
        {
            Ok(upstream) => upstream,
            Err(err) => {
                warn!(error = ?err, "forward HTTP/3 WebTransport CONNECT establish failed");
                let response = finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(state.messages.proxy_error.clone()))?,
                    response_headers.as_deref(),
                    false,
                );
                send_qpx_policy_response(
                    &mut req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: handler.listener_name.as_ref(),
                        conn: &conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: crate::http::dispatch::DispatchOutcome::Error,
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
                )
                .await?;
                return Ok(());
            }
        };

    let qpx_h3::WebTransportSession {
        session_id,
        opener: downstream_opener,
        datagrams: downstream_datagrams,
        bidi_streams: downstream_bidi_streams,
        uni_streams: downstream_uni_streams,
    } = session;
    let qpx_h3::ExtendedConnectStream {
        interim,
        response,
        request_stream: upstream_request,
        datagrams: upstream_datagrams,
        opener: upstream_opener,
        associated_bidi,
        associated_uni,
        _critical_streams,
        _endpoint,
        driver,
        datagram_task,
        _connection_use,
    } = upstream;

    for interim in interim {
        let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
        timeout(
            h3_body_read_timeout(&handler.runtime),
            req_stream.send_response_head(&interim),
        )
        .await
        .map_err(|_| anyhow!("qpx-h3 interim response send timed out"))??;
    }
    if !response.status().is_success() {
        let response = upstream_qpx_extended_connect_error_response(
            response,
            upstream_request,
            proxy_name.as_str(),
            response_headers.as_deref(),
            h3_body_read_timeout(&handler.runtime),
        )?;
        send_qpx_response_stream(
            &mut req_stream,
            response,
            &http::Method::CONNECT,
            max_h3_response_body_bytes,
            h3_body_read_timeout(&handler.runtime),
        )
        .await?;
        if let Some(task) = datagram_task {
            task.abort();
            let _ = task.await;
        }
        let _ = driver.await;
        return Ok(());
    }

    let established = finalize_qpx_connect_head_response(
        response,
        proxy_name.as_str(),
        response_headers.as_deref(),
    )?;
    tokio::time::timeout(
        tunnel_idle_timeout,
        req_stream.send_response_head(&established),
    )
    .await
    .map_err(|_| anyhow!("forward qpx-h3 extended CONNECT response send timeout"))??;
    emit_audit_log(
        &state,
        AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Forward,
            name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            outcome: crate::http::dispatch::DispatchOutcome::Allow,
            status: Some(StatusCode::OK.as_u16()),
            matched_rule: matched_rule.as_deref(),
            matched_route: None,
            ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        },
        &log_context,
    );
    let flow_limits = {
        let rate_limiters = &state.policy.rate_limiters;
        let selected_plan = state
            .plan
            .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
            .ok_or_else(|| anyhow!("compiled WebTransport execution plan not found"))?;
        let profile = rate_limit_profile.as_deref();
        WebTransportFlowLimits {
            bidi: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportBidi,
            )?,
            bidi_downstream: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportBidiDownstream,
            )?,
            bidi_upstream: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportBidiUpstream,
            )?,
            uni: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportUni,
            )?,
            uni_downstream: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportUniDownstream,
            )?,
            uni_upstream: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportUniUpstream,
            )?,
            datagram: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportDatagram,
            )?,
            datagram_downstream: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportDatagramDownstream,
            )?,
            datagram_upstream: rate_limiters.collect_plan_with_profile(
                &selected_plan.rate_limits,
                profile,
                crate::rate_limit::TransportScope::WebtransportDatagramUpstream,
            )?,
        }
    };
    let relay_result = relay_qpx_webtransport_session(QpxWebTransportRelayContext {
        downstream_request: req_stream,
        downstream_datagrams,
        downstream_opener,
        downstream_bidi_streams,
        downstream_uni_streams,
        upstream_request,
        upstream_datagrams,
        upstream_opener: upstream_opener
            .ok_or_else(|| anyhow!("missing upstream WebTransport opener"))?,
        upstream_bidi_streams: associated_bidi
            .ok_or_else(|| anyhow!("missing upstream WebTransport bidi channel"))?,
        upstream_uni_streams: associated_uni
            .ok_or_else(|| anyhow!("missing upstream WebTransport uni channel"))?,
        session_id,
        idle_timeout: tunnel_idle_timeout,
        rate_limit_ctx: request_limit_ctx,
        request_limits,
        flow_limits,
    })
    .await;
    if let Err(err) = relay_result {
        warn!(error = ?err, "forward HTTP/3 WebTransport relay failed");
    }
    if let Some(task) = datagram_task {
        task.abort();
        let _ = task.await;
    }
    let _ = driver.await;
    Ok(())
}
