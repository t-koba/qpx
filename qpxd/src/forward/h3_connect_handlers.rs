use super::super::connect::ConnectPolicyInput;
use super::h3_connect_extended::OpenUpstreamExtendedConnectInput;
use super::h3_connect_tunnel::H3ConnectPolicyContext;
#[cfg(feature = "mitm")]
use super::h3_connect_tunnel::MitmH3ConnectInput;
use super::*;

pub(crate) async fn handle_h3_connect(
    req_head: ::http::Request<()>,
    mut req_stream: H3ServerRequestStream,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
) -> Result<()> {
    let prepared = match prepare_h3_connect_request(
        &req_head,
        &mut req_stream,
        &handler,
        &conn,
        None,
    )
    .await?
    {
        H3ConnectPreparation::Continue(prepared) => *prepared,
        H3ConnectPreparation::Responded => return Ok(()),
    };

    let state = handler.runtime.state();
    let tunnel_idle_timeout =
        Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms.max(1));
    let proxy_name = state.config.identity.proxy_name.clone();
    let PreparedH3Connect {
        authority,
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
        mut rate_limit_context,
        sanitized_headers,
        identity,
    } = prepared;
    let mut request_limits = state.policy.rate_limiters.collect(
        handler.listener_name.as_ref(),
        matched_rule.as_deref(),
        None,
        crate::rate_limit::TransportScope::Connect,
    );
    request_limits.extend_from(&state.policy.rate_limiters.collect_profile(
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Connect,
    )?);
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
    macro_rules! send_policy {
        ($req_stream:expr, $response:expr, $outcome:expr) => {
            send_h3_policy_response(
                $req_stream,
                $response,
                H3PolicyResponseContext {
                    request_method: &http::Method::CONNECT,
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: $outcome,
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
        };
    }
    match action.kind {
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy | ActionKind::Inspect => {}
        _ => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            send_policy!(&mut req_stream, response, "block").await?;
            return Ok(());
        }
    }
    if matches!(action.kind, ActionKind::Inspect) {
        #[cfg(not(feature = "mitm"))]
        {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            send_policy!(&mut req_stream, response, "block").await?;
            return Ok(());
        }

        #[cfg(feature = "mitm")]
        {
            let tls_inspection = state
                .listener_config(handler.listener_name.as_ref())
                .and_then(|l| l.tls_inspection.as_ref());
            if !tls_inspection.map(|t| t.enabled).unwrap_or(false) {
                let response = finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    blocked(state.messages.blocked.as_str()),
                    response_headers.as_deref(),
                    false,
                );
                send_policy!(&mut req_stream, response, "block").await?;
                return Ok(());
            }
            let verify_upstream = tls_inspection
                .map(|t| {
                    t.verify_upstream
                        && !state
                            .tls_verify_exception_matches(handler.listener_name.as_ref(), &host)
                })
                .unwrap_or(true);
            let mitm = match state.security.mitm.clone() {
                Some(mitm) => mitm,
                None => {
                    let response = finalize_response_with_headers(
                        &http::Method::CONNECT,
                        http::Version::HTTP_3,
                        proxy_name.as_str(),
                        blocked(state.messages.blocked.as_str()),
                        response_headers.as_deref(),
                        false,
                    );
                    send_policy!(&mut req_stream, response, "block").await?;
                    return Ok(());
                }
            };

            let upstream = match crate::forward::request::resolve_upstream(
                &action,
                &state,
                handler.listener_name.as_ref(),
            ) {
                Ok(upstream) => upstream,
                Err(err) => {
                    warn!(error = ?err, "forward HTTP/3 CONNECT upstream resolution failed");
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
                    send_policy!(&mut req_stream, response, "error").await?;
                    return Ok(());
                }
            };
            rate_limit_context.upstream =
                upstream.as_ref().map(|upstream| upstream.key().to_string());
            let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_context)
            {
                Some(permits) => permits,
                None => {
                    let response = finalize_response_with_headers(
                        &http::Method::CONNECT,
                        http::Version::HTTP_3,
                        proxy_name.as_str(),
                        too_many_requests(None),
                        response_headers.as_deref(),
                        false,
                    );
                    send_policy!(&mut req_stream, response, "concurrency_limited").await?;
                    return Ok(());
                }
            };
            let upstream_connected = match connect_tunnel_target(
                &host,
                port,
                upstream.as_ref(),
                proxy_name.as_str(),
                upstream_timeout,
            )
            .await
            {
                Ok(stream) => stream.io,
                Err(err) => {
                    warn!(
                        error = ?err,
                        upstream = upstream.as_ref().map(|u| u.endpoint().cache_key()),
                        "forward HTTP/3 CONNECT tunnel establish failed"
                    );
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
                    send_policy!(&mut req_stream, response, "error").await?;
                    return Ok(());
                }
            };
            let established = build_h3_connect_success_response(
                proxy_name.as_str(),
                &http::Method::CONNECT,
                false,
                response_headers.as_deref(),
            )?;
            tokio::time::timeout(tunnel_idle_timeout, req_stream.send_response(established))
                .await
                .map_err(|_| anyhow!("forward HTTP/3 CONNECT response send timeout"))??;
            let initial_post_connect_action = action.clone();
            let (mut req_stream, client_prefetch, client_hello, mut action) =
                prepare_h3_connect_stream(
                    req_stream,
                    &handler.runtime,
                    H3ConnectPolicyContext {
                        listener_name: handler.listener_name.as_ref(),
                        remote_addr: conn.remote_addr,
                        host: host.as_str(),
                        port,
                        authority: authority.as_str(),
                        sanitized_headers: sanitized_headers.clone(),
                        identity: &identity,
                        initial_action: action,
                    },
                )
                .await?;
            let listener_cfg = state
                .listener_config(handler.listener_name.as_ref())
                .ok_or_else(|| anyhow!("listener not found"))?;
            let listener_trust = listener_upstream_trust(listener_cfg)?;
            let mut upstream_connected = Some(upstream_connected);
            if let Some(client_hello) = client_hello.as_ref() {
                if listener_requires_upstream_cert_preview(listener_cfg)
                    && matches!(
                        action.kind,
                        ActionKind::Inspect
                            | ActionKind::Tunnel
                            | ActionKind::Direct
                            | ActionKind::Proxy
                    )
                {
                    let preview_verify = listener_cfg
                        .tls_inspection
                        .as_ref()
                        .map(|cfg| {
                            cfg.verify_upstream
                                && !state.tls_verify_exception_matches(
                                    handler.listener_name.as_ref(),
                                    host.as_str(),
                                )
                        })
                        .unwrap_or(true);
                    let preview_server = upstream_connected
                        .take()
                        .expect("HTTP/3 CONNECT upstream tunnel must exist before cert preview");
                    match preview_tls_certificate_with_options(
                        host.as_str(),
                        preview_server,
                        preview_verify,
                        listener_trust.as_deref(),
                    )
                    .await
                    {
                        Ok(upstream_cert) => {
                            action = decide_connect_action_from_tls_metadata(ConnectPolicyInput {
                                runtime: &handler.runtime,
                                listener_name: handler.listener_name.as_ref(),
                                remote_addr: conn.remote_addr,
                                host: host.as_str(),
                                port,
                                authority: authority.as_str(),
                                sanitized_headers: &sanitized_headers,
                                identity: &identity,
                                client_hello,
                                upstream_cert: Some(&upstream_cert),
                            })
                            .await?;
                        }
                        Err(err) => {
                            if listener_trust.is_some() {
                                return Err(err);
                            }
                            warn!(
                                error = ?err,
                                "forward HTTP/3 CONNECT upstream certificate preview failed"
                            );
                        }
                    }
                }
            }
            if (upstream_connected.is_none() || action != initial_post_connect_action)
                && matches!(
                    action.kind,
                    ActionKind::Inspect
                        | ActionKind::Tunnel
                        | ActionKind::Direct
                        | ActionKind::Proxy
                )
            {
                let upstream = crate::forward::request::resolve_upstream(
                    &action,
                    &state,
                    handler.listener_name.as_ref(),
                )?;
                upstream_connected = Some(
                    connect_tunnel_target(
                        host.as_str(),
                        port,
                        upstream.as_ref(),
                        proxy_name.as_str(),
                        upstream_timeout,
                    )
                    .await?
                    .io,
                );
            }
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "forward",
                    name: handler.listener_name.as_ref(),
                    remote_ip: conn.remote_addr.ip(),
                    host: Some(host.as_str()),
                    sni: Some(host.as_str()),
                    method: Some("CONNECT"),
                    path: audit_path.as_deref(),
                    outcome: "allow",
                    status: Some(StatusCode::OK.as_u16()),
                    matched_rule: matched_rule.as_deref(),
                    matched_route: None,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &log_context,
            );
            match action.kind {
                ActionKind::Block | ActionKind::Respond => {
                    let _ = req_stream.finish().await;
                    return Ok(());
                }
                ActionKind::Inspect => {}
                ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {
                    if let Err(err) = relay_h3_connect_stream(
                        req_stream,
                        client_prefetch,
                        upstream_connected.expect("HTTP/3 CONNECT tunnel upstream"),
                        tunnel_idle_timeout,
                    )
                    .await
                    {
                        warn!(error = ?err, "forward HTTP/3 CONNECT relay failed");
                    }
                    return Ok(());
                }
            }
            if let Err(err) = mitm_h3_connect_stream(MitmH3ConnectInput {
                req_stream,
                client_prefetch,
                upstream_tcp: upstream_connected.expect("HTTP/3 CONNECT MITM upstream"),
                runtime: handler.runtime.clone(),
                listener_name: handler.listener_name.clone(),
                remote_addr: conn.remote_addr,
                host,
                port,
                mitm,
                verify_upstream,
                trust: listener_trust,
                header_read_timeout: Duration::from_millis(
                    state.config.runtime.http_header_read_timeout_ms,
                ),
                upstream_timeout,
                tunnel_idle_timeout,
            })
            .await
            {
                warn!(error = ?err, "forward HTTP/3 CONNECT MITM failed");
            }
            return Ok(());
        }
    }

    let upstream = match crate::forward::request::resolve_upstream(
        &action,
        &state,
        handler.listener_name.as_ref(),
    ) {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT upstream resolution failed");
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
            send_policy!(&mut req_stream, response, "error").await?;
            return Ok(());
        }
    };
    rate_limit_context.upstream = upstream.as_ref().map(|upstream| upstream.key().to_string());
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_context) {
        Some(permits) => permits,
        None => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                too_many_requests(None),
                response_headers.as_deref(),
                false,
            );
            send_policy!(&mut req_stream, response, "concurrency_limited").await?;
            return Ok(());
        }
    };
    let server: TunnelIo = match connect_tunnel_target(
        &host,
        port,
        upstream.as_ref(),
        proxy_name.as_str(),
        upstream_timeout,
    )
    .await
    {
        Ok(stream) => stream.io,
        Err(err) => {
            warn!(
                error = ?err,
                upstream = upstream.as_ref().map(|u| u.endpoint().cache_key()),
                "forward HTTP/3 CONNECT tunnel establish failed"
            );
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
            send_policy!(&mut req_stream, response, "error").await?;
            return Ok(());
        }
    };

    let established = build_h3_connect_success_response(
        proxy_name.as_str(),
        &http::Method::CONNECT,
        false,
        response_headers.as_deref(),
    )?;
    tokio::time::timeout(tunnel_idle_timeout, req_stream.send_response(established))
        .await
        .map_err(|_| anyhow!("forward HTTP/3 CONNECT response send timeout"))??;
    let initial_post_connect_action = action.clone();
    let (mut req_stream, client_prefetch, client_hello, mut action) = prepare_h3_connect_stream(
        req_stream,
        &handler.runtime,
        H3ConnectPolicyContext {
            listener_name: handler.listener_name.as_ref(),
            remote_addr: conn.remote_addr,
            host: host.as_str(),
            port,
            authority: authority.as_str(),
            sanitized_headers: sanitized_headers.clone(),
            identity: &identity,
            initial_action: action,
        },
    )
    .await?;
    let listener_cfg = state
        .listener_config(handler.listener_name.as_ref())
        .ok_or_else(|| anyhow!("listener not found"))?;
    let listener_trust = listener_upstream_trust(listener_cfg)?;
    let mut server = Some(server);
    if let Some(client_hello) = client_hello.as_ref() {
        if listener_requires_upstream_cert_preview(listener_cfg)
            && matches!(
                action.kind,
                ActionKind::Inspect | ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
            )
        {
            let preview_verify = listener_cfg
                .tls_inspection
                .as_ref()
                .map(|cfg| {
                    cfg.verify_upstream
                        && !state.tls_verify_exception_matches(
                            handler.listener_name.as_ref(),
                            host.as_str(),
                        )
                })
                .unwrap_or(true);
            let preview_server = server
                .take()
                .expect("HTTP/3 CONNECT upstream tunnel must exist before cert preview");
            match preview_tls_certificate_with_options(
                host.as_str(),
                preview_server,
                preview_verify,
                listener_trust.as_deref(),
            )
            .await
            {
                Ok(upstream_cert) => {
                    action = decide_connect_action_from_tls_metadata(ConnectPolicyInput {
                        runtime: &handler.runtime,
                        listener_name: handler.listener_name.as_ref(),
                        remote_addr: conn.remote_addr,
                        host: host.as_str(),
                        port,
                        authority: authority.as_str(),
                        sanitized_headers: &sanitized_headers,
                        identity: &identity,
                        client_hello,
                        upstream_cert: Some(&upstream_cert),
                    })
                    .await?;
                }
                Err(err) => {
                    if listener_trust.is_some() {
                        return Err(err);
                    }
                    warn!(
                        error = ?err,
                        "forward HTTP/3 CONNECT upstream certificate preview failed"
                    );
                }
            }
        }
    }
    if (server.is_none() || action != initial_post_connect_action)
        && matches!(
            action.kind,
            ActionKind::Inspect | ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
        )
    {
        let upstream = crate::forward::request::resolve_upstream(
            &action,
            &state,
            handler.listener_name.as_ref(),
        )?;
        server = Some(
            connect_tunnel_target(
                host.as_str(),
                port,
                upstream.as_ref(),
                proxy_name.as_str(),
                upstream_timeout,
            )
            .await?
            .io,
        );
    }
    emit_audit_log(
        &state,
        AuditRecord {
            kind: "forward",
            name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            outcome: "allow",
            status: Some(StatusCode::OK.as_u16()),
            matched_rule: matched_rule.as_deref(),
            matched_route: None,
            ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        },
        &log_context,
    );
    match action.kind {
        ActionKind::Block | ActionKind::Respond => {
            let _ = req_stream.finish().await;
            return Ok(());
        }
        ActionKind::Inspect => {
            #[cfg(not(feature = "mitm"))]
            {
                return Ok(());
            }
            #[cfg(feature = "mitm")]
            {
                let tls_inspection = state
                    .listener_config(handler.listener_name.as_ref())
                    .and_then(|l| l.tls_inspection.as_ref());
                if !tls_inspection.map(|t| t.enabled).unwrap_or(false) {
                    return Ok(());
                }
                let verify_upstream = tls_inspection
                    .map(|t| {
                        t.verify_upstream
                            && !state
                                .tls_verify_exception_matches(handler.listener_name.as_ref(), &host)
                    })
                    .unwrap_or(true);
                let Some(mitm) = state.security.mitm.clone() else {
                    return Ok(());
                };
                if let Err(err) = mitm_h3_connect_stream(MitmH3ConnectInput {
                    req_stream,
                    client_prefetch,
                    upstream_tcp: server.expect("HTTP/3 CONNECT MITM upstream"),
                    runtime: handler.runtime.clone(),
                    listener_name: handler.listener_name.clone(),
                    remote_addr: conn.remote_addr,
                    host,
                    port,
                    mitm,
                    verify_upstream,
                    trust: listener_trust,
                    header_read_timeout: Duration::from_millis(
                        state.config.runtime.http_header_read_timeout_ms,
                    ),
                    upstream_timeout,
                    tunnel_idle_timeout,
                })
                .await
                {
                    warn!(error = ?err, "forward HTTP/3 CONNECT MITM failed");
                }
                return Ok(());
            }
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }
    if let Err(err) = relay_h3_connect_stream(
        req_stream,
        client_prefetch,
        server.expect("HTTP/3 CONNECT tunnel upstream"),
        tunnel_idle_timeout,
    )
    .await
    {
        warn!(error = ?err, "forward HTTP/3 CONNECT relay failed");
    }
    Ok(())
}

pub(crate) async fn handle_h3_extended_connect(
    req_head: ::http::Request<()>,
    mut req_stream: H3ServerRequestStream,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
    protocol: ::h3::ext::Protocol,
    datagrams: Option<H3StreamDatagrams>,
) -> Result<()> {
    if protocol == ::h3::ext::Protocol::WEB_TRANSPORT {
        send_h3_static_response(
            &mut req_stream,
            ::http::StatusCode::NOT_IMPLEMENTED,
            b"WEBTRANSPORT relay requires the http3-backend-qpx build",
            &http::Method::CONNECT,
            handler.runtime.state().config.identity.proxy_name.as_str(),
            handler
                .runtime
                .state()
                .config
                .runtime
                .max_h3_response_body_bytes,
        )
        .await?;
        return Ok(());
    }
    let prepared = match prepare_h3_connect_request(
        &req_head,
        &mut req_stream,
        &handler,
        &conn,
        None,
    )
    .await?
    {
        H3ConnectPreparation::Continue(prepared) => *prepared,
        H3ConnectPreparation::Responded => return Ok(()),
    };

    let state = handler.runtime.state();
    let tunnel_idle_timeout =
        Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms.max(1));
    let proxy_name = state.config.identity.proxy_name.clone();
    let PreparedH3Connect {
        host,
        port: _,
        action,
        response_headers,
        log_context,
        matched_rule,
        ext_authz_policy_id,
        audit_path,
        timeout_override,
        rate_limit_profile,
        rate_limit_context,
        sanitized_headers,
        ..
    } = prepared;
    let mut request_limits = state.policy.rate_limiters.collect(
        handler.listener_name.as_ref(),
        matched_rule.as_deref(),
        None,
        crate::rate_limit::TransportScope::Connect,
    );
    request_limits.extend_from(&state.policy.rate_limiters.collect_profile(
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Connect,
    )?);
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
    macro_rules! send_policy {
        ($req_stream:expr, $response:expr, $outcome:expr) => {
            send_h3_policy_response(
                $req_stream,
                $response,
                H3PolicyResponseContext {
                    request_method: &http::Method::CONNECT,
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: $outcome,
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
        };
    }

    if !matches!(
        action.kind,
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
    ) {
        let response = finalize_response_with_headers(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            proxy_name.as_str(),
            blocked(state.messages.blocked.as_str()),
            response_headers.as_deref(),
            false,
        );
        send_policy!(&mut req_stream, response, "block").await?;
        return Ok(());
    }

    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_context) {
        Some(permits) => permits,
        None => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                too_many_requests(None),
                response_headers.as_deref(),
                false,
            );
            send_policy!(&mut req_stream, response, "concurrency_limited").await?;
            return Ok(());
        }
    };

    let verify_upstream = state
        .listener_config(handler.listener_name.as_ref())
        .and_then(|listener| listener.tls_inspection.as_ref())
        .map(|cfg| {
            cfg.verify_upstream
                && !state
                    .tls_verify_exception_matches(handler.listener_name.as_ref(), host.as_str())
        })
        .unwrap_or(true);

    let upstream = match open_upstream_extended_connect_stream(OpenUpstreamExtendedConnectInput {
        req_head: &req_head,
        sanitized_headers: &sanitized_headers,
        proxy_name: proxy_name.as_str(),
        upstream: action.upstream.as_deref(),
        verify_upstream,
        protocol,
        enable_datagram: datagrams.is_some(),
        timeout_dur: upstream_timeout,
    })
    .await
    {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(error = ?err, protocol = ?protocol, "forward HTTP/3 extended CONNECT establish failed");
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
            send_policy!(&mut req_stream, response, "error").await?;
            return Ok(());
        }
    };

    let UpstreamExtendedConnectStream {
        interim,
        response,
        req_stream: upstream_stream,
        datagrams: upstream_datagrams,
        _endpoint,
        driver,
        datagram_task,
        ..
    } = upstream;
    for interim in interim {
        let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
        tokio::time::timeout(tunnel_idle_timeout, req_stream.send_response(interim))
            .await
            .map_err(|_| anyhow!("HTTP/3 extended CONNECT interim response send timed out"))??;
    }
    if !response.status().is_success() {
        let response = upstream_extended_connect_error_response(
            response,
            upstream_stream,
            proxy_name.as_str(),
            response_headers.as_deref(),
            Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
        )?;
        send_h3_response(
            response,
            &http::Method::CONNECT,
            &mut req_stream,
            state.config.runtime.max_h3_response_body_bytes,
            Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
        )
        .await?;
        if let Some(task) = datagram_task {
            task.abort();
            let _ = task.await;
        }
        let _ = driver.await;
        return Ok(());
    }

    let established = finalize_h3_connect_head_response(
        response,
        proxy_name.as_str(),
        response_headers.as_deref(),
    )?;
    tokio::time::timeout(tunnel_idle_timeout, req_stream.send_response(established))
        .await
        .map_err(|_| anyhow!("forward HTTP/3 extended CONNECT response send timeout"))??;
    if let Err(err) = relay_h3_extended_connect_stream(
        req_stream,
        datagrams,
        upstream_stream,
        upstream_datagrams,
        tunnel_idle_timeout,
    )
    .await
    {
        warn!(error = ?err, protocol = ?protocol, "forward HTTP/3 extended CONNECT relay failed");
    }
    if let Some(task) = datagram_task {
        task.abort();
        let _ = task.await;
    }
    let _ = driver.await;
    Ok(())
}
