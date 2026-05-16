use super::*;
use crate::destination::DestinationInputs;
use crate::policy_context::{
    ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, apply_ext_authz_action_overrides,
    emit_audit_log, enforce_ext_authz, resolve_identity, validate_ext_authz_allow_mode,
};
use crate::transparent::destination::ConnectTarget;
use qpx_core::config::ActionKind;
use qpx_core::rules::RuleMatchContext;

pub(super) struct NewUdpSessionContext<'a> {
    pub(super) listener_socket: Arc<UdpSocket>,
    pub(super) sessions: Arc<RwLock<SessionIndex>>,
    pub(super) session_id: u64,
    pub(super) listener_name: &'a str,
    pub(super) runtime: Runtime,
    pub(super) client_addr: SocketAddr,
    pub(super) original_target: Option<SocketAddr>,
    pub(super) packet: Vec<u8>,
    pub(super) run_started: Instant,
    pub(super) idle_timeout: Duration,
}

pub(super) async fn handle_new_udp_session(ctx: NewUdpSessionContext<'_>) -> Result<&'static str> {
    let NewUdpSessionContext {
        listener_socket,
        sessions,
        session_id,
        listener_name,
        runtime,
        client_addr,
        original_target,
        packet,
        run_started,
        idle_timeout,
    } = ctx;
    let state = runtime.state();
    let base_plan = state
        .plan
        .ingress_edge_execution_plan(listener_name, None)
        .ok_or_else(|| anyhow!("listener plan not found"))?;
    let effective_policy = base_plan.policy_context.clone();
    let engine = state
        .policy
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;

    let is_quic = looks_like_quic_initial(&packet);
    let client_hello = is_quic
        .then(|| extract_quic_client_hello_info(&packet))
        .flatten();
    let sni = client_hello.as_ref().and_then(|hello| hello.sni.clone());

    let connect_target = match original_target {
        Some(target) => ConnectTarget::Socket(target),
        None => match sni.clone() {
            Some(host) => ConnectTarget::HostPort(host, 443),
            None => {
                return Ok("blocked");
            }
        },
    };

    let host_for_match_owned = match &connect_target {
        ConnectTarget::HostPort(host, _) => Some(host.clone()),
        ConnectTarget::Socket(addr) => Some(addr.ip().to_string()),
    };
    let authority = connect_target.authority();
    let scheme = if is_quic { "quic" } else { "udp" };
    let identity = resolve_identity(&state, &effective_policy, client_addr.ip(), None, None)?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: host_for_match_owned.as_deref(),
            ip: match &connect_target {
                ConnectTarget::Socket(addr) => Some(addr.ip()),
                ConnectTarget::HostPort(_, _) => host_for_match_owned
                    .as_deref()
                    .and_then(|value| value.parse().ok()),
            },
            sni: sni.as_deref(),
            scheme: Some(scheme),
            port: Some(connect_target.port()),
            alpn: client_hello
                .as_ref()
                .and_then(|hello| hello.alpn.as_deref()),
            ja3: client_hello.as_ref().and_then(|hello| hello.ja3.as_deref()),
            ja4: client_hello.as_ref().and_then(|hello| hello.ja4.as_deref()),
            ..Default::default()
        },
        base_plan.destination_resolution.as_ref(),
    );

    let ctx = RuleMatchContext {
        src_ip: Some(client_addr.ip()),
        dst_port: Some(connect_target.port()),
        host: host_for_match_owned.as_deref(),
        sni: sni.as_deref(),
        authority: Some(authority.as_str()),
        scheme: Some(scheme),
        http_version: client_hello.as_ref().and_then(|hello| {
            hello.alpn.as_deref().and_then(|alpn| {
                if alpn.starts_with("h3") {
                    Some("HTTP/3")
                } else {
                    None
                }
            })
        }),
        alpn: client_hello
            .as_ref()
            .and_then(|hello| hello.alpn.as_deref()),
        tls_version: client_hello
            .as_ref()
            .and_then(|hello| hello.tls_version.as_deref()),
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        ja3: client_hello.as_ref().and_then(|hello| hello.ja3.as_deref()),
        ja4: client_hello.as_ref().and_then(|hello| hello.ja4.as_deref()),
        request_size: Some(packet.len() as u64),
        user: identity.user.as_deref(),
        user_groups: &identity.groups,
        device_id: identity.device_id.as_deref(),
        posture: &identity.posture,
        tenant: identity.tenant.as_deref(),
        auth_strength: identity.auth_strength.as_deref(),
        idp: identity.idp.as_deref(),
        ..Default::default()
    };
    let outcome = engine.evaluate_ref(&ctx);
    let request_limit_ctx =
        RateLimitContext::from_identity(client_addr.ip(), &identity, outcome.matched_rule, None);
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(listener_name, outcome.matched_rule)
        .ok_or_else(|| anyhow!("compiled transparent UDP execution plan not found"))?;
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        crate::rate_limit::TransportScope::Udp,
        &request_limit_ctx,
        1,
    )?;
    if retry_after.is_some() {
        return Ok("blocked");
    }

    let auth_required = outcome.auth.map(|a| !a.require.is_empty()).unwrap_or(false);
    if auth_required || matches!(outcome.action.kind, ActionKind::Block) {
        let log_context = identity.to_log_context(outcome.matched_rule, None, None);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: crate::http::dispatch::ProxyKind::Transparent,
                name: listener_name,
                remote_ip: client_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni.as_deref(),
                method: None,
                path: None,
                outcome: crate::http::dispatch::DispatchOutcome::Block,
                status: None,
                matched_rule: outcome.matched_rule,
                matched_route: None,
                ext_authz_policy_id: None,
            },
            &log_context,
        );
        return Ok("blocked");
    }

    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Transparent,
            proxy_name: state.plan.identity.proxy_name.as_ref(),
            scope_name: listener_name,
            remote_ip: client_addr.ip(),
            dst_port: Some(connect_target.port()),
            host: host_for_match_owned.as_deref(),
            sni: sni.as_deref(),
            method: None,
            path: None,
            uri: None,
            matched_rule: outcome.matched_rule,
            matched_route: None,
            action: Some(outcome.action),
            headers: None,
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
    let rate_limit_profile = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.rate_limit_profile.clone(),
        ExtAuthzEnforcement::Deny(_) => None,
    };
    let mut log_context =
        identity.to_log_context(outcome.matched_rule, None, ext_authz_policy_id.as_deref());
    log_context.policy_tags = ext_authz_policy_tags;
    let mut action = outcome.action.clone();
    let timeout_override = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::TransparentUdp)?;
            if request_limits
                .merge_profile_and_check(
                    &state.policy.rate_limiters,
                    allow.rate_limit_profile.as_deref(),
                    crate::rate_limit::TransportScope::Udp,
                    &request_limit_ctx,
                    1,
                )?
                .is_some()
            {
                return Ok("blocked");
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            allow.timeout_override
        }
        ExtAuthzEnforcement::Deny(_) => {
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: crate::http::dispatch::ProxyKind::Transparent,
                    name: listener_name,
                    remote_ip: client_addr.ip(),
                    host: host_for_match_owned.as_deref(),
                    sni: sni.as_deref(),
                    method: None,
                    path: None,
                    outcome: crate::http::dispatch::DispatchOutcome::ExtAuthzDeny,
                    status: None,
                    matched_rule: outcome.matched_rule,
                    matched_route: None,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &log_context,
            );
            return Ok("blocked");
        }
    };

    if matches!(
        action.kind,
        ActionKind::Inspect | ActionKind::Respond | ActionKind::Block
    ) {
        emit_audit_log(
            &state,
            AuditRecord {
                kind: crate::http::dispatch::ProxyKind::Transparent,
                name: listener_name,
                remote_ip: client_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni.as_deref(),
                method: None,
                path: None,
                outcome: crate::http::dispatch::DispatchOutcome::Block,
                status: None,
                matched_rule: outcome.matched_rule,
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &log_context,
        );
        return Ok("blocked");
    }

    let rate_limit_ctx = RateLimitContext::from_identity(
        client_addr.ip(),
        &identity,
        outcome.matched_rule,
        Some(authority.as_str()),
    );
    let concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
        Some(permits) => permits,
        None => return Ok("blocked"),
    };
    let udp = Arc::new(
        connect_udp_target(
            &connect_target,
            timeout_override.unwrap_or_else(|| {
                Duration::from_millis(state.plan.limits.upstream_http_timeout_ms)
            }),
        )
        .await?,
    );
    let (close_tx, _close_rx) = watch::channel(false);
    let target_key = authority.clone();
    let now_ms = run_started.elapsed().as_millis() as u64;
    let session = Arc::new(TransparentUdpSession::new(TransparentUdpSessionInit {
        socket: udp.clone(),
        close_tx,
        client_addr,
        target_key: target_key.clone(),
        matched_rule: outcome.matched_rule.map(str::to_string),
        rate_limit_profile,
        seen_ms: now_ms,
        limits: request_limits.clone(),
        rate_limit_ctx: rate_limit_ctx.clone(),
        concurrency_permits,
    }));
    {
        let mut guard = sessions
            .write()
            .map_err(|_| anyhow!("transparent udp session lock poisoned"))?;
        guard.insert(session_id, session.clone());
        guard.observe_client_packet(session_id, &packet);
    }

    let relay_task = spawn_transparent_udp_relay(
        listener_socket.clone(),
        sessions.clone(),
        session_id,
        session.clone(),
        udp.clone(),
        idle_timeout,
        run_started,
    );
    session.attach_relay_task(relay_task);

    if let Ok(delay) =
        apply_udp_bandwidth_controls(&rate_limit_ctx, &request_limits, packet.len() as u64)
    {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    } else {
        return Ok("blocked");
    }
    udp.send(packet.as_slice()).await?;
    emit_audit_log(
        &state,
        AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Transparent,
            name: listener_name,
            remote_ip: client_addr.ip(),
            host: host_for_match_owned.as_deref(),
            sni: sni.as_deref(),
            method: None,
            path: None,
            outcome: crate::http::dispatch::DispatchOutcome::Allow,
            status: None,
            matched_rule: outcome.matched_rule,
            matched_route: None,
            ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        },
        &log_context,
    );
    Ok("tunneled")
}

async fn connect_udp_target(target: &ConnectTarget, timeout_dur: Duration) -> Result<UdpSocket> {
    match target {
        ConnectTarget::Socket(addr) => {
            let bind_addr: SocketAddr = if addr.is_ipv4() {
                UNSPECIFIED_V4
            } else {
                UNSPECIFIED_V6
            };
            let udp = UdpSocket::bind(bind_addr).await?;
            timeout(timeout_dur, udp.connect(*addr)).await??;
            Ok(udp)
        }
        ConnectTarget::HostPort(host, port) => {
            let resolved = timeout(timeout_dur, tokio::net::lookup_host((host.as_str(), *port)))
                .await??
                .next()
                .ok_or_else(|| anyhow!("no UDP target address resolved for {}:{}", host, port))?;
            let bind_addr: SocketAddr = if resolved.is_ipv4() {
                UNSPECIFIED_V4
            } else {
                UNSPECIFIED_V6
            };
            let udp = UdpSocket::bind(bind_addr).await?;
            timeout(timeout_dur, udp.connect(resolved)).await??;
            Ok(udp)
        }
    }
}

pub(super) fn apply_udp_bandwidth_controls(
    ctx: &RateLimitContext,
    limits: &AppliedRateLimits,
    bytes: u64,
) -> Result<Duration, ()> {
    limits.reserve_bytes(ctx, bytes)
}
