use super::destination::ConnectTarget;
use super::quic::{extract_quic_client_hello_info, looks_like_quic_initial};
use crate::destination::DestinationInputs;
use crate::policy_context::{
    apply_ext_authz_action_overrides, emit_audit_log, enforce_ext_authz, resolve_identity,
    validate_ext_authz_allow_mode, AuditRecord, EffectivePolicyContext, ExtAuthzEnforcement,
    ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use crate::runtime::Runtime;
use crate::sidecar_control::SidecarControl;
use crate::udp_session_handoff::{
    ExportedQuicConnectionId, TransparentUdpListenerRestore, TransparentUdpSessionRestore,
    UdpSessionRestoreState,
};
use crate::udp_socket_handoff::duplicate_tokio_udp_socket;
use anyhow::{anyhow, Context, Result};
use metrics::{counter, histogram};
use qpx_core::config::{ActionKind, ListenerConfig};
use qpx_core::rules::RuleMatchContext;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{timeout, Duration, MissedTickBehavior};
use tracing::{info, warn};

#[path = "udp_session.rs"]
mod udp_session;
#[cfg(test)]
use self::udp_session::parse_quic_long_header;
use self::udp_session::{SessionIndex, TransparentUdpSession, TransparentUdpSessionInit};
use super::udp_socket::{bind_udp_listener, recv_transparent_datagram};

struct NewUdpSessionContext<'a> {
    listener_socket: Arc<UdpSocket>,
    sessions: Arc<RwLock<SessionIndex>>,
    session_id: u64,
    listener_name: &'a str,
    runtime: Runtime,
    client_addr: SocketAddr,
    original_target: Option<SocketAddr>,
    packet: Vec<u8>,
    run_started: Instant,
    idle_timeout: Duration,
}

pub(super) async fn run_transparent_udp_listener(
    listener: ListenerConfig,
    runtime: Runtime,
    mut shutdown: watch::Receiver<SidecarControl>,
    inherited_socket: Option<std::net::UdpSocket>,
    restore: Option<TransparentUdpListenerRestore>,
    export_sink: Arc<Mutex<UdpSessionRestoreState>>,
) -> Result<()> {
    let listen_addr: SocketAddr = listener
        .http3
        .as_ref()
        .and_then(|cfg| cfg.listen.clone())
        .unwrap_or_else(|| listener.listen.clone())
        .parse()?;
    let socket = Arc::new(match inherited_socket {
        Some(socket) => {
            socket
                .set_nonblocking(true)
                .context("failed to set inherited transparent UDP socket nonblocking")?;
            UdpSocket::from_std(socket)
                .context("failed to adopt inherited transparent UDP socket")?
        }
        None => bind_udp_listener(listen_addr, &runtime.state().config.runtime)?,
    });
    let sessions: Arc<RwLock<SessionIndex>> = Arc::new(RwLock::new(SessionIndex::new()));
    let idle_timeout =
        Duration::from_millis(runtime.state().config.runtime.tunnel_idle_timeout_ms.max(1));
    let idle_timeout_ms = idle_timeout.as_millis() as u64;
    let run_started = restore
        .as_ref()
        .map(|state| run_started_from_exported_elapsed(state.exported_elapsed_ms))
        .unwrap_or_else(Instant::now);
    let listener_name = listener.name.clone();

    info!(
        listener = %listener.name,
        addr = %listen_addr,
        "transparent UDP/QUIC listener starting"
    );

    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut next_session_id = 1u64;
    if let Some(restore) = restore {
        next_session_id = restore_transparent_udp_sessions(
            listener_name.as_str(),
            socket.clone(),
            sessions.clone(),
            &runtime,
            restore,
            idle_timeout,
            run_started,
        )
        .await?;
    }
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                let stop_mode = if changed.is_err() {
                    SidecarControl::Stop
                } else {
                    *shutdown.borrow()
                };
                if stop_mode.should_stop() {
                    drain_transparent_udp_sessions(
                        listener_name.as_str(),
                        listen_addr,
                        sessions.clone(),
                        run_started,
                        stop_mode.should_export(),
                        export_sink.as_ref(),
                    )
                    .await?;
                    break;
                }
            }
            _ = cleanup.tick() => {
                let now_ms = run_started.elapsed().as_millis() as u64;
                let expired = {
                    let mut guard = sessions.write().expect("transparent udp session lock");
                    guard.evict_expired(now_ms, idle_timeout_ms)
                };
                for session in expired {
                    let _ = session.close_tx.send(true);
                }
            }
            recv = recv_transparent_datagram(socket.as_ref(), &mut buf) => {
                let started = Instant::now();
                let (n, client_addr, original_target) = recv?;
                let packet = buf[..n].to_vec();
                let target_key = original_target
                    .filter(|target| Some(*target) != socket.local_addr().ok())
                    .map(|target| target.to_string());
                let existing = {
                    let guard = sessions.read().expect("transparent udp session lock");
                    guard.find_session_for_client_packet(
                        client_addr,
                        target_key.as_deref(),
                        &packet,
                    ).and_then(|session_id| guard.session(session_id))
                };

                let result = if let Some(session) = existing {
                    let now_ms = run_started.elapsed().as_millis() as u64;
                    session.mark_client_seen(now_ms);
                    let bandwidth = apply_udp_bandwidth_controls(
                        &session.rate_limit_ctx,
                        &session.limits,
                        packet.len() as u64,
                    );
                    if let Err(()) = bandwidth {
                        "blocked"
                    } else if let Ok(delay) = bandwidth {
                        if !delay.is_zero() {
                            tokio::time::sleep(delay).await;
                        }
                        if let Err(err) = session.socket.send(packet.as_slice()).await {
                            warn!(
                                error = ?err,
                                client = %client_addr,
                                target = %session.target_key,
                                "transparent UDP upstream send failed"
                            );
                            let mut guard = sessions.write().expect("transparent udp session lock");
                            if let Some(session_id) = guard.find_session_for_client_packet(
                                client_addr,
                                target_key.as_deref(),
                                &packet,
                            ) {
                                if let Some(session) = guard.remove_session(session_id) {
                                    let _ = session.close_tx.send(true);
                                }
                            }
                            "error"
                        } else {
                            let session_id = {
                                let guard = sessions.read().expect("transparent udp session lock");
                                guard.find_session_for_client_packet(
                                    client_addr,
                                    target_key.as_deref(),
                                    &packet,
                                )
                            };
                            if let Some(session_id) = session_id {
                                let mut guard = sessions.write().expect("transparent udp session lock");
                                guard.update_client_address(session_id, client_addr);
                                guard.observe_client_packet(session_id, &packet);
                            }
                            "tunneled"
                        }
                    } else {
                        warn!(
                            client = %client_addr,
                            target = %session.target_key,
                            "transparent UDP bandwidth evaluation reached unexpected state"
                        );
                        "error"
                    }
                } else {
                    match handle_new_udp_session(NewUdpSessionContext {
                        listener_socket: socket.clone(),
                        sessions: sessions.clone(),
                        session_id: next_session_id,
                        listener_name: &listener_name,
                        runtime: runtime.clone(),
                        client_addr,
                        original_target,
                        packet,
                        run_started,
                        idle_timeout,
                    })
                    .await {
                        Ok(result) => {
                            if result == "tunneled" {
                                next_session_id = next_session_id.wrapping_add(1);
                            }
                            result
                        }
                        Err(err) => {
                            warn!(error = ?err, "transparent UDP session setup failed");
                            "error"
                        }
                    }
                };

                let state = runtime.state();
                counter!(
                    state.observability.metric_names.transparent_requests_total.clone(),
                    "result" => result
                )
                .increment(1);
                histogram!(state.observability.metric_names.transparent_latency_ms.clone())
                    .record(started.elapsed().as_secs_f64() * 1000.0);
            }
        }
    }
    Ok(())
}

fn run_started_from_exported_elapsed(exported_elapsed_ms: u64) -> Instant {
    Instant::now()
        .checked_sub(Duration::from_millis(exported_elapsed_ms))
        .unwrap_or_else(Instant::now)
}

async fn drain_transparent_udp_sessions(
    listener_name: &str,
    listen_addr: SocketAddr,
    sessions: Arc<RwLock<SessionIndex>>,
    run_started: Instant,
    export: bool,
    export_sink: &Mutex<UdpSessionRestoreState>,
) -> Result<()> {
    let drained = {
        let mut guard = sessions.write().expect("transparent udp session lock");
        guard.drain_all()
    };
    for (_, session) in &drained {
        let _ = session.close_tx.send(true);
    }
    for task in drained
        .iter()
        .filter_map(|(_, session)| session.take_relay_task())
    {
        task.await
            .map_err(|err| anyhow!("transparent UDP relay join failed: {err}"))?;
    }
    if export && !drained.is_empty() {
        let exported_elapsed_ms = run_started.elapsed().as_millis() as u64;
        let mut restored = Vec::with_capacity(drained.len());
        for (session_id, session) in drained {
            restored.push(TransparentUdpSessionRestore {
                session_id,
                upstream_local_addr: session
                    .socket
                    .local_addr()
                    .context("failed to resolve transparent UDP upstream local addr")?,
                upstream_peer_addr: session
                    .socket
                    .peer_addr()
                    .context("failed to resolve transparent UDP upstream peer addr")?,
                socket: duplicate_tokio_udp_socket(session.socket.as_ref())?,
                client_addr: session.current_client_addr(),
                target_key: session.target_key.clone(),
                last_seen_ms: session.last_seen_ms(),
                client_cid_len: session.client_cid_len(),
                server_cid_len: session.server_cid_len(),
                cids: session
                    .snapshot_cids()
                    .into_iter()
                    .map(|cid| ExportedQuicConnectionId {
                        len: cid.len,
                        bytes: cid.bytes,
                    })
                    .collect(),
                matched_rule: session.matched_rule.clone(),
                rate_limit_profile: session.rate_limit_profile.clone(),
                rate_limit_ctx: session.rate_limit_ctx.clone(),
            });
        }
        export_sink
            .lock()
            .expect("transparent export lock")
            .insert_transparent(
                listener_name.to_string(),
                TransparentUdpListenerRestore {
                    listen: listen_addr.to_string(),
                    exported_elapsed_ms,
                    sessions: restored,
                },
            );
    }
    Ok(())
}

async fn restore_transparent_udp_sessions(
    listener_name: &str,
    listener_socket: Arc<UdpSocket>,
    sessions: Arc<RwLock<SessionIndex>>,
    runtime: &Runtime,
    restore: TransparentUdpListenerRestore,
    idle_timeout: Duration,
    run_started: Instant,
) -> Result<u64> {
    let mut next_session_id = 1u64;
    for restored in restore.sessions {
        restored
            .socket
            .set_nonblocking(true)
            .context("failed to set restored transparent UDP session nonblocking")?;
        let socket = Arc::new(
            UdpSocket::from_std(restored.socket)
                .context("failed to adopt restored transparent UDP session socket")?,
        );
        let limits = runtime.state().policy.rate_limiters.collect(
            listener_name,
            restored.matched_rule.as_deref(),
            restored.rate_limit_profile.as_deref(),
            crate::rate_limit::TransportScope::Udp,
        );
        let concurrency_permits = limits
            .acquire_concurrency(&restored.rate_limit_ctx)
            .ok_or_else(|| anyhow!("failed to reacquire transparent UDP concurrency permit"))?;
        let (close_tx, _close_rx) = watch::channel(false);
        let session = Arc::new(TransparentUdpSession::new(TransparentUdpSessionInit {
            socket: socket.clone(),
            close_tx,
            client_addr: restored.client_addr,
            target_key: restored.target_key,
            matched_rule: restored.matched_rule,
            rate_limit_profile: restored.rate_limit_profile,
            seen_ms: restored.last_seen_ms,
            limits: limits.clone(),
            rate_limit_ctx: restored.rate_limit_ctx,
            concurrency_permits,
        }));
        session.set_client_cid_len_if_some(restored.client_cid_len);
        session.set_server_cid_len_if_some(restored.server_cid_len);
        let cids = restored
            .cids
            .into_iter()
            .map(|cid| udp_session::QuicConnectionId {
                len: cid.len,
                bytes: cid.bytes,
            })
            .collect::<Vec<_>>();
        {
            let mut guard = sessions.write().expect("transparent udp session lock");
            guard.insert_restored(restored.session_id, session.clone(), cids);
        }
        let relay_task = spawn_transparent_udp_relay(
            listener_socket.clone(),
            sessions.clone(),
            restored.session_id,
            session.clone(),
            socket,
            idle_timeout,
            run_started,
        );
        session.attach_relay_task(relay_task);
        next_session_id = next_session_id.max(restored.session_id.wrapping_add(1));
    }
    Ok(next_session_id)
}

fn spawn_transparent_udp_relay(
    listener_socket: Arc<UdpSocket>,
    sessions: Arc<RwLock<SessionIndex>>,
    session_id: u64,
    session: Arc<TransparentUdpSession>,
    udp_recv: Arc<UdpSocket>,
    idle_timeout: Duration,
    run_started: Instant,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut recv_buf = vec![0u8; 65535];
        let mut close_rx = session.close_tx.subscribe();
        loop {
            let n = tokio::select! {
                changed = close_rx.changed() => {
                    if changed.is_ok() && *close_rx.borrow() {
                        break;
                    }
                    continue;
                }
                recv = timeout(idle_timeout, udp_recv.recv(&mut recv_buf)) => {
                    match recv {
                        Ok(Ok(n)) => n,
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
            };
            let now_ms = run_started.elapsed().as_millis() as u64;
            session.mark_upstream_seen(now_ms);
            if let Ok(delay) =
                apply_udp_bandwidth_controls(&session.rate_limit_ctx, &session.limits, n as u64)
            {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            } else {
                break;
            }
            {
                let mut guard = sessions.write().expect("transparent udp session lock");
                guard.observe_upstream_packet(session_id, &recv_buf[..n]);
            }
            let client_addr = session.current_client_addr();
            if listener_socket
                .send_to(&recv_buf[..n], client_addr)
                .await
                .is_err()
            {
                break;
            }
        }
        let mut guard = sessions.write().expect("transparent udp session lock");
        let _ = guard.remove_session(session_id);
    })
}

async fn handle_new_udp_session(ctx: NewUdpSessionContext<'_>) -> Result<&'static str> {
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
    let listener_cfg = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let effective_policy =
        EffectivePolicyContext::from_single(listener_cfg.policy_context.as_ref());
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
        listener_cfg.destination_resolution.as_ref(),
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
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_request(
        crate::rate_limit::RequestLimitCollectInput {
            listener: Some(listener_name),
            rule: outcome.matched_rule,
            profile: None,
            scope: crate::rate_limit::TransportScope::Udp,
            extra: None,
            ctx: &request_limit_ctx,
            cost: 1,
        },
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
                kind: "transparent",
                name: listener_name,
                remote_ip: client_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni.as_deref(),
                method: None,
                path: None,
                outcome: "block",
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
            proxy_kind: "transparent",
            proxy_name: state.config.identity.proxy_name.as_str(),
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
                    kind: "transparent",
                    name: listener_name,
                    remote_ip: client_addr.ip(),
                    host: host_for_match_owned.as_deref(),
                    sni: sni.as_deref(),
                    method: None,
                    path: None,
                    outcome: "ext_authz_deny",
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
                kind: "transparent",
                name: listener_name,
                remote_ip: client_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni.as_deref(),
                method: None,
                path: None,
                outcome: "block",
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
                Duration::from_millis(state.config.runtime.upstream_http_timeout_ms)
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
        let mut guard = sessions.write().expect("transparent udp session lock");
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
            kind: "transparent",
            name: listener_name,
            remote_ip: client_addr.ip(),
            host: host_for_match_owned.as_deref(),
            sni: sni.as_deref(),
            method: None,
            path: None,
            outcome: "allow",
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
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
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
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let udp = UdpSocket::bind(bind_addr).await?;
            timeout(timeout_dur, udp.connect(resolved)).await??;
            Ok(udp)
        }
    }
}

fn apply_udp_bandwidth_controls(
    ctx: &RateLimitContext,
    limits: &AppliedRateLimits,
    bytes: u64,
) -> Result<Duration, ()> {
    limits.reserve_bytes(ctx, bytes)
}

#[cfg(test)]
#[path = "udp_path_tests.rs"]
mod tests;
