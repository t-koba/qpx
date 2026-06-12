use super::session::SharedSessionIndex;
use super::{
    TransparentUdpSession, TransparentUdpSessionInit, UNSPECIFIED_V4, UNSPECIFIED_V6,
    spawn_transparent_udp_relay,
};
use crate::http::dispatch::{DispatchOutcome, ProxyKind};
use crate::policy_context::{
    AuditRecord, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, emit_audit_log,
    enforce_ext_authz, prepare_ext_authz_allow_controls,
};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext, TransportScope};
use crate::runtime::Runtime;
use crate::transparent::destination::ConnectTarget;
use anyhow::{Result, anyhow};
use qpx_core::config::ActionKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::{Duration, timeout};

mod rule_eval;

use self::rule_eval::{UdpRuleEvaluation, prepare_udp_rule_evaluation};

pub(super) struct NewUdpSessionContext<'a> {
    pub(super) listener_socket: Arc<UdpSocket>,
    pub(super) sessions: Arc<SharedSessionIndex>,
    pub(super) session_id: u64,
    pub(super) listener_name: &'a str,
    pub(super) runtime: Runtime,
    pub(super) client_addr: SocketAddr,
    pub(super) original_target: Option<SocketAddr>,
    pub(super) packet: &'a [u8],
    pub(super) run_started: Instant,
    pub(super) idle_timeout: Duration,
}

struct StartUdpSessionInput<'a> {
    listener_socket: Arc<UdpSocket>,
    sessions: Arc<SharedSessionIndex>,
    session_id: u64,
    client_addr: SocketAddr,
    connect_target: ConnectTarget,
    authority: String,
    matched_rule: Option<&'a str>,
    rate_limit_profile: Option<String>,
    request_limits: AppliedRateLimits,
    rate_limit_ctx: RateLimitContext,
    concurrency_permits: crate::rate_limit::ConcurrencyPermits,
    packet: &'a [u8],
    run_started: Instant,
    idle_timeout: Duration,
    upstream_timeout: Duration,
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

    let UdpRuleEvaluation {
        connect_target,
        host_for_match_owned,
        authority,
        identity,
        sni,
        outcome,
        request_limit_ctx,
        mut request_limits,
    } = match prepare_udp_rule_evaluation(
        &state,
        engine,
        listener_name,
        &effective_policy,
        client_addr,
        original_target,
        packet,
        base_plan.destination_resolution.as_ref(),
    )? {
        Some(evaluation) => evaluation,
        None => return Ok("blocked"),
    };

    let auth_required = outcome.auth.map(|a| !a.require.is_empty()).unwrap_or(false);
    if auth_required || matches!(outcome.action.kind, ActionKind::Block) {
        let log_context = identity.to_log_context(outcome.matched_rule, None, None);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: ProxyKind::Transparent,
                name: listener_name,
                remote_ip: client_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni.as_deref(),
                method: None,
                path: None,
                outcome: DispatchOutcome::Block,
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
            proxy_kind: ProxyKind::Transparent,
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
    let ext_authz_policy_id = ext_authz.policy_id().map(str::to_owned);
    let ext_authz_policy_tags = ext_authz.policy_tags().to_vec();
    let rate_limit_profile;
    let mut log_context =
        identity.to_log_context(outcome.matched_rule, None, ext_authz_policy_id.as_deref());
    log_context.policy_tags = ext_authz_policy_tags;
    let emit_decision_audit = |audit_outcome| {
        emit_audit_log(
            &state,
            AuditRecord {
                kind: ProxyKind::Transparent,
                name: listener_name,
                remote_ip: client_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni.as_deref(),
                method: None,
                path: None,
                outcome: audit_outcome,
                status: None,
                matched_rule: outcome.matched_rule,
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &log_context,
        );
    };
    let mut action = outcome.action.clone();
    let timeout_override = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            let allow =
                prepare_ext_authz_allow_controls(allow, ExtAuthzMode::TransparentUdp, None)?;
            if request_limits
                .merge_profile_and_check(
                    &state.policy.rate_limiters,
                    allow.rate_limit_profile.as_deref(),
                    TransportScope::Udp,
                    &request_limit_ctx,
                    1,
                )?
                .is_some()
            {
                return Ok("blocked");
            }
            rate_limit_profile = allow.rate_limit_profile.clone();
            allow.apply_action_overrides(&mut action);
            allow.timeout_override
        }
        ExtAuthzEnforcement::Deny(_) => {
            emit_decision_audit(DispatchOutcome::ExtAuthzDeny);
            return Ok("blocked");
        }
    };

    if matches!(
        action.kind,
        ActionKind::Inspect | ActionKind::Respond | ActionKind::Block
    ) {
        emit_decision_audit(DispatchOutcome::Block);
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
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    let started = start_udp_session(StartUdpSessionInput {
        listener_socket,
        sessions,
        session_id,
        client_addr,
        connect_target,
        authority,
        matched_rule: outcome.matched_rule,
        rate_limit_profile,
        request_limits,
        rate_limit_ctx,
        concurrency_permits,
        packet,
        run_started,
        idle_timeout,
        upstream_timeout,
    })
    .await?;
    if !started {
        return Ok("blocked");
    }
    emit_decision_audit(DispatchOutcome::Allow);
    Ok("tunneled")
}

async fn start_udp_session(input: StartUdpSessionInput<'_>) -> Result<bool> {
    let udp = Arc::new(connect_udp_target(&input.connect_target, input.upstream_timeout).await?);
    let (close_tx, _close_rx) = watch::channel(false);
    let session = Arc::new(TransparentUdpSession::new(TransparentUdpSessionInit {
        socket: udp.clone(),
        close_tx,
        client_addr: input.client_addr,
        target_key: input.authority,
        matched_rule: input.matched_rule.map(str::to_string),
        rate_limit_profile: input.rate_limit_profile,
        seen_ms: input.run_started.elapsed().as_millis() as u64,
        limits: input.request_limits.clone(),
        rate_limit_ctx: input.rate_limit_ctx.clone(),
        concurrency_permits: input.concurrency_permits,
    }));
    input.sessions.insert(input.session_id, session.clone());
    input
        .sessions
        .observe_client_packet(input.session_id, input.packet);
    let relay_task = spawn_transparent_udp_relay(
        input.listener_socket,
        input.sessions.clone(),
        input.session_id,
        session.clone(),
        udp.clone(),
        input.idle_timeout,
        input.run_started,
    );
    session.attach_relay_task(relay_task);
    let delay = match apply_udp_bandwidth_controls(
        &input.rate_limit_ctx,
        &input.request_limits,
        input.packet.len() as u64,
    ) {
        Ok(delay) => delay,
        Err(()) => {
            cleanup_new_udp_session(&input.sessions, input.session_id);
            return Ok(false);
        }
    };
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    if let Err(err) = udp.send(input.packet).await {
        cleanup_new_udp_session(&input.sessions, input.session_id);
        return Err(err.into());
    }
    Ok(true)
}

fn cleanup_new_udp_session(sessions: &SharedSessionIndex, session_id: u64) {
    if let Some(session) = sessions.remove_session(session_id) {
        let _ = session.close_tx.send(true);
    }
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
