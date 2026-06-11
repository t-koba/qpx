use super::destination::{ConnectTarget, connect_target_stream, resolve_upstream};
use crate::http::dispatch::{DispatchOutcome, ProxyKind};
use crate::policy_context::{
    AuditRecord, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, emit_audit_log,
    enforce_ext_authz, prepare_ext_authz_allow_controls, resolve_identity,
};
use crate::rate_limit::{RateLimitContext, TransportScope};
use crate::runtime::Runtime;
use crate::tls::TlsClientHelloInfo;
use anyhow::{Result, anyhow};
use qpx_core::config::ActionKind;
use qpx_http::tls::client::preview_tls_certificate_with_options;
use std::net::SocketAddr;
use tokio::time::Duration;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransparentTlsOutcome {
    Tunneled,
    #[cfg(feature = "mitm")]
    Inspected,
    Blocked,
}

fn resolve_tls_connect_target(
    original_target: Option<ConnectTarget>,
    client_hello: Option<&TlsClientHelloInfo>,
) -> Result<(ConnectTarget, Option<String>)> {
    let sni = client_hello.and_then(|hello| hello.sni.clone());
    let connect_target = match original_target {
        Some(target) => target,
        None => match sni.clone() {
            Some(host) => ConnectTarget::HostPort(host, 443),
            None => {
                return Err(anyhow!(
                    "transparent TLS on this OS requires SNI when original destination is unavailable"
                ));
            }
        },
    };
    Ok((connect_target, sni))
}

impl TransparentTlsOutcome {
    pub(super) fn metric_result(self) -> &'static str {
        match self {
            Self::Tunneled => "tunneled",
            #[cfg(feature = "mitm")]
            Self::Inspected => "inspected",
            Self::Blocked => "blocked",
        }
    }
}

pub(super) async fn handle_tls_connection<I>(
    stream: I,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
    runtime: Runtime,
    client_hello: Option<TlsClientHelloInfo>,
) -> Result<TransparentTlsOutcome>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (connect_target, sni) = resolve_tls_connect_target(original_target, client_hello.as_ref())?;

    let host_for_match_owned = match &connect_target {
        ConnectTarget::HostPort(host, _) => Some(host.clone()),
        ConnectTarget::Socket(addr) => Some(addr.ip().to_string()),
    };
    let sni_for_match = matches!(&connect_target, ConnectTarget::HostPort(_, _))
        .then_some(sni.as_deref())
        .flatten();

    let state = runtime.state();
    let listener_cfg = state
        .ingress_edge_settings(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let base_plan = state
        .plan
        .ingress_edge_execution_plan(listener_name, None)
        .ok_or_else(|| anyhow!("listener plan not found"))?;
    let effective_policy = base_plan.policy_context.clone();
    let identity = resolve_identity(&state, &effective_policy, remote_addr.ip(), None, None)?;
    let listener_trust = listener_upstream_trust(listener_cfg)?;
    let mut decision = evaluate_tls_policy_decision(TransparentTlsPolicyInput {
        runtime: &runtime,
        listener_name,
        remote_addr,
        connect_target: &connect_target,
        host_for_match: host_for_match_owned.as_deref(),
        sni_for_match,
        client_hello: client_hello.as_ref(),
        identity: &identity,
        upstream_cert: None,
    })?;
    if client_hello.is_some()
        && listener_requires_upstream_cert_preview(listener_cfg)
        && matches!(
            decision.action.kind,
            ActionKind::Inspect | ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
        )
    {
        let verify_upstream = listener_cfg
            .tls_inspection
            .as_ref()
            .map(|cfg| {
                let verify = cfg.verify_upstream;
                #[cfg(feature = "mitm")]
                {
                    verify
                        && !state.tls_verify_exception_matches(
                            listener_name,
                            sni_for_match
                                .or(host_for_match_owned.as_deref())
                                .unwrap_or_default(),
                        )
                }
                #[cfg(not(feature = "mitm"))]
                verify
            })
            .unwrap_or(true);
        let preview_domain = sni_for_match
            .or(host_for_match_owned.as_deref())
            .unwrap_or_default();
        let preview_upstream = resolve_upstream(&decision.action, &state, listener_cfg)?;
        match connect_target_stream(
            &connect_target,
            preview_upstream.as_ref(),
            state.plan.identity.proxy_name.as_ref(),
            Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms),
        )
        .await
        {
            Ok(upstream_connected) => {
                match preview_tls_certificate_with_options(
                    preview_domain,
                    upstream_connected.io,
                    verify_upstream,
                    listener_trust.as_deref(),
                )
                .await
                {
                    Ok(upstream_cert) => {
                        decision = evaluate_tls_policy_decision(TransparentTlsPolicyInput {
                            runtime: &runtime,
                            listener_name,
                            remote_addr,
                            connect_target: &connect_target,
                            host_for_match: host_for_match_owned.as_deref(),
                            sni_for_match,
                            client_hello: client_hello.as_ref(),
                            identity: &identity,
                            upstream_cert: Some(&upstream_cert),
                        })?;
                    }
                    Err(err) => {
                        if listener_trust.is_some() {
                            return Err(err);
                        }
                        warn!(error = ?err, "transparent TLS upstream certificate preview failed");
                    }
                }
            }
            Err(err) => {
                warn!(error = ?err, "transparent TLS upstream certificate preview connect failed");
            }
        }
    }
    let request_limit_ctx = RateLimitContext::from_identity(
        remote_addr.ip(),
        &identity,
        decision.matched_rule.as_deref(),
        None,
    );
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(listener_name, decision.matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled transparent TLS execution plan not found"))?;
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        TransportScope::Connect,
        &request_limit_ctx,
        1,
    )?;
    if retry_after.is_some() {
        return Ok(TransparentTlsOutcome::Blocked);
    }
    if decision.auth_required || matches!(decision.action.kind, ActionKind::Block) {
        let log_context = identity.to_log_context(decision.matched_rule.as_deref(), None, None);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: ProxyKind::Transparent,
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni_for_match,
                method: None,
                path: None,
                outcome: DispatchOutcome::Block,
                status: None,
                matched_rule: decision.matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: None,
            },
            &log_context,
        );
        return Ok(TransparentTlsOutcome::Blocked);
    }

    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: ProxyKind::Transparent,
            proxy_name: state.plan.identity.proxy_name.as_ref(),
            scope_name: listener_name,
            remote_ip: remote_addr.ip(),
            dst_port: Some(connect_target.port()),
            host: host_for_match_owned.as_deref(),
            sni: sni_for_match,
            method: None,
            path: None,
            uri: None,
            matched_rule: decision.matched_rule.as_deref(),
            matched_route: None,
            action: Some(&decision.action),
            headers: None,
            identity: &identity,
        },
    )
    .await?;
    let ext_authz_policy_id = ext_authz.policy_id().map(str::to_owned);
    let ext_authz_policy_tags = ext_authz.policy_tags().to_vec();
    let mut log_context = identity.to_log_context(
        decision.matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    log_context.policy_tags = ext_authz_policy_tags;
    let emit_decision_audit = |audit_outcome| {
        emit_audit_log(
            &state,
            AuditRecord {
                kind: ProxyKind::Transparent,
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni_for_match,
                method: None,
                path: None,
                outcome: audit_outcome,
                status: None,
                matched_rule: decision.matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &log_context,
        );
    };
    let mut action = decision.action.clone();
    let timeout_override = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            let allow =
                prepare_ext_authz_allow_controls(allow, ExtAuthzMode::TransparentTls, None)?;
            if request_limits
                .merge_profile_and_check(
                    &state.policy.rate_limiters,
                    allow.rate_limit_profile.as_deref(),
                    TransportScope::Connect,
                    &request_limit_ctx,
                    1,
                )?
                .is_some()
            {
                return Ok(TransparentTlsOutcome::Blocked);
            }
            allow.apply_action_overrides(&mut action);
            allow.timeout_override
        }
        ExtAuthzEnforcement::Deny(_) => {
            emit_decision_audit(DispatchOutcome::ExtAuthzDeny);
            return Ok(TransparentTlsOutcome::Blocked);
        }
    };

    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    let upstream = resolve_upstream(&action, &state, listener_cfg)?;
    let rate_limit_ctx = RateLimitContext::from_identity(
        remote_addr.ip(),
        &identity,
        decision.matched_rule.as_deref(),
        upstream.as_ref().map(|upstream| upstream.key()),
    );
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
        Some(permits) => permits,
        None => {
            emit_decision_audit(DispatchOutcome::ConcurrencyLimited);
            return Ok(TransparentTlsOutcome::Blocked);
        }
    };

    if matches!(action.kind, ActionKind::Respond) {
        warn!(
            listener = %listener_name,
            "respond action is not valid for transparent TLS; blocking connection"
        );
        emit_decision_audit(DispatchOutcome::Block);
        return Ok(TransparentTlsOutcome::Blocked);
    }

    if matches!(action.kind, ActionKind::Inspect) {
        #[cfg(not(feature = "mitm"))]
        {
            warn!(
                listener = %listener_name,
                "inspect action requires build feature mitm; blocking connection"
            );
            emit_decision_audit(DispatchOutcome::Block);
            return Ok(TransparentTlsOutcome::Blocked);
        }

        #[cfg(feature = "mitm")]
        {
            let inspect_enabled = listener_cfg
                .tls_inspection
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            if !inspect_enabled {
                return Err(anyhow!(
                    "transparent inspect action matched but tls_inspection is disabled"
                ));
            }
            let sni_host = sni
                .clone()
                .ok_or_else(|| anyhow!("transparent inspect requires SNI; refusing fail-open"))?;
            let mitm = state
                .security
                .destination
                .tls
                .mitm
                .clone()
                .ok_or_else(|| anyhow!("mitm not available for transparent inspect"))?;

            let verify_upstream = listener_cfg
                .tls_inspection
                .as_ref()
                .map(|cfg| {
                    cfg.verify_upstream
                        && !state.tls_verify_exception_matches(listener_name, sni_host.as_str())
                })
                .unwrap_or(true);

            let mitm_context = TransparentMitmContext {
                connect_target,
                upstream_proxy: upstream,
                runtime,
                listener_name: listener_name.to_string(),
                remote_addr,
                sni: sni_host,
                mitm,
                verify_upstream,
                trust: listener_trust,
            };

            transparent_mitm(stream, mitm_context).await?;
            emit_decision_audit(DispatchOutcome::Allow);
            return Ok(TransparentTlsOutcome::Inspected);
        }
    }

    let upstream_connected = connect_target_stream(
        &connect_target,
        upstream.as_ref(),
        state.plan.identity.proxy_name.as_ref(),
        upstream_timeout,
    )
    .await?;
    let export = upstream_connected
        .peer_addr
        .and_then(|server_addr| state.export_session(remote_addr, server_addr));
    let idle_timeout = Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms);
    let throttle = crate::upstream::io_copy::BandwidthThrottle::with_context(
        rate_limit_ctx,
        request_limits.byte_limiters.clone(),
        request_limits.byte_quota_limiters.clone(),
    );
    crate::tunnel::relay_tcp_tunnel(
        stream,
        upstream_connected.io,
        crate::tunnel::TunnelPolicy::tcp(Some(idle_timeout), throttle, export),
    )
    .await?;
    emit_decision_audit(DispatchOutcome::Allow);
    Ok(TransparentTlsOutcome::Tunneled)
}

#[cfg(feature = "mitm")]
mod mitm;
#[cfg(feature = "mitm")]
use self::mitm::{TransparentMitmContext, transparent_mitm};
mod policy;
use self::policy::{
    TransparentTlsPolicyInput, evaluate_tls_policy_decision,
    listener_requires_upstream_cert_preview, listener_upstream_trust,
};
