use super::destination::{connect_target_stream, resolve_upstream, ConnectTarget};
use crate::destination::DestinationInputs;
#[cfg(feature = "mitm")]
use crate::http::body::Body;
#[cfg(feature = "mitm")]
use crate::http::http1_codec::serve_http1_with_interim;
use crate::policy_context::{
    apply_ext_authz_action_overrides, emit_audit_log, enforce_ext_authz, resolve_identity,
    validate_ext_authz_allow_mode, AuditRecord, EffectivePolicyContext, ExtAuthzEnforcement,
    ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use crate::tls::client::preview_tls_certificate_with_options;
use crate::tls::{CompiledUpstreamTlsTrust, TlsClientHelloInfo, UpstreamCertificateInfo};
#[cfg(feature = "mitm")]
use anyhow::Context;
use anyhow::{anyhow, Result};
#[cfg(feature = "mitm")]
use hyper::Request;
use qpx_core::config::{ActionConfig, ActionKind, ListenerConfig};
use qpx_core::rules::RuleMatchContext;
#[cfg(feature = "mitm")]
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
#[cfg(feature = "mitm")]
use qpx_observability::handler_fn;
#[cfg(feature = "mitm")]
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "mitm")]
use tokio::time::timeout;
use tokio::time::Duration;
use tracing::warn;

#[cfg(feature = "mitm")]
use crate::http::mitm::{proxy_mitm_request, MitmRouteContext};
#[cfg(feature = "mitm")]
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransparentTlsOutcome {
    Tunneled,
    #[cfg(feature = "mitm")]
    Inspected,
    Blocked,
}

#[derive(Debug, Clone)]
struct TransparentTlsDecision {
    action: ActionConfig,
    matched_rule: Option<String>,
    auth_required: bool,
}

struct TransparentTlsPolicyInput<'a> {
    runtime: &'a Runtime,
    listener_name: &'a str,
    remote_addr: SocketAddr,
    connect_target: &'a ConnectTarget,
    host_for_match: Option<&'a str>,
    sni_for_match: Option<&'a str>,
    client_hello: Option<&'a TlsClientHelloInfo>,
    identity: &'a crate::policy_context::ResolvedIdentity,
    upstream_cert: Option<&'a UpstreamCertificateInfo>,
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
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let effective_policy =
        EffectivePolicyContext::from_single(listener_cfg.policy_context.as_ref());
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
            state.config.identity.proxy_name.as_str(),
            Duration::from_millis(state.config.runtime.upstream_http_timeout_ms),
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
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_request(
        crate::rate_limit::RequestLimitCollectInput {
            listener: Some(listener_name),
            rule: decision.matched_rule.as_deref(),
            profile: None,
            scope: crate::rate_limit::TransportScope::Connect,
            extra: None,
            ctx: &request_limit_ctx,
            cost: 1,
        },
    )?;
    if retry_after.is_some() {
        return Ok(TransparentTlsOutcome::Blocked);
    }
    if decision.auth_required || matches!(decision.action.kind, ActionKind::Block) {
        let log_context = identity.to_log_context(decision.matched_rule.as_deref(), None, None);
        emit_audit_log(
            &state,
            AuditRecord {
                kind: "transparent",
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni_for_match,
                method: None,
                path: None,
                outcome: "block",
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
            proxy_kind: "transparent",
            proxy_name: state.config.identity.proxy_name.as_str(),
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
    let ext_authz_policy_id = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    };
    let ext_authz_policy_tags = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
    };
    let mut log_context = identity.to_log_context(
        decision.matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    log_context.policy_tags = ext_authz_policy_tags;
    let mut action = decision.action.clone();
    let timeout_override = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::TransparentTls)?;
            if request_limits
                .merge_profile_and_check(
                    &state.policy.rate_limiters,
                    allow.rate_limit_profile.as_deref(),
                    crate::rate_limit::TransportScope::Connect,
                    &request_limit_ctx,
                    1,
                )?
                .is_some()
            {
                return Ok(TransparentTlsOutcome::Blocked);
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
                    remote_ip: remote_addr.ip(),
                    host: host_for_match_owned.as_deref(),
                    sni: sni_for_match,
                    method: None,
                    path: None,
                    outcome: "ext_authz_deny",
                    status: None,
                    matched_rule: decision.matched_rule.as_deref(),
                    matched_route: None,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &log_context,
            );
            return Ok(TransparentTlsOutcome::Blocked);
        }
    };

    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
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
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "transparent",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: host_for_match_owned.as_deref(),
                    sni: sni_for_match,
                    method: None,
                    path: None,
                    outcome: "concurrency_limited",
                    status: None,
                    matched_rule: decision.matched_rule.as_deref(),
                    matched_route: None,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &log_context,
            );
            return Ok(TransparentTlsOutcome::Blocked);
        }
    };

    if matches!(action.kind, ActionKind::Respond) {
        warn!(
            listener = %listener_name,
            "respond action is not valid for transparent TLS; blocking connection"
        );
        emit_audit_log(
            &state,
            AuditRecord {
                kind: "transparent",
                name: listener_name,
                remote_ip: remote_addr.ip(),
                host: host_for_match_owned.as_deref(),
                sni: sni_for_match,
                method: None,
                path: None,
                outcome: "block",
                status: None,
                matched_rule: decision.matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &log_context,
        );
        return Ok(TransparentTlsOutcome::Blocked);
    }

    if matches!(action.kind, ActionKind::Inspect) {
        #[cfg(not(feature = "mitm"))]
        {
            warn!(
                listener = %listener_name,
                "inspect action requires build feature mitm; blocking connection"
            );
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "transparent",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: host_for_match_owned.as_deref(),
                    sni: sni_for_match,
                    method: None,
                    path: None,
                    outcome: "block",
                    status: None,
                    matched_rule: decision.matched_rule.as_deref(),
                    matched_route: None,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &log_context,
            );
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
            emit_audit_log(
                &state,
                AuditRecord {
                    kind: "transparent",
                    name: listener_name,
                    remote_ip: remote_addr.ip(),
                    host: host_for_match_owned.as_deref(),
                    sni: sni_for_match,
                    method: None,
                    path: None,
                    outcome: "allow",
                    status: None,
                    matched_rule: decision.matched_rule.as_deref(),
                    matched_route: None,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                },
                &log_context,
            );
            return Ok(TransparentTlsOutcome::Inspected);
        }
    }

    let upstream_connected = connect_target_stream(
        &connect_target,
        upstream.as_ref(),
        runtime.state().config.identity.proxy_name.as_str(),
        upstream_timeout,
    )
    .await?;
    let export = upstream_connected
        .peer_addr
        .and_then(|server_addr| runtime.state().export_session(remote_addr, server_addr));
    let idle_timeout = Duration::from_millis(runtime.state().config.runtime.tunnel_idle_timeout_ms);
    let throttle = crate::io_copy::BandwidthThrottle::with_context(
        rate_limit_ctx,
        request_limits.byte_limiters.clone(),
        request_limits.byte_quota_limiters.clone(),
    );
    crate::io_copy::copy_bidirectional_with_export_and_idle(
        stream,
        upstream_connected.io,
        export,
        Some(idle_timeout),
        throttle,
    )
    .await?;
    emit_audit_log(
        &state,
        AuditRecord {
            kind: "transparent",
            name: listener_name,
            remote_ip: remote_addr.ip(),
            host: host_for_match_owned.as_deref(),
            sni: sni_for_match,
            method: None,
            path: None,
            outcome: "allow",
            status: None,
            matched_rule: decision.matched_rule.as_deref(),
            matched_route: None,
            ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        },
        &log_context,
    );
    Ok(TransparentTlsOutcome::Tunneled)
}

fn evaluate_tls_policy_decision(
    input: TransparentTlsPolicyInput<'_>,
) -> Result<TransparentTlsDecision> {
    let TransparentTlsPolicyInput {
        runtime,
        listener_name,
        remote_addr,
        connect_target,
        host_for_match,
        sni_for_match,
        client_hello,
        identity,
        upstream_cert,
    } = input;
    let state = runtime.state();
    let engine = state
        .policy
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: host_for_match,
            ip: host_for_match.and_then(|value| value.parse().ok()),
            sni: sni_for_match,
            scheme: Some("https"),
            port: Some(connect_target.port()),
            alpn: client_hello.and_then(|hello| hello.alpn.as_deref()),
            ja3: client_hello.and_then(|hello| hello.ja3.as_deref()),
            ja4: client_hello.and_then(|hello| hello.ja4.as_deref()),
            cert_subject: upstream_cert.and_then(|cert| cert.subject.as_deref()),
            cert_issuer: upstream_cert.and_then(|cert| cert.issuer.as_deref()),
            cert_san_dns: upstream_cert
                .map(|cert| cert.san_dns.as_slice())
                .unwrap_or(&[]),
            cert_san_uri: upstream_cert
                .map(|cert| cert.san_uri.as_slice())
                .unwrap_or(&[]),
            cert_fingerprint_sha256: upstream_cert
                .and_then(|cert| cert.fingerprint_sha256.as_deref()),
        },
        state
            .listener_config(listener_name)
            .and_then(|cfg| cfg.destination_resolution.as_ref()),
    );
    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: Some(connect_target.port()),
        host: host_for_match,
        sni: sni_for_match,
        method: None,
        path: None,
        alpn: client_hello.and_then(|hello| hello.alpn.as_deref()),
        tls_version: client_hello.and_then(|hello| hello.tls_version.as_deref()),
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        ja3: client_hello.and_then(|hello| hello.ja3.as_deref()),
        ja4: client_hello.and_then(|hello| hello.ja4.as_deref()),
        headers: None,
        user: identity.user.as_deref(),
        user_groups: &identity.groups,
        device_id: identity.device_id.as_deref(),
        posture: &identity.posture,
        tenant: identity.tenant.as_deref(),
        auth_strength: identity.auth_strength.as_deref(),
        idp: identity.idp.as_deref(),
        upstream_cert_present: upstream_cert.map(|cert| cert.present),
        upstream_cert_subject: upstream_cert.and_then(|cert| cert.subject.as_deref()),
        upstream_cert_issuer: upstream_cert.and_then(|cert| cert.issuer.as_deref()),
        upstream_cert_san_dns: upstream_cert
            .map(|cert| cert.san_dns.as_slice())
            .unwrap_or(&[]),
        upstream_cert_san_uri: upstream_cert
            .map(|cert| cert.san_uri.as_slice())
            .unwrap_or(&[]),
        upstream_cert_fingerprint_sha256: upstream_cert
            .and_then(|cert| cert.fingerprint_sha256.as_deref()),
        ..Default::default()
    };
    let outcome = engine.evaluate_ref(&ctx);
    Ok(TransparentTlsDecision {
        action: outcome.action.clone(),
        matched_rule: outcome.matched_rule.map(str::to_string),
        auth_required: outcome
            .auth
            .map(|auth| !auth.require.is_empty())
            .unwrap_or(false),
    })
}

fn listener_uses_upstream_cert_match(listener_cfg: &ListenerConfig) -> bool {
    listener_cfg.rules.iter().any(|rule| {
        rule.r#match
            .as_ref()
            .and_then(|m| m.upstream_cert.as_ref())
            .is_some()
    })
}

fn listener_upstream_trust(
    listener_cfg: &ListenerConfig,
) -> Result<Option<Arc<CompiledUpstreamTlsTrust>>> {
    CompiledUpstreamTlsTrust::from_config(
        listener_cfg
            .tls_inspection
            .as_ref()
            .and_then(|cfg| cfg.upstream_trust.as_ref()),
    )
}

fn listener_requires_upstream_cert_preview(listener_cfg: &ListenerConfig) -> bool {
    listener_uses_upstream_cert_match(listener_cfg)
        || listener_cfg
            .tls_inspection
            .as_ref()
            .and_then(|cfg| cfg.upstream_trust.as_ref())
            .is_some()
}

#[cfg(feature = "mitm")]
struct TransparentMitmContext {
    connect_target: ConnectTarget,
    upstream_proxy: Option<crate::upstream::pool::ResolvedUpstreamProxy>,
    runtime: Runtime,
    listener_name: String,
    remote_addr: SocketAddr,
    sni: String,
    mitm: qpx_core::tls::MitmConfig,
    verify_upstream: bool,
    trust: Option<Arc<CompiledUpstreamTlsTrust>>,
}

#[cfg(feature = "mitm")]
async fn transparent_mitm<I>(stream: I, ctx: TransparentMitmContext) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let TransparentMitmContext {
        connect_target,
        upstream_proxy,
        runtime,
        listener_name,
        remote_addr,
        sni,
        mitm,
        verify_upstream,
        trust,
    } = ctx;
    let upstream_timeout =
        Duration::from_millis(runtime.state().config.runtime.upstream_http_timeout_ms);

    let upstream_connected = timeout(
        upstream_timeout,
        connect_target_stream(
            &connect_target,
            upstream_proxy.as_ref(),
            runtime.state().config.identity.proxy_name.as_str(),
            upstream_timeout,
        ),
    )
    .await??;
    let client_tls = accept_mitm_client(stream, &mitm, upstream_timeout).await?;
    let (sender, upstream_cert) = connect_mitm_upstream(
        upstream_connected.io,
        sni.as_str(),
        verify_upstream,
        trust.as_deref(),
        upstream_timeout,
        "transparent MITM upstream conn",
    )
    .await?;
    let upstream_cert = Arc::new(upstream_cert);
    let runtime_for_service = runtime.clone();
    let listener_for_service = listener_name.clone();
    let sni_for_service = sni.clone();
    let connect_target_for_service = connect_target.clone();
    let access_cfg = runtime.state().config.access_log.clone();
    let access_name = Arc::<str>::from(listener_name.as_str());

    let service = handler_fn(move |req: Request<Body>| {
        let sender = sender.clone();
        let runtime = runtime_for_service.clone();
        let listener_name = listener_for_service.clone();
        let sni = sni_for_service.clone();
        let connect_target = connect_target_for_service.clone();
        let upstream_cert = upstream_cert.clone();

        async move {
            let proxy_name = runtime.state().config.identity.proxy_name.clone();
            let proxy_error = runtime.state().messages.proxy_error.clone();
            let request_method = req.method().clone();
            let request_version = req.version();
            let target_host = connect_target.host_for_connect();
            let route = MitmRouteContext {
                listener_name: listener_name.as_str(),
                src_addr: remote_addr,
                dst_port: connect_target.port(),
                host: target_host.as_str(),
                sni: sni.as_str(),
                upstream_cert: Some(upstream_cert),
            };
            match proxy_mitm_request(req, runtime, sender, route).await {
                Ok(response) => Ok::<_, Infallible>(response),
                Err(err) => {
                    warn!(error = ?err, "transparent MITM request failed");
                    Ok(crate::http::l7::finalize_response_for_request(
                        &request_method,
                        request_version,
                        proxy_name.as_str(),
                        hyper::Response::builder()
                            .status(hyper::StatusCode::BAD_GATEWAY)
                            .body(Body::from(proxy_error))
                            .unwrap_or_else(|_| hyper::Response::new(Body::from("proxy error"))),
                        false,
                    ))
                }
            }
        }
    });
    let service = AccessLogService::new(
        service,
        remote_addr,
        AccessLogContext {
            kind: "transparent",
            name: access_name,
        },
        &access_cfg,
    );

    let header_read_timeout =
        Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
    serve_http1_with_interim(client_tls, service, header_read_timeout)
        .await
        .context("transparent MITM serve_connection failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::{
        AccessLogConfig, AuditLogConfig, AuthConfig, CacheConfig, CertificateMatchConfig, Config,
        IdentityConfig, ListenerConfig, ListenerMode, MatchConfig, MessagesConfig, RuleConfig,
        RuntimeConfig, SystemLogConfig, TlsInspectionConfig,
    };

    fn tls_runtime(rules: Vec<RuleConfig>) -> Runtime {
        Runtime::new(Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            ext_authz: Vec::new(),
            destination_resolution: Default::default(),
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            listeners: vec![ListenerConfig {
                name: "transparent".to_string(),
                mode: ListenerMode::Transparent,
                listen: "127.0.0.1:18443".to_string(),
                default_action: ActionConfig {
                    kind: ActionKind::Tunnel,
                    upstream: None,
                    local_response: None,
                },
                tls_inspection: Some(TlsInspectionConfig {
                    enabled: true,
                    ca: None,
                    verify_upstream: false,
                    verify_exceptions: Vec::new(),
                    upstream_trust_profile: None,
                    upstream_trust: None,
                }),
                rules,
                connection_filter: Vec::new(),
                upstream_proxy: None,
                http3: None,
                ftp: qpx_core::config::FtpConfig::default(),
                xdp: None,
                cache: None,
                rate_limit: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                http_modules: Vec::new(),
            }],
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
        })
        .expect("runtime")
    }

    #[test]
    fn upstream_cert_match_can_force_block_before_mitm() {
        let runtime = tls_runtime(vec![RuleConfig {
            name: "block-bad-issuer".to_string(),
            r#match: Some(MatchConfig {
                upstream_cert: Some(CertificateMatchConfig {
                    issuer: vec!["Bad Issuer".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            auth: None,
            action: Some(ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            }),
            headers: None,
            rate_limit: None,
        }]);
        let client_hello = TlsClientHelloInfo {
            sni: Some("example.com".to_string()),
            alpn: Some("h2".to_string()),
            tls_version: Some("TLS1.3".to_string()),
            ja3: Some("ja3".to_string()),
            ja4: Some("ja4".to_string()),
        };
        let identity = crate::policy_context::ResolvedIdentity::default();
        let upstream_cert = UpstreamCertificateInfo {
            present: true,
            issuer: Some("Bad Issuer".to_string()),
            ..Default::default()
        };
        let target = ConnectTarget::HostPort("example.com".to_string(), 443);
        let decision = evaluate_tls_policy_decision(TransparentTlsPolicyInput {
            runtime: &runtime,
            listener_name: "transparent",
            remote_addr: "127.0.0.1:44321".parse().expect("remote"),
            connect_target: &target,
            host_for_match: Some("example.com"),
            sni_for_match: Some("example.com"),
            client_hello: Some(&client_hello),
            identity: &identity,
            upstream_cert: Some(&upstream_cert),
        })
        .expect("decision");
        assert_eq!(decision.action.kind, ActionKind::Block);
        assert_eq!(decision.matched_rule.as_deref(), Some("block-bad-issuer"));
    }

    #[test]
    fn resolve_tls_connect_target_uses_sni_when_original_target_is_missing() {
        let (target, sni) = resolve_tls_connect_target(
            None,
            Some(&TlsClientHelloInfo {
                sni: Some("example.com".to_string()),
                alpn: Some("h2".to_string()),
                tls_version: Some("TLS1.3".to_string()),
                ja3: None,
                ja4: None,
            }),
        )
        .expect("target");
        assert!(matches!(target, ConnectTarget::HostPort(ref host, 443) if host == "example.com"));
        assert_eq!(sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn resolve_tls_connect_target_prefers_original_target_over_sni() {
        let (target, sni) = resolve_tls_connect_target(
            Some(ConnectTarget::Socket(
                "127.0.0.1:18443".parse().expect("socket"),
            )),
            Some(&TlsClientHelloInfo {
                sni: Some("example.com".to_string()),
                alpn: None,
                tls_version: None,
                ja3: None,
                ja4: None,
            }),
        )
        .expect("target");
        assert!(matches!(target, ConnectTarget::Socket(addr) if addr.port() == 18443));
        assert_eq!(sni.as_deref(), Some("example.com"));
    }
}
