use super::destination::{connect_target_stream, resolve_upstream, ConnectTarget};
#[cfg(feature = "mitm")]
use crate::http::server::serve_http1_with_upgrades;
use crate::runtime::Runtime;
#[cfg(feature = "mitm")]
use anyhow::Context;
use anyhow::{anyhow, Result};
#[cfg(feature = "mitm")]
use hyper::service::service_fn;
#[cfg(feature = "mitm")]
use hyper::{Body, Request};
use qpx_core::config::ActionKind;
#[cfg(feature = "mitm")]
use qpx_core::middleware::access_log::{AccessLogContext, AccessLogService};
use qpx_core::rules::RuleMatchContext;
use std::net::SocketAddr;
#[cfg(feature = "mitm")]
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
    sni: Option<String>,
) -> Result<TransparentTlsOutcome>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
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

    let host_for_match_owned = match &connect_target {
        ConnectTarget::HostPort(host, _) => Some(host.clone()),
        ConnectTarget::Socket(addr) => Some(addr.ip().to_string()),
    };
    let sni_for_match = matches!(&connect_target, ConnectTarget::HostPort(_, _))
        .then_some(sni.as_deref())
        .flatten();

    let state = runtime.state();
    if let Some(limits) = state.rate_limiters.listener(listener_name) {
        if let Some(limiter) = limits.listener.requests.as_ref() {
            if limiter.try_acquire(remote_addr.ip(), 1).is_some() {
                return Ok(TransparentTlsOutcome::Blocked);
            }
        }
    }
    let upstream_timeout = Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);
    let listener_cfg = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let engine = state
        .rules_by_listener
        .get(listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;

    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: Some(connect_target.port()),
        host: host_for_match_owned.as_deref(),
        sni: sni_for_match,
        method: None,
        path: None,
        headers: None,
        user_groups: &[],
    };
    let outcome = engine.evaluate_ref(&ctx);
    if let Some(rule) = outcome.matched_rule {
        if let Some(limits) = state.rate_limiters.listener(listener_name) {
            if let Some(rule_limits) = limits.rules.get(rule) {
                if let Some(limiter) = rule_limits.requests.as_ref() {
                    if limiter.try_acquire(remote_addr.ip(), 1).is_some() {
                        return Ok(TransparentTlsOutcome::Blocked);
                    }
                }
            }
        }
    }
    let auth_required = outcome.auth.map(|a| !a.require.is_empty()).unwrap_or(false);
    if auth_required || matches!(outcome.action.kind, ActionKind::Block) {
        return Ok(TransparentTlsOutcome::Blocked);
    }

    let upstream = resolve_upstream(outcome.action, &state, listener_cfg)?;

    if matches!(outcome.action.kind, ActionKind::Respond) {
        warn!(
            listener = %listener_name,
            "respond action is not valid for transparent TLS; blocking connection"
        );
        return Ok(TransparentTlsOutcome::Blocked);
    }

    if matches!(outcome.action.kind, ActionKind::Inspect) {
        #[cfg(not(feature = "mitm"))]
        {
            warn!(
                listener = %listener_name,
                "inspect action requires build feature mitm; blocking connection"
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
            };

            transparent_mitm(stream, mitm_context).await?;
            return Ok(TransparentTlsOutcome::Inspected);
        }
    }

    let upstream_connected =
        connect_target_stream(&connect_target, upstream.as_deref(), upstream_timeout).await?;
    let export = upstream_connected
        .peer_addr
        .and_then(|server_addr| runtime.state().export_session(remote_addr, server_addr));
    let idle_timeout = Duration::from_millis(runtime.state().config.runtime.tunnel_idle_timeout_ms);
    let mut bandwidth_limiters = Vec::new();
    if let Some(limits) = state.rate_limiters.listener(listener_name) {
        if let Some(limiter) = limits.listener.bytes.as_ref() {
            bandwidth_limiters.push(limiter.clone());
        }
        if let Some(rule) = outcome.matched_rule {
            if let Some(rule_limits) = limits.rules.get(rule) {
                if let Some(limiter) = rule_limits.bytes.as_ref() {
                    bandwidth_limiters.push(limiter.clone());
                }
            }
        }
    }
    let throttle = crate::io_copy::BandwidthThrottle::new(remote_addr.ip(), bandwidth_limiters);
    crate::io_copy::copy_bidirectional_with_export_and_idle(
        stream,
        upstream_connected.io,
        export,
        Some(idle_timeout),
        throttle,
    )
    .await?;
    Ok(TransparentTlsOutcome::Tunneled)
}

#[cfg(feature = "mitm")]
struct TransparentMitmContext {
    connect_target: ConnectTarget,
    upstream_proxy: Option<String>,
    runtime: Runtime,
    listener_name: String,
    remote_addr: SocketAddr,
    sni: String,
    mitm: qpx_core::tls::MitmConfig,
    verify_upstream: bool,
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
    } = ctx;
    let upstream_timeout =
        Duration::from_millis(runtime.state().config.runtime.upstream_http_timeout_ms);

    let upstream_connected = timeout(
        upstream_timeout,
        connect_target_stream(&connect_target, upstream_proxy.as_deref(), upstream_timeout),
    )
    .await??;
    let client_tls = accept_mitm_client(stream, &mitm, upstream_timeout).await?;
    let sender = connect_mitm_upstream(
        upstream_connected.io,
        sni.as_str(),
        &mitm,
        verify_upstream,
        upstream_timeout,
        "transparent MITM upstream conn",
    )
    .await?;
    let runtime_for_service = runtime.clone();
    let listener_for_service = listener_name.clone();
    let sni_for_service = sni.clone();
    let connect_target_for_service = connect_target.clone();
    let access_cfg = runtime.state().config.access_log.clone();
    let access_name = Arc::<str>::from(listener_name.as_str());

    let service = service_fn(move |req: Request<Body>| {
        let sender = sender.clone();
        let runtime = runtime_for_service.clone();
        let listener_name = listener_for_service.clone();
        let sni = sni_for_service.clone();
        let connect_target = connect_target_for_service.clone();

        async move {
            let target_host = connect_target.host_for_connect();
            let route = MitmRouteContext {
                listener_name: listener_name.as_str(),
                src_addr: remote_addr,
                dst_port: connect_target.port(),
                host: target_host.as_str(),
                sni: sni.as_str(),
            };
            let response = proxy_mitm_request(req, runtime, sender, route).await?;
            Ok::<_, anyhow::Error>(response)
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
    serve_http1_with_upgrades(client_tls, service, header_read_timeout, false)
        .await
        .context("transparent MITM serve_connection failed")?;

    Ok(())
}
