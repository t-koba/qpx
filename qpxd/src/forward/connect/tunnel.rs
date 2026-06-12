use super::{
    ConnectPolicyInput, decide_connect_action_from_client_hello,
    decide_connect_action_from_tls_metadata, listener_requires_upstream_cert_preview,
    listener_upstream_trust, resolve_upstream,
};
#[cfg(feature = "mitm")]
use crate::http::mitm::{MitmRouteContext, proxy_mitm_request};
#[cfg(feature = "mitm")]
use crate::http::protocol::common::blocked_response as blocked;
use crate::http::protocol::io_prefix::PrefixedIo;
#[cfg(feature = "mitm")]
use crate::http::protocol::l7::finalize_response_for_request;
use crate::runtime::{PlanFlags, Runtime};
#[cfg(feature = "mitm")]
use crate::tls::mitm::prewarm_mitm_cert;
#[cfg(feature = "mitm")]
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream};
use crate::tls::{
    TlsClientHelloInfo, extract_client_hello_info_with_fingerprints, looks_like_tls_client_hello,
    try_read_client_hello_with_timeout,
};
use crate::upstream::connect::{ConnectedTunnel, connect_tunnel_target};
use crate::upstream::io_copy::BandwidthThrottle;
use ::http::{HeaderMap, Request};
#[cfg(feature = "mitm")]
use ::http::{Response, StatusCode};
#[cfg(feature = "mitm")]
use anyhow::Context;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use qpx_core::config::{ActionConfig, ActionKind};
use qpx_http::body::Body;
use qpx_http::tls::client::preview_tls_certificate_with_options;
#[cfg(feature = "mitm")]
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
#[cfg(feature = "mitm")]
use qpx_observability::handler_fn;
#[cfg(feature = "mitm")]
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(super) struct TunnelConnectContext {
    pub remote_addr: SocketAddr,
    pub listener_name: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub sanitized_headers: HeaderMap,
    pub identity: crate::policy_context::ResolvedIdentity,
    pub initial_action: ActionConfig,
    pub matched_rule: Option<String>,
    pub verify_upstream: bool,
    pub _concurrency_permits: Option<crate::rate_limit::ConcurrencyPermits>,
    pub throttle: Option<BandwidthThrottle>,
}

pub(super) async fn tunnel_connect(
    mut req: Request<Body>,
    server: ConnectedTunnel,
    runtime: Runtime,
    ctx: TunnelConnectContext,
) -> Result<()> {
    let state = runtime.state();
    let listener_cfg = state
        .ingress_edge_settings(ctx.listener_name.as_str())
        .ok_or_else(|| anyhow!("listener not found"))?;
    let upgrade_wait = Duration::from_millis(state.plan.limits.timeouts.upgrade_wait_timeout_ms);
    let upstream_timeout =
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms);
    let upgraded = timeout(upgrade_wait, crate::http::protocol::upgrade::on(&mut req)).await??;
    let (client_io, client_hello, action) =
        prepare_connect_client_io(upgraded, &runtime, &ctx).await?;
    let listener_upstream_trust = listener_upstream_trust(listener_cfg)?;
    let (action, server) = prepare_connect_upstream_after_preview(
        &runtime,
        listener_cfg,
        &ctx,
        client_hello.as_ref(),
        action,
        Some(server),
        upstream_timeout,
        listener_upstream_trust.clone(),
    )
    .await?;
    let TunnelConnectContext {
        remote_addr,
        listener_name,
        host,
        port,
        authority: _,
        sanitized_headers: _,
        identity: _,
        initial_action: _,
        matched_rule,
        verify_upstream,
        _concurrency_permits,
        throttle,
    } = ctx;
    #[cfg(not(feature = "mitm"))]
    let _ = (&host, port);

    match action.kind {
        ActionKind::Block | ActionKind::Respond => Ok(()),
        ActionKind::Inspect => {
            #[cfg(not(feature = "mitm"))]
            {
                let _ = (verify_upstream, client_io, server);
                Ok(())
            }

            #[cfg(feature = "mitm")]
            {
                if !listener_cfg
                    .tls_inspection
                    .as_ref()
                    .map(|cfg| cfg.enabled)
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                let mitm = state
                    .security
                    .destination
                    .tls
                    .mitm
                    .clone()
                    .ok_or_else(|| anyhow!("mitm not available"))?;
                let mitm_server_name = client_hello
                    .as_ref()
                    .and_then(|hello| hello.sni.as_deref())
                    .unwrap_or("unknown");
                prewarm_mitm_cert(&mitm, mitm_server_name, upstream_timeout).await?;
                let client_tls = accept_mitm_client(client_io, &mitm, upstream_timeout).await?;
                let server =
                    server.ok_or_else(|| anyhow!("reconnected server missing for CONNECT MITM"))?;
                let (sender, upstream_cert) = connect_mitm_upstream(
                    server.io,
                    host.as_str(),
                    verify_upstream,
                    listener_upstream_trust.as_deref(),
                    upstream_timeout,
                    "forward MITM upstream conn",
                )
                .await?;
                let upstream_cert = Arc::new(upstream_cert);
                let connect_host = host.clone();
                let header_read_timeout =
                    Duration::from_millis(state.plan.limits.timeouts.http_header_read_timeout_ms);
                let body_channel_capacity = state.plan.limits.body.body_channel_capacity;
                let access_cfg = state.resources.access_log.clone();
                let access_name = Arc::<str>::from(listener_name.as_str());
                let request_runtime = runtime.clone();
                let service = handler_fn(move |inner_req: Request<Body>| {
                    let sender = sender.clone();
                    let runtime = request_runtime.clone();
                    let listener_name = listener_name.clone();
                    let connect_host = connect_host.clone();
                    let upstream_cert = upstream_cert.clone();
                    async move {
                        let proxy_name = runtime.state().plan.identity.proxy_name.to_string();
                        let proxy_error = runtime.state().messages.proxy_error.clone();
                        let request_method = inner_req.method().clone();
                        let request_version = inner_req.version();
                        let route = MitmRouteContext {
                            listener_name: listener_name.as_str(),
                            src_addr: remote_addr,
                            dst_port: port,
                            host: connect_host.as_str(),
                            sni: connect_host.as_str(),
                            upstream_cert: Some(upstream_cert),
                        };
                        match proxy_mitm_request(inner_req, runtime, sender, route).await {
                            Ok(response) => Ok::<_, Infallible>(response),
                            Err(err) => {
                                warn!(error = ?err, "forward CONNECT MITM request failed");
                                Ok(finalize_response_for_request(
                                    &request_method,
                                    request_version,
                                    proxy_name.as_str(),
                                    Response::builder()
                                        .status(StatusCode::BAD_GATEWAY)
                                        .body(Body::from(proxy_error))
                                        .unwrap_or_else(|_| blocked("proxy error")),
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
                        kind: crate::http::dispatch::ProxyKind::Forward.as_str(),
                        name: access_name,
                    },
                    &access_cfg,
                );

                crate::http::codec::h1::serve_http1_with_interim_and_capacity(
                    client_tls,
                    service,
                    header_read_timeout,
                    body_channel_capacity,
                )
                .await
                .context("serve_connection failed")?;
                Ok(())
            }
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {
            let server =
                server.ok_or_else(|| anyhow!("reconnected server missing for CONNECT tunnel"))?;
            let selected_plan = state
                .plan
                .ingress_edge_execution_plan(listener_name.as_str(), matched_rule.as_deref())
                .ok_or_else(|| anyhow!("compiled CONNECT listener execution plan not found"))?;
            let export = server.peer_addr.and_then(|server_addr| {
                state.export_session_for_plan(selected_plan, remote_addr, server_addr)
            });
            let idle_timeout =
                Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms);
            let _stats = crate::tunnel::relay_tcp_tunnel(
                client_io,
                server.io,
                crate::tunnel::TunnelPolicy::tcp(Some(idle_timeout), throttle, export),
            )
            .await?;
            Ok(())
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "CONNECT preview keeps derived tunnel facts explicit without widening shared state"
)]
async fn prepare_connect_upstream_after_preview(
    runtime: &Runtime,
    listener_cfg: &crate::runtime::CompiledListenerSettings,
    ctx: &TunnelConnectContext,
    client_hello: Option<&TlsClientHelloInfo>,
    mut action: ActionConfig,
    mut server: Option<ConnectedTunnel>,
    upstream_timeout: Duration,
    listener_upstream_trust: Option<Arc<qpx_core::tls::CompiledUpstreamTlsTrust>>,
) -> Result<(ActionConfig, Option<ConnectedTunnel>)> {
    let state = runtime.state();
    if let Some(client_hello) = client_hello
        && listener_requires_upstream_cert_preview(listener_cfg)
        && connect_action_uses_upstream(&action)
    {
        let preview_verify = listener_cfg
            .tls_inspection
            .as_ref()
            .map(|cfg| {
                cfg.verify_upstream
                    && !state
                        .tls_verify_exception_matches(ctx.listener_name.as_str(), ctx.host.as_str())
            })
            .unwrap_or(true);
        let preview_server = server
            .take()
            .ok_or_else(|| anyhow!("CONNECT upstream tunnel missing before cert preview"))?;
        match preview_tls_certificate_with_options(
            ctx.host.as_str(),
            preview_server.io,
            preview_verify,
            listener_upstream_trust.as_deref(),
        )
        .await
        {
            Ok(upstream_cert) => {
                action = decide_connect_action_from_tls_metadata(ConnectPolicyInput {
                    runtime,
                    listener_name: ctx.listener_name.as_str(),
                    remote_addr: ctx.remote_addr,
                    host: ctx.host.as_str(),
                    port: ctx.port,
                    authority: ctx.authority.as_str(),
                    sanitized_headers: &ctx.sanitized_headers,
                    identity: &ctx.identity,
                    client_hello,
                    upstream_cert: Some(&upstream_cert),
                })
                .await?;
            }
            Err(err) => {
                if listener_upstream_trust.is_some() {
                    return Err(err);
                }
                warn!(error = ?err, "forward CONNECT upstream certificate preview failed");
            }
        }
    }

    let reconnect_needed = server.is_none() || action != ctx.initial_action;
    if reconnect_needed && connect_action_uses_upstream(&action) {
        let upstream = resolve_upstream(&action, &state, ctx.listener_name.as_str())?;
        server = Some(
            connect_tunnel_target(
                ctx.host.as_str(),
                ctx.port,
                upstream.as_ref(),
                state.plan.identity.proxy_name.as_ref(),
                upstream_timeout,
            )
            .await?,
        );
    }
    Ok((action, server))
}

fn connect_action_uses_upstream(action: &ActionConfig) -> bool {
    matches!(
        action.kind,
        ActionKind::Inspect | ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
    )
}

pub(super) async fn prepare_connect_client_io<I>(
    mut upgraded: I,
    runtime: &Runtime,
    ctx: &TunnelConnectContext,
) -> Result<(PrefixedIo<I>, Option<TlsClientHelloInfo>, ActionConfig)>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let peek_timeout =
        Duration::from_millis(runtime.state().plan.limits.timeouts.tls_peek_timeout_ms);
    let sniff = try_read_client_hello_with_timeout(&mut upgraded, peek_timeout).await?;
    let include_fingerprints =
        connect_tls_fingerprints_required(runtime, ctx.listener_name.as_str());
    let client_hello = looks_like_tls_client_hello(&sniff)
        .then(|| extract_client_hello_info_with_fingerprints(&sniff, include_fingerprints))
        .flatten();
    let action = match client_hello.as_ref() {
        Some(client_hello) => {
            decide_connect_action_from_client_hello(ConnectPolicyInput {
                runtime,
                listener_name: ctx.listener_name.as_str(),
                remote_addr: ctx.remote_addr,
                host: ctx.host.as_str(),
                port: ctx.port,
                authority: ctx.authority.as_str(),
                sanitized_headers: &ctx.sanitized_headers,
                identity: &ctx.identity,
                client_hello,
                upstream_cert: None,
            })
            .await?
        }
        None if matches!(ctx.initial_action.kind, ActionKind::Inspect) => ActionConfig {
            kind: ActionKind::Tunnel,
            upstream: ctx.initial_action.upstream.clone(),
            local_response: None,
        },
        None => ctx.initial_action.clone(),
    };
    Ok((
        PrefixedIo::new(upgraded, Bytes::from(sniff)),
        client_hello,
        action,
    ))
}

fn connect_tls_fingerprints_required(runtime: &Runtime, listener_name: &str) -> bool {
    let state = runtime.state();
    state
        .plan
        .forward_edge(listener_name)
        .map(|edge| edge.flags.contains(PlanFlags::TLS_FINGERPRINT))
        .unwrap_or(false)
        || state
            .policy
            .connection_filters_by_listener
            .get(listener_name)
            .map(|engine| engine.any_rule_requires_tls_fingerprint())
            .unwrap_or(false)
}
