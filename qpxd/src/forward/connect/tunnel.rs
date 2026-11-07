use super::{
    ConnectPolicyInput, decide_connect_action_from_client_hello,
    decide_connect_action_from_tls_metadata, resolve_upstream,
};
#[cfg(feature = "mitm")]
use crate::http::mitm::{MitmRouteContext, proxy_mitm_request};
use crate::http::protocol::io_prefix::PrefixedIo;
#[cfg(feature = "mitm")]
use crate::http::protocol::l7::finalize_response_for_request;
use crate::runtime::{PlanFlags, Runtime};
#[cfg(feature = "mitm")]
use crate::tls::mitm::prewarm_mitm_cert;
#[cfg(feature = "mitm")]
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream};
use crate::tls::preview::preview_client_certificate_with_timeout;
use crate::tls::{
    TlsClientHelloInfo, extract_client_hello_info_with_fingerprints, looks_like_tls_client_hello,
    try_read_client_hello_with_timeout,
};
use crate::upstream::connect::{ConnectedTunnel, connect_tunnel_target};
use crate::upstream::io_copy::BandwidthThrottle;
#[cfg(feature = "mitm")]
use ::http::Request as HyperRequest;
#[cfg(feature = "mitm")]
use ::http::StatusCode;
#[cfg(feature = "mitm")]
use anyhow::Context;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use qpx_core::config::{ActionConfig, ActionKind};
use qpx_core::http_message::Response as OwnerResponse;
use qpx_core::http_message::{Headers, Request as OwnerRequest};
use qpx_http::body::Body;
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
    pub request_version: http::Version,
    pub sanitized_headers: Headers,
    pub identity: crate::policy_context::ResolvedIdentity,
    pub initial_action: ActionConfig,
    pub matched_rule: Option<String>,
    pub verify_upstream: bool,
    pub _concurrency_permits: Option<crate::rate_limit::ConcurrencyPermits>,
    pub throttle: Option<BandwidthThrottle>,
}

// Only an established classic H2 CONNECT gets a streaming response. Other
// responses (including locally generated 2xx replies) never acquire this marker.
pub(super) enum TunnelConnectClient {
    Upgrade(OwnerRequest<Body>),
    H2(Body, qpx_http::body::Sender),
}

impl TunnelConnectClient {
    pub(super) fn new(req: OwnerRequest<Body>, response: &mut OwnerResponse<Body>) -> Self {
        if req.version() != http::Version::HTTP_2 {
            return Self::Upgrade(req);
        }
        let (sender, body) = Body::channel_with_capacity(1);
        // The tunnel owns idle/IO deadlines; the codec still watches resets.
        *response.body_mut() = body.mark_read_timeout_enforced();
        response
            .extensions_mut()
            .insert(crate::http::codec::h2::ClassicConnectTunnel);
        Self::H2(req.into_head_and_body().1, sender)
    }
}

pub(super) async fn tunnel_connect(
    client: TunnelConnectClient,
    server: ConnectedTunnel,
    runtime: Runtime,
    ctx: TunnelConnectContext,
) -> Result<()> {
    match client {
        TunnelConnectClient::Upgrade(mut req) => {
            let upgrade_wait =
                Duration::from_millis(runtime.state().plan.limits.timeouts.upgrade_wait_timeout_ms);
            let upgraded = timeout(
                upgrade_wait,
                crate::http::protocol::upgrade::on(req.extensions_mut()),
            )
            .await??;
            tunnel_connect_io(upgraded, server, runtime, ctx).await
        }
        TunnelConnectClient::H2(body, sender) => {
            let mut sender = Some(sender);
            // One codec-sized buffer and one response frame bound the bridge.
            // Reading request DATA remains demand-driven by the tunnel relay.
            let frame_size = crate::http::codec::h2::h2_upstream_response_frame_size();
            let (writer, mut reader) = tokio::io::duplex(frame_size);
            let input = futures_util::stream::try_unfold(body, |mut body| async {
                match body.data().await {
                    Some(Ok(bytes)) => Ok(Some((bytes, body))),
                    Some(Err(err)) => Err(std::io::Error::other(err)),
                    None => Ok(None),
                }
            });
            let io = tokio::io::join(tokio_util::io::StreamReader::new(Box::pin(input)), writer);
            let download = async {
                use tokio::io::AsyncReadExt;
                let mut buffer = vec![0; frame_size];
                let tx = sender
                    .as_mut()
                    .ok_or_else(|| anyhow!("CONNECT sender missing"))?;
                loop {
                    let len = tokio::select! {
                        result = reader.read(&mut buffer) => result?,
                        _ = tx.closed() => return Err(anyhow!("CONNECT response cancelled")),
                    };
                    if len == 0 {
                        break;
                    }
                    tx.send_data(Bytes::copy_from_slice(&buffer[..len])).await?;
                }
                // END_STREAM is independent of the still-live upload half.
                sender.take();
                Ok(())
            };
            let result = tokio::try_join!(tunnel_connect_io(io, server, runtime, ctx), download,);
            if result.is_err()
                && let Some(sender) = sender.as_mut()
            {
                sender.abort();
            }
            result.map(|_| ())
        }
    }
}

async fn tunnel_connect_io<I>(
    upgraded: I,
    server: ConnectedTunnel,
    runtime: Runtime,
    ctx: TunnelConnectContext,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let state = runtime.state();
    let listener_cfg = state
        .ingress_edge_settings(ctx.listener_name.as_str())
        .ok_or_else(|| anyhow!("listener not found"))?;
    let upstream_timeout =
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms);
    let (client_io, client_hello, action) =
        prepare_connect_client_io(upgraded, &runtime, &ctx).await?;
    let listener_upstream_trust = listener_cfg.upstream_tls_trust();
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
        request_version: _,
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
                let header_read_timeout = state.plan.limits.timeouts.http_header_read_timeout();
                let body_channel_capacity = state.plan.limits.body.body_channel_capacity;
                let access_cfg = state.resources.access_log.clone();
                let access_name = Arc::<str>::from(listener_name.as_str());
                let request_runtime = runtime.clone();
                let service = handler_fn(move |inner_req: HyperRequest<Body>| {
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
                                    {
                                        let mut response =
                                            OwnerResponse::new(Body::from(proxy_error));
                                        *response.status_mut() = StatusCode::BAD_GATEWAY;
                                        response
                                    },
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
        && listener_cfg.requires_upstream_cert_preview
        && connect_action_uses_upstream(&action)
    {
        let preview_verify = state.tls_verify_upstream(
            Some(listener_cfg),
            ctx.listener_name.as_str(),
            ctx.host.as_str(),
        );
        let preview_server = server
            .take()
            .ok_or_else(|| anyhow!("CONNECT upstream tunnel missing before cert preview"))?;
        match preview_client_certificate_with_timeout(
            ctx.host.as_str(),
            preview_server.io,
            preview_verify,
            listener_upstream_trust.as_deref(),
            upstream_timeout,
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
                    request_version: ctx.request_version,
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
                request_version: ctx.request_version,
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

/// Whether a forward plan or listener connection filter needs CONNECT TLS fingerprints.
pub(in crate::forward) fn connect_tls_fingerprints_required(
    runtime: &Runtime,
    listener_name: &str,
) -> bool {
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
