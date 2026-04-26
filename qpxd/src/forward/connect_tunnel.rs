use super::*;
#[cfg(feature = "mitm")]
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
#[cfg(feature = "mitm")]
use qpx_observability::handler_fn;
#[cfg(feature = "mitm")]
use std::convert::Infallible;

pub(super) struct TunnelConnectContext {
    pub remote_addr: SocketAddr,
    pub listener_name: String,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub sanitized_headers: HeaderMap,
    pub identity: crate::policy_context::ResolvedIdentity,
    pub initial_action: ActionConfig,
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
        .listener_config(ctx.listener_name.as_str())
        .ok_or_else(|| anyhow!("listener not found"))?;
    let upgrade_wait = Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
    let upstream_timeout = Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);
    let upgraded = timeout(upgrade_wait, crate::http::upgrade::on(&mut req)).await??;
    let (client_io, client_hello, mut action) =
        prepare_connect_client_io(upgraded, &runtime, &ctx).await?;
    let TunnelConnectContext {
        remote_addr,
        listener_name,
        host,
        port,
        authority,
        sanitized_headers,
        identity,
        initial_action,
        verify_upstream,
        _concurrency_permits,
        throttle,
    } = ctx;
    let mut server = Some(server);
    let listener_upstream_trust = listener_upstream_trust(listener_cfg)?;

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
                        && !state
                            .tls_verify_exception_matches(listener_name.as_str(), host.as_str())
                })
                .unwrap_or(true);
            let preview_server = server
                .take()
                .expect("CONNECT upstream tunnel must exist before cert preview");
            match preview_tls_certificate_with_options(
                host.as_str(),
                preview_server.io,
                preview_verify,
                listener_upstream_trust.as_deref(),
            )
            .await
            {
                Ok(upstream_cert) => {
                    action = decide_connect_action_from_tls_metadata(ConnectPolicyInput {
                        runtime: &runtime,
                        listener_name: listener_name.as_str(),
                        remote_addr,
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
                    if listener_upstream_trust.is_some() {
                        return Err(err);
                    }
                    warn!(error = ?err, "forward CONNECT upstream certificate preview failed");
                }
            }
        }
    }

    let reconnect_needed = server.is_none() || action != initial_action;
    if reconnect_needed
        && matches!(
            action.kind,
            ActionKind::Inspect | ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
        )
    {
        let upstream = resolve_upstream(&action, &state, listener_name.as_str())?;
        server = Some(
            connect_tunnel_target(
                host.as_str(),
                port,
                upstream.as_ref(),
                state.config.identity.proxy_name.as_str(),
                upstream_timeout,
            )
            .await?,
        );
    }

    match action.kind {
        ActionKind::Block | ActionKind::Respond => Ok(()),
        ActionKind::Inspect => {
            #[cfg(not(feature = "mitm"))]
            {
                let _ = verify_upstream;
                let _ = client_io;
                let _ = server;
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
                    .mitm
                    .clone()
                    .ok_or_else(|| anyhow!("mitm not available"))?;
                let client_tls = accept_mitm_client(client_io, &mitm, upstream_timeout).await?;
                let (sender, upstream_cert) = connect_mitm_upstream(
                    server.expect("reconnected server for CONNECT MITM").io,
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
                    Duration::from_millis(state.config.runtime.http_header_read_timeout_ms);
                let access_cfg = state.config.access_log.clone();
                let access_name = Arc::<str>::from(listener_name.as_str());
                let service = handler_fn(move |inner_req: Request<Body>| {
                    let sender = sender.clone();
                    let runtime = runtime.clone();
                    let listener_name = listener_name.clone();
                    let connect_host = connect_host.clone();
                    let upstream_cert = upstream_cert.clone();
                    async move {
                        let proxy_name = runtime.state().config.identity.proxy_name.clone();
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
                        kind: "forward",
                        name: access_name,
                    },
                    &access_cfg,
                );

                crate::http::http1_codec::serve_http1_with_interim(
                    client_tls,
                    service,
                    header_read_timeout,
                )
                .await
                .context("serve_connection failed")?;
                Ok(())
            }
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {
            let server = server.expect("reconnected server for CONNECT tunnel");
            let export = server
                .peer_addr
                .and_then(|server_addr| state.export_session(remote_addr, server_addr));
            let idle_timeout = Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
            copy_bidirectional_with_export_and_idle(
                client_io,
                server.io,
                export,
                Some(idle_timeout),
                throttle,
            )
            .await?;
            Ok(())
        }
    }
}

pub(super) async fn prepare_connect_client_io<I>(
    mut upgraded: I,
    runtime: &Runtime,
    ctx: &TunnelConnectContext,
) -> Result<(PrefixedIo<I>, Option<TlsClientHelloInfo>, ActionConfig)>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let peek_timeout = Duration::from_millis(runtime.state().config.runtime.tls_peek_timeout_ms);
    let sniff = try_read_client_hello_with_timeout(&mut upgraded, peek_timeout).await?;
    let client_hello = looks_like_tls_client_hello(&sniff)
        .then(|| extract_client_hello_info(&sniff))
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
