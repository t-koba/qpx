use crate::forward::connect::{ConnectPolicyInput, decide_connect_action_from_client_hello};
#[cfg(feature = "mitm")]
use crate::http::body::Body;
#[cfg(feature = "mitm")]
use crate::http::codec::h1::serve_http1_with_interim_and_capacity;
#[cfg(feature = "mitm")]
use crate::http::mitm::{MitmRouteContext, proxy_mitm_request};
use crate::http3::server::H3ServerRequestStream;
use crate::runtime::PlanFlags;
#[cfg(feature = "mitm")]
use crate::tls::CompiledUpstreamTlsTrust;
#[cfg(feature = "mitm")]
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream, prewarm_mitm_cert};
use crate::tls::{
    TlsClientHelloInfo, extract_client_hello_info_with_fingerprints, looks_like_tls_client_hello,
};
use crate::upstream::connect::TunnelIo;
use anyhow::Result;
use bytes::{Buf, Bytes};
#[cfg(feature = "mitm")]
use hyper::Request;
use qpx_core::config::{ActionConfig, ActionKind};
#[cfg(feature = "mitm")]
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
#[cfg(feature = "mitm")]
use qpx_observability::handler_fn;
#[cfg(feature = "mitm")]
use std::convert::Infallible;
use std::net::SocketAddr;
#[cfg(feature = "mitm")]
use std::sync::Arc;
use tokio::time::{Duration, Instant};

const MAX_H3_CONNECT_PEEK_BYTES: usize = 64 * 1024;

pub(super) struct H3ConnectPolicyContext<'a> {
    pub(super) listener_name: &'a str,
    pub(super) remote_addr: SocketAddr,
    pub(super) host: &'a str,
    pub(super) port: u16,
    pub(super) authority: &'a str,
    pub(super) sanitized_headers: http::HeaderMap,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) initial_action: ActionConfig,
}

#[cfg(feature = "mitm")]
pub(super) struct MitmH3ConnectInput {
    pub(super) req_stream: H3ServerRequestStream,
    pub(super) client_prefetch: Bytes,
    pub(super) upstream_tcp: TunnelIo,
    pub(super) runtime: crate::runtime::Runtime,
    pub(super) listener_name: Arc<str>,
    pub(super) remote_addr: SocketAddr,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) mitm_server_name: String,
    pub(super) mitm: qpx_core::tls::MitmConfig,
    pub(super) verify_upstream: bool,
    pub(super) trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    pub(super) header_read_timeout: Duration,
    pub(super) upstream_timeout: Duration,
    pub(super) tunnel_idle_timeout: Duration,
}

pub(super) async fn relay_h3_connect_stream(
    req_stream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    client_prefetch: Bytes,
    server: TunnelIo,
    idle_timeout: Duration,
) -> Result<()> {
    let (req_send, req_recv) = req_stream.split();
    let (server_read, server_write) = tokio::io::split(server);
    let req_recv = crate::tunnel::stream::PrefixedTunnelHalf::new(req_recv, client_prefetch);
    let _stats = crate::tunnel::relay_tunnel(
        req_recv,
        req_send,
        server_read,
        server_write,
        crate::tunnel::TunnelPolicy::h3(Some(idle_timeout), "h3_connect", "unknown"),
    )
    .await?;
    Ok(())
}

pub(super) async fn prepare_h3_connect_stream(
    mut req_stream: H3ServerRequestStream,
    runtime: &crate::runtime::Runtime,
    ctx: H3ConnectPolicyContext<'_>,
) -> Result<(
    H3ServerRequestStream,
    Bytes,
    Option<TlsClientHelloInfo>,
    ActionConfig,
)> {
    let peek_timeout =
        Duration::from_millis(runtime.state().plan.limits.timeouts.tls_peek_timeout_ms);
    let sniff = sniff_h3_connect_client_hello(&mut req_stream, peek_timeout).await?;
    let include_fingerprints = h3_connect_tls_fingerprints_required(runtime, ctx.listener_name);
    let client_hello = looks_like_tls_client_hello(&sniff)
        .then(|| extract_client_hello_info_with_fingerprints(&sniff, include_fingerprints))
        .flatten();
    let action = match client_hello.as_ref() {
        Some(client_hello) => {
            decide_connect_action_from_client_hello(ConnectPolicyInput {
                runtime,
                listener_name: ctx.listener_name,
                remote_addr: ctx.remote_addr,
                host: ctx.host,
                port: ctx.port,
                authority: ctx.authority,
                sanitized_headers: &ctx.sanitized_headers,
                identity: ctx.identity,
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
        None => ctx.initial_action,
    };
    Ok((req_stream, Bytes::from(sniff), client_hello, action))
}

async fn sniff_h3_connect_client_hello(
    req_stream: &mut H3ServerRequestStream,
    timeout_dur: Duration,
) -> Result<Vec<u8>> {
    let deadline = crate::runtime::tokio_deadline_after(timeout_dur);
    let mut out = Vec::new();
    loop {
        if out.len() >= 5 {
            if !looks_like_tls_client_hello(&out) {
                return Ok(out);
            }
            if extract_client_hello_info_with_fingerprints(&out, false).is_some()
                || out.len() >= MAX_H3_CONNECT_PEEK_BYTES
            {
                out.truncate(MAX_H3_CONNECT_PEEK_BYTES);
                return Ok(out);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let recv = match tokio::time::timeout(remaining, req_stream.recv_data()).await {
            Ok(recv) => recv?,
            Err(_) => return Ok(out),
        };
        let Some(mut bytes) = recv else {
            return Ok(out);
        };
        let remaining = bytes.remaining();
        if remaining == 0 {
            return Ok(out);
        }
        let take = (MAX_H3_CONNECT_PEEK_BYTES - out.len()).min(remaining);
        let bytes = bytes.copy_to_bytes(take);
        out.extend_from_slice(bytes.as_ref());
        if out.len() >= MAX_H3_CONNECT_PEEK_BYTES {
            return Ok(out);
        }
    }
}

fn h3_connect_tls_fingerprints_required(
    runtime: &crate::runtime::Runtime,
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

#[cfg(feature = "mitm")]
pub(super) async fn mitm_h3_connect_stream(input: MitmH3ConnectInput) -> Result<()> {
    let MitmH3ConnectInput {
        req_stream,
        client_prefetch,
        upstream_tcp,
        runtime,
        listener_name,
        remote_addr,
        host,
        port,
        mitm_server_name,
        mitm,
        verify_upstream,
        trust,
        header_read_timeout,
        upstream_timeout,
        tunnel_idle_timeout,
    } = input;
    let (client_io, bridge_io) = tokio::io::duplex(64 * 1024);

    let bridge = relay_h3_connect_stream_to_io(req_stream, bridge_io, tunnel_idle_timeout);
    let mitm_fut = async move {
        let client_io =
            crate::http::protocol::io_prefix::PrefixedIo::new(client_io, client_prefetch);
        prewarm_mitm_cert(&mitm, mitm_server_name.as_str(), upstream_timeout).await?;
        let client_tls = accept_mitm_client(client_io, &mitm, upstream_timeout).await?;
        let (sender, upstream_cert) = connect_mitm_upstream(
            upstream_tcp,
            host.as_str(),
            verify_upstream,
            trust.as_deref(),
            upstream_timeout,
            "forward HTTP/3 MITM upstream conn",
        )
        .await?;
        let upstream_cert = Arc::new(upstream_cert);
        let connect_host = host.clone();
        let runtime_for_service = runtime.clone();
        let listener_name_for_service = listener_name.clone();
        let service = handler_fn(move |inner_req: Request<Body>| {
            let sender = sender.clone();
            let runtime = runtime_for_service.clone();
            let listener_name = listener_name_for_service.clone();
            let connect_host = connect_host.clone();
            let upstream_cert = upstream_cert.clone();
            async move {
                let proxy_name = runtime.state().plan.identity.proxy_name.to_string();
                let proxy_error = runtime.state().messages.proxy_error.clone();
                let request_method = inner_req.method().clone();
                let request_version = inner_req.version();
                let route = MitmRouteContext {
                    listener_name: listener_name.as_ref(),
                    src_addr: remote_addr,
                    dst_port: port,
                    host: connect_host.as_str(),
                    sni: connect_host.as_str(),
                    upstream_cert: Some(upstream_cert),
                };
                match proxy_mitm_request(inner_req, runtime, sender, route).await {
                    Ok(response) => Ok::<_, Infallible>(response),
                    Err(err) => {
                        tracing::warn!(error = ?err, "forward HTTP/3 MITM request failed");
                        Ok(crate::http::protocol::l7::finalize_response_for_request(
                            &request_method,
                            request_version,
                            proxy_name.as_str(),
                            hyper::Response::builder()
                                .status(hyper::StatusCode::BAD_GATEWAY)
                                .body(Body::from(proxy_error))
                                .unwrap_or_else(|_| {
                                    hyper::Response::new(Body::from("proxy error"))
                                }),
                            false,
                        ))
                    }
                }
            }
        });
        let access_cfg = runtime.state().resources.access_log.clone();
        let service = AccessLogService::new(
            service,
            remote_addr,
            AccessLogContext {
                kind: crate::http::dispatch::ProxyKind::Forward.as_str(),
                name: listener_name,
            },
            &access_cfg,
        );

        serve_http1_with_interim_and_capacity(
            client_tls,
            service,
            header_read_timeout,
            runtime.state().plan.limits.body.body_channel_capacity,
        )
        .await?;
        Ok::<(), anyhow::Error>(())
    };

    let _ = tokio::try_join!(mitm_fut, bridge)?;
    Ok(())
}

#[cfg(feature = "mitm")]
async fn relay_h3_connect_stream_to_io(
    req_stream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    io: tokio::io::DuplexStream,
    idle_timeout: Duration,
) -> Result<()> {
    let (req_send, req_recv) = req_stream.split();
    let (io_read, io_write) = tokio::io::split(io);
    let _stats = crate::tunnel::relay_tunnel(
        req_recv,
        req_send,
        io_read,
        io_write,
        crate::tunnel::TunnelPolicy::h3(Some(idle_timeout), "h3_connect_mitm_bridge", "unknown"),
    )
    .await?;
    Ok(())
}
