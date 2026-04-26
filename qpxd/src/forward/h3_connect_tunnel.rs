use super::super::connect::{decide_connect_action_from_client_hello, ConnectPolicyInput};
#[cfg(feature = "mitm")]
use crate::http::body::Body;
#[cfg(feature = "mitm")]
use crate::http::http1_codec::serve_http1_with_interim;
#[cfg(feature = "mitm")]
use crate::http::mitm::{proxy_mitm_request, MitmRouteContext};
use crate::http3::server::H3ServerRequestStream;
#[cfg(feature = "mitm")]
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream};
#[cfg(feature = "mitm")]
use crate::tls::CompiledUpstreamTlsTrust;
use crate::tls::{extract_client_hello_info, looks_like_tls_client_hello, TlsClientHelloInfo};
use crate::upstream::connect::TunnelIo;
use anyhow::{anyhow, Result};
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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    let (mut req_send, mut req_recv) = req_stream.split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let mut client_eof = false;
    let mut server_eof = false;
    let mut buf = [0u8; 16 * 1024];

    if !client_prefetch.is_empty() {
        timeout_write_all(&mut server_write, client_prefetch.as_ref(), idle_timeout).await?;
        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
    }

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                return Err(anyhow!("forward HTTP/3 CONNECT tunnel idle timeout"));
            }
            recv = req_recv.recv_data(), if !client_eof => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        timeout_write_all(&mut server_write, &bytes, idle_timeout).await?;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => {
                        client_eof = true;
                        // Half-close upstream; the other direction may still drain.
                        let _ = server_write.shutdown().await;
                        if server_eof {
                            break;
                        }
                    }
                }
            }
            n = server_read.read(&mut buf), if !server_eof => {
                let n = n?;
                if n == 0 {
                    server_eof = true;
                    let _ = tokio::time::timeout(idle_timeout, req_send.finish()).await;
                    if client_eof {
                        break;
                    }
                } else {
                    tokio::time::timeout(
                        idle_timeout,
                        req_send.send_data(Bytes::copy_from_slice(&buf[..n])),
                    )
                    .await
                    .map_err(|_| anyhow!("forward HTTP/3 CONNECT downstream send timed out"))??;
                    idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        }
    }
    Ok(())
}

async fn timeout_write_all<W>(writer: &mut W, bytes: &[u8], idle_timeout: Duration) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(idle_timeout, writer.write_all(bytes))
        .await
        .map_err(|_| anyhow!("forward HTTP/3 CONNECT tunnel write timed out"))??;
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
    let peek_timeout = Duration::from_millis(runtime.state().config.runtime.tls_peek_timeout_ms);
    let sniff = sniff_h3_connect_client_hello(&mut req_stream, peek_timeout).await?;
    let client_hello = looks_like_tls_client_hello(&sniff)
        .then(|| extract_client_hello_info(&sniff))
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
    let deadline = Instant::now() + timeout_dur;
    let mut out = Vec::new();
    loop {
        if out.len() >= 5 {
            if !looks_like_tls_client_hello(&out) {
                return Ok(out);
            }
            if extract_client_hello_info(&out).is_some() || out.len() >= MAX_H3_CONNECT_PEEK_BYTES {
                out.truncate(MAX_H3_CONNECT_PEEK_BYTES);
                return Ok(out);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let recv = match tokio::time::timeout(remaining, req_stream.recv_data()).await {
            Ok(recv) => recv?,
            Err(_) => return Ok(out),
        };
        let Some(mut chunk) = recv else {
            return Ok(out);
        };
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        if bytes.is_empty() {
            return Ok(out);
        }
        let take = (MAX_H3_CONNECT_PEEK_BYTES - out.len()).min(bytes.len());
        out.extend_from_slice(&bytes[..take]);
        if out.len() >= MAX_H3_CONNECT_PEEK_BYTES {
            return Ok(out);
        }
    }
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
        let client_io = crate::io_prefix::PrefixedIo::new(client_io, client_prefetch);
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
                let proxy_name = runtime.state().config.identity.proxy_name.clone();
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
                        Ok(crate::http::l7::finalize_response_for_request(
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
        let access_cfg = runtime.state().config.access_log.clone();
        let service = AccessLogService::new(
            service,
            remote_addr,
            AccessLogContext {
                kind: "forward",
                name: listener_name,
            },
            &access_cfg,
        );

        serve_http1_with_interim(client_tls, service, header_read_timeout).await?;
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
    let (mut req_send, mut req_recv) = req_stream.split();
    let (mut io_read, mut io_write) = tokio::io::split(io);

    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let mut client_eof = false;
    let mut io_eof = false;
    let mut buf = [0u8; 16 * 1024];

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                return Err(anyhow!("forward HTTP/3 CONNECT tunnel idle timeout"));
            }
            recv = req_recv.recv_data(), if !client_eof => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        timeout_write_all(&mut io_write, &bytes, idle_timeout).await?;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => {
                        client_eof = true;
                        let _ = io_write.shutdown().await;
                        if io_eof {
                            break;
                        }
                    }
                }
            }
            n = io_read.read(&mut buf), if !io_eof => {
                let n = n?;
                if n == 0 {
                    io_eof = true;
                    let _ = tokio::time::timeout(idle_timeout, req_send.finish()).await;
                    if client_eof {
                        break;
                    }
                } else {
                    tokio::time::timeout(
                        idle_timeout,
                        req_send.send_data(Bytes::copy_from_slice(&buf[..n])),
                    )
                    .await
                    .map_err(|_| anyhow!("forward HTTP/3 CONNECT downstream send timeout"))??;
                    idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        }
    }
    Ok(())
}
