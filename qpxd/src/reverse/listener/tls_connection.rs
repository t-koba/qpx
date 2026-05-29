use super::{ReverseInterimService, reverse_body_channel_capacity};
use crate::http::codec::h1::serve_http1_with_interim_and_capacity;
use crate::http::codec::interim::serve_h2_with_interim_and_capacity;
use crate::reverse::transport::ReverseConnInfo;
use crate::reverse::{
    ReloadableReverse, record_reverse_connection_filter_block, reverse_connection_filter_match,
    reverse_tls_fingerprints_required,
};
use crate::tcp_bindings::filter::ConnectionFilterStage;
use crate::tls::{extract_client_hello_info_with_fingerprints, read_client_hello_with_timeout};
use crate::xdp::remote::resolve_remote_addr_with_xdp;
use anyhow::Result;
use bytes::Bytes;
use qpx_observability::access_log::{AccessLogContext, AccessLogService};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::{Duration, timeout};
use tracing::warn;

#[cfg(feature = "tls-rustls")]
struct ReverseTlsContext {
    reverse: ReloadableReverse,
}

#[cfg(feature = "tls-rustls")]
pub(crate) async fn run_reverse_tls_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            permit = semaphore.clone().acquire_owned() => Some(permit?),
        };
        let Some(permit) = permit else {
            break;
        };
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => Some(accepted),
                Err(err) => {
                    warn!(error = ?err, "reverse TLS accept failed");
                    continue;
                }
            }
        };
        let Some((stream, remote_addr)) = accepted else {
            break;
        };
        let _ = stream.set_nodelay(true);
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve reverse local addr");
                continue;
            }
        };
        let reverse = reverse.clone();
        let xdp_cfg = xdp_cfg.clone();
        let reverse_name = reverse.name.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let header_read_timeout = Duration::from_millis(
                reverse
                    .runtime
                    .state()
                    .plan
                    .limits
                    .timeouts
                    .http_header_read_timeout_ms,
            );
            let (stream, remote_addr) = match resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            if let Some(matched_rule) =
                reverse_connection_filter_match(&reverse, remote_addr, local_port, None)
            {
                record_reverse_connection_filter_block(
                    &reverse,
                    remote_addr,
                    local_port,
                    ConnectionFilterStage::Accept,
                    matched_rule.as_str(),
                    None,
                );
                return;
            }
            let reverse_name_for_log = reverse_name.clone();
            let ctx = ReverseTlsContext { reverse };
            if let Err(err) = handle_tls_connection(stream, remote_addr, local_port, ctx).await {
                warn!(error = ?err, "reverse tls connection failed");
                if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                    tracing::warn!(
                        target: "audit_log",
                        event = "tls_error",
                        reverse = %reverse_name_for_log,
                        remote = %remote_addr,
                        error = ?err,
                    );
                }
            }
        });
    }
    Ok(())
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
struct ReverseTlsContext {
    reverse: ReloadableReverse,
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(crate) async fn run_reverse_tls_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            permit = semaphore.clone().acquire_owned() => Some(permit?),
        };
        let Some(permit) = permit else {
            break;
        };
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => Some(accepted),
                Err(err) => {
                    warn!(error = ?err, "reverse TLS accept failed");
                    continue;
                }
            }
        };
        let Some((stream, remote_addr)) = accepted else {
            break;
        };
        let _ = stream.set_nodelay(true);
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve reverse local addr");
                continue;
            }
        };
        let reverse = reverse.clone();
        let xdp_cfg = xdp_cfg.clone();
        let reverse_name = reverse.name.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let header_read_timeout = Duration::from_millis(
                reverse
                    .runtime
                    .state()
                    .plan
                    .limits
                    .timeouts
                    .http_header_read_timeout_ms,
            );
            let (stream, remote_addr) = match resolve_remote_addr_with_xdp(
                stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(resolved) => resolved,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            if let Some(matched_rule) =
                reverse_connection_filter_match(&reverse, remote_addr, local_port, None)
            {
                record_reverse_connection_filter_block(
                    &reverse,
                    remote_addr,
                    local_port,
                    ConnectionFilterStage::Accept,
                    matched_rule.as_str(),
                    None,
                );
                return;
            }
            let reverse_name_for_log = reverse_name.clone();
            let ctx = ReverseTlsContext { reverse };
            if let Err(err) = handle_tls_connection(stream, remote_addr, local_port, ctx).await {
                warn!(error = ?err, "reverse tls connection failed");
                if tracing::enabled!(target: "audit_log", tracing::Level::WARN) {
                    tracing::warn!(
                        target: "audit_log",
                        event = "tls_error",
                        reverse = %reverse_name_for_log,
                        remote = %remote_addr,
                        error = ?err,
                    );
                }
            }
        });
    }
    Ok(())
}

#[cfg(feature = "tls-rustls")]
async fn handle_tls_connection(
    stream: crate::http::protocol::io_prefix::PrefixedIo<TcpStream>,
    remote_addr: std::net::SocketAddr,
    local_port: u16,
    ctx: ReverseTlsContext,
) -> Result<()> {
    let ReverseTlsContext { reverse } = ctx;
    let mut stream = stream;
    let peek_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .plan
            .limits
            .timeouts
            .tls_peek_timeout_ms,
    );
    let peek = read_client_hello_with_timeout(&mut stream, peek_timeout).await?;
    let client_hello = extract_client_hello_info_with_fingerprints(
        &peek,
        reverse_tls_fingerprints_required(&reverse),
    );
    let sni = client_hello
        .as_ref()
        .and_then(|hello| hello.sni.clone())
        .map(Arc::<str>::from);
    if let Some(matched_rule) =
        reverse_connection_filter_match(&reverse, remote_addr, local_port, client_hello.as_ref())
    {
        record_reverse_connection_filter_block(
            &reverse,
            remote_addr,
            local_port,
            ConnectionFilterStage::ClientHello,
            matched_rule.as_str(),
            client_hello.as_ref().and_then(|hello| hello.sni.as_deref()),
        );
        return Ok(());
    }
    let stream = crate::http::protocol::io_prefix::PrefixedIo::new(stream, Bytes::from(peek));

    let compiled = reverse.compiled().await;
    if let Some(upstream) = compiled.router.select_tls_passthrough_upstream(
        remote_addr.ip(),
        local_port,
        sni.as_deref(),
    ) {
        let addr = upstream.origin.connect_authority(443)?;
        let upstream_timeout = Duration::from_millis(
            reverse
                .runtime
                .state()
                .plan
                .limits
                .timeouts
                .upstream_http_timeout_ms,
        );
        let upstream_stream =
            tokio::time::timeout(upstream_timeout, TcpStream::connect(&addr)).await??;
        let _ = upstream_stream.set_nodelay(true);
        let export = upstream_stream.peer_addr().ok().and_then(|server_addr| {
            reverse
                .runtime
                .state()
                .export_session(remote_addr, server_addr)
        });
        let idle_timeout = Duration::from_millis(
            reverse
                .runtime
                .state()
                .plan
                .limits
                .timeouts
                .tunnel_idle_timeout_ms,
        );
        crate::tunnel::relay_tcp_tunnel(
            stream,
            upstream_stream,
            crate::tunnel::TunnelPolicy::tcp(Some(idle_timeout), None, export),
        )
        .await?;
        return Ok(());
    }

    let tls_accept_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .plan
            .limits
            .timeouts
            .upstream_http_timeout_ms,
    );
    let acceptor = compiled
        .tls_acceptor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reverse tls acceptor missing"))?
        .clone();
    let tls_stream = timeout(tls_accept_timeout, acceptor.accept(stream)).await??;
    let negotiated_h2 = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|alpn| alpn == b"h2")
        .unwrap_or(false);
    let peer_certificates = tls_stream.get_ref().1.peer_certificates().map(|certs| {
        Arc::new(
            certs
                .iter()
                .map(|cert| cert.as_ref().to_vec())
                .collect::<Vec<_>>(),
        )
    });
    let header_read_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .plan
            .limits
            .timeouts
            .http_header_read_timeout_ms,
    );
    let conn = ReverseConnInfo::terminated(remote_addr, local_port, sni.clone(), peer_certificates);
    let access_cfg = reverse.runtime.state().resources.access_log.clone();
    let reverse_name = reverse.name.clone();
    if negotiated_h2 {
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse: reverse.clone(),
                conn,
            },
            remote_addr,
            AccessLogContext {
                kind: crate::http::dispatch::ProxyKind::Reverse.as_str(),
                name: reverse_name.clone(),
            },
            &access_cfg,
        );
        serve_h2_with_interim_and_capacity(
            tls_stream,
            service,
            false,
            header_read_timeout,
            reverse_body_channel_capacity(&reverse),
        )
        .await?;
    } else {
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse: reverse.clone(),
                conn,
            },
            remote_addr,
            AccessLogContext {
                kind: crate::http::dispatch::ProxyKind::Reverse.as_str(),
                name: reverse_name.clone(),
            },
            &access_cfg,
        );
        serve_http1_with_interim_and_capacity(
            tls_stream,
            service,
            header_read_timeout,
            reverse_body_channel_capacity(&reverse),
        )
        .await?;
    }
    Ok(())
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
async fn handle_tls_connection(
    stream: crate::http::protocol::io_prefix::PrefixedIo<TcpStream>,
    remote_addr: std::net::SocketAddr,
    local_port: u16,
    ctx: ReverseTlsContext,
) -> Result<()> {
    let ReverseTlsContext { reverse } = ctx;
    let mut stream = stream;
    let peek_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .plan
            .limits
            .timeouts
            .tls_peek_timeout_ms,
    );
    let peek = read_client_hello_with_timeout(&mut stream, peek_timeout).await?;
    let client_hello = extract_client_hello_info_with_fingerprints(
        &peek,
        reverse_tls_fingerprints_required(&reverse),
    );
    let sni = client_hello
        .as_ref()
        .and_then(|hello| hello.sni.clone())
        .map(Arc::<str>::from);
    if let Some(matched_rule) =
        reverse_connection_filter_match(&reverse, remote_addr, local_port, client_hello.as_ref())
    {
        record_reverse_connection_filter_block(
            &reverse,
            remote_addr,
            local_port,
            ConnectionFilterStage::ClientHello,
            matched_rule.as_str(),
            client_hello.as_ref().and_then(|hello| hello.sni.as_deref()),
        );
        return Ok(());
    }
    let stream = crate::http::protocol::io_prefix::PrefixedIo::new(stream, Bytes::from(peek));

    let compiled = reverse.compiled().await;
    if let Some(upstream) = compiled.router.select_tls_passthrough_upstream(
        remote_addr.ip(),
        local_port,
        sni.as_deref(),
    ) {
        let addr = upstream.origin.connect_authority(443)?;
        let upstream_timeout = Duration::from_millis(
            reverse
                .runtime
                .state()
                .plan
                .limits
                .timeouts
                .upstream_http_timeout_ms,
        );
        let upstream_stream =
            tokio::time::timeout(upstream_timeout, TcpStream::connect(&addr)).await??;
        let _ = upstream_stream.set_nodelay(true);
        let export = upstream_stream.peer_addr().ok().and_then(|server_addr| {
            reverse
                .runtime
                .state()
                .export_session(remote_addr, server_addr)
        });
        let idle_timeout = Duration::from_millis(
            reverse
                .runtime
                .state()
                .plan
                .limits
                .timeouts
                .tunnel_idle_timeout_ms,
        );
        crate::tunnel::relay_tcp_tunnel(
            stream,
            upstream_stream,
            crate::tunnel::TunnelPolicy::tcp(Some(idle_timeout), None, export),
        )
        .await?;
        return Ok(());
    }

    let tls_accept_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .plan
            .limits
            .timeouts
            .upstream_http_timeout_ms,
    );
    let acceptor = compiled
        .tls_acceptor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reverse tls acceptor missing"))?
        .clone();
    let tls_stream = timeout(tls_accept_timeout, acceptor.accept(stream, sni.as_deref())).await??;
    let negotiated_h2 = tls_stream
        .get_ref()
        .negotiated_alpn()
        .ok()
        .flatten()
        .map(|alpn| alpn == b"h2")
        .unwrap_or(false);
    let header_read_timeout = Duration::from_millis(
        reverse
            .runtime
            .state()
            .plan
            .limits
            .timeouts
            .http_header_read_timeout_ms,
    );
    let conn = ReverseConnInfo::terminated(remote_addr, local_port, sni.clone(), None);
    let access_cfg = reverse.runtime.state().resources.access_log.clone();
    let reverse_name = reverse.name.clone();
    if negotiated_h2 {
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse: reverse.clone(),
                conn,
            },
            remote_addr,
            AccessLogContext {
                kind: crate::http::dispatch::ProxyKind::Reverse.as_str(),
                name: reverse_name.clone(),
            },
            &access_cfg,
        );
        serve_h2_with_interim_and_capacity(
            tls_stream,
            service,
            false,
            header_read_timeout,
            reverse_body_channel_capacity(&reverse),
        )
        .await?;
    } else {
        let service = AccessLogService::new(
            ReverseInterimService {
                reverse: reverse.clone(),
                conn,
            },
            remote_addr,
            AccessLogContext {
                kind: crate::http::dispatch::ProxyKind::Reverse.as_str(),
                name: reverse_name.clone(),
            },
            &access_cfg,
        );
        serve_http1_with_interim_and_capacity(
            tls_stream,
            service,
            header_read_timeout,
            reverse_body_channel_capacity(&reverse),
        )
        .await?;
    }
    Ok(())
}
