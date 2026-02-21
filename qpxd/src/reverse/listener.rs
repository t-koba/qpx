use super::transport::{handle_request, ReverseConnInfo};
use super::ReloadableReverse;
use crate::http::server::serve_http1_with_upgrades;
use crate::xdp::remote::resolve_remote_addr_with_xdp;
use anyhow::Result;
use hyper::service::service_fn;
use qpx_core::middleware::access_log::{AccessLogContext, AccessLogService};
use tokio::net::TcpListener;
use tokio::time::Duration;
use tracing::warn;

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use std::sync::Arc;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use crate::io_copy::copy_bidirectional_with_export_and_idle;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use crate::tls::{extract_sni, read_client_hello_with_timeout};
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use crate::upstream::origin::parse_upstream_addr;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use bytes::Bytes;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use tokio::net::TcpStream;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use tokio::time::timeout;

#[cfg(feature = "tls-rustls")]
struct ReverseTlsContext {
    reverse: ReloadableReverse,
}

#[cfg(feature = "tls-rustls")]
pub(super) async fn run_reverse_tls_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = semaphore.clone().acquire_owned().await?;
        let (stream, remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = ?err, "reverse TLS accept failed");
                continue;
            }
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
            let header_read_timeout =
                Duration::from_millis(reverse.runtime.state().config.runtime.http_header_read_timeout_ms);
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
            let reverse_name_for_log = reverse_name.clone();
            let ctx = ReverseTlsContext {
                reverse,
            };
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
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
struct ReverseTlsContext {
    reverse: ReloadableReverse,
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(super) async fn run_reverse_tls_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = semaphore.clone().acquire_owned().await?;
        let (stream, remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = ?err, "reverse TLS accept failed");
                continue;
            }
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
            let header_read_timeout =
                Duration::from_millis(reverse.runtime.state().config.runtime.http_header_read_timeout_ms);
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
            let reverse_name_for_log = reverse_name.clone();
            let ctx = ReverseTlsContext {
                reverse,
            };
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
}

pub(super) async fn run_reverse_http_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    reverse: ReloadableReverse,
) -> Result<()> {
    let semaphore = reverse.runtime.state().connection_semaphore.clone();
    loop {
        let permit = semaphore.clone().acquire_owned().await?;
        let (stream, remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = ?err, "reverse accept failed");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve reverse local addr");
                continue;
            }
        };
        let xdp_cfg = xdp_cfg.clone();
        let reverse = reverse.clone();
        let reverse_name = reverse.name.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let header_read_timeout =
                Duration::from_millis(reverse.runtime.state().config.runtime.http_header_read_timeout_ms);
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
            let conn = ReverseConnInfo::plain(remote_addr, local_port);
            let access_cfg = reverse.runtime.state().config.access_log.clone();
            let service = service_fn(move |req| {
                handle_request(req, reverse.clone(), conn.clone())
            });
            let service = AccessLogService::new(
                service,
                remote_addr,
                AccessLogContext {
                    kind: "reverse",
                    name: reverse_name,
                },
                &access_cfg,
            );
            if let Err(err) =
                serve_http1_with_upgrades(stream, service, header_read_timeout, false).await
            {
                warn!(error = ?err, "reverse connection failed");
            }
        });
    }
}

#[cfg(feature = "tls-rustls")]
async fn handle_tls_connection(
    stream: crate::io_prefix::PrefixedIo<TcpStream>,
    remote_addr: std::net::SocketAddr,
    local_port: u16,
    ctx: ReverseTlsContext,
) -> Result<()> {
    let ReverseTlsContext { reverse } = ctx;
    let mut stream = stream;
    let peek_timeout =
        Duration::from_millis(reverse.runtime.state().config.runtime.tls_peek_timeout_ms);
    let peek = read_client_hello_with_timeout(&mut stream, peek_timeout).await?;
    let sni = extract_sni(&peek).map(Arc::<str>::from);
    let stream = crate::io_prefix::PrefixedIo::new(stream, Bytes::from(peek));

    let compiled = reverse.compiled().await;
    if let Some(upstream) =
        compiled
            .router
            .select_tls_passthrough_upstream(remote_addr.ip(), local_port, sni.as_deref())
    {
        let addr = parse_upstream_addr(&upstream, 443)?;
        let upstream_timeout =
            Duration::from_millis(reverse.runtime.state().config.runtime.upstream_http_timeout_ms);
        let upstream_stream =
            tokio::time::timeout(upstream_timeout, TcpStream::connect(&addr)).await??;
        let _ = upstream_stream.set_nodelay(true);
        let export = upstream_stream
            .peer_addr()
            .ok()
            .and_then(|server_addr| reverse.runtime.state().export_session(remote_addr, server_addr));
        let idle_timeout =
            Duration::from_millis(reverse.runtime.state().config.runtime.tunnel_idle_timeout_ms);
        copy_bidirectional_with_export_and_idle(
            stream,
            upstream_stream,
            export,
            Some(idle_timeout),
            None,
        )
        .await?;
        return Ok(());
    }

    let tls_accept_timeout =
        Duration::from_millis(reverse.runtime.state().config.runtime.upstream_http_timeout_ms);
    let acceptor = compiled
        .tls_acceptor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reverse tls acceptor missing"))?
        .clone();
    let tls_stream = timeout(tls_accept_timeout, acceptor.accept(stream)).await??;
    let header_read_timeout =
        Duration::from_millis(reverse.runtime.state().config.runtime.http_header_read_timeout_ms);
    let conn = ReverseConnInfo::terminated(remote_addr, local_port, sni.clone());
    let access_cfg = reverse.runtime.state().config.access_log.clone();
    let reverse_name = reverse.name.clone();
    let service = service_fn(move |req| {
        handle_request(req, reverse.clone(), conn.clone())
    });
    let service = AccessLogService::new(
        service,
        remote_addr,
        AccessLogContext {
            kind: "reverse",
            name: reverse_name.clone(),
        },
        &access_cfg,
    );
    serve_http1_with_upgrades(tls_stream, service, header_read_timeout, false).await?;
    Ok(())
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
async fn handle_tls_connection(
    stream: crate::io_prefix::PrefixedIo<TcpStream>,
    remote_addr: std::net::SocketAddr,
    local_port: u16,
    ctx: ReverseTlsContext,
) -> Result<()> {
    let ReverseTlsContext { reverse } = ctx;
    let mut stream = stream;
    let peek_timeout =
        Duration::from_millis(reverse.runtime.state().config.runtime.tls_peek_timeout_ms);
    let peek = read_client_hello_with_timeout(&mut stream, peek_timeout).await?;
    let sni = extract_sni(&peek).map(Arc::<str>::from);
    let stream = crate::io_prefix::PrefixedIo::new(stream, Bytes::from(peek));

    let compiled = reverse.compiled().await;
    if let Some(upstream) =
        compiled
            .router
            .select_tls_passthrough_upstream(remote_addr.ip(), local_port, sni.as_deref())
    {
        let addr = parse_upstream_addr(&upstream, 443)?;
        let upstream_timeout =
            Duration::from_millis(reverse.runtime.state().config.runtime.upstream_http_timeout_ms);
        let upstream_stream =
            tokio::time::timeout(upstream_timeout, TcpStream::connect(&addr)).await??;
        let _ = upstream_stream.set_nodelay(true);
        let export = upstream_stream
            .peer_addr()
            .ok()
            .and_then(|server_addr| reverse.runtime.state().export_session(remote_addr, server_addr));
        let idle_timeout =
            Duration::from_millis(reverse.runtime.state().config.runtime.tunnel_idle_timeout_ms);
        copy_bidirectional_with_export_and_idle(
            stream,
            upstream_stream,
            export,
            Some(idle_timeout),
            None,
        )
        .await?;
        return Ok(());
    }

    let tls_accept_timeout =
        Duration::from_millis(reverse.runtime.state().config.runtime.upstream_http_timeout_ms);
    let acceptor = compiled
        .tls_acceptor
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reverse tls acceptor missing"))?
        .clone();
    let tls_stream = timeout(tls_accept_timeout, acceptor.accept(stream, sni.as_deref())).await??;
    let header_read_timeout =
        Duration::from_millis(reverse.runtime.state().config.runtime.http_header_read_timeout_ms);
    let conn = ReverseConnInfo::terminated(remote_addr, local_port, sni.clone());
    let access_cfg = reverse.runtime.state().config.access_log.clone();
    let reverse_name = reverse.name.clone();
    let service = service_fn(move |req| {
        handle_request(req, reverse.clone(), conn.clone())
    });
    let service = AccessLogService::new(
        service,
        remote_addr,
        AccessLogContext {
            kind: "reverse",
            name: reverse_name.clone(),
        },
        &access_cfg,
    );
    serve_http1_with_upgrades(tls_stream, service, header_read_timeout, false).await?;
    Ok(())
}
