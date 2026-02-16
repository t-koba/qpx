use super::router::ReverseRouter;
use super::security::ReverseTlsHostPolicy;
use super::transport::{handle_request, ReverseConnInfo};
use crate::http::server::serve_http1_with_upgrades;
use crate::io_copy::copy_bidirectional_with_export_and_idle;
use crate::runtime::Runtime;
use crate::tls::{extract_sni, peek_client_hello_with_timeout};
use crate::upstream::origin::parse_upstream_addr;
use crate::xdp::remote::resolve_remote_addr_with_xdp;
use anyhow::Result;
use hyper::service::service_fn;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use tracing::warn;

#[cfg(feature = "tls-rustls")]
pub(super) async fn run_reverse_tls_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    acceptor: super::transport::ReverseTlsAcceptor,
    router: Arc<ReverseRouter>,
    runtime: Runtime,
    security_policy: Arc<ReverseTlsHostPolicy>,
) -> Result<()> {
    loop {
        let (mut stream, remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = ?err, "reverse TLS accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let runtime = runtime.clone();
        let security_policy = security_policy.clone();
        let xdp_cfg = xdp_cfg.clone();
        tokio::spawn(async move {
            let header_read_timeout =
                Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
            let remote_addr = match resolve_remote_addr_with_xdp(
                &mut stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            if let Err(err) = handle_tls_connection(
                stream,
                remote_addr,
                router,
                runtime,
                acceptor,
                security_policy,
            )
            .await
            {
                warn!(error = ?err, "reverse tls connection failed");
            }
        });
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(super) async fn run_reverse_tls_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    acceptor: super::transport::ReverseTlsAcceptor,
    router: Arc<ReverseRouter>,
    runtime: Runtime,
    security_policy: Arc<ReverseTlsHostPolicy>,
) -> Result<()> {
    loop {
        let (mut stream, remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = ?err, "reverse TLS accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        let runtime = runtime.clone();
        let security_policy = security_policy.clone();
        let xdp_cfg = xdp_cfg.clone();
        tokio::spawn(async move {
            let header_read_timeout =
                Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
            let remote_addr = match resolve_remote_addr_with_xdp(
                &mut stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            if let Err(err) = handle_tls_connection(
                stream,
                remote_addr,
                router,
                runtime,
                acceptor,
                security_policy,
            )
            .await
            {
                warn!(error = ?err, "reverse tls connection failed");
            }
        });
    }
}

pub(super) async fn run_reverse_http_acceptor(
    listener: TcpListener,
    xdp_cfg: Option<crate::xdp::CompiledXdpConfig>,
    router: Arc<ReverseRouter>,
    runtime: Runtime,
    security_policy: Arc<ReverseTlsHostPolicy>,
) -> Result<()> {
    loop {
        let (mut stream, remote_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                warn!(error = ?err, "reverse accept failed");
                continue;
            }
        };
        let local_port = match stream.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => {
                warn!(error = ?err, "failed to resolve reverse local addr");
                continue;
            }
        };
        let router = router.clone();
        let runtime = runtime.clone();
        let security_policy = security_policy.clone();
        let xdp_cfg = xdp_cfg.clone();
        tokio::spawn(async move {
            let header_read_timeout =
                Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
            let remote_addr = match resolve_remote_addr_with_xdp(
                &mut stream,
                remote_addr,
                xdp_cfg.as_ref(),
                header_read_timeout,
            )
            .await
            {
                Ok(addr) => addr,
                Err(err) => {
                    warn!(error = ?err, "failed to resolve xdp remote metadata");
                    return;
                }
            };
            let conn = ReverseConnInfo::plain(remote_addr, local_port);
            let service = service_fn(move |req| {
                handle_request(
                    req,
                    router.clone(),
                    runtime.clone(),
                    conn.clone(),
                    security_policy.clone(),
                )
            });
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
    stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    router: Arc<ReverseRouter>,
    runtime: Runtime,
    acceptor: super::transport::ReverseTlsAcceptor,
    security_policy: Arc<ReverseTlsHostPolicy>,
) -> Result<()> {
    let local_port = stream.local_addr()?.port();
    let peek_timeout = Duration::from_millis(runtime.state().config.runtime.tls_peek_timeout_ms);
    let peek = peek_client_hello_with_timeout(&stream, peek_timeout).await?;
    let sni = extract_sni(&peek).map(Arc::<str>::from);

    if let Some(upstream) =
        router.select_tls_passthrough_upstream(remote_addr.ip(), local_port, sni.as_deref())
    {
        let addr = parse_upstream_addr(&upstream, 443)?;
        let upstream_timeout =
            Duration::from_millis(runtime.state().config.runtime.upstream_http_timeout_ms);
        let upstream_stream =
            tokio::time::timeout(upstream_timeout, TcpStream::connect(&addr)).await??;
        let export = upstream_stream
            .peer_addr()
            .ok()
            .and_then(|server_addr| runtime.state().export_session(remote_addr, server_addr));
        let idle_timeout =
            Duration::from_millis(runtime.state().config.runtime.tunnel_idle_timeout_ms);
        copy_bidirectional_with_export_and_idle(
            stream,
            upstream_stream,
            export,
            Some(idle_timeout),
        )
        .await?;
        return Ok(());
    }

    let tls_accept_timeout =
        Duration::from_millis(runtime.state().config.runtime.upstream_http_timeout_ms);
    let tls_stream = timeout(tls_accept_timeout, acceptor.accept(stream)).await??;
    let header_read_timeout =
        Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
    let conn = ReverseConnInfo::terminated(remote_addr, local_port, sni.clone());
    let service = service_fn(move |req| {
        handle_request(
            req,
            router.clone(),
            runtime.clone(),
            conn.clone(),
            security_policy.clone(),
        )
    });
    serve_http1_with_upgrades(tls_stream, service, header_read_timeout, false).await?;
    Ok(())
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
async fn handle_tls_connection(
    stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    router: Arc<ReverseRouter>,
    runtime: Runtime,
    acceptor: super::transport::ReverseTlsAcceptor,
    security_policy: Arc<ReverseTlsHostPolicy>,
) -> Result<()> {
    let local_port = stream.local_addr()?.port();
    let peek_timeout = Duration::from_millis(runtime.state().config.runtime.tls_peek_timeout_ms);
    let peek = peek_client_hello_with_timeout(&stream, peek_timeout).await?;
    let sni = extract_sni(&peek).map(Arc::<str>::from);

    if let Some(upstream) =
        router.select_tls_passthrough_upstream(remote_addr.ip(), local_port, sni.as_deref())
    {
        let addr = parse_upstream_addr(&upstream, 443)?;
        let upstream_timeout =
            Duration::from_millis(runtime.state().config.runtime.upstream_http_timeout_ms);
        let upstream_stream =
            tokio::time::timeout(upstream_timeout, TcpStream::connect(&addr)).await??;
        let export = upstream_stream
            .peer_addr()
            .ok()
            .and_then(|server_addr| runtime.state().export_session(remote_addr, server_addr));
        let idle_timeout =
            Duration::from_millis(runtime.state().config.runtime.tunnel_idle_timeout_ms);
        copy_bidirectional_with_export_and_idle(
            stream,
            upstream_stream,
            export,
            Some(idle_timeout),
        )
        .await?;
        return Ok(());
    }

    let tls_accept_timeout =
        Duration::from_millis(runtime.state().config.runtime.upstream_http_timeout_ms);
    let tls_stream = timeout(tls_accept_timeout, acceptor.accept(stream, sni.as_deref())).await??;
    let header_read_timeout =
        Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
    let conn = ReverseConnInfo::terminated(remote_addr, local_port, sni.clone());
    let service = service_fn(move |req| {
        handle_request(
            req,
            router.clone(),
            runtime.clone(),
            conn.clone(),
            security_policy.clone(),
        )
    });
    serve_http1_with_upgrades(tls_stream, service, header_read_timeout, false).await?;
    Ok(())
}
