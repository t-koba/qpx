use crate::upstream::connect::TunnelIo;
use anyhow::{anyhow, Result};
use hyper::client::conn::Builder as ClientConnBuilder;
use hyper::Body;
use qpx_core::tls::MitmConfig;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::warn;

pub(crate) async fn accept_mitm_client<C>(
    client_io: C,
    mitm: &MitmConfig,
    timeout_dur: Duration,
) -> Result<tokio_rustls::server::TlsStream<C>>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let acceptor = TlsAcceptor::from(mitm.server_config.clone());
    Ok(timeout(timeout_dur, acceptor.accept(client_io)).await??)
}

pub(crate) async fn connect_mitm_upstream(
    upstream_io: TunnelIo,
    host: &str,
    mitm: &MitmConfig,
    verify_upstream: bool,
    timeout_dur: Duration,
    log_context: &'static str,
) -> Result<Arc<tokio::sync::Mutex<hyper::client::conn::SendRequest<Body>>>> {
    // For MITM traffic we force HTTP/1.1 upstream to keep Upgrade/WebSocket semantics working
    // and to avoid relying on HTTP/2 pseudo-header inference.
    let base = mitm.ca.client_config(verify_upstream)?;
    let mut client_config = (*base).clone();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = server_name_for_host(host)?;
    let server_tls = timeout(timeout_dur, connector.connect(server_name, upstream_io)).await??;
    let (sender, conn): (hyper::client::conn::SendRequest<Body>, _) = timeout(
        timeout_dur,
        ClientConnBuilder::new().handshake::<_, Body>(server_tls),
    )
    .await??;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!(error = ?err, context = log_context, "upstream conn closed");
        }
    });

    Ok(Arc::new(tokio::sync::Mutex::new(sender)))
}

fn server_name_for_host(host: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
    }
    rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("invalid server name for TLS: {}", host))
}
