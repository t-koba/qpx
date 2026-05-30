use crate::tls::cert_info::UpstreamCertificateInfo;
use crate::tls::trust::CompiledUpstreamTlsTrust;
use crate::upstream::connect::TunnelIo;
use anyhow::{Result, anyhow};
use qpx_core::tls::MitmConfig;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsAcceptor;
use tracing::warn;

pub(crate) async fn prewarm_mitm_cert(
    mitm: &MitmConfig,
    server_name: &str,
    timeout_dur: Duration,
) -> Result<()> {
    let resolver = mitm.resolver.clone();
    let server_name = server_name.to_string();
    timeout(
        timeout_dur,
        tokio::task::spawn_blocking(move || resolver.prewarm_server_name(server_name.as_str())),
    )
    .await
    .map_err(|_| anyhow!("MITM certificate prewarm timed out"))?
    .map_err(|err| anyhow!("MITM certificate prewarm task failed: {err}"))
    .and_then(|ok| {
        ok.then_some(())
            .ok_or_else(|| anyhow!("failed to prewarm MITM certificate"))
    })
}

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
    verify_upstream: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
    timeout_dur: Duration,
    log_context: &'static str,
) -> Result<(
    Arc<tokio::sync::Mutex<crate::http::protocol::common::Http1SendRequest>>,
    UpstreamCertificateInfo,
)> {
    // For MITM traffic we force HTTP/1.1 upstream to keep Upgrade/WebSocket semantics working
    // and to avoid relying on HTTP/2 pseudo-header inference.
    let (server_tls, cert_info) = timeout(
        timeout_dur,
        crate::tls::builder::connect_client_http1(host, upstream_io, verify_upstream, trust),
    )
    .await??;
    let (sender, conn) = timeout(
        timeout_dur,
        crate::http::protocol::common::handshake_http1(server_tls),
    )
    .await??;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            warn!(error = ?err, context = log_context, "upstream conn closed");
        }
    });

    Ok((Arc::new(tokio::sync::Mutex::new(sender)), cert_info))
}
