use anyhow::{anyhow, Result};
#[cfg(feature = "http3")]
use quinn::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;
use std::sync::Arc;

#[cfg(feature = "http3")]
pub(crate) fn build_h3_client_config(verify_upstream: bool) -> Result<quinn::ClientConfig> {
    let mut tls =
        (*qpx_core::tls::build_client_config(None, None, None, !verify_upstream)?).clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(tls)
        .map_err(|_| anyhow!("failed to build upstream HTTP/3 client crypto"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

pub(crate) fn build_h3_server_config_from_tls(
    mut tls: quinn::rustls::ServerConfig,
    max_bidi_streams: u32,
    max_uni_streams: u32,
) -> Result<quinn::ServerConfig> {
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // Disable 0-RTT by default to avoid replay risks on non-idempotent requests.
    tls.max_early_data_size = 0;

    let quic_crypto = QuicServerConfig::try_from(tls)
        .map_err(|_| anyhow!("failed to build QUIC server crypto"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow!("failed to configure QUIC transport"))?;
    transport.max_concurrent_bidi_streams(max_bidi_streams.into());
    transport.max_concurrent_uni_streams(max_uni_streams.into());
    server_config.migration(false);
    Ok(server_config)
}
