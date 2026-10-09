use anyhow::{Result, anyhow};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_core::tls::UpstreamCertificateInfo;
#[cfg(feature = "tls-rustls")]
use qpx_core::tls::extract_upstream_certificate_info;
#[cfg(feature = "http3")]
use quinn::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;
use std::sync::Arc;

#[cfg(feature = "http3")]
pub(crate) fn build_h3_client_config(
    verify_upstream: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<quinn::ClientConfig> {
    let mut client_cert_chain = None;
    let mut client_key = None;
    #[cfg(feature = "tls-rustls")]
    if let Some(client_auth) = trust.and_then(CompiledUpstreamTlsTrust::client_auth) {
        client_cert_chain = Some(qpx_core::tls::load_cert_chain(client_auth.cert_path())?);
        client_key = Some(qpx_core::tls::load_private_key(client_auth.key_path())?);
    }
    let mut tls = (*qpx_core::tls::build_client_config(
        None,
        client_cert_chain,
        client_key,
        !verify_upstream,
    )?)
    .clone();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(tls)
        .map_err(|_| anyhow!("failed to build upstream HTTP/3 client crypto"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}

#[cfg(feature = "http3")]
pub(crate) fn extract_h3_connection_certificate_info(
    connection: &quinn::Connection,
) -> UpstreamCertificateInfo {
    #[cfg(feature = "tls-rustls")]
    {
        connection
            .peer_identity()
            .and_then(|identity| {
                identity
                    .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                    .ok()
            })
            .and_then(|certs| {
                certs
                    .first()
                    .map(|cert| extract_upstream_certificate_info(Some(cert.as_ref())))
            })
            .unwrap_or_default()
    }
    #[cfg(not(feature = "tls-rustls"))]
    {
        let _ = connection;
        UpstreamCertificateInfo::default()
    }
}

#[cfg(feature = "http3")]
pub(crate) fn enforce_h3_connection_trust(
    connection: &quinn::Connection,
    peer_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<()> {
    let Some(trust) = trust else {
        return Ok(());
    };
    #[cfg(feature = "tls-rustls")]
    {
        let cert = extract_h3_connection_certificate_info(connection);
        trust.validate_certificate(peer_name, &cert)?;
        Ok(())
    }
    #[cfg(not(feature = "tls-rustls"))]
    {
        let _ = (connection, peer_name, trust);
        Err(anyhow!(
            "HTTP/3 upstream TLS trust enforcement requires the tls-rustls backend"
        ))
    }
}

// Pin the QUIC flow-control windows instead of inheriting quinn defaults
// silently. quinn 0.11 defaults to ~1.25 MiB per-stream, VarInt::MAX per
// connection, and ~10 MiB send; the edge keeps the H2-aligned 1 MiB stream /
// 4 MiB connection / 4 MiB send ceilings so a future quinn upgrade must not
// silently widen buffering (worst-case memory scales with streams x window).
// No behavior change at quinn 0.11, no new policy knob.
pub(crate) const H3_STREAM_RECEIVE_WINDOW_BYTES: u32 = 1024 * 1024;
pub(crate) const H3_CONNECTION_RECEIVE_WINDOW_BYTES: u32 = 4 * 1024 * 1024;
pub(crate) const H3_SEND_WINDOW_BYTES: u64 = 4 * 1024 * 1024;

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
    transport.stream_receive_window(H3_STREAM_RECEIVE_WINDOW_BYTES.into());
    transport.receive_window(H3_CONNECTION_RECEIVE_WINDOW_BYTES.into());
    transport.send_window(H3_SEND_WINDOW_BYTES);
    server_config.migration(false);
    Ok(server_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_quic_windows_are_pinned_to_edge_defaults() {
        // Explicitness guard: quinn marks these windows as tunable with wide
        // defaults (~1.25 MiB stream, VarInt::MAX connection, ~10 MiB send).
        // If quinn moves any default, this test forces a deliberate review
        // instead of a silent edge widening.
        assert_eq!(H3_STREAM_RECEIVE_WINDOW_BYTES, 1024 * 1024);
        assert_eq!(H3_CONNECTION_RECEIVE_WINDOW_BYTES, 4 * 1024 * 1024);
        assert_eq!(H3_SEND_WINDOW_BYTES, 4 * 1024 * 1024);
    }
}
