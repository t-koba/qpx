use crate::runtime::H3ChannelLimits;
use anyhow::{Result, anyhow};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_core::tls::UpstreamCertificateInfo;
#[cfg(feature = "tls-rustls")]
use qpx_core::tls::extract_upstream_certificate_info;
#[cfg(feature = "http3")]
use quinn::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;
#[cfg(feature = "http3")]
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "http3")]
pub(crate) fn upstream_client_bind_addr(remote_addr: SocketAddr) -> SocketAddr {
    if remote_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    }
}

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

// These are the exact values passed to quinn; its transport fields are private.
fn h3_flow_control_windows(
    limits: &H3ChannelLimits,
) -> Result<(quinn::VarInt, quinn::VarInt, u64)> {
    Ok((
        quinn::VarInt::from_u64(limits.stream_receive_window_bytes)?,
        quinn::VarInt::from_u64(limits.connection_receive_window_bytes)?,
        limits.send_window_bytes,
    ))
}

fn h3_bidi_stream_limit(configured: usize) -> u32 {
    (configured.min(u32::MAX as usize) as u32).max(1)
}

pub(crate) fn build_h3_server_config_from_tls(
    mut tls: quinn::rustls::ServerConfig,
    limits: &H3ChannelLimits,
) -> Result<quinn::ServerConfig> {
    let (stream_receive, connection_receive, send) = h3_flow_control_windows(limits)?;
    let max_uni_streams = u32::try_from(limits.max_uni_streams)
        .map_err(|_| anyhow!("runtime.h3_max_uni_streams exceeds the QUIC API stream bound"))?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // Disable 0-RTT by default to avoid replay risks on non-idempotent requests.
    tls.max_early_data_size = 0;

    let quic_crypto = QuicServerConfig::try_from(tls)
        .map_err(|_| anyhow!("failed to build QUIC server crypto"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow!("failed to configure QUIC transport"))?;
    transport.max_concurrent_bidi_streams(
        h3_bidi_stream_limit(limits.max_h3_streams_per_connection).into(),
    );
    transport.max_concurrent_uni_streams(max_uni_streams.into());
    transport.stream_receive_window(stream_receive);
    transport.receive_window(connection_receive);
    transport.send_window(send);
    server_config.migration(false);
    Ok(server_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h3_quic_windows_follow_compiled_runtime_defaults_and_overrides() {
        for (runtime_yaml, expected) in [
            (
                "{}".to_string(),
                (1024 * 1024, 4 * 1024 * 1024, 4 * 1024 * 1024),
            ),
            (
                format!(
                    "h3_stream_receive_window_bytes: {}\nh3_connection_receive_window_bytes: {}\nh3_send_window_bytes: {}",
                    u64::from(u32::MAX) + 1,
                    quinn::VarInt::MAX.into_inner(),
                    u64::MAX
                ),
                (
                    u64::from(u32::MAX) + 1,
                    quinn::VarInt::MAX.into_inner(),
                    u64::MAX,
                ),
            ),
        ] {
            let mut config: qpx_core::config::Config =
                serde_yaml::from_str("edges: []").expect("config");
            config.runtime = serde_yaml::from_str(&runtime_yaml).expect("runtime settings");
            let plan = crate::runtime::RuntimeState::compile_plan(config).expect("compile plan");
            let (stream, connection, send) =
                h3_flow_control_windows(&plan.limits.h3).expect("windows");
            assert_eq!(
                (stream.into_inner(), connection.into_inner(), send),
                expected
            );

            // Invalid receive credit must fail conversion, not be clamped.
            for invalid in [quinn::VarInt::MAX.into_inner() + 1, u64::MAX] {
                let mut limits = plan.limits.h3;
                limits.stream_receive_window_bytes = invalid;
                assert!(h3_flow_control_windows(&limits).is_err());
                limits = plan.limits.h3;
                limits.connection_receive_window_bytes = invalid;
                assert!(h3_flow_control_windows(&limits).is_err());
            }
        }
    }

    fn test_h3_server_tls_config() -> Result<quinn::rustls::ServerConfig> {
        use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
        let provider = quinn::rustls::crypto::ring::default_provider();
        Ok(
            quinn::rustls::ServerConfig::builder_with_provider(provider.into())
                .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        cert.signing_key.serialize_der(),
                    )),
                )?,
        )
    }

    #[test]
    fn h3_server_config_applies_compiled_runtime_window_overrides() -> Result<()> {
        let mut config: qpx_core::config::Config = serde_yaml::from_str("edges: []")?;
        config.runtime = serde_yaml::from_str(
            "h3_stream_receive_window_bytes: 123\nh3_connection_receive_window_bytes: 234\nh3_send_window_bytes: 345\nh3_max_uni_streams: 789",
        )?;
        let plan = crate::runtime::RuntimeState::compile_plan(config)?;
        let server =
            build_h3_server_config_from_tls(test_h3_server_tls_config()?, &plan.limits.h3)?;

        // Quinn has no public getters for these fields; inspect the transport object
        // returned by the production builder rather than only testing its inputs.
        let transport = format!("{:?}", server.transport);
        for (field, value) in [
            ("stream_receive_window", 123_u64),
            ("receive_window", 234_u64),
            ("send_window", 345_u64),
            ("max_concurrent_uni_streams", 789_u64),
        ] {
            assert!(
                transport.contains(&format!("{field}: {value},")),
                "constructed transport did not apply {field}={value}: {transport}"
            );
        }
        Ok(())
    }

    #[test]
    fn h3_bidi_stream_limit_is_bounded_and_nonzero() {
        assert_eq!(h3_bidi_stream_limit(0), 1);
        assert_eq!(h3_bidi_stream_limit(17), 17);
        assert_eq!(
            h3_bidi_stream_limit(usize::MAX),
            u32::try_from(usize::MAX).unwrap_or(u32::MAX)
        );
        if let Ok(over_u32) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert_eq!(h3_bidi_stream_limit(over_u32), u32::MAX);
        }
    }
}
