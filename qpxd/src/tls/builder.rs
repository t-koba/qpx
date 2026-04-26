#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use super::cert_info::extract_upstream_certificate_info;
use super::cert_info::UpstreamCertificateInfo;
use super::trust::CompiledUpstreamTlsTrust;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> IoStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub(crate) type BoxTlsStream = Box<dyn IoStream>;

pub(crate) async fn connect_client_http1<S>(
    domain: &str,
    stream: S,
    verify: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<(BoxTlsStream, UpstreamCertificateInfo)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    imp::connect_client_http1(domain, stream, verify, trust).await
}

pub(crate) async fn connect_client_h2_h1<S>(
    domain: &str,
    stream: S,
    verify: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<(BoxTlsStream, bool, UpstreamCertificateInfo)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    imp::connect_client_h2_h1(domain, stream, verify, trust).await
}

pub(crate) async fn preview_client_certificate<S>(
    domain: &str,
    stream: S,
    verify: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<UpstreamCertificateInfo>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    imp::preview_client_certificate(domain, stream, verify, trust).await
}

#[cfg(feature = "tls-rustls")]
mod imp {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;

    #[derive(Debug)]
    struct NoVerifier;

    impl rustls::client::danger::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    pub(super) async fn connect_client_http1<S>(
        domain: &str,
        stream: S,
        verify: bool,
        trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<(BoxTlsStream, UpstreamCertificateInfo)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = tokio_rustls::TlsConnector::from(client_config(
            &[b"http/1.1".as_slice()],
            verify,
            trust,
        )?);
        let server_name = server_name_for_host(domain)?;
        let tls = connector.connect(server_name, stream).await?;
        let cert = peer_certificate_info(&tls);
        enforce_trust(domain, trust, &cert)?;
        Ok((Box::new(tls), cert))
    }

    pub(super) async fn connect_client_h2_h1<S>(
        domain: &str,
        stream: S,
        verify: bool,
        trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<(BoxTlsStream, bool, UpstreamCertificateInfo)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = tokio_rustls::TlsConnector::from(client_config(
            &[b"h2".as_slice(), b"http/1.1".as_slice()],
            verify,
            trust,
        )?);
        let server_name = server_name_for_host(domain)?;
        let tls = connector.connect(server_name, stream).await?;
        let cert = peer_certificate_info(&tls);
        enforce_trust(domain, trust, &cert)?;
        let negotiated_h2 = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|value| value == b"h2")
            .unwrap_or(false);
        Ok((Box::new(tls), negotiated_h2, cert))
    }

    pub(super) async fn preview_client_certificate<S>(
        domain: &str,
        stream: S,
        verify: bool,
        trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<UpstreamCertificateInfo>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = tokio_rustls::TlsConnector::from(client_config(&[], verify, trust)?);
        let server_name = server_name_for_host(domain)?;
        let tls = connector.connect(server_name, stream).await?;
        let cert = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| extract_upstream_certificate_info(Some(cert.as_ref())))
            .unwrap_or_default();
        enforce_trust(domain, trust, &cert)?;
        Ok(cert)
    }

    fn client_config(
        alpn: &[&[u8]],
        verify: bool,
        trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<Arc<rustls::ClientConfig>> {
        let mut client_cert_chain = None;
        let mut client_key = None;
        if let Some(client_auth) = trust.and_then(CompiledUpstreamTlsTrust::client_auth) {
            client_cert_chain = Some(qpx_core::tls::load_cert_chain(client_auth.cert_path())?);
            client_key = Some(qpx_core::tls::load_private_key(client_auth.key_path())?);
        }
        let mut config =
            (*qpx_core::tls::build_client_config(None, client_cert_chain, client_key, !verify)?)
                .clone();
        if !verify {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
        }
        if alpn.is_empty() {
            config.alpn_protocols.clear();
        } else {
            config.alpn_protocols = alpn.iter().map(|value| value.to_vec()).collect();
        }
        Ok(Arc::new(config))
    }

    fn peer_certificate_info<S>(tls: &tokio_rustls::client::TlsStream<S>) -> UpstreamCertificateInfo
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        tls.get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| extract_upstream_certificate_info(Some(cert.as_ref())))
            .unwrap_or_default()
    }

    fn enforce_trust(
        domain: &str,
        trust: Option<&CompiledUpstreamTlsTrust>,
        cert: &UpstreamCertificateInfo,
    ) -> Result<()> {
        if let Some(trust) = trust {
            trust.validate_certificate(domain, cert)?;
        }
        Ok(())
    }

    fn server_name_for_host(host: &str) -> Result<rustls::pki_types::ServerName<'static>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(rustls::pki_types::ServerName::IpAddress(ip.into()));
        }
        rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| anyhow::anyhow!("invalid server name for TLS: {}", host))
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
mod imp {
    use super::*;

    pub(super) async fn connect_client_http1<S>(
        domain: &str,
        stream: S,
        verify: bool,
        trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<(BoxTlsStream, UpstreamCertificateInfo)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = native_connector(&["http/1.1"], verify, trust)?;
        let tls = connector.connect(domain, stream).await?;
        let cert = peer_certificate_info(tls.get_ref())?;
        enforce_trust(domain, trust, &cert)?;
        Ok((Box::new(tls), cert))
    }

    pub(super) async fn connect_client_h2_h1<S>(
        domain: &str,
        stream: S,
        verify: bool,
        trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<(BoxTlsStream, bool, UpstreamCertificateInfo)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = native_connector(&["h2", "http/1.1"], verify, trust)?;
        let tls = connector.connect(domain, stream).await?;
        let cert = peer_certificate_info(tls.get_ref())?;
        enforce_trust(domain, trust, &cert)?;
        let negotiated_h2 = tls
            .get_ref()
            .negotiated_alpn()
            .ok()
            .flatten()
            .map(|value| value == b"h2")
            .unwrap_or(false);
        Ok((Box::new(tls), negotiated_h2, cert))
    }

    pub(super) async fn preview_client_certificate<S>(
        domain: &str,
        stream: S,
        verify: bool,
        trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<UpstreamCertificateInfo>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connector = native_connector(&[], verify, trust)?;
        let tls = connector.connect(domain, stream).await?;
        let cert = peer_certificate_info(tls.get_ref())?;
        enforce_trust(domain, trust, &cert)?;
        Ok(cert)
    }

    fn native_connector(
        alpn: &[&str],
        verify: bool,
        trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<tokio_native_tls::TlsConnector> {
        if trust
            .and_then(CompiledUpstreamTlsTrust::client_auth)
            .is_some_and(|client_auth| client_auth.is_configured())
        {
            return Err(anyhow::anyhow!(
                "upstream TLS client certificates require the tls-rustls backend"
            ));
        }
        let mut builder = native_tls::TlsConnector::builder();
        if !verify {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        if !alpn.is_empty() {
            builder.request_alpns(alpn);
        }
        Ok(tokio_native_tls::TlsConnector::from(builder.build()?))
    }

    fn peer_certificate_info<S>(
        stream: &native_tls::TlsStream<S>,
    ) -> Result<UpstreamCertificateInfo>
    where
        S: std::io::Read + std::io::Write,
    {
        let cert = stream
            .peer_certificate()?
            .and_then(|cert| cert.to_der().ok());
        Ok(extract_upstream_certificate_info(cert.as_deref()))
    }

    fn enforce_trust(
        domain: &str,
        trust: Option<&CompiledUpstreamTlsTrust>,
        cert: &UpstreamCertificateInfo,
    ) -> Result<()> {
        if let Some(trust) = trust {
            trust.validate_certificate(domain, cert)?;
        }
        Ok(())
    }
}

#[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
mod imp {
    use super::*;

    pub(super) async fn connect_client_http1<S>(
        _domain: &str,
        _stream: S,
        _verify: bool,
        _trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<(BoxTlsStream, UpstreamCertificateInfo)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Err(anyhow::anyhow!(
            "TLS client connect requires either feature tls-rustls or tls-native"
        ))
    }

    pub(super) async fn connect_client_h2_h1<S>(
        _domain: &str,
        _stream: S,
        _verify: bool,
        _trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<(BoxTlsStream, bool, UpstreamCertificateInfo)>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Err(anyhow::anyhow!(
            "TLS client connect requires either feature tls-rustls or tls-native"
        ))
    }

    pub(super) async fn preview_client_certificate<S>(
        _domain: &str,
        _stream: S,
        _verify: bool,
        _trust: Option<&CompiledUpstreamTlsTrust>,
    ) -> Result<UpstreamCertificateInfo>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Err(anyhow::anyhow!(
            "TLS certificate preview requires either feature tls-rustls or tls-native"
        ))
    }
}
