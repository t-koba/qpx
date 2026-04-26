use super::builder;
pub(crate) use super::builder::{BoxTlsStream, IoStream};
#[cfg(test)]
#[cfg(feature = "tls-rustls")]
use super::cert_info::extract_upstream_certificate_info;
use super::cert_info::UpstreamCertificateInfo;
use super::trust::CompiledUpstreamTlsTrust;
use anyhow::Result;
use tokio::net::TcpStream;

pub(crate) async fn connect_tls_http1(domain: &str, stream: TcpStream) -> Result<BoxTlsStream> {
    connect_tls_http1_with_options(domain, stream, true, None).await
}

pub(crate) async fn connect_tls_http1_with_options(
    domain: &str,
    stream: TcpStream,
    verify: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<BoxTlsStream> {
    Ok(builder::connect_client_http1(domain, stream, verify, trust)
        .await?
        .0)
}

pub(crate) async fn connect_tls_h2_h1_with_options(
    domain: &str,
    stream: TcpStream,
    verify: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<(BoxTlsStream, bool)> {
    let (stream, negotiated_h2, _) =
        builder::connect_client_h2_h1(domain, stream, verify, trust).await?;
    Ok((stream, negotiated_h2))
}

pub(crate) async fn connect_tls_h2_h1_with_info_with_options(
    domain: &str,
    stream: TcpStream,
    verify: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<(BoxTlsStream, bool, UpstreamCertificateInfo)> {
    builder::connect_client_h2_h1(domain, stream, verify, trust).await
}

pub(crate) async fn preview_tls_certificate_with_options(
    domain: &str,
    stream: BoxTlsStream,
    verify: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<UpstreamCertificateInfo> {
    builder::preview_client_certificate(domain, stream, verify, trust).await
}

#[cfg(all(test, feature = "tls-rustls"))]
mod tests {
    use super::*;
    use qpx_core::config::UpstreamTlsTrustConfig;
    use rcgen::generate_simple_self_signed;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::time::Duration;
    use tokio_rustls::TlsAcceptor;

    fn ensure_rustls_provider() {
        if CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    }

    async fn spawn_tls_server(host: &str) -> (std::net::SocketAddr, String) {
        ensure_rustls_provider();
        let certified =
            generate_simple_self_signed(vec![host.to_string()]).expect("self-signed cert");
        let cert_der = certified.cert.der().clone();
        let fingerprint = extract_upstream_certificate_info(Some(cert_der.as_ref()))
            .fingerprint_sha256
            .expect("fingerprint");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .expect("server config");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let _tls = acceptor.accept(stream).await.expect("tls accept");
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        (addr, fingerprint)
    }

    #[tokio::test]
    async fn connect_tls_http1_with_options_accepts_matching_pin() {
        ensure_rustls_provider();
        let (addr, fingerprint) = spawn_tls_server("example.com").await;
        let trust = CompiledUpstreamTlsTrust::from_config(Some(&UpstreamTlsTrustConfig {
            pin_sha256: vec![fingerprint],
            issuer: Vec::new(),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        }))
        .expect("compile trust")
        .expect("trust present");
        let stream = TcpStream::connect(addr).await.expect("connect");
        connect_tls_http1_with_options("example.com", stream, false, Some(trust.as_ref()))
            .await
            .expect("TLS connect should succeed");
    }

    #[tokio::test]
    async fn connect_tls_http1_with_options_rejects_pin_mismatch() {
        ensure_rustls_provider();
        let (addr, _) = spawn_tls_server("example.com").await;
        let trust = CompiledUpstreamTlsTrust::from_config(Some(&UpstreamTlsTrustConfig {
            pin_sha256: vec![
                "0000000000000000000000000000000000000000000000000000000000000000".into(),
            ],
            issuer: Vec::new(),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        }))
        .expect("compile trust")
        .expect("trust present");
        let stream = TcpStream::connect(addr).await.expect("connect");
        let err = match connect_tls_http1_with_options(
            "example.com",
            stream,
            false,
            Some(trust.as_ref()),
        )
        .await
        {
            Ok(_) => panic!("pin mismatch should fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("pin mismatch"));
    }
}
