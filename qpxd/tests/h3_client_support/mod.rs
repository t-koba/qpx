use anyhow::{Context, Result, anyhow};
use quinn::crypto::rustls::QuicClientConfig;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

pub fn build_quinn_client_endpoint() -> Result<quinn::Endpoint> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    quinn::Endpoint::client(addr)
        .map_err(|err| anyhow!(err))
        .context("bind quinn client endpoint")
}

pub fn build_h3_test_client_config(ca_cert_pem: &Path) -> Result<quinn::ClientConfig> {
    let mut roots = quinn::rustls::RootCertStore::empty();
    let certs = qpx_core::tls::load_cert_chain(ca_cert_pem)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("no certs loaded from {}", ca_cert_pem.display()));
    }

    let provider = quinn::rustls::crypto::ring::default_provider();
    let mut tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure h3 client tls versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto =
        QuicClientConfig::try_from(tls).map_err(|_| anyhow!("failed to build h3 client crypto"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
}
