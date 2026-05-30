use anyhow::{Context, Result, anyhow};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

use super::ca::CaStore;

impl CaStore {
    pub fn client_config(&self, verify: bool) -> Result<Arc<ClientConfig>> {
        let mut root = RootCertStore::empty();
        root.extend(TLS_SERVER_ROOTS.iter().cloned());
        let mut config = ClientConfig::builder()
            .with_root_certificates(root)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        if verify {
            Ok(Arc::new(config))
        } else {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoVerifier));
            Ok(Arc::new(config))
        }
    }
}

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
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
pub fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = fs::read(path).with_context(|| format!("failed to read cert {}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("invalid cert {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificate found in {}", path.display()));
    }
    Ok(certs)
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = fs::read(path).with_context(|| format!("failed to read key {}", path.display()))?;
    let mut keys = PrivateKeyDer::pem_slice_iter(&data)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("invalid key {}: {e}", path.display()))?;
    keys.pop()
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

pub fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn build_client_config(
    ca_cert: Option<&Path>,
    client_cert_chain: Option<Vec<CertificateDer<'static>>>,
    client_key: Option<PrivateKeyDer<'static>>,
    insecure_skip_verify: bool,
) -> Result<Arc<ClientConfig>> {
    let mut root = RootCertStore::empty();
    if let Some(path) = ca_cert {
        let certs = load_cert_chain(path)?;
        let (added, _) = root.add_parsable_certificates(certs);
        if added == 0 {
            return Err(anyhow!("no CA certs loaded from {}", path.display()));
        }
    } else {
        root.extend(TLS_SERVER_ROOTS.iter().cloned());
    }

    let builder = ClientConfig::builder().with_root_certificates(root);
    let mut config = match (client_cert_chain, client_key) {
        (Some(chain), Some(key)) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|_| anyhow!("invalid client certificate/key"))?,
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(anyhow!(
                "client_cert_chain and client_key must be set together"
            ));
        }
    };
    if insecure_skip_verify {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }
    Ok(Arc::new(config))
}
