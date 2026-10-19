use anyhow::{Result, anyhow};
use qpx_core::config::ReverseEdgeConfig;
use qpx_core::tls::{load_cert_chain, load_private_key};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

pub(crate) fn build_reverse_tls_config(
    reverse: &ReverseEdgeConfig,
) -> Result<quinn::rustls::ServerConfig> {
    let tls = reverse
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("reverse TLS config required for HTTP/3 terminate"))?;
    if tls.certificates.is_empty() {
        return Err(anyhow!(
            "at least one certificate is required for HTTP/3 terminate"
        ));
    }
    let resolver = Arc::new(QuicSniResolver::new(tls)?);

    let provider = quinn::rustls::crypto::aws_lc_rs::default_provider();
    let base = quinn::rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&quinn::rustls::version::TLS13])
        .map_err(|_| anyhow!("failed to configure TLS versions for HTTP/3"))?;
    let tls_config = if let Some(client_ca) = tls
        .client_ca
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        use quinn::rustls::RootCertStore;
        use quinn::rustls::server::WebPkiClientVerifier;
        let certs = load_cert_chain(Path::new(client_ca))?;
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(anyhow!("no client CA certs loaded from {}", client_ca));
        }
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| anyhow!("invalid reverse.tls.client_ca"))?;
        base.with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver)
    } else {
        base.with_no_client_auth().with_cert_resolver(resolver)
    };
    Ok(tls_config)
}

#[derive(Debug)]
struct QuicSniResolver {
    certs: HashMap<String, Arc<quinn::rustls::sign::CertifiedKey>>,
    acme_snis: std::collections::HashSet<String>,
}

impl QuicSniResolver {
    fn new(tls: &qpx_core::config::ReverseTlsConfig) -> Result<Self> {
        let mut certs = HashMap::new();
        let mut acme_snis = std::collections::HashSet::new();
        for cert in &tls.certificates {
            let cert_path = cert.cert.as_deref().unwrap_or("").trim();
            let key_path = cert.key.as_deref().unwrap_or("").trim();
            if cert_path.is_empty() && key_path.is_empty() {
                acme_snis.insert(cert.sni.to_ascii_lowercase());
            } else {
                if cert_path.is_empty() {
                    return Err(anyhow!("reverse.tls.certificates[].cert must not be empty"));
                }
                if key_path.is_empty() {
                    return Err(anyhow!("reverse.tls.certificates[].key must not be empty"));
                }
                let chain = load_cert_chain(Path::new(cert_path))?;
                let key = load_private_key(Path::new(key_path))?;
                let signing_key = quinn::rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
                    .map_err(|_| anyhow!("unsupported key"))?;
                let certified =
                    Arc::new(quinn::rustls::sign::CertifiedKey::new(chain, signing_key));
                certs.insert(cert.sni.to_ascii_lowercase(), certified);
            }
        }
        Ok(Self { certs, acme_snis })
    }
}

impl quinn::rustls::server::ResolvesServerCert for QuicSniResolver {
    fn resolve(
        &self,
        client_hello: quinn::rustls::server::ClientHello<'_>,
    ) -> Option<Arc<quinn::rustls::sign::CertifiedKey>> {
        let name = client_hello.server_name()?.to_ascii_lowercase();
        if let Some(key) = self.certs.get(&name) {
            return Some(key.clone());
        }
        if self.acme_snis.contains(&name) {
            #[cfg(feature = "acme")]
            {
                return qpx_acme::quic_cert_store().and_then(|store| store.get(&name));
            }
            #[cfg(not(feature = "acme"))]
            {
                return None;
            }
        }
        None
    }
}
