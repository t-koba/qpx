use anyhow::{anyhow, Result};
use qpx_core::config::ReverseConfig;
#[cfg(feature = "tls-rustls")]
use std::sync::Arc;

#[cfg(feature = "tls-rustls")]
pub(in crate::reverse) type ReverseTlsAcceptor = tokio_rustls::TlsAcceptor;

#[cfg(feature = "tls-rustls")]
pub(in crate::reverse) fn build_tls_acceptor(
    reverse: &ReverseConfig,
) -> Result<ReverseTlsAcceptor> {
    use qpx_core::tls::load_cert_chain;
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};
    use std::path::Path;

    let tls = reverse
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("tls config missing"))?;
    let resolver = Arc::new(SniResolver::new(tls)?);
    let mut config = if let Some(client_ca) = tls
        .client_ca
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let certs = load_cert_chain(Path::new(client_ca))?;
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(anyhow!("no client CA certs loaded from {}", client_ca));
        }
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| anyhow!("invalid reverse.tls.client_ca"))?;
        RustlsServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver)
    } else {
        RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver)
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

#[cfg(feature = "tls-rustls")]
#[derive(Debug)]
struct SniResolver {
    certs: std::collections::HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    acme_snis: std::collections::HashSet<String>,
}

#[cfg(feature = "tls-rustls")]
impl SniResolver {
    fn new(tls: &qpx_core::config::ReverseTlsConfig) -> Result<Self> {
        use qpx_core::tls::{load_cert_chain, load_private_key};
        use rustls::crypto::ring::sign::any_supported_type;
        use rustls::sign::CertifiedKey;
        use std::collections::{HashMap, HashSet};
        use std::path::Path;

        let mut certs = HashMap::new();
        let mut acme_snis = HashSet::new();
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
                let signing_key =
                    any_supported_type(&key).map_err(|_| anyhow!("unsupported key"))?;
                let certified = Arc::new(CertifiedKey::new(chain, signing_key));
                certs.insert(cert.sni.to_ascii_lowercase(), certified);
            }
        }
        Ok(Self { certs, acme_snis })
    }
}

#[cfg(feature = "tls-rustls")]
impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = client_hello.server_name()?.to_ascii_lowercase();
        if let Some(key) = self.certs.get(&name) {
            return Some(key.clone());
        }
        if self.acme_snis.contains(&name) {
            #[cfg(feature = "acme")]
            {
                return qpx_acme::cert_store().and_then(|store| store.get(&name));
            }
            #[cfg(not(feature = "acme"))]
            {
                return None;
            }
        }
        None
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(in crate::reverse) type ReverseTlsAcceptor = NativeTlsAcceptor;

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
#[derive(Clone)]
pub(in crate::reverse) struct NativeTlsAcceptor {
    by_sni: std::collections::HashMap<String, tokio_native_tls::TlsAcceptor>,
    default: Option<tokio_native_tls::TlsAcceptor>,
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
impl NativeTlsAcceptor {
    pub(in crate::reverse) async fn accept<S>(
        &self,
        stream: S,
        sni: Option<&str>,
    ) -> Result<tokio_native_tls::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let key = sni.map(|v| v.to_ascii_lowercase());
        let acceptor = key
            .as_deref()
            .and_then(|k| self.by_sni.get(k))
            .or(self.default.as_ref())
            .ok_or_else(|| anyhow!("no TLS certificate for SNI {:?}", sni))?;
        Ok(acceptor.accept(stream).await?)
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(in crate::reverse) fn build_tls_acceptor(
    reverse: &ReverseConfig,
) -> Result<ReverseTlsAcceptor> {
    use anyhow::Context;
    use std::collections::HashMap;
    use std::fs;

    let tls = reverse
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("tls config missing"))?;

    let mut by_sni: HashMap<String, tokio_native_tls::TlsAcceptor> = HashMap::new();
    let mut default: Option<tokio_native_tls::TlsAcceptor> = None;

    for cert in &tls.certificates {
        let pkcs12_path = cert
            .pkcs12
            .as_deref()
            .ok_or_else(|| anyhow!("reverse.tls.certificates[].pkcs12 is required for tls-native"))?
            .trim();
        if pkcs12_path.is_empty() {
            return Err(anyhow!(
                "reverse.tls.certificates[].pkcs12 must not be empty"
            ));
        }
        let password = cert
            .pkcs12_password_env
            .as_deref()
            .map(|env| std::env::var(env).map_err(|_| anyhow!("{env} is set but missing")))
            .transpose()?
            .unwrap_or_default();

        let der = fs::read(pkcs12_path)
            .with_context(|| format!("failed to read pkcs12 {}", pkcs12_path))?;
        let identity = native_tls::Identity::from_pkcs12(&der, password.as_str())
            .map_err(|_| anyhow!("invalid pkcs12 identity: {}", pkcs12_path))?;
        let acceptor = tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);

        let sni = cert.sni.trim();
        if sni.is_empty() {
            return Err(anyhow!("reverse.tls.certificates[].sni must not be empty"));
        }
        if sni == "*" {
            default = Some(acceptor);
        } else {
            by_sni.insert(sni.to_ascii_lowercase(), acceptor);
        }
    }

    Ok(NativeTlsAcceptor { by_sni, default })
}
