use anyhow::{Result, anyhow};
use qpx_core::config::ReverseEdgeConfig;
#[cfg(feature = "tls-rustls")]
use std::sync::Arc;

#[cfg(feature = "tls-rustls")]
pub(in crate::reverse) type ReverseTlsAcceptor = tokio_rustls::TlsAcceptor;

#[cfg(feature = "tls-rustls")]
pub(in crate::reverse) fn build_tls_acceptor(
    reverse: &ReverseEdgeConfig,
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
    // Explicit fail-closed: RFC 8470 early data stays disabled on reverse listeners.
    config.max_early_data_size = 0;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    #[cfg(feature = "acme")]
    config.alpn_protocols.push(b"acme-tls/1".to_vec());
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
        use rustls::crypto::aws_lc_rs::sign::any_supported_type;
        use rustls::sign::CertifiedKey;
        use std::collections::{HashMap, HashSet};

        let mut certs = HashMap::new();
        let mut acme_snis = HashSet::new();
        for cert in &tls.certificates {
            if let Some((cert_path, key_path)) = super::certificate_file_paths(cert)? {
                let chain = load_cert_chain(cert_path)?;
                let key = load_private_key(key_path)?;
                let signing_key =
                    any_supported_type(&key).map_err(|_| anyhow!("unsupported key"))?;
                let certified = Arc::new(CertifiedKey::new(chain, signing_key));
                certs.insert(cert.sni.to_ascii_lowercase(), certified);
            } else {
                acme_snis.insert(cert.sni.to_ascii_lowercase());
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
        #[cfg(feature = "acme")]
        if client_hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|protocol| protocol == b"acme-tls/1"))
            && self.acme_snis.contains(&name)
            && let Some(cert) = qpx_acme::tls_alpn01_cert(&name)
        {
            return Some(cert);
        }
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
        let wildcard = super::wildcard_sni_for_name(&name)?;
        if let Some(key) = self.certs.get(&wildcard) {
            return Some(key.clone());
        }
        if self.acme_snis.contains(&wildcard) {
            #[cfg(feature = "acme")]
            {
                return qpx_acme::cert_store().and_then(|store| store.get(&wildcard));
            }
        }
        None
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(in crate::reverse) type ReverseTlsAcceptor = NativeTlsAcceptor;

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
fn native_cert_sni<V>(
    by_sni: &std::collections::HashMap<String, V>,
    sni: Option<&str>,
) -> Option<String> {
    let name = sni?.to_ascii_lowercase();
    if by_sni.contains_key(&name) {
        return Some(name);
    }
    let wildcard = super::wildcard_sni_for_name(&name)?;
    by_sni.contains_key(&wildcard).then_some(wildcard)
}

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
        let key = native_cert_sni(&self.by_sni, sni);
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
    reverse: &ReverseEdgeConfig,
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

#[cfg(all(test, feature = "tls-rustls"))]
mod tests {
    use super::*;
    use qpx_core::config::{ReverseTlsConfig, TlsCertConfig};
    use rustls::client::ClientConfig;
    use rustls::server::{Acceptor, ResolvesServerCert};
    use rustls::{ClientConnection, RootCertStore};
    use std::fs;

    fn resolve_for_sni(
        resolver: &SniResolver,
        name: &str,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut connection = ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap(),
        )
        .unwrap();
        let mut wire = Vec::new();
        connection.write_tls(&mut wire).unwrap();
        let mut acceptor = Acceptor::default();
        acceptor.read_tls(&mut wire.as_slice()).unwrap();
        let accepted = acceptor.accept().unwrap().expect("complete ClientHello");
        resolver.resolve(accepted.client_hello())
    }

    #[test]
    fn wildcard_certificate_selects_for_one_label_sni() {
        let _ = qpx_core::tls::init_rustls_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let pair = rcgen::generate_simple_self_signed(vec!["*.example.test".to_owned()]).unwrap();
        fs::write(&cert_path, pair.cert.pem()).unwrap();
        fs::write(&key_path, pair.signing_key.serialize_pem()).unwrap();
        let tls = ReverseTlsConfig {
            certificates: vec![TlsCertConfig {
                sni: "*.example.test".to_owned(),
                pkcs12: None,
                pkcs12_password_env: None,
                cert: Some(cert_path.to_str().unwrap().to_owned()),
                key: Some(key_path.to_str().unwrap().to_owned()),
            }],
            client_ca: None,
        };
        let resolver = SniResolver::new(&tls).unwrap();
        let selected =
            resolve_for_sni(&resolver, "shop.example.test").expect("wildcard certificate");
        assert_eq!(selected.cert[0].as_ref(), pair.cert.der().as_ref());
        assert!(resolve_for_sni(&resolver, "example.test").is_none());
        assert!(resolve_for_sni(&resolver, "a.shop.example.test").is_none());
    }
}

#[cfg(all(test, not(feature = "tls-rustls"), feature = "tls-native"))]
mod native_tests {
    use super::*;

    #[test]
    fn native_sni_uses_one_label_wildcard() {
        let wildcard_only = std::collections::HashMap::from([("*.example.test".to_string(), ())]);
        assert_eq!(
            native_cert_sni(&wildcard_only, Some("shop.example.test")).as_deref(),
            Some("*.example.test")
        );
        assert_eq!(
            native_cert_sni(&wildcard_only, Some("a.shop.example.test")),
            None
        );
        assert_eq!(native_cert_sni(&wildcard_only, Some("example.test")), None);

        let exact_and_wildcard = std::collections::HashMap::from([
            ("*.example.test".to_string(), ()),
            ("shop.example.test".to_string(), ()),
        ]);
        assert_eq!(
            native_cert_sni(&exact_and_wildcard, Some("SHOP.EXAMPLE.TEST")).as_deref(),
            Some("shop.example.test")
        );
    }
}
