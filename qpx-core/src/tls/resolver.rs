use anyhow::{Result, anyhow};
use lru::LruCache;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::ServerConfig;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Condvar, Mutex};

use super::ca::CaStore;

#[derive(Clone)]
pub struct MitmConfig {
    pub ca: CaStore,
    pub resolver: Arc<DynamicCertResolver>,
    pub server_config: Arc<ServerConfig>,
}

impl CaStore {
    pub fn mitm_config(&self) -> Result<MitmConfig> {
        let resolver = Arc::new(DynamicCertResolver::new(self.clone()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(MitmConfig {
            ca: self.clone(),
            resolver,
            server_config: Arc::new(config),
        })
    }
}

#[derive(Clone)]
pub struct DynamicCertResolver {
    ca: CaStore,
    cache: Arc<Mutex<LruCache<String, Arc<CertifiedKey>>>>,
    pending: Arc<Mutex<HashMap<String, Arc<PendingCertificate>>>>,
}

struct PendingCertificate {
    result: Mutex<Option<Option<Arc<CertifiedKey>>>>,
    ready: Condvar,
}

impl PendingCertificate {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn wait(&self) -> Option<Arc<CertifiedKey>> {
        let mut guard = self.result.lock().ok()?;
        loop {
            if let Some(result) = guard.as_ref() {
                return result.clone();
            }
            guard = self.ready.wait(guard).ok()?;
        }
    }

    fn complete(&self, result: Option<Arc<CertifiedKey>>) {
        if let Ok(mut guard) = self.result.lock() {
            *guard = Some(result);
            self.ready.notify_all();
        }
    }
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver").finish()
    }
}

impl DynamicCertResolver {
    fn new(ca: CaStore) -> Self {
        Self {
            ca,
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(256).unwrap_or(NonZeroUsize::MIN),
            ))),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn issue_cert(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        let key_pair = KeyPair::generate()?;
        let leaf = params.signed_by(&key_pair, self.ca.issuer.as_ref())?;

        let cert_chain = vec![
            leaf.der().clone(),
            CertificateDer::from(self.ca.ca_der.clone()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let signing_key =
            any_supported_type(&key).map_err(|_| anyhow!("failed to create signing key"))?;
        Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
    }

    pub fn prewarm_server_name(&self, server_name: &str) -> bool {
        let server_name = if server_name.trim().is_empty() {
            "unknown"
        } else {
            server_name.trim()
        };
        self.resolve_server_name(server_name.to_string()).is_some()
    }

    pub(crate) fn cached_server_name(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        self.cache
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(server_name).cloned())
    }

    fn resolve_server_name(&self, server_name: String) -> Option<Arc<CertifiedKey>> {
        if let Ok(mut cache) = self.cache.lock()
            && let Some(entry) = cache.get(&server_name)
        {
            return Some(entry.clone());
        }

        let (pending, issuer) = match self.pending.lock() {
            Ok(mut pending) => {
                if let Some(existing) = pending.get(&server_name) {
                    (existing.clone(), false)
                } else {
                    let created = Arc::new(PendingCertificate::new());
                    pending.insert(server_name.clone(), created.clone());
                    (created, true)
                }
            }
            Err(_) => return self.issue_cert(&server_name).ok(),
        };
        if !issuer {
            return pending.wait();
        }

        let issued = self.issue_cert(&server_name);
        let issued = issued.ok();
        if let Some(cert) = issued.as_ref()
            && let Ok(mut cache) = self.cache.lock()
        {
            cache.put(server_name.clone(), cert.clone());
        }
        pending.complete(issued.clone());
        if let Ok(mut active) = self.pending.lock() {
            active.remove(&server_name);
        }
        issued
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello
            .server_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        self.cached_server_name(server_name.as_str())
    }
}
