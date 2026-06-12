use arc_swap::ArcSwap;
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::Arc;

/// TLS certificate store populated by ACME renewals.
pub struct AcmeCertStore {
    by_sni: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
}

impl AcmeCertStore {
    pub(crate) fn new() -> Self {
        Self {
            by_sni: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Returns a certificate for the given SNI name.
    pub fn get(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        self.by_sni.load().get(&sni.to_ascii_lowercase()).cloned()
    }

    pub(crate) fn upsert(&self, sni: String, key: Arc<CertifiedKey>) {
        let mut next = (**self.by_sni.load()).clone();
        next.insert(sni.to_ascii_lowercase(), key);
        self.by_sni.store(Arc::new(next));
    }
}

#[cfg(feature = "http3")]
/// QUIC certificate store populated by ACME renewals.
pub struct AcmeQuicCertStore {
    by_sni: ArcSwap<HashMap<String, Arc<quinn::rustls::sign::CertifiedKey>>>,
}

#[cfg(feature = "http3")]
impl AcmeQuicCertStore {
    pub(crate) fn new() -> Self {
        Self {
            by_sni: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    /// Returns a QUIC certificate for the given SNI name.
    pub fn get(&self, sni: &str) -> Option<Arc<quinn::rustls::sign::CertifiedKey>> {
        self.by_sni.load().get(&sni.to_ascii_lowercase()).cloned()
    }

    pub(crate) fn upsert(&self, sni: String, key: Arc<quinn::rustls::sign::CertifiedKey>) {
        let mut next = (**self.by_sni.load()).clone();
        next.insert(sni.to_ascii_lowercase(), key);
        self.by_sni.store(Arc::new(next));
    }
}

pub(crate) struct Http01TokenStore {
    by_token: ArcSwap<HashMap<String, String>>,
}

impl Http01TokenStore {
    pub(crate) fn new() -> Self {
        Self {
            by_token: ArcSwap::from_pointee(HashMap::new()),
        }
    }

    pub(crate) fn insert(&self, token: String, key_auth: String) {
        let mut next = (**self.by_token.load()).clone();
        next.insert(token, key_auth);
        self.by_token.store(Arc::new(next));
    }

    pub(crate) fn remove(&self, token: &str) {
        let mut next = (**self.by_token.load()).clone();
        next.remove(token);
        self.by_token.store(Arc::new(next));
    }

    pub(crate) fn get(&self, token: &str) -> Option<String> {
        self.by_token.load().get(token).cloned()
    }
}
