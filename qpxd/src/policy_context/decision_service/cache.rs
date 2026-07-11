use super::{CompiledDecisionService, DecisionServiceEnforcement, sha256_output_to_digest};
use anyhow::Result;
use lru::LruCache;
use qpx_core::config::DecisionServiceConfig;
use sha2::{Digest, Sha256};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct DecisionServiceCache {
    entries: Mutex<LruCache<String, CachedDecision>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct CachedDecision {
    expires_at: Instant,
    enforcement: DecisionServiceEnforcement,
}

impl DecisionServiceCache {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        let max_entries = match NonZeroUsize::new(max_entries) {
            Some(max_entries) => max_entries,
            None => NonZeroUsize::MIN,
        };
        Self {
            entries: Mutex::new(LruCache::new(max_entries)),
            ttl,
        }
    }

    pub(super) fn get(&self, key: &str) -> Option<DecisionServiceEnforcement> {
        let mut entries = self.entries.lock().ok()?;
        let now = Instant::now();
        match entries.get(key) {
            Some(entry) if entry.expires_at > now => Some(entry.enforcement.clone()),
            Some(_) => {
                entries.pop(key);
                None
            }
            None => None,
        }
    }

    pub(super) fn insert(&self, key: String, enforcement: DecisionServiceEnforcement) {
        self.insert_with_ttl(key, enforcement, self.ttl);
    }

    pub(super) fn insert_with_ttl(
        &self,
        key: String,
        enforcement: DecisionServiceEnforcement,
        ttl: Duration,
    ) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.put(
            key,
            CachedDecision {
                expires_at: Instant::now() + ttl.min(self.ttl),
                enforcement,
            },
        );
    }
}

pub(super) fn compile_cache(
    config: &DecisionServiceConfig,
) -> Result<Option<Arc<DecisionServiceCache>>> {
    if !config.cache.enabled {
        return Ok(None);
    }
    Ok(Some(Arc::new(DecisionServiceCache::new(
        config.cache.max_entries.unwrap_or(1024),
        Duration::from_millis(config.cache.ttl_ms.unwrap_or(1_000)),
    ))))
}

pub(super) fn decision_cache_key(cfg: &CompiledDecisionService, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cfg.profile_id.as_bytes());
    hasher.update([0]);
    if let Some(contract_id) = cfg.contract_id.as_deref() {
        hasher.update(contract_id.as_bytes());
    }
    hasher.update([0]);
    hasher.update(body);
    sha256_output_to_digest(hasher.finalize())
}
