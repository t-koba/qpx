use anyhow::Result;
use async_trait::async_trait;
use hyper::{Body, Response};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

pub(super) const CACHE_HEADER: &str = "x-qpx-cache";
pub(super) const CACHE_WARNING_STALE: &str = "110 - \"Response is stale\"";
pub(super) const CACHE_WARNING_REVALIDATION_FAILED: &str = "111 - \"Revalidation failed\"";
pub(super) const INDEX_TTL_SECS: u64 = 24 * 60 * 60;
pub(super) const MAX_CACHE_OBJECT_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_VARIANTS_PER_PRIMARY: usize = 256;
const BACKGROUND_REVALIDATIONS_SHARDS: usize = 64;

struct InFlightRevalidations {
    shards: Vec<Mutex<HashSet<Arc<str>>>>,
    mask: usize,
}

impl InFlightRevalidations {
    fn new(shards: usize) -> Self {
        let shards = shards.max(1);
        debug_assert!(shards.is_power_of_two());
        let mut out = Vec::with_capacity(shards);
        for _ in 0..shards {
            out.push(Mutex::new(HashSet::new()));
        }
        Self {
            shards: out,
            mask: shards.saturating_sub(1),
        }
    }

    fn shard_for(&self, key: &str) -> usize {
        if self.mask == 0 {
            return 0;
        }
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.mask
    }

    fn try_insert(&self, key: Arc<str>) -> bool {
        let shard = self.shard_for(key.as_ref());
        let mut set = self.shards[shard].lock().unwrap_or_else(|p| p.into_inner());
        set.insert(key)
    }

    fn remove(&self, key: &str) {
        let shard = self.shard_for(key);
        let mut set = self.shards[shard].lock().unwrap_or_else(|p| p.into_inner());
        let _ = set.remove(key);
    }
}

static BACKGROUND_REVALIDATIONS_IN_FLIGHT: OnceLock<InFlightRevalidations> = OnceLock::new();

#[async_trait]
pub trait CacheBackend: Send + Sync {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>>;
    async fn put(&self, namespace: &str, key: &str, value: &[u8], ttl_secs: u64) -> Result<()>;
    async fn delete(&self, namespace: &str, key: &str) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct CacheRequestKey {
    pub(super) scheme: String,
    pub(super) authority: String,
    pub(super) path_and_query: String,
}

#[derive(Debug)]
pub enum LookupOutcome {
    Hit(Response<Body>),
    StaleWhileRevalidate(Response<Body>, RevalidationState),
    Miss,
    Revalidate(RevalidationState),
    OnlyIfCachedMiss,
}

#[derive(Debug, Clone)]
pub struct RevalidationState {
    pub(super) namespace: String,
    pub(super) variant_key: String,
    pub(super) envelope: CachedResponseEnvelope,
    pub(super) stale_if_error_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CachedResponseEnvelope {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body_b64: String,
    pub(super) stored_at_ms: u64,
    pub(super) initial_age_secs: u64,
    #[serde(default)]
    pub(super) response_delay_secs: u64,
    pub(super) freshness_lifetime_secs: u64,
    pub(super) vary_headers: Vec<String>,
    pub(super) vary_values: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct VariantIndex {
    pub(super) variants: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RequestDirectives {
    pub(super) no_store: bool,
    pub(super) no_cache: bool,
    pub(super) only_if_cached: bool,
    pub(super) max_age: Option<u64>,
    pub(super) max_stale: Option<Option<u64>>,
    pub(super) min_fresh: Option<u64>,
    pub(super) has_conditional: bool,
    pub(super) if_none_match: Vec<String>,
    pub(super) if_modified_since: Option<u64>,
    pub(super) has_unsupported_conditionals: bool,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ResponseDirectives {
    pub(super) no_store: bool,
    pub(super) no_cache: bool,
    pub(super) no_cache_fields: Vec<String>,
    pub(super) private: bool,
    pub(super) private_fields: Vec<String>,
    pub(super) public: bool,
    pub(super) must_revalidate: bool,
    pub(super) proxy_revalidate: bool,
    pub(super) max_age: Option<u64>,
    pub(super) s_maxage: Option<u64>,
    pub(super) stale_while_revalidate: Option<u64>,
    pub(super) stale_if_error: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) enum CacheEntryDisposition {
    ServeFresh,
    ServeStale,
    ServeStaleWhileRevalidate,
    RequiresRevalidation,
}

pub(crate) struct BackgroundRevalidationGuard {
    key: Arc<str>,
}

pub(crate) fn try_begin_background_revalidation(
    state: &RevalidationState,
) -> Option<BackgroundRevalidationGuard> {
    let in_flight = BACKGROUND_REVALIDATIONS_IN_FLIGHT
        .get_or_init(|| InFlightRevalidations::new(BACKGROUND_REVALIDATIONS_SHARDS));

    let key: Arc<str> = format!("{}::{}", state.namespace, state.variant_key).into();
    if !in_flight.try_insert(key.clone()) {
        return None;
    }
    Some(BackgroundRevalidationGuard { key })
}

impl Drop for BackgroundRevalidationGuard {
    fn drop(&mut self) {
        let in_flight = BACKGROUND_REVALIDATIONS_IN_FLIGHT
            .get_or_init(|| InFlightRevalidations::new(BACKGROUND_REVALIDATIONS_SHARDS));
        in_flight.remove(self.key.as_ref());
    }
}

#[derive(Debug, Clone)]
pub(super) enum VarySpec {
    Any,
    Fields(Vec<String>),
}
