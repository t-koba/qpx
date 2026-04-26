use crate::http::body::Body;
use anyhow::Result;
use async_trait::async_trait;
use hyper::Response;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Notify;

pub(super) const CACHE_HEADER: &str = "x-qpx-cache";
pub(super) const INDEX_TTL_SECS: u64 = 24 * 60 * 60;
pub(super) const MAX_CACHE_OBJECT_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_VARIANTS_PER_PRIMARY: usize = 256;
const BACKGROUND_REVALIDATIONS_SHARDS: usize = 64;
const REQUEST_COLLAPSE_SHARDS: usize = 64;

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
static REQUEST_COLLAPSE_IN_FLIGHT: OnceLock<InFlightLookups> = OnceLock::new();

#[async_trait]
pub trait CacheBackend: Send + Sync {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>>;
    async fn put(&self, namespace: &str, key: &str, value: &[u8], ttl_secs: u64) -> Result<()>;
    async fn delete(&self, namespace: &str, key: &str) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct CacheRequestKey {
    pub(super) method: String,
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
    pub(super) if_match: Vec<String>,
    pub(super) if_none_match: Vec<String>,
    pub(super) if_modified_since: Option<u64>,
    pub(super) if_unmodified_since: Option<u64>,
    pub(super) if_range: Option<IfRangeCondition>,
    pub(super) range: Option<ByteRangeSpec>,
    pub(super) has_unsupported_conditionals: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum IfRangeCondition {
    Etag(String),
    Date(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ByteRangeSpec {
    From { start: u64, end: Option<u64> },
    Suffix { len: u64 },
}

#[derive(Debug, Clone, Default)]
pub(super) struct ResponseDirectives {
    pub(super) no_store: bool,
    pub(super) no_cache: bool,
    pub(super) no_cache_fields: Vec<String>,
    pub(super) must_understand: bool,
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

struct InFlightLookups {
    shards: Vec<Mutex<HashMap<Arc<str>, Arc<Notify>>>>,
    mask: usize,
}

impl InFlightLookups {
    fn new(shards: usize) -> Self {
        let shards = shards.max(1);
        debug_assert!(shards.is_power_of_two());
        let mut out = Vec::with_capacity(shards);
        for _ in 0..shards {
            out.push(Mutex::new(HashMap::new()));
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
}

pub(crate) enum RequestCollapseJoin {
    Leader(RequestCollapseGuard),
    Follower(RequestCollapseWaiter),
}

pub(crate) struct RequestCollapseGuard {
    key: Arc<str>,
    notify: Arc<Notify>,
}

pub(crate) struct RequestCollapseWaiter {
    notify: Arc<Notify>,
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

pub(crate) fn begin_request_collapse(key: &CacheRequestKey) -> RequestCollapseJoin {
    let in_flight =
        REQUEST_COLLAPSE_IN_FLIGHT.get_or_init(|| InFlightLookups::new(REQUEST_COLLAPSE_SHARDS));
    let key: Arc<str> = key.primary_hash().into();
    let shard = in_flight.shard_for(key.as_ref());
    let mut entries = in_flight.shards[shard]
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(notify) = entries.get(key.as_ref()) {
        return RequestCollapseJoin::Follower(RequestCollapseWaiter {
            notify: notify.clone(),
        });
    }
    let notify = Arc::new(Notify::new());
    entries.insert(key.clone(), notify.clone());
    RequestCollapseJoin::Leader(RequestCollapseGuard { key, notify })
}

impl RequestCollapseWaiter {
    pub(crate) async fn wait(&self, timeout_dur: std::time::Duration) -> bool {
        tokio::time::timeout(timeout_dur, self.notify.notified())
            .await
            .is_ok()
    }
}

impl Drop for RequestCollapseGuard {
    fn drop(&mut self) {
        let in_flight = REQUEST_COLLAPSE_IN_FLIGHT
            .get_or_init(|| InFlightLookups::new(REQUEST_COLLAPSE_SHARDS));
        let shard = in_flight.shard_for(self.key.as_ref());
        let mut entries = in_flight.shards[shard]
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let _ = entries.remove(self.key.as_ref());
        self.notify.notify_waiters();
    }
}

#[derive(Debug, Clone)]
pub(super) enum VarySpec {
    Any,
    Fields(Vec<String>),
}
