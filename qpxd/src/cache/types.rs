use crate::http::body::Body;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use hyper::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
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
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Bytes>>;
    async fn get_many(&self, namespace: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>>;
    async fn get_object(&self, namespace: &str, key: &str) -> Result<Option<CachedBody>> {
        Ok(self.get(namespace, key).await?.map(CachedBody::from_bytes))
    }
    async fn get_object_stream(
        &self,
        _namespace: &str,
        _key: &str,
        _expected_len: u64,
        _range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        Err(anyhow!(
            "cache backend must implement streaming get_object_stream"
        ))
    }
    async fn put(&self, namespace: &str, key: &str, value: &[u8], ttl_secs: u64) -> Result<()>;
    async fn put_object(
        &self,
        namespace: &str,
        key: &str,
        body: &CachedBody,
        ttl_secs: u64,
    ) -> Result<()> {
        match body {
            CachedBody::Memory(value) => self.put(namespace, key, value.as_ref(), ttl_secs).await,
            CachedBody::File(_) => Err(anyhow!(
                "cache backend must implement streaming put_object for file-backed cache bodies"
            )),
        }
    }
    async fn put_object_stream(
        &self,
        _namespace: &str,
        _key: &str,
        _body: Body,
        _max_body_bytes: usize,
        _body_read_timeout: Duration,
        _ttl_secs: u64,
    ) -> Result<u64> {
        Err(anyhow!(
            "cache backend must implement streaming put_object_stream"
        ))
    }
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
    StaleWhileRevalidate(Box<Response<Body>>, RevalidationState),
    Miss,
    Revalidate(RevalidationState),
    OnlyIfCachedMiss,
}

#[derive(Clone)]
pub struct RevalidationState {
    pub(super) backend: Arc<dyn CacheBackend>,
    pub(super) namespace: String,
    pub(super) variant_key: String,
    pub(super) request_method: Method,
    pub(super) request_directives: RequestDirectives,
    pub(super) envelope: CachedResponseEnvelope,
    pub(super) stale_if_error_secs: Option<u64>,
}

impl std::fmt::Debug for RevalidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevalidationState")
            .field("namespace", &self.namespace)
            .field("variant_key", &self.variant_key)
            .field("request_method", &self.request_method)
            .field("request_directives", &self.request_directives)
            .field("envelope", &self.envelope)
            .field("stale_if_error_secs", &self.stale_if_error_secs)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub(super) struct CachedResponseEnvelope {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: CachedBody,
    pub(super) body_len: u64,
    pub(super) stored_at_ms: u64,
    pub(super) initial_age_secs: u64,
    pub(super) response_delay_secs: u64,
    pub(super) freshness_lifetime_secs: u64,
    pub(super) vary_headers: Vec<String>,
    pub(super) vary_values: Vec<(String, String)>,
}

mod body;

pub(super) use self::body::bounded_cache_body_stream;
pub use self::body::{CachedBody, CachedBodyStream};

#[derive(Debug, Serialize, Deserialize)]
struct CachedResponseMetadata {
    status: u16,
    headers: Vec<(String, String)>,
    body_len: u64,
    stored_at_ms: u64,
    initial_age_secs: u64,
    #[serde(default)]
    response_delay_secs: u64,
    freshness_lifetime_secs: u64,
    vary_headers: Vec<String>,
    vary_values: Vec<(String, String)>,
}

const CACHE_METADATA_MAGIC: &[u8] = b"QPX-CACHE-META\0\x01";

pub(super) fn cache_body_storage_key(variant_key: &str) -> String {
    format!("{variant_key}:body")
}

pub(super) fn encode_cached_response_metadata(
    envelope: &CachedResponseEnvelope,
) -> Result<Vec<u8>> {
    let metadata = CachedResponseMetadata {
        status: envelope.status,
        headers: envelope.headers.clone(),
        body_len: envelope.body_len,
        stored_at_ms: envelope.stored_at_ms,
        initial_age_secs: envelope.initial_age_secs,
        response_delay_secs: envelope.response_delay_secs,
        freshness_lifetime_secs: envelope.freshness_lifetime_secs,
        vary_headers: envelope.vary_headers.clone(),
        vary_values: envelope.vary_values.clone(),
    };
    let metadata = serde_json::to_vec(&metadata)?;
    let mut out = Vec::with_capacity(CACHE_METADATA_MAGIC.len() + metadata.len());
    out.extend_from_slice(CACHE_METADATA_MAGIC);
    out.extend_from_slice(&metadata);
    Ok(out)
}

pub(super) fn decode_cached_response_metadata(raw: Bytes) -> Result<CachedResponseEnvelope> {
    if !raw.starts_with(CACHE_METADATA_MAGIC) {
        return Err(anyhow!("invalid cache metadata format"));
    }
    let metadata: CachedResponseMetadata =
        serde_json::from_slice(&raw[CACHE_METADATA_MAGIC.len()..])?;
    crate::http::protocol::semantics::validate_http_status_class(
        StatusCode::from_u16(metadata.status)
            .map_err(|err| anyhow!("invalid cached response status: {err}"))?,
        "cached response",
    )?;
    Ok(CachedResponseEnvelope {
        status: metadata.status,
        headers: metadata.headers,
        body: CachedBody::default(),
        body_len: metadata.body_len,
        stored_at_ms: metadata.stored_at_ms,
        initial_age_secs: metadata.initial_age_secs,
        response_delay_secs: metadata.response_delay_secs,
        freshness_lifetime_secs: metadata.freshness_lifetime_secs,
        vary_headers: metadata.vary_headers,
        vary_values: metadata.vary_values,
    })
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
    pub(super) invalid_freshness: bool,
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
