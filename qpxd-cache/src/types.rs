use anyhow::{Result, anyhow};
use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use bytes::Bytes;
use hyper::{Method, Response, StatusCode};
use qpx_http::body::Body;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub const CACHE_HEADER: &str = "cache-status";
pub const INDEX_TTL_SECS: u64 = 24 * 60 * 60;
pub const MAX_CACHE_OBJECT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_VARIANTS_PER_PRIMARY: usize = 256;
const BACKGROUND_REVALIDATIONS_SHARDS: usize = 64;
const REQUEST_COLLAPSE_SHARDS: usize = 64;
const CACHE_WRITEBACK_CONCURRENCY: usize = 16;

/// Bounds cache writeback work so slow durable backends cannot exhaust runtime
/// tasks, memory, or file descriptors while origin responses keep flowing.
pub struct CacheWritebackAdmission {
    permits: Arc<Semaphore>,
}

impl CacheWritebackAdmission {
    /// Creates the per-runtime writeback admission controller.
    pub fn with_default_capacity() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(CACHE_WRITEBACK_CONCURRENCY)),
        }
    }

    pub(crate) fn try_acquire(&self) -> Option<CacheWritebackPermit> {
        self.permits
            .clone()
            .try_acquire_owned()
            .ok()
            .map(|permit| CacheWritebackPermit { _permit: permit })
    }
}

pub(crate) struct CacheWritebackPermit {
    _permit: OwnedSemaphorePermit,
}

pub(crate) fn cache_status_header(
    state: &'static str,
    ttl: Option<u64>,
) -> Result<http::HeaderValue> {
    const SFV_MAX_INTEGER: u64 = 999_999_999_999_999;
    let value = match state {
        "HIT" => match ttl {
            Some(ttl) if ttl <= SFV_MAX_INTEGER => format!("qpx; hit; ttl={ttl}"),
            Some(ttl) => {
                return Err(anyhow!(
                    "Cache-Status ttl {ttl} exceeds the RFC 9651 integer range"
                ));
            }
            None => "qpx; hit".to_string(),
        },
        "MISS" => "qpx; fwd=miss".to_string(),
        "BYPASS" => "qpx; fwd=bypass".to_string(),
        "REVALIDATED" => "qpx; fwd=stale; fwd-status=304".to_string(),
        _ => return Err(anyhow!("unsupported internal cache status: {state}")),
    };
    // Every shape is constructed from fixed RFC 9651 tokens plus a decimal u64.
    // Conformance tests validate the complete shape set; reparsing it for every
    // cache hit adds no runtime safety and materially penalizes the hot path.
    http::HeaderValue::from_maybe_shared(value)
        .map_err(|err| anyhow!("invalid generated Cache-Status header value: {err}"))
}

/// Tracks which `(namespace, variant)` entries currently have an in-flight
/// background revalidation, so duplicates are suppressed. Owned per-runtime by
/// `CacheRuntime` (see the qpxd runtime (`CacheRuntime`)); resetting it on config reload is
/// harmless because entries are transient and self-heal.
pub struct InFlightRevalidations {
    shards: Vec<Mutex<HashSet<Arc<str>>>>,
    mask: usize,
}

impl InFlightRevalidations {
    fn new(shards: usize) -> Self {
        let shards = shards.max(1);
        debug_assert!(shards.is_power_of_two());
        Self {
            shards: qpx_http::sharding::sync_mutex_shards(shards, HashSet::new),
            mask: shards.saturating_sub(1),
        }
    }

    /// Creates a registry with the default shard count.
    pub fn with_default_shards() -> Self {
        Self::new(BACKGROUND_REVALIDATIONS_SHARDS)
    }

    /// Begins a background revalidation for `(namespace, variant_key)`, returning a
    /// guard that releases the slot on drop, or `None` if one is already in flight.
    pub fn try_begin(
        self: &Arc<Self>,
        namespace: &str,
        variant_key: &str,
    ) -> Option<BackgroundRevalidationGuard> {
        let key: Arc<str> = format!("{namespace}::{variant_key}").into();
        if !self.try_insert(key.clone()) {
            return None;
        }
        Some(BackgroundRevalidationGuard {
            registry: Arc::clone(self),
            key,
        })
    }

    fn try_insert(&self, key: Arc<str>) -> bool {
        let shard = qpx_http::sharding::masked(key.as_ref(), self.mask);
        let mut set = self.shards[shard].lock().unwrap_or_else(|p| p.into_inner());
        set.insert(key)
    }

    fn remove(&self, key: &str) {
        let shard = qpx_http::sharding::masked(key, self.mask);
        let mut set = self.shards[shard].lock().unwrap_or_else(|p| p.into_inner());
        let _ = set.remove(key);
    }
}

#[async_trait]
pub trait CacheBackend: Send + Sync {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Bytes>>;
    async fn get_many(&self, namespace: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>>;
    async fn get_decoded_variant_index(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<Arc<VariantIndex>>> {
        let Some(raw) = self.get(namespace, key).await? else {
            return Ok(None);
        };
        Ok(Some(Arc::new(serde_json::from_slice(&raw)?)))
    }
    async fn get_decoded_response_metadata_many(
        &self,
        namespace: &str,
        keys: &[String],
    ) -> Result<Vec<Option<Arc<CachedResponseEnvelope>>>> {
        self.get_many(namespace, keys)
            .await?
            .into_iter()
            .map(|raw| {
                raw.map(decode_cached_response_metadata)
                    .transpose()
                    .map(|decoded| decoded.map(Arc::new))
            })
            .collect()
    }
    /// Returns a compound single-variant response when the backend can do so
    /// without making the normal index, metadata, and body reads separately.
    /// `default_variant_key` is the canonical Vary-less variant the backend
    /// probes when no variant index exists for the primary.
    fn get_response_candidate(
        &self,
        _namespace: &str,
        _index_key: &str,
        _default_variant_key: &str,
        _now_ms: u64,
    ) -> Result<Option<CachedResponseCandidate>> {
        Ok(None)
    }

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

pub struct CachedResponseCandidate {
    pub(crate) envelope: Arc<CachedResponseEnvelope>,
    pub(crate) body: CachedBodyStream,
}

impl CachedResponseCandidate {
    /// Creates a response candidate from already validated metadata and body.
    pub fn new(envelope: Arc<CachedResponseEnvelope>, body: CachedBodyStream) -> Self {
        Self { envelope, body }
    }
}

#[derive(Debug, Clone)]
pub struct CacheRequestKey {
    pub method: std::sync::Arc<str>,
    pub scheme: std::sync::Arc<str>,
    pub authority: std::sync::Arc<str>,
    pub path_and_query: std::sync::Arc<str>,
    pub content_digest: Option<std::sync::Arc<str>>,
    pub(crate) primary_index_storage_key: std::sync::Arc<OnceLock<std::sync::Arc<str>>>,
    pub(crate) primary_default_variant_storage_key: std::sync::Arc<OnceLock<std::sync::Arc<str>>>,
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
    pub backend: Arc<dyn CacheBackend>,
    pub namespace: String,
    pub variant_key: String,
    pub request_method: Method,
    pub request_directives: RequestDirectives,
    pub envelope: CachedResponseEnvelope,
    pub stale_if_error_secs: Option<u64>,
    /// Per-runtime background-revalidation registry, carried so the spawned task
    /// can dedupe without a process-global.
    pub revalidations: Arc<InFlightRevalidations>,
}

impl RevalidationState {
    /// Attempts to claim the background-revalidation slot for this entry, returning
    /// a guard or `None` if one is already in flight.
    pub fn begin_background_revalidation(&self) -> Option<BackgroundRevalidationGuard> {
        self.revalidations
            .try_begin(&self.namespace, &self.variant_key)
    }
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
pub struct CachedResponseEnvelope {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: CachedBody,
    pub body_len: u64,
    pub stored_at_ms: u64,
    pub initial_age_secs: u64,
    pub response_delay_secs: u64,
    pub freshness_lifetime_secs: u64,
    pub vary_headers: Vec<String>,
    pub vary_values: Vec<(String, String)>,
    /// Lazily-hydrated `HeaderMap` view of `headers`. Derived (not serialized);
    /// built once on first access so lookup-path freshness/directive parsing does
    /// not rebuild a `HeaderMap` from the stored `Vec` on every call. Boxed to keep
    /// `CachedResponseEnvelope` small (it is embedded by value in several enums).
    /// Access via [`CachedResponseEnvelope::header_map`] / [`CachedResponseEnvelope::header_str`].
    pub header_map: OnceLock<Box<http::HeaderMap>>,
    /// Parsed response cache directives derived from `header_map`. They are immutable
    /// for the lifetime of an envelope, so repeated hot-cache lookups reuse one parse.
    pub response_directives: OnceLock<ResponseDirectives>,
    /// Last rendered age-dependent response fields. Cache age advances in whole
    /// seconds, so all hits within the same second can share immutable values.
    pub(crate) response_header_values: OnceLock<Arc<ArcSwapOption<CachedResponseHeaderValues>>>,
}

#[derive(Debug)]
pub(crate) struct CachedResponseHeaderValues {
    cache_state: &'static str,
    current_age: u64,
    ttl: Option<u64>,
    pub(crate) age: http::HeaderValue,
    pub(crate) cache_status: http::HeaderValue,
}

impl CachedResponseEnvelope {
    /// Returns the hydrated `HeaderMap` for this envelope, building it once from
    /// the stored `headers` on first access.
    pub fn header_map(&self) -> &http::HeaderMap {
        self.header_map
            .get_or_init(|| Box::new(super::entry::header_map_from_vec(&self.headers)))
    }

    /// First case-insensitive value for `name` from the hydrated headers.
    pub fn header_str(&self, name: &http::HeaderName) -> Option<&str> {
        self.header_map().get(name).and_then(|v| v.to_str().ok())
    }

    pub fn response_directives(&self) -> &ResponseDirectives {
        self.response_directives
            .get_or_init(|| super::directives::parse_response_directives(self.header_map()))
    }

    pub(crate) fn response_header_values(
        &self,
        cache_state: &'static str,
        current_age: u64,
        ttl: Option<u64>,
    ) -> Result<(http::HeaderValue, http::HeaderValue)> {
        let cache = self
            .response_header_values
            .get_or_init(|| Arc::new(ArcSwapOption::empty()));
        let cached = cache.load();
        if let Some(values) = cached.as_ref()
            && values.cache_state == cache_state
            && values.current_age == current_age
            && values.ttl == ttl
        {
            return Ok((values.age.clone(), values.cache_status.clone()));
        }
        drop(cached);
        let values = Arc::new(CachedResponseHeaderValues {
            cache_state,
            current_age,
            ttl,
            age: http::HeaderValue::from_maybe_shared(current_age.to_string())
                .map_err(|error| anyhow!("invalid generated Age header value: {error}"))?,
            cache_status: cache_status_header(cache_state, ttl)?,
        });
        let rendered = (values.age.clone(), values.cache_status.clone());
        cache.store(Some(Arc::clone(&values)));
        Ok(rendered)
    }
}

mod body;

pub(crate) use self::body::bounded_cache_body_stream;
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

pub fn cache_body_storage_key(variant_key: &str) -> String {
    format!("{variant_key}:body")
}

pub(crate) fn is_cache_body_storage_key(key: &str) -> bool {
    key.strip_suffix(":body")
        .is_some_and(|variant| !variant.is_empty())
}

pub fn encode_cached_response_metadata(envelope: &CachedResponseEnvelope) -> Result<Vec<u8>> {
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

pub fn decode_cached_response_metadata(raw: Bytes) -> Result<CachedResponseEnvelope> {
    if !raw.starts_with(CACHE_METADATA_MAGIC) {
        return Err(anyhow!("invalid cache metadata format"));
    }
    let metadata: CachedResponseMetadata =
        serde_json::from_slice(&raw[CACHE_METADATA_MAGIC.len()..])?;
    qpx_http::protocol::semantics::validate_http_status_class(
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
        header_map: OnceLock::new(),
        response_directives: OnceLock::new(),
        response_header_values: OnceLock::new(),
    })
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VariantIndex {
    pub variants: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RequestDirectives {
    pub no_store: bool,
    pub no_cache: bool,
    pub only_if_cached: bool,
    pub max_age: Option<u64>,
    pub max_stale: Option<Option<u64>>,
    pub min_fresh: Option<u64>,
    pub has_conditional: bool,
    pub if_match: Vec<String>,
    pub if_none_match: Vec<String>,
    pub if_modified_since: Option<u64>,
    pub if_unmodified_since: Option<u64>,
    pub if_range: Option<IfRangeCondition>,
    pub range: Option<ByteRangeSpec>,
    pub has_unsupported_conditionals: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfRangeCondition {
    Etag(String),
    Date(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ByteRangeSpec {
    From { start: u64, end: Option<u64> },
    Suffix { len: u64 },
}

#[derive(Debug, Clone, Default)]
pub struct ResponseDirectives {
    pub no_store: bool,
    pub no_cache: bool,
    pub no_cache_fields: Vec<String>,
    pub must_understand: bool,
    pub private: bool,
    pub private_fields: Vec<String>,
    pub public: bool,
    pub must_revalidate: bool,
    pub proxy_revalidate: bool,
    pub immutable: bool,
    pub max_age: Option<u64>,
    pub s_maxage: Option<u64>,
    pub invalid_freshness: bool,
    pub stale_while_revalidate: Option<u64>,
    pub stale_if_error: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum CacheEntryDisposition {
    ServeFresh,
    ServeStale,
    ServeStaleWhileRevalidate,
    RequiresRevalidation,
}

pub struct BackgroundRevalidationGuard {
    registry: Arc<InFlightRevalidations>,
    key: Arc<str>,
}

/// Per-runtime request-collapse registry: coalesces concurrent cache fills for the
/// same key behind a single leader. Owned by `CacheRuntime`.
pub struct InFlightLookups {
    shards: Vec<Mutex<HashMap<Arc<str>, Arc<Notify>>>>,
    mask: usize,
}

impl InFlightLookups {
    fn new(shards: usize) -> Self {
        let shards = shards.max(1);
        debug_assert!(shards.is_power_of_two());
        Self {
            shards: qpx_http::sharding::sync_mutex_shards(shards, HashMap::new),
            mask: shards.saturating_sub(1),
        }
    }

    /// Creates a registry with the default shard count.
    pub fn with_default_shards() -> Self {
        Self::new(REQUEST_COLLAPSE_SHARDS)
    }

    /// Joins the request-collapse group for `key`: the first caller becomes the
    /// leader (and receives a guard that wakes followers on drop), others wait.
    pub fn begin(self: &Arc<Self>, key: &CacheRequestKey) -> RequestCollapseJoin {
        let key = key.primary_hash_arc();
        let shard = qpx_http::sharding::masked(key.as_ref(), self.mask);
        let mut entries = self.shards[shard].lock().unwrap_or_else(|p| p.into_inner());
        if let Some(notify) = entries.get(key.as_ref()) {
            return RequestCollapseJoin::Follower(RequestCollapseWaiter {
                notify: notify.clone(),
            });
        }
        let notify = Arc::new(Notify::new());
        entries.insert(key.clone(), notify.clone());
        RequestCollapseJoin::Leader(RequestCollapseGuard {
            registry: Arc::clone(self),
            key,
            notify,
        })
    }

    fn remove(&self, key: &str) {
        let shard = qpx_http::sharding::masked(key, self.mask);
        let mut entries = self.shards[shard].lock().unwrap_or_else(|p| p.into_inner());
        let _ = entries.remove(key);
    }
}

pub enum RequestCollapseJoin {
    Leader(RequestCollapseGuard),
    Follower(RequestCollapseWaiter),
}

pub struct RequestCollapseGuard {
    registry: Arc<InFlightLookups>,
    key: Arc<str>,
    notify: Arc<Notify>,
}

pub struct RequestCollapseWaiter {
    notify: Arc<Notify>,
}

impl Drop for BackgroundRevalidationGuard {
    fn drop(&mut self) {
        self.registry.remove(self.key.as_ref());
    }
}

impl RequestCollapseWaiter {
    pub async fn wait(&self, timeout_dur: std::time::Duration) -> bool {
        tokio::time::timeout(timeout_dur, self.notify.notified())
            .await
            .is_ok()
    }
}

impl Drop for RequestCollapseGuard {
    fn drop(&mut self) {
        self.registry.remove(self.key.as_ref());
        self.notify.notify_waiters();
    }
}

#[derive(Debug, Clone)]
pub enum VarySpec {
    Any,
    Fields(Vec<String>),
}

#[cfg(test)]
mod cache_status_tests {
    use super::{
        CACHE_WRITEBACK_CONCURRENCY, CacheWritebackAdmission, CachedBody, CachedResponseEnvelope,
        cache_status_header,
    };
    use std::sync::{Arc, OnceLock};

    #[test]
    fn generated_cache_status_shapes_are_rfc_9651_lists() {
        for (state, ttl) in [
            ("HIT", None),
            ("HIT", Some(0)),
            ("HIT", Some(999_999_999_999_999)),
            ("MISS", None),
            ("BYPASS", None),
            ("REVALIDATED", None),
        ] {
            let value = cache_status_header(state, ttl).expect("build Cache-Status");
            qpx_http::structured_fields::parse_list(value.as_bytes())
                .expect("parse generated Cache-Status");
        }
        assert!(cache_status_header("HIT", Some(u64::MAX)).is_err());
    }

    #[test]
    fn cache_writeback_admission_is_bounded_and_recovers_capacity() {
        let admission = CacheWritebackAdmission::with_default_capacity();
        let mut permits = (0..CACHE_WRITEBACK_CONCURRENCY)
            .map(|_| admission.try_acquire().expect("writeback permit"))
            .collect::<Vec<_>>();

        assert!(admission.try_acquire().is_none());
        permits.pop();
        assert!(admission.try_acquire().is_some());
    }

    #[test]
    fn age_dependent_response_fields_are_shared_only_for_an_exact_value_set() {
        let envelope = CachedResponseEnvelope {
            status: 200,
            headers: Vec::new(),
            body: CachedBody::default(),
            body_len: 0,
            stored_at_ms: 0,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            header_map: OnceLock::new(),
            response_directives: OnceLock::new(),
            response_header_values: OnceLock::new(),
        };

        let first = envelope
            .response_header_values("HIT", 7, Some(53))
            .expect("first response fields");
        let first_cached = envelope
            .response_header_values
            .get()
            .expect("initialized response field cache")
            .load_full()
            .expect("first cached response fields");
        let repeated = envelope
            .response_header_values("HIT", 7, Some(53))
            .expect("repeated response fields");
        let repeated_cached = envelope
            .response_header_values
            .get()
            .expect("initialized response field cache")
            .load_full()
            .expect("repeated cached response fields");
        let advanced = envelope
            .response_header_values("HIT", 8, Some(52))
            .expect("advanced response fields");

        assert!(Arc::ptr_eq(&first_cached, &repeated_cached));
        assert_eq!(first, repeated);
        assert_ne!(first, advanced);
        assert_eq!(advanced.0, "8");
        assert_eq!(advanced.1, "qpx; hit; ttl=52");
    }
}
