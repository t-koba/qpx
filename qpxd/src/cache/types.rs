use anyhow::Result;
use async_trait::async_trait;
use hyper::{Body, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

pub(super) const CACHE_HEADER: &str = "x-qpx-cache";
pub(super) const CACHE_WARNING_STALE: &str = "110 - \"Response is stale\"";
pub(super) const CACHE_WARNING_REVALIDATION_FAILED: &str = "111 - \"Revalidation failed\"";
pub(super) const INDEX_TTL_SECS: u64 = 24 * 60 * 60;
pub(super) const MAX_CACHE_OBJECT_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_VARIANTS_PER_PRIMARY: usize = 256;
static BACKGROUND_REVALIDATIONS_IN_FLIGHT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

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
    key: String,
}

pub(crate) fn try_begin_background_revalidation(state: &RevalidationState) -> Option<BackgroundRevalidationGuard> {
    let in_flight =
        BACKGROUND_REVALIDATIONS_IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()));

    let key = format!("{}::{}", state.namespace, state.variant_key);
    match in_flight.lock() {
        Ok(mut set) => {
            if !set.insert(key.clone()) {
                return None;
            }
        }
        Err(poisoned) => {
            let mut set = poisoned.into_inner();
            if !set.insert(key.clone()) {
                return None;
            }
        }
    }
    Some(BackgroundRevalidationGuard { key })
}

impl Drop for BackgroundRevalidationGuard {
    fn drop(&mut self) {
        let in_flight =
            BACKGROUND_REVALIDATIONS_IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()));
        if let Ok(mut set) = in_flight.lock() {
            let _ = set.remove(self.key.as_str());
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum VarySpec {
    Any,
    Fields(Vec<String>),
}
