use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Mutex, Semaphore};

pub(super) type UpstreamProxySender = qpx_http::protocol::common::Http1SendRequest;

const DEFAULT_MAX_CONCURRENT_PER_ENDPOINT: usize = 8;

pub(crate) struct UpstreamProxySlot {
    pub(crate) senders: Mutex<Vec<UpstreamProxySender>>,
    pub(crate) semaphore: Arc<Semaphore>,
}

type UpstreamProxySlotHandle = Arc<UpstreamProxySlot>;

/// Per-runtime pool of reusable HTTP/1 upstream-proxy senders, keyed by endpoint.
/// Owned by [`crate::pool::PoolRegistry`] (formerly a process-global `OnceLock`).
pub(crate) struct UpstreamProxyPool {
    shards: qpx_http::sharding::AsyncShardMap<String, UpstreamProxySlotHandle>,
    max_concurrent_per_endpoint: AtomicUsize,
}

impl Default for UpstreamProxyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl UpstreamProxyPool {
    pub(crate) fn new() -> Self {
        Self {
            shards: qpx_http::sharding::AsyncShardMap::new(64),
            max_concurrent_per_endpoint: AtomicUsize::new(DEFAULT_MAX_CONCURRENT_PER_ENDPOINT),
        }
    }

    /// Applies the configured per-endpoint concurrency limit (used on build/reload).
    pub(crate) fn set_max_concurrent_per_endpoint(&self, value: usize) {
        self.max_concurrent_per_endpoint
            .store(value.max(1), Ordering::Relaxed);
    }

    pub(crate) fn max_concurrent_per_endpoint(&self) -> usize {
        self.max_concurrent_per_endpoint
            .load(Ordering::Relaxed)
            .max(1)
    }

    pub(crate) async fn slot_for(&self, key: &str) -> UpstreamProxySlotHandle {
        let limit = self.max_concurrent_per_endpoint();
        let mut guard = self.shards.lock(key).await;
        guard
            .entry(key.to_string())
            .or_insert_with(|| {
                Arc::new(UpstreamProxySlot {
                    senders: Mutex::new(Vec::new()),
                    semaphore: Arc::new(Semaphore::new(limit)),
                })
            })
            .clone()
    }
}
