use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};
#[cfg(test)]
use tokio::sync::TryAcquireError;
use tokio::sync::{AcquireError, Mutex, OwnedSemaphorePermit, Semaphore};

pub(super) type UpstreamProxySender = qpx_http::protocol::common::Http1SendRequest;

const DEFAULT_MAX_CONCURRENT_PER_ENDPOINT: usize = 8;

struct UpstreamProxySlotLimiter {
    /// Limit already applied to `semaphore`; it lags the configured pool limit
    /// until the next checkout of this endpoint.
    limit: usize,
    /// Permits to permanently remove as their holders release them after a shrink.
    pending_shrink: usize,
}

pub(crate) struct UpstreamProxySlot {
    pub(crate) senders: Mutex<Vec<UpstreamProxySender>>,
    pub(crate) semaphore: Arc<Semaphore>,
    limiter: StdMutex<UpstreamProxySlotLimiter>,
}

/// A semaphore permit checked out from a slot. On release it settles one
/// outstanding shrink, so a reduced limit converges without revoking permits
/// that were already in flight.
pub(crate) struct UpstreamProxySlotPermit {
    slot: Arc<UpstreamProxySlot>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for UpstreamProxySlotPermit {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let mut limiter = self.slot.lock_limiter();
        if limiter.pending_shrink > 0 {
            limiter.pending_shrink -= 1;
            // Forget while the limiter is locked so a concurrent reload cannot
            // mistake this permit for one still available to hand out.
            permit.forget();
        } else {
            drop(limiter);
            drop(permit);
        }
    }
}

impl UpstreamProxySlot {
    fn new(limit: usize) -> Self {
        Self {
            senders: Mutex::new(Vec::new()),
            semaphore: Arc::new(Semaphore::new(limit)),
            limiter: StdMutex::new(UpstreamProxySlotLimiter {
                limit,
                pending_shrink: 0,
            }),
        }
    }

    fn lock_limiter(&self) -> StdMutexGuard<'_, UpstreamProxySlotLimiter> {
        self.limiter
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Applies the configured limit to this slot's semaphore without discarding
    /// the slot, its pooled senders, or permits already in flight.
    fn reconcile_limit(&self, desired: usize) {
        let mut limiter = self.lock_limiter();
        if limiter.limit == desired {
            return;
        }
        if desired > limiter.limit {
            let increase = desired - limiter.limit;
            let cancelled = limiter.pending_shrink.min(increase);
            limiter.pending_shrink -= cancelled;
            let added = increase - cancelled;
            if added > 0 {
                self.semaphore.add_permits(added);
            }
        } else {
            let shrink = limiter.limit - desired;
            let immediate = shrink.min(self.semaphore.available_permits());
            if immediate > 0 {
                self.semaphore.forget_permits(immediate);
            }
            limiter.pending_shrink += shrink - immediate;
        }
        limiter.limit = desired;
    }

    pub(crate) async fn acquire(self: &Arc<Self>) -> Result<UpstreamProxySlotPermit, AcquireError> {
        let permit = self.semaphore.clone().acquire_owned().await?;
        Ok(UpstreamProxySlotPermit {
            slot: self.clone(),
            permit: Some(permit),
        })
    }

    #[cfg(test)]
    pub(crate) fn try_acquire(
        self: &Arc<Self>,
    ) -> Result<UpstreamProxySlotPermit, TryAcquireError> {
        let permit = self.semaphore.clone().try_acquire_owned()?;
        Ok(UpstreamProxySlotPermit {
            slot: self.clone(),
            permit: Some(permit),
        })
    }
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
        let mut guard = self.shards.lock(key).await;
        let limit = self.max_concurrent_per_endpoint();
        let slot = guard
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(UpstreamProxySlot::new(limit)));
        slot.reconcile_limit(limit);
        slot.clone()
    }
}
