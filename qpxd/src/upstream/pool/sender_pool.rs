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

impl UpstreamProxySlotPermit {
    fn release(&mut self, before_unlock: impl FnOnce()) {
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
            // Return while the limiter is locked too: a reconcile that observes
            // the permit before it is handed back would record shrink debt for
            // a permit that is about to become available again.
            drop(permit);
        }
        before_unlock();
        drop(limiter);
    }

    #[cfg(test)]
    fn release_with_hook(&mut self, hook: impl FnOnce()) {
        self.release(hook);
    }
}

impl Drop for UpstreamProxySlotPermit {
    fn drop(&mut self) {
        self.release(|| {});
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

    /// Removes as many permits as are immediately available and carries the
    /// remainder as pending shrink. `forget_permits` reports what it actually
    /// removed, so concurrent acquisitions cannot make the limit drift upward.
    /// `before_forget` is a test seam that forces an acquire into the old
    /// read-to-forget window; production passes a no-op.
    fn settle_shrink(
        &self,
        limiter: &mut UpstreamProxySlotLimiter,
        shrink: usize,
        before_forget: impl FnOnce(),
    ) {
        let _available_snapshot = self.semaphore.available_permits();
        before_forget();
        let removed = self.semaphore.forget_permits(shrink);
        limiter.pending_shrink += shrink.saturating_sub(removed);
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
            self.settle_shrink(&mut limiter, shrink, || {});
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

#[cfg(test)]
mod shrink_tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn release_racing_shrink_cannot_readmit_above_new_cap() {
        let slot = Arc::new(UpstreamProxySlot::new(2));
        let mut released = slot.try_acquire().expect("first permit");
        let still_active = slot.try_acquire().expect("second permit");
        let observer = slot.clone();

        released.release_with_hook(|| {
            assert!(
                observer.limiter.try_lock().is_err(),
                "limiter must stay locked until the released permit is visible"
            );
            assert_eq!(
                observer.semaphore.available_permits(),
                1,
                "returned permit must be visible before reconciliation can observe the slot"
            );
        });
        slot.reconcile_limit(1);

        assert_eq!(
            slot.semaphore.available_permits(),
            0,
            "shrink must consume the released permit rather than leaving it available"
        );
        assert!(
            slot.try_acquire().is_err(),
            "the active request must keep the new cap full"
        );
        drop(still_active);
    }

    #[test]
    fn shrink_accounts_for_permits_stolen_after_availability_read() {
        let slot = Arc::new(UpstreamProxySlot::new(4));
        let stolen = Mutex::new(Vec::new());
        let mut limiter = slot.lock_limiter();

        slot.settle_shrink(&mut limiter, 3, || {
            let mut held = stolen.lock().expect("stolen permit list");
            for _ in 0..2 {
                held.push(slot.try_acquire().expect("permit stolen during shrink"));
            }
        });

        assert_eq!(
            limiter.pending_shrink, 1,
            "only two of the three requested permits could be removed"
        );
        drop(limiter);
        drop(stolen.into_inner().expect("stolen permit list"));
        assert_eq!(
            slot.semaphore.available_permits(),
            1,
            "effective limit must converge to the configured value"
        );
    }
}
