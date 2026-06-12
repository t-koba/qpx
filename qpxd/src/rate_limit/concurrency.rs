// Extracted from rate_limit.rs; public surface is re-exported by mod.rs.
use super::RateLimitContext;
use super::key::{KeyKind, LimiterKey, make_limiter_key, shard_count_for_key_kind};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct ConcurrencyInner {
    counts: HashMap<LimiterKey, usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct ConcurrencyLimiter {
    key_kind: KeyKind,
    max: usize,
    shards: Arc<Vec<Mutex<ConcurrencyInner>>>,
    shard_mask: usize,
}

#[derive(Debug)]
pub(crate) struct ConcurrencyPermit {
    shards: Arc<Vec<Mutex<ConcurrencyInner>>>,
    shard: usize,
    key: LimiterKey,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        let mut inner = self.shards[self.shard]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = inner.counts.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.counts.remove(&self.key);
            }
        }
    }
}

impl ConcurrencyLimiter {
    pub(super) fn new(key_kind: KeyKind, max: usize) -> Self {
        let shard_count = shard_count_for_key_kind(key_kind);
        debug_assert!(shard_count.is_power_of_two());
        let shards = (0..shard_count)
            .map(|_| {
                Mutex::new(ConcurrencyInner {
                    counts: HashMap::new(),
                })
            })
            .collect::<Vec<_>>();
        Self {
            key_kind,
            max: max.max(1),
            shards: Arc::new(shards),
            shard_mask: shard_count.saturating_sub(1),
        }
    }

    fn make_key(&self, ctx: &RateLimitContext) -> LimiterKey {
        make_limiter_key(self.key_kind, ctx)
    }

    pub(crate) fn try_acquire_with_context(
        &self,
        ctx: &RateLimitContext,
    ) -> Option<ConcurrencyPermit> {
        let key = self.make_key(ctx);
        let shard = qpx_http::sharding::masked(&key, self.shard_mask);
        let mut inner = self.shards[shard]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = inner.counts.entry(key.clone()).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        Some(ConcurrencyPermit {
            shards: self.shards.clone(),
            shard,
            key,
        })
    }
}
