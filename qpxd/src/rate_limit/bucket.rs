// Extracted from rate_limit.rs; public surface is re-exported by mod.rs.
use super::RateLimitContext;
use super::key::{
    DEFAULT_ENTRY_TTL, KeyKind, LimiterKey, make_limiter_key, max_entries_for_key_kind,
    shard_count_for_key_kind,
};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

#[derive(Debug, Clone)]
struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill);
        let add = elapsed.as_secs_f64() * self.refill_per_sec;
        if add > 0.0 {
            self.tokens = (self.tokens + add).min(self.capacity);
            self.last_refill = now;
        }
    }

    fn try_take(&mut self, now: Instant, cost: f64) -> Option<Duration> {
        self.refill(now);
        if self.tokens >= cost {
            self.tokens -= cost;
            return None;
        }
        let missing = (cost - self.tokens).max(0.0);
        Some(Duration::from_secs_f64(missing / self.refill_per_sec))
    }

    fn reserve_delay(&mut self, now: Instant, cost: f64) -> Duration {
        self.refill(now);
        self.tokens -= cost;
        if self.tokens >= 0.0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64((-self.tokens) / self.refill_per_sec)
    }
}

#[derive(Debug)]
struct BucketEntry {
    bucket: TokenBucket,
    last_seen: Instant,
}

#[derive(Debug)]
struct LimiterInner {
    buckets: LruCache<LimiterKey, BucketEntry>,
    ttl: Duration,
}

impl LimiterInner {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            buckets: LruCache::new(nonzero_capacity(max_entries)),
            ttl,
        }
    }

    fn prune(&mut self, now: Instant) {
        while self
            .buckets
            .peek_lru()
            .is_some_and(|(_, entry)| now.duration_since(entry.last_seen) > self.ttl)
        {
            let _ = self.buckets.pop_lru();
        }
    }

    fn entry(
        &mut self,
        key: LimiterKey,
        now: Instant,
        capacity: f64,
        refill_per_sec: f64,
    ) -> &mut BucketEntry {
        if self.buckets.contains(&key) {
            let Some(entry) = self.buckets.get_mut(&key) else {
                unreachable!("bucket key disappeared between contains and get_mut");
            };
            entry.last_seen = now;
            return entry;
        }
        self.prune(now);
        self.buckets.put(
            key.clone(),
            BucketEntry {
                bucket: TokenBucket::new(capacity, refill_per_sec, now),
                last_seen: now,
            },
        );
        let Some(entry) = self.buckets.get_mut(&key) else {
            unreachable!("bucket was inserted into the same LRU map immediately before lookup");
        };
        entry
    }
}

fn nonzero_capacity(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value.max(1)) {
        Some(capacity) => capacity,
        None => unreachable!("usize::max(1) is always non-zero"),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RateLimiter {
    key_kind: KeyKind,
    capacity: f64,
    refill_per_sec: f64,
    shards: Arc<Vec<Mutex<LimiterInner>>>,
    shard_mask: usize,
}

impl RateLimiter {
    pub(super) fn new(key_kind: KeyKind, capacity: f64, refill_per_sec: f64) -> Self {
        let max_entries = max_entries_for_key_kind(key_kind);
        let shard_count = shard_count_for_key_kind(key_kind);
        debug_assert!(shard_count.is_power_of_two());
        let per_shard_max_entries = (max_entries / shard_count).max(1);
        let shards = (0..shard_count)
            .map(|_| Mutex::new(LimiterInner::new(per_shard_max_entries, DEFAULT_ENTRY_TTL)))
            .collect::<Vec<_>>();
        Self {
            key_kind,
            capacity,
            refill_per_sec,
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
        cost: u64,
    ) -> Option<Duration> {
        let now = Instant::now();
        let cost = cost as f64;
        let key = self.make_key(ctx);
        let shard = qpx_http::sharding::masked(&key, self.shard_mask);
        let mut inner = self.shards[shard]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner
            .entry(key, now, self.capacity, self.refill_per_sec)
            .bucket
            .try_take(now, cost)
    }

    pub(crate) fn reserve_delay_with_context(&self, ctx: &RateLimitContext, cost: u64) -> Duration {
        let now = Instant::now();
        let cost = cost as f64;
        let key = self.make_key(ctx);
        let shard = qpx_http::sharding::masked(&key, self.shard_mask);
        let mut inner = self.shards[shard]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner
            .entry(key, now, self.capacity, self.refill_per_sec)
            .bucket
            .reserve_delay(now, cost)
    }

    #[cfg(test)]
    pub(super) fn test_entry_count_for_context(&self, ctx: &RateLimitContext) -> usize {
        let key = self.make_key(ctx);
        let shard = qpx_http::sharding::masked(&key, self.shard_mask);
        self.shards[shard]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .buckets
            .len()
    }
}
