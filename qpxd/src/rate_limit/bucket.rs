// Extracted from rate_limit.rs; public surface is re-exported by mod.rs.
use super::RateLimitContext;
use super::key::{
    DEFAULT_ENTRY_TTL, KeyKind, LimiterKey, make_limiter_key, max_entries_for_key_kind,
    shard_count_for_key_kind,
};
use arc_swap::ArcSwapOption;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
struct AtomicGcra {
    theoretical_arrival_nanos: AtomicU64,
    interval_nanos: u64,
    burst_nanos: u64,
}

impl AtomicGcra {
    fn new(capacity: f64, refill_per_sec: f64) -> Option<Self> {
        if !capacity.is_finite()
            || !refill_per_sec.is_finite()
            || capacity < 1.0
            || refill_per_sec < 1.0
            || capacity.fract() != 0.0
            || refill_per_sec.fract() != 0.0
            || capacity > u64::MAX as f64
            || refill_per_sec > 1_000_000_000.0
        {
            return None;
        }
        let capacity = capacity as u64;
        let refill_per_sec = refill_per_sec as u64;
        if 1_000_000_000 % refill_per_sec != 0 {
            return None;
        }
        let interval_nanos = 1_000_000_000 / refill_per_sec;
        let burst_nanos = capacity.checked_mul(interval_nanos)?;
        Some(Self {
            theoretical_arrival_nanos: AtomicU64::new(0),
            interval_nanos,
            burst_nanos,
        })
    }

    fn try_take(&self, now_nanos: u64, cost: u64) -> Option<Duration> {
        loop {
            let current = self.theoretical_arrival_nanos.load(Ordering::Acquire);
            let base = current.max(now_nanos) as u128;
            let next = base.saturating_add((cost as u128) * (self.interval_nanos as u128));
            let limit = (now_nanos as u128).saturating_add(self.burst_nanos as u128);
            if next > limit {
                return Some(duration_from_nanos(next - limit));
            }
            let next = next.min(u64::MAX as u128) as u64;
            if self
                .theoretical_arrival_nanos
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return None;
            }
        }
    }

    fn reserve_delay(&self, now_nanos: u64, cost: u64) -> Duration {
        loop {
            let current = self.theoretical_arrival_nanos.load(Ordering::Acquire);
            let base = current.max(now_nanos) as u128;
            let next = base.saturating_add((cost as u128) * (self.interval_nanos as u128));
            let stored = next.min(u64::MAX as u128) as u64;
            if self
                .theoretical_arrival_nanos
                .compare_exchange_weak(current, stored, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let limit = (now_nanos as u128).saturating_add(self.burst_nanos as u128);
                return duration_from_nanos(next.saturating_sub(limit));
            }
        }
    }
}

fn duration_from_nanos(nanos: u128) -> Duration {
    let seconds = nanos / 1_000_000_000;
    if seconds > u64::MAX as u128 {
        return Duration::MAX;
    }
    Duration::new(
        seconds as u64,
        (nanos % 1_000_000_000).min(u32::MAX as u128) as u32,
    )
}

#[derive(Debug)]
enum BucketState {
    Atomic(AtomicGcra),
    Locked(Mutex<TokenBucket>),
}

impl BucketState {
    fn new(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        AtomicGcra::new(capacity, refill_per_sec).map_or_else(
            || Self::Locked(Mutex::new(TokenBucket::new(capacity, refill_per_sec, now))),
            Self::Atomic,
        )
    }

    fn try_take(&self, now: Instant, now_nanos: u64, cost: u64) -> Option<Duration> {
        match self {
            Self::Atomic(bucket) => bucket.try_take(now_nanos, cost),
            Self::Locked(bucket) => bucket.lock().try_take(now, cost as f64),
        }
    }

    fn reserve_delay(&self, now: Instant, now_nanos: u64, cost: u64) -> Duration {
        match self {
            Self::Atomic(bucket) => bucket.reserve_delay(now_nanos, cost),
            Self::Locked(bucket) => bucket.lock().reserve_delay(now, cost as f64),
        }
    }
}

#[derive(Debug)]
struct BucketEntry {
    bucket: BucketState,
    last_seen_nanos: AtomicU64,
}

#[derive(Debug)]
struct LimiterInner {
    buckets: LruCache<LimiterKey, Arc<BucketEntry>>,
    ttl_nanos: u64,
}

impl LimiterInner {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            buckets: LruCache::new(nonzero_capacity(max_entries)),
            ttl_nanos: ttl.as_nanos().min(u64::MAX as u128) as u64,
        }
    }

    fn prune(&mut self, now_nanos: u64) {
        while self.buckets.peek_lru().is_some_and(|(_, entry)| {
            now_nanos.saturating_sub(entry.last_seen_nanos.load(Ordering::Relaxed)) > self.ttl_nanos
        }) {
            let _ = self.buckets.pop_lru();
        }
    }

    fn entry(
        &mut self,
        key: LimiterKey,
        now: Instant,
        now_nanos: u64,
        capacity: f64,
        refill_per_sec: f64,
    ) -> Arc<BucketEntry> {
        if self.buckets.contains(&key) {
            let Some(entry) = self.buckets.get_mut(&key) else {
                unreachable!("bucket key disappeared between contains and get_mut");
            };
            return entry.clone();
        }
        self.prune(now_nanos);
        let entry = Arc::new(BucketEntry {
            bucket: BucketState::new(capacity, refill_per_sec, now),
            last_seen_nanos: AtomicU64::new(now_nanos),
        });
        self.buckets.put(key, entry.clone());
        entry
    }
}

#[derive(Debug)]
struct HotBucketEntry {
    key: LimiterKey,
    entry: Arc<BucketEntry>,
}

fn with_bucket<R>(
    hot: &ArcSwapOption<HotBucketEntry>,
    shards: &[Mutex<LimiterInner>],
    shard_mask: usize,
    key: LimiterKey,
    now: Instant,
    now_nanos: u64,
    capacity: f64,
    refill_per_sec: f64,
    operation: impl FnOnce(&BucketState) -> R,
) -> R {
    let cached = hot.load();
    if let Some(cached) = cached.as_ref()
        && cached.key == key
    {
        cached
            .entry
            .last_seen_nanos
            .store(now_nanos, Ordering::Relaxed);
        return operation(&cached.entry.bucket);
    }
    drop(cached);

    let shard = qpx_http::sharding::masked(&key, shard_mask);
    let entry = shards[shard]
        .lock()
        .entry(key.clone(), now, now_nanos, capacity, refill_per_sec);
    hot.store(Some(Arc::new(HotBucketEntry {
        key,
        entry: entry.clone(),
    })));
    entry.last_seen_nanos.store(now_nanos, Ordering::Relaxed);
    operation(&entry.bucket)
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
    hot: Arc<ArcSwapOption<HotBucketEntry>>,
    epoch: Instant,
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
            hot: Arc::new(ArcSwapOption::empty()),
            epoch: Instant::now(),
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
        let now_nanos = now
            .duration_since(self.epoch)
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        let key = self.make_key(ctx);
        with_bucket(
            &self.hot,
            self.shards.as_slice(),
            self.shard_mask,
            key,
            now,
            now_nanos,
            self.capacity,
            self.refill_per_sec,
            |bucket| bucket.try_take(now, now_nanos, cost),
        )
    }

    pub(crate) fn reserve_delay_with_context(&self, ctx: &RateLimitContext, cost: u64) -> Duration {
        let now = Instant::now();
        let now_nanos = now
            .duration_since(self.epoch)
            .as_nanos()
            .min(u64::MAX as u128) as u64;
        let key = self.make_key(ctx);
        with_bucket(
            &self.hot,
            self.shards.as_slice(),
            self.shard_mask,
            key,
            now,
            now_nanos,
            self.capacity,
            self.refill_per_sec,
            |bucket| bucket.reserve_delay(now, now_nanos, cost),
        )
    }

    #[cfg(test)]
    pub(super) fn test_entry_count_for_context(&self, ctx: &RateLimitContext) -> usize {
        let key = self.make_key(ctx);
        let shard = qpx_http::sharding::masked(&key, self.shard_mask);
        self.shards[shard].lock().buckets.len()
    }
}

#[cfg(test)]
mod atomic_tests {
    use super::*;

    #[test]
    fn gcra_preserves_burst_rejection_and_refill_without_advancing_on_reject() {
        let bucket = AtomicGcra::new(2.0, 1.0).expect("atomic GCRA");
        let now = 1_000;

        assert_eq!(bucket.try_take(now, 1), None);
        assert_eq!(bucket.try_take(now, 1), None);
        assert_eq!(bucket.try_take(now, 1), Some(Duration::from_secs(1)));
        assert_eq!(
            bucket.try_take(now + 1_000_000_000, 1),
            None,
            "a rejected request must not consume future capacity"
        );
    }

    #[test]
    fn gcra_reservation_accumulates_exact_delay() {
        let bucket = AtomicGcra::new(1.0, 1.0).expect("atomic GCRA");
        let now = 1_000;

        assert_eq!(bucket.reserve_delay(now, 1), Duration::ZERO);
        assert_eq!(bucket.reserve_delay(now, 1), Duration::from_secs(1));
        assert_eq!(bucket.reserve_delay(now, 1), Duration::from_secs(2));
    }

    #[test]
    fn gcra_uses_locked_fallback_when_nanoseconds_cannot_represent_rate_exactly() {
        assert!(AtomicGcra::new(10.0, 7.0).is_none());
        let state = BucketState::new(10.0, 7.0, Instant::now());
        assert!(matches!(state, BucketState::Locked(_)));
    }
}
