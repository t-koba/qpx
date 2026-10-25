// Extracted from rate_limit.rs; public surface is re-exported by mod.rs.
use super::RateLimitContext;
use super::key::{
    KeyKind, LimiterKey, make_limiter_key, max_entries_for_key_kind, shard_count_for_key_kind,
};
use super::nonzero_capacity;
use lru::LruCache;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

#[derive(Debug, Clone)]
pub(super) struct QuotaEntry {
    pub(super) window_started: Instant,
    pub(super) requests_used: u64,
    pub(super) bytes_used: u64,
}

#[derive(Debug, Clone)]
pub(super) struct QuotaState {
    pub(super) entries: LruCache<LimiterKey, QuotaEntry>,
}

impl QuotaState {
    pub(super) fn new(max_entries: usize) -> Self {
        Self {
            entries: LruCache::new(nonzero_capacity(max_entries)),
        }
    }

    fn prune(&mut self, now: Instant, interval: Duration) {
        while self
            .entries
            .peek_lru()
            .is_some_and(|(_, entry)| now.duration_since(entry.window_started) >= interval)
        {
            let _ = self.entries.pop_lru();
        }
    }

    pub(super) fn entry(
        &mut self,
        key: LimiterKey,
        now: Instant,
        interval: Duration,
    ) -> &mut QuotaEntry {
        if !self.entries.contains(&key) {
            self.prune(now, interval);
            self.entries.put(
                key.clone(),
                QuotaEntry {
                    window_started: now,
                    requests_used: 0,
                    bytes_used: 0,
                },
            );
        }
        self.entries
            .get_mut(&key)
            .unwrap_or_else(|| unreachable!("quota entry missing after lookup or insertion"))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct QuotaLimiter {
    key_kind: KeyKind,
    interval: Duration,
    request_limit: Option<u64>,
    byte_limit: Option<u64>,
    shards: Arc<Vec<Mutex<QuotaState>>>,
    shard_mask: usize,
}

impl QuotaLimiter {
    pub(super) fn new(
        key_kind: KeyKind,
        interval: Duration,
        request_limit: Option<u64>,
        byte_limit: Option<u64>,
    ) -> Self {
        let max_entries = max_entries_for_key_kind(key_kind);
        let shard_count = shard_count_for_key_kind(key_kind);
        debug_assert!(shard_count.is_power_of_two());
        let per_shard_max_entries = (max_entries / shard_count).max(1);
        let shards = (0..shard_count)
            .map(|_| Mutex::new(QuotaState::new(per_shard_max_entries)))
            .collect::<Vec<_>>();
        Self {
            key_kind,
            interval,
            request_limit,
            byte_limit,
            shards: Arc::new(shards),
            shard_mask: shard_count.saturating_sub(1),
        }
    }

    fn try_take_with_context(
        &self,
        ctx: &RateLimitContext,
        cost: u64,
        limit: u64,
        used: impl FnOnce(&mut QuotaEntry) -> &mut u64,
    ) -> Option<Duration> {
        let now = Instant::now();
        let key = make_limiter_key(self.key_kind, ctx);
        let shard = qpx_http::sharding::masked(&key, self.shard_mask);
        let mut inner = self.shards[shard]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = inner.entry(key, now, self.interval);
        if now.duration_since(entry.window_started) >= self.interval {
            entry.window_started = now;
            entry.requests_used = 0;
            entry.bytes_used = 0;
        }
        let window_started = entry.window_started;
        let used = used(entry);
        if used.saturating_add(cost) > limit {
            return Some(
                self.interval
                    .saturating_sub(now.duration_since(window_started)),
            );
        }
        *used = used.saturating_add(cost);
        None
    }

    pub(crate) fn try_take_requests_with_context(
        &self,
        ctx: &RateLimitContext,
        cost: u64,
    ) -> Option<Duration> {
        let limit = self.request_limit?;
        self.try_take_with_context(ctx, cost, limit, |entry| &mut entry.requests_used)
    }

    pub(crate) fn try_take_bytes_with_context(&self, ctx: &RateLimitContext, cost: u64) -> bool {
        let Some(limit) = self.byte_limit else {
            return true;
        };
        self.try_take_with_context(ctx, cost, limit, |entry| &mut entry.bytes_used)
            .is_none()
    }
}
