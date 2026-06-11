use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const BROKER_SOURCE_RATE_WINDOW: Duration = Duration::from_secs(1);
const BROKER_SOURCE_DATAGRAMS_PER_WINDOW: usize = 512;
const BROKER_SOURCE_RATE_TABLE_CAPACITY: usize = 8192;

#[derive(Debug)]
struct DatagramRateLimiter {
    sources: HashMap<SocketAddr, SourceRateState>,
    last_cleanup: Instant,
    max_entries: usize,
}

#[derive(Debug)]
pub(super) struct ShardedDatagramRateLimiter {
    shards: Vec<Mutex<DatagramRateLimiter>>,
}

impl ShardedDatagramRateLimiter {
    pub(super) fn new(shards: usize) -> Self {
        let shards = shards.max(1);
        let per_shard_capacity = (BROKER_SOURCE_RATE_TABLE_CAPACITY / shards).max(1);
        Self {
            shards: qpx_http::sharding::sync_mutex_shards(shards, || {
                DatagramRateLimiter::new(per_shard_capacity)
            }),
        }
    }

    pub(super) fn allow(&self, addr: SocketAddr) -> bool {
        let shard = qpx_http::sharding::modulo(&addr, self.shards.len());
        self.shards[shard]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .allow(addr)
    }
}

impl Default for DatagramRateLimiter {
    fn default() -> Self {
        Self::new(BROKER_SOURCE_RATE_TABLE_CAPACITY)
    }
}

impl DatagramRateLimiter {
    fn new(max_entries: usize) -> Self {
        Self {
            sources: HashMap::new(),
            last_cleanup: Instant::now(),
            max_entries: max_entries.max(1),
        }
    }

    fn allow(&mut self, addr: SocketAddr) -> bool {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) >= BROKER_SOURCE_RATE_WINDOW {
            self.sources
                .retain(|_, state| now.duration_since(state.last_seen) < BROKER_SOURCE_RATE_WINDOW);
            self.last_cleanup = now;
        }
        if !self.sources.contains_key(&addr) && self.sources.len() >= self.max_entries {
            return false;
        }
        let state = self.sources.entry(addr).or_insert(SourceRateState {
            window_start: now,
            last_seen: now,
            count: 0,
        });
        state.last_seen = now;
        if now.duration_since(state.window_start) >= BROKER_SOURCE_RATE_WINDOW {
            state.window_start = now;
            state.count = 0;
        }
        if state.count >= BROKER_SOURCE_DATAGRAMS_PER_WINDOW {
            return false;
        }
        state.count += 1;
        true
    }
}

#[derive(Debug)]
struct SourceRateState {
    window_start: Instant,
    last_seen: Instant,
    count: usize,
}

#[cfg(test)]
mod tests {
    use crate::http3::quinn_socket::broker::rate_limiter::*;

    #[test]
    fn datagram_rate_limiter_caps_source_table() {
        let mut limiter = DatagramRateLimiter::default();
        for port in 1..=BROKER_SOURCE_RATE_TABLE_CAPACITY {
            let addr = SocketAddr::from(([198, 51, 100, 1], port as u16));
            assert!(limiter.allow(addr));
        }

        let overflow = SocketAddr::from(([198, 51, 100, 2], 1));
        assert!(!limiter.allow(overflow));
    }
}
