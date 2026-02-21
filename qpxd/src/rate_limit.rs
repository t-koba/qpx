use qpx_core::config::{ListenerConfig, RateLimitConfig};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

const DEFAULT_MAX_ENTRIES: usize = 65_536;
const DEFAULT_ENTRY_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Global,
    SrcIp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LimiterKey {
    Global,
    Ip(IpAddr),
}

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
    gen: u64,
}

#[derive(Debug)]
struct LimiterInner {
    buckets: HashMap<LimiterKey, BucketEntry>,
    queue: VecDeque<(LimiterKey, u64)>,
    max_entries: usize,
    ttl: Duration,
}

impl LimiterInner {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            buckets: HashMap::new(),
            queue: VecDeque::new(),
            max_entries: max_entries.max(1),
            ttl,
        }
    }

    fn prune(&mut self, now: Instant) {
        while let Some((key, gen)) = self.queue.front().cloned() {
            let Some(entry) = self.buckets.get(&key) else {
                let _ = self.queue.pop_front();
                continue;
            };
            if entry.gen != gen {
                let _ = self.queue.pop_front();
                continue;
            }
            let expired = now.duration_since(entry.last_seen) > self.ttl;
            let oversize = self.buckets.len() > self.max_entries;
            if expired || oversize {
                let _ = self.queue.pop_front();
                self.buckets.remove(&key);
                continue;
            }
            break;
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RateLimiter {
    key_kind: KeyKind,
    capacity: f64,
    refill_per_sec: f64,
    inner: Arc<Mutex<LimiterInner>>,
}

impl RateLimiter {
    fn new(key_kind: KeyKind, capacity: f64, refill_per_sec: f64) -> Self {
        let max_entries = match key_kind {
            KeyKind::Global => 1,
            KeyKind::SrcIp => DEFAULT_MAX_ENTRIES,
        };
        let ttl = match key_kind {
            KeyKind::Global => DEFAULT_ENTRY_TTL,
            KeyKind::SrcIp => DEFAULT_ENTRY_TTL,
        };
        Self {
            key_kind,
            capacity,
            refill_per_sec,
            inner: Arc::new(Mutex::new(LimiterInner::new(max_entries, ttl))),
        }
    }

    fn make_key(&self, src_ip: IpAddr) -> LimiterKey {
        match self.key_kind {
            KeyKind::Global => LimiterKey::Global,
            KeyKind::SrcIp => LimiterKey::Ip(src_ip),
        }
    }

    pub(crate) fn try_acquire(&self, src_ip: IpAddr, cost: u64) -> Option<Duration> {
        let now = Instant::now();
        let cost = cost as f64;
        let mut inner = self.inner.lock().expect("rate limiter mutex");
        inner.prune(now);
        let key = self.make_key(src_ip);
        let (gen, decision) = {
            let entry = inner.buckets.entry(key.clone()).or_insert_with(|| BucketEntry {
                bucket: TokenBucket::new(self.capacity, self.refill_per_sec, now),
                last_seen: now,
                gen: 0,
            });
            entry.last_seen = now;
            entry.gen = entry.gen.wrapping_add(1);
            let gen = entry.gen;
            let decision = entry.bucket.try_take(now, cost);
            (gen, decision)
        };
        inner.queue.push_back((key, gen));
        decision
    }

    pub(crate) fn reserve_delay(&self, src_ip: IpAddr, cost: u64) -> Duration {
        let now = Instant::now();
        let cost = cost as f64;
        let mut inner = self.inner.lock().expect("rate limiter mutex");
        inner.prune(now);
        let key = self.make_key(src_ip);
        let (gen, delay) = {
            let entry = inner.buckets.entry(key.clone()).or_insert_with(|| BucketEntry {
                bucket: TokenBucket::new(self.capacity, self.refill_per_sec, now),
                last_seen: now,
                gen: 0,
            });
            entry.last_seen = now;
            entry.gen = entry.gen.wrapping_add(1);
            let gen = entry.gen;
            let delay = entry.bucket.reserve_delay(now, cost);
            (gen, delay)
        };
        inner.queue.push_back((key, gen));
        delay
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RateLimitSet {
    pub(crate) requests: Option<Arc<RateLimiter>>,
    pub(crate) bytes: Option<Arc<RateLimiter>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ListenerRateLimits {
    pub(crate) listener: RateLimitSet,
    pub(crate) rules: HashMap<String, RateLimitSet>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RateLimiters {
    listeners: HashMap<String, ListenerRateLimits>,
}

impl RateLimiters {
    pub(crate) fn from_config(listeners: &[ListenerConfig]) -> Self {
        let mut out = HashMap::new();
        for listener in listeners {
            let mut limits = ListenerRateLimits {
                listener: RateLimitSet::from_config(listener.rate_limit.as_ref()),
                ..Default::default()
            };
            for rule in &listener.rules {
                let set = RateLimitSet::from_config(rule.rate_limit.as_ref());
                if set.requests.is_some() || set.bytes.is_some() {
                    limits.rules.insert(rule.name.clone(), set);
                }
            }
            if limits.listener.requests.is_some()
                || limits.listener.bytes.is_some()
                || !limits.rules.is_empty()
            {
                out.insert(listener.name.clone(), limits);
            }
        }
        Self { listeners: out }
    }

    pub(crate) fn listener(&self, name: &str) -> Option<&ListenerRateLimits> {
        self.listeners.get(name)
    }
}

impl RateLimitSet {
    fn parse_key_kind(raw: &str) -> KeyKind {
        match raw.trim().to_ascii_lowercase().as_str() {
            "global" => KeyKind::Global,
            _ => KeyKind::SrcIp,
        }
    }

    fn from_config(cfg: Option<&RateLimitConfig>) -> Self {
        let Some(cfg) = cfg.filter(|c| c.enabled) else {
            return Self::default();
        };
        let key_kind = Self::parse_key_kind(cfg.key.as_str());
        let requests = cfg.rps.map(|rps| {
            let burst = cfg.burst.unwrap_or(rps).max(1) as f64;
            Arc::new(RateLimiter::new(key_kind, burst, rps.max(1) as f64))
        });
        let bytes = cfg.bytes_per_sec.map(|bps| {
            let burst = cfg.bytes_burst.unwrap_or(bps).max(1) as f64;
            Arc::new(RateLimiter::new(key_kind, burst, bps.max(1) as f64))
        });
        Self { requests, bytes }
    }
}
