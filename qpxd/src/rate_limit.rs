use anyhow::{anyhow, Result};
use qpx_core::config::{ListenerConfig, RateLimitApplyTo, RateLimitConfig, RateLimitProfileConfig};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

const DEFAULT_MAX_ENTRIES: usize = 65_536;
const DEFAULT_ENTRY_TTL: Duration = Duration::from_secs(600);
const SRC_IP_SHARDS: usize = 64;
const MISSING_USER: &str = "__missing_user__";
const MISSING_GROUP: &str = "__missing_group__";
const MISSING_TENANT: &str = "__missing_tenant__";
const MISSING_DEVICE: &str = "__missing_device__";
const MISSING_ROUTE: &str = "__missing_route__";
const MISSING_UPSTREAM: &str = "__missing_upstream__";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Global,
    SrcIp,
    User,
    Group,
    Tenant,
    Device,
    Route,
    Upstream,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum LimiterKey {
    Global,
    Ip(IpAddr),
    Text(Arc<str>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RateLimitContext {
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) user: Option<String>,
    pub(crate) groups: Vec<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) tenant: Option<String>,
    pub(crate) route: Option<String>,
    pub(crate) upstream: Option<String>,
}

impl RateLimitContext {
    pub(crate) fn from_identity(
        src_ip: IpAddr,
        identity: &crate::policy_context::ResolvedIdentity,
        route: Option<&str>,
        upstream: Option<&str>,
    ) -> Self {
        Self {
            src_ip: Some(src_ip),
            user: identity.user.clone(),
            groups: identity.groups.clone(),
            device_id: identity.device_id.clone(),
            tenant: identity.tenant.clone(),
            route: route.map(str::to_string),
            upstream: upstream.map(str::to_string),
        }
    }
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
    shards: Arc<Vec<Mutex<LimiterInner>>>,
    shard_mask: usize,
}

impl RateLimiter {
    fn new(key_kind: KeyKind, capacity: f64, refill_per_sec: f64) -> Self {
        let max_entries = match key_kind {
            KeyKind::Global => 1,
            _ => DEFAULT_MAX_ENTRIES,
        };
        let ttl = DEFAULT_ENTRY_TTL;
        let shard_count = match key_kind {
            KeyKind::Global => 1,
            _ => SRC_IP_SHARDS,
        }
        .max(1);
        debug_assert!(shard_count.is_power_of_two());
        let per_shard_max_entries = (max_entries / shard_count).max(1);
        let shards = (0..shard_count)
            .map(|_| Mutex::new(LimiterInner::new(per_shard_max_entries, ttl)))
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
        match self.key_kind {
            KeyKind::Global => LimiterKey::Global,
            KeyKind::SrcIp => {
                LimiterKey::Ip(ctx.src_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
            }
            KeyKind::User => LimiterKey::Text(text_key(ctx.user.as_deref(), MISSING_USER)),
            KeyKind::Group => LimiterKey::Text(text_key(
                normalized_groups_key(ctx.groups.as_slice()).as_deref(),
                MISSING_GROUP,
            )),
            KeyKind::Tenant => LimiterKey::Text(text_key(ctx.tenant.as_deref(), MISSING_TENANT)),
            KeyKind::Device => LimiterKey::Text(text_key(ctx.device_id.as_deref(), MISSING_DEVICE)),
            KeyKind::Route => LimiterKey::Text(text_key(ctx.route.as_deref(), MISSING_ROUTE)),
            KeyKind::Upstream => {
                LimiterKey::Text(text_key(ctx.upstream.as_deref(), MISSING_UPSTREAM))
            }
        }
    }

    fn shard_for(&self, key: &LimiterKey) -> usize {
        if self.shard_mask == 0 {
            return 0;
        }
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.shard_mask
    }

    pub(crate) fn try_acquire_with_context(
        &self,
        ctx: &RateLimitContext,
        cost: u64,
    ) -> Option<Duration> {
        let now = Instant::now();
        let cost = cost as f64;
        let key = self.make_key(ctx);
        let shard = self.shard_for(&key);
        let mut inner = self.shards[shard].lock().expect("rate limiter mutex");
        inner.prune(now);
        let (gen, decision) = {
            let entry = inner
                .buckets
                .entry(key.clone())
                .or_insert_with(|| BucketEntry {
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

    pub(crate) fn reserve_delay_with_context(&self, ctx: &RateLimitContext, cost: u64) -> Duration {
        let now = Instant::now();
        let cost = cost as f64;
        let key = self.make_key(ctx);
        let shard = self.shard_for(&key);
        let mut inner = self.shards[shard].lock().expect("rate limiter mutex");
        inner.prune(now);
        let (gen, delay) = {
            let entry = inner
                .buckets
                .entry(key.clone())
                .or_insert_with(|| BucketEntry {
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

#[derive(Debug)]
struct ConcurrencyInner {
    counts: HashMap<LimiterKey, usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct ConcurrencyLimiter {
    key_kind: KeyKind,
    max: usize,
    inner: Arc<Mutex<ConcurrencyInner>>,
}

#[derive(Debug)]
pub(crate) struct ConcurrencyPermit {
    inner: Arc<Mutex<ConcurrencyInner>>,
    key: LimiterKey,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        let mut inner = self.inner.lock().expect("concurrency limiter mutex");
        if let Some(count) = inner.counts.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.counts.remove(&self.key);
            }
        }
    }
}

impl ConcurrencyLimiter {
    fn new(key_kind: KeyKind, max: usize) -> Self {
        Self {
            key_kind,
            max: max.max(1),
            inner: Arc::new(Mutex::new(ConcurrencyInner {
                counts: HashMap::new(),
            })),
        }
    }

    fn make_key(&self, ctx: &RateLimitContext) -> LimiterKey {
        RateLimiter {
            key_kind: self.key_kind,
            capacity: 1.0,
            refill_per_sec: 1.0,
            shards: Arc::new(Vec::new()),
            shard_mask: 0,
        }
        .make_key(ctx)
    }

    pub(crate) fn try_acquire_with_context(
        &self,
        ctx: &RateLimitContext,
    ) -> Option<ConcurrencyPermit> {
        let key = self.make_key(ctx);
        let mut inner = self.inner.lock().expect("concurrency limiter mutex");
        let count = inner.counts.entry(key.clone()).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        Some(ConcurrencyPermit {
            inner: self.inner.clone(),
            key,
        })
    }
}

#[derive(Debug, Clone)]
struct QuotaEntry {
    window_started: Instant,
    requests_used: u64,
    bytes_used: u64,
}

#[derive(Debug, Clone)]
struct QuotaState {
    entries: HashMap<LimiterKey, QuotaEntry>,
}

#[derive(Debug, Clone)]
pub(crate) struct QuotaLimiter {
    key_kind: KeyKind,
    interval: Duration,
    request_limit: Option<u64>,
    byte_limit: Option<u64>,
    inner: Arc<Mutex<QuotaState>>,
}

impl QuotaLimiter {
    fn new(
        key_kind: KeyKind,
        interval: Duration,
        request_limit: Option<u64>,
        byte_limit: Option<u64>,
    ) -> Self {
        Self {
            key_kind,
            interval,
            request_limit,
            byte_limit,
            inner: Arc::new(Mutex::new(QuotaState {
                entries: HashMap::new(),
            })),
        }
    }

    fn make_key(&self, ctx: &RateLimitContext) -> LimiterKey {
        RateLimiter {
            key_kind: self.key_kind,
            capacity: 1.0,
            refill_per_sec: 1.0,
            shards: Arc::new(Vec::new()),
            shard_mask: 0,
        }
        .make_key(ctx)
    }

    pub(crate) fn try_take_requests_with_context(
        &self,
        ctx: &RateLimitContext,
        cost: u64,
    ) -> Option<Duration> {
        let limit = self.request_limit?;
        let now = Instant::now();
        let key = self.make_key(ctx);
        let mut inner = self.inner.lock().expect("quota limiter mutex");
        let entry = inner.entries.entry(key).or_insert_with(|| QuotaEntry {
            window_started: now,
            requests_used: 0,
            bytes_used: 0,
        });
        if now.duration_since(entry.window_started) >= self.interval {
            entry.window_started = now;
            entry.requests_used = 0;
            entry.bytes_used = 0;
        }
        if entry.requests_used.saturating_add(cost) > limit {
            return Some(
                self.interval
                    .saturating_sub(now.duration_since(entry.window_started)),
            );
        }
        entry.requests_used = entry.requests_used.saturating_add(cost);
        None
    }

    pub(crate) fn try_take_bytes_with_context(&self, ctx: &RateLimitContext, cost: u64) -> bool {
        let Some(limit) = self.byte_limit else {
            return true;
        };
        let now = Instant::now();
        let key = self.make_key(ctx);
        let mut inner = self.inner.lock().expect("quota limiter mutex");
        let entry = inner.entries.entry(key).or_insert_with(|| QuotaEntry {
            window_started: now,
            requests_used: 0,
            bytes_used: 0,
        });
        if now.duration_since(entry.window_started) >= self.interval {
            entry.window_started = now;
            entry.requests_used = 0;
            entry.bytes_used = 0;
        }
        if entry.bytes_used.saturating_add(cost) > limit {
            return false;
        }
        entry.bytes_used = entry.bytes_used.saturating_add(cost);
        true
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RateLimitSet {
    apply_to: Arc<[TransportScope]>,
    pub(crate) requests: Option<Arc<RateLimiter>>,
    pub(crate) bytes: Option<Arc<RateLimiter>>,
    pub(crate) concurrency: Option<Arc<ConcurrencyLimiter>>,
    pub(crate) request_quota: Option<Arc<QuotaLimiter>>,
    pub(crate) byte_quota: Option<Arc<QuotaLimiter>>,
    pub(crate) session_quota: Option<Arc<QuotaLimiter>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ListenerRateLimits {
    pub(crate) listener: RateLimitSet,
    pub(crate) rules: HashMap<String, RateLimitSet>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AppliedRateLimits {
    pub(crate) request_limiters: Vec<Arc<RateLimiter>>,
    pub(crate) byte_limiters: Vec<Arc<RateLimiter>>,
    pub(crate) concurrency_limiters: Vec<Arc<ConcurrencyLimiter>>,
    pub(crate) request_quota_limiters: Vec<Arc<QuotaLimiter>>,
    pub(crate) byte_quota_limiters: Vec<Arc<QuotaLimiter>>,
    pub(crate) session_quota_limiters: Vec<Arc<QuotaLimiter>>,
}

#[derive(Debug)]
pub(crate) struct ConcurrencyPermits {
    _permits: Vec<ConcurrencyPermit>,
}

#[derive(Debug)]
pub(crate) struct RequestLimitAcquire {
    pub(crate) limits: AppliedRateLimits,
    pub(crate) retry_after: Option<Duration>,
}

pub(crate) struct RequestLimitCollectInput<'a> {
    pub(crate) listener: Option<&'a str>,
    pub(crate) rule: Option<&'a str>,
    pub(crate) profile: Option<&'a str>,
    pub(crate) scope: TransportScope,
    pub(crate) extra: Option<&'a RateLimitSet>,
    pub(crate) ctx: &'a RateLimitContext,
    pub(crate) cost: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TransportScope {
    Request,
    Connect,
    Udp,
    Http3Datagram,
    Webtransport,
    WebtransportBidi,
    WebtransportBidiDownstream,
    WebtransportBidiUpstream,
    WebtransportUni,
    WebtransportUniDownstream,
    WebtransportUniUpstream,
    WebtransportDatagram,
    WebtransportDatagramDownstream,
    WebtransportDatagramUpstream,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RateLimiters {
    listeners: HashMap<String, ListenerRateLimits>,
    profiles: HashMap<String, RateLimitSet>,
}

impl RateLimiters {
    pub(crate) fn from_config(
        listeners: &[ListenerConfig],
        profiles: &[RateLimitProfileConfig],
    ) -> Self {
        let mut out = HashMap::new();
        for listener in listeners {
            let mut limits = ListenerRateLimits {
                listener: RateLimitSet::from_config(listener.rate_limit.as_ref()),
                ..Default::default()
            };
            for rule in &listener.rules {
                let set = RateLimitSet::from_config(rule.rate_limit.as_ref());
                if set.requests.is_some()
                    || set.bytes.is_some()
                    || set.concurrency.is_some()
                    || set.request_quota.is_some()
                    || set.byte_quota.is_some()
                    || set.session_quota.is_some()
                {
                    limits.rules.insert(rule.name.clone(), set);
                }
            }
            if limits.listener.requests.is_some()
                || limits.listener.bytes.is_some()
                || limits.listener.concurrency.is_some()
                || limits.listener.request_quota.is_some()
                || limits.listener.byte_quota.is_some()
                || limits.listener.session_quota.is_some()
                || !limits.rules.is_empty()
            {
                out.insert(listener.name.clone(), limits);
            }
        }

        let mut compiled_profiles = HashMap::new();
        for profile in profiles {
            let set = RateLimitSet::from_config(Some(&profile.limit));
            if set.requests.is_some()
                || set.bytes.is_some()
                || set.concurrency.is_some()
                || set.request_quota.is_some()
                || set.byte_quota.is_some()
                || set.session_quota.is_some()
            {
                compiled_profiles.insert(profile.name.clone(), set);
            }
        }

        Self {
            listeners: out,
            profiles: compiled_profiles,
        }
    }

    pub(crate) fn collect_profile(
        &self,
        profile: Option<&str>,
        scope: TransportScope,
    ) -> Result<AppliedRateLimits> {
        let mut out = AppliedRateLimits::default();
        if let Some(profile) = profile {
            let profile_limits = self
                .profiles
                .get(profile)
                .ok_or_else(|| anyhow!("unknown rate limit profile: {profile}"))?;
            out.extend_set(profile_limits, scope);
        }
        Ok(out)
    }

    pub(crate) fn collect(
        &self,
        listener: &str,
        rule: Option<&str>,
        profile: Option<&str>,
        scope: TransportScope,
    ) -> AppliedRateLimits {
        let mut out = AppliedRateLimits::default();
        if let Some(listener_limits) = self.listeners.get(listener) {
            out.extend_set(&listener_limits.listener, scope);
            if let Some(rule) = rule {
                if let Some(rule_limits) = listener_limits.rules.get(rule) {
                    out.extend_set(rule_limits, scope);
                }
            }
        }
        if let Some(profile) = profile {
            if let Some(profile_limits) = self.profiles.get(profile) {
                out.extend_set(profile_limits, scope);
            }
        }
        out
    }

    pub(crate) fn collect_checked_request(
        &self,
        input: RequestLimitCollectInput<'_>,
    ) -> Result<RequestLimitAcquire> {
        let RequestLimitCollectInput {
            listener,
            rule,
            profile,
            scope,
            extra,
            ctx,
            cost,
        } = input;
        let mut limits = AppliedRateLimits::default();
        if let Some(listener) = listener {
            limits.extend_from(&self.collect(listener, rule, None, scope));
        }
        if let Some(extra) = extra {
            limits.extend_set(extra, scope);
        }
        let retry_after = limits.merge_profile_and_check(self, profile, scope, ctx, cost)?;
        Ok(RequestLimitAcquire {
            limits,
            retry_after,
        })
    }
}

impl AppliedRateLimits {
    pub(crate) fn extend_from(&mut self, other: &AppliedRateLimits) {
        self.request_limiters
            .extend(other.request_limiters.iter().cloned());
        self.byte_limiters
            .extend(other.byte_limiters.iter().cloned());
        self.concurrency_limiters
            .extend(other.concurrency_limiters.iter().cloned());
        self.request_quota_limiters
            .extend(other.request_quota_limiters.iter().cloned());
        self.byte_quota_limiters
            .extend(other.byte_quota_limiters.iter().cloned());
        self.session_quota_limiters
            .extend(other.session_quota_limiters.iter().cloned());
    }

    pub(crate) fn extend_set(&mut self, set: &RateLimitSet, scope: TransportScope) {
        if !set.applies_to(scope) {
            return;
        }
        if let Some(limiter) = set.requests.as_ref() {
            self.request_limiters.push(limiter.clone());
        }
        if let Some(limiter) = set.bytes.as_ref() {
            self.byte_limiters.push(limiter.clone());
        }
        if let Some(limiter) = set.concurrency.as_ref() {
            self.concurrency_limiters.push(limiter.clone());
        }
        if let Some(limiter) = set.request_quota.as_ref() {
            self.request_quota_limiters.push(limiter.clone());
        }
        if let Some(limiter) = set.byte_quota.as_ref() {
            self.byte_quota_limiters.push(limiter.clone());
        }
        if let Some(limiter) = set.session_quota.as_ref() {
            self.session_quota_limiters.push(limiter.clone());
        }
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.request_limiters.is_empty()
            && self.byte_limiters.is_empty()
            && self.concurrency_limiters.is_empty()
            && self.request_quota_limiters.is_empty()
            && self.byte_quota_limiters.is_empty()
            && self.session_quota_limiters.is_empty()
    }

    pub(crate) fn try_acquire_request(
        &self,
        ctx: &RateLimitContext,
        cost: u64,
    ) -> Option<Duration> {
        let mut retry_after = Duration::ZERO;
        for limiter in &self.request_limiters {
            if let Some(delay) = limiter.try_acquire_with_context(ctx, cost) {
                retry_after = retry_after.max(delay);
            }
        }
        for limiter in &self.request_quota_limiters {
            if let Some(delay) = limiter.try_take_requests_with_context(ctx, cost) {
                retry_after = retry_after.max(delay);
            }
        }
        (!retry_after.is_zero()).then_some(retry_after)
    }

    pub(crate) fn acquire_concurrency(&self, ctx: &RateLimitContext) -> Option<ConcurrencyPermits> {
        let mut permits = Vec::with_capacity(self.concurrency_limiters.len());
        for limiter in &self.concurrency_limiters {
            let permit = limiter.try_acquire_with_context(ctx)?;
            permits.push(permit);
        }
        for quota in &self.session_quota_limiters {
            quota.try_take_requests_with_context(ctx, 1)?;
        }
        Some(ConcurrencyPermits { _permits: permits })
    }

    #[cfg(any(feature = "http3", test))]
    pub(crate) fn reserve_bytes(
        &self,
        ctx: &RateLimitContext,
        bytes: u64,
    ) -> std::result::Result<Duration, ()> {
        let mut delay = Duration::ZERO;
        for limiter in &self.byte_limiters {
            delay = delay.max(limiter.reserve_delay_with_context(ctx, bytes));
        }
        for quota in &self.byte_quota_limiters {
            if !quota.try_take_bytes_with_context(ctx, bytes) {
                return Err(());
            }
        }
        Ok(delay)
    }

    pub(crate) fn merge_profile_and_check(
        &mut self,
        rate_limiters: &RateLimiters,
        profile: Option<&str>,
        scope: TransportScope,
        ctx: &RateLimitContext,
        cost: u64,
    ) -> Result<Option<Duration>> {
        if let Some(profile) = profile {
            let profile_limits = rate_limiters.collect_profile(Some(profile), scope)?;
            let retry_after = profile_limits.try_acquire_request(ctx, cost);
            self.extend_from(&profile_limits);
            Ok(retry_after)
        } else {
            Ok(self.try_acquire_request(ctx, cost))
        }
    }
}

impl RateLimitSet {
    fn parse_key_kind(raw: &str) -> KeyKind {
        match raw.trim().to_ascii_lowercase().as_str() {
            "global" => KeyKind::Global,
            "user" => KeyKind::User,
            "group" => KeyKind::Group,
            "tenant" => KeyKind::Tenant,
            "device" => KeyKind::Device,
            "route" => KeyKind::Route,
            "upstream" => KeyKind::Upstream,
            _ => KeyKind::SrcIp,
        }
    }

    pub(crate) fn from_config(cfg: Option<&RateLimitConfig>) -> Self {
        let Some(cfg) = cfg.filter(|c| c.enabled) else {
            return Self::default();
        };
        let key_kind = Self::parse_key_kind(cfg.key.as_str());
        let requests = cfg
            .requests
            .as_ref()
            .and_then(|requests| requests.rps)
            .map(|rps| {
                let burst = cfg
                    .requests
                    .as_ref()
                    .and_then(|requests| requests.burst)
                    .unwrap_or(rps)
                    .max(1) as f64;
                Arc::new(RateLimiter::new(key_kind, burst, rps.max(1) as f64))
            });
        let bytes = cfg
            .traffic
            .as_ref()
            .and_then(|traffic| traffic.bytes_per_sec)
            .map(|bps| {
                let burst = cfg
                    .traffic
                    .as_ref()
                    .and_then(|traffic| traffic.burst_bytes)
                    .unwrap_or(bps)
                    .max(1) as f64;
                Arc::new(RateLimiter::new(key_kind, burst, bps.max(1) as f64))
            });
        let concurrency = cfg
            .sessions
            .as_ref()
            .and_then(|sessions| sessions.max_concurrency)
            .map(|max| Arc::new(ConcurrencyLimiter::new(key_kind, max as usize)));
        let request_quota = cfg
            .requests
            .as_ref()
            .and_then(|requests| requests.quota.as_ref())
            .map(|quota| {
                Arc::new(QuotaLimiter::new(
                    key_kind,
                    Duration::from_secs(quota.interval_secs.max(1)),
                    quota.amount,
                    None,
                ))
            });
        let byte_quota = cfg
            .traffic
            .as_ref()
            .and_then(|traffic| traffic.quota_bytes.as_ref())
            .map(|quota| {
                Arc::new(QuotaLimiter::new(
                    key_kind,
                    Duration::from_secs(quota.interval_secs.max(1)),
                    None,
                    quota.amount,
                ))
            });
        let session_quota = cfg
            .sessions
            .as_ref()
            .and_then(|sessions| sessions.quota_sessions.as_ref())
            .map(|quota| {
                Arc::new(QuotaLimiter::new(
                    key_kind,
                    Duration::from_secs(quota.interval_secs.max(1)),
                    quota.amount,
                    None,
                ))
            });
        Self {
            apply_to: Arc::from(parse_transport_scopes(cfg.apply_to.as_slice())),
            requests,
            bytes,
            concurrency,
            request_quota,
            byte_quota,
            session_quota,
        }
    }

    fn applies_to(&self, scope: TransportScope) -> bool {
        self.apply_to.contains(&scope)
    }
}

fn parse_transport_scopes(scopes: &[RateLimitApplyTo]) -> Vec<TransportScope> {
    let mut out = Vec::new();
    for scope in scopes {
        let parsed = match scope {
            RateLimitApplyTo::Request => TransportScope::Request,
            RateLimitApplyTo::Connect => TransportScope::Connect,
            RateLimitApplyTo::Udp => TransportScope::Udp,
            RateLimitApplyTo::Http3Datagram => TransportScope::Http3Datagram,
            RateLimitApplyTo::Webtransport => TransportScope::Webtransport,
            RateLimitApplyTo::WebtransportBidi => TransportScope::WebtransportBidi,
            RateLimitApplyTo::WebtransportBidiDownstream => {
                TransportScope::WebtransportBidiDownstream
            }
            RateLimitApplyTo::WebtransportBidiUpstream => TransportScope::WebtransportBidiUpstream,
            RateLimitApplyTo::WebtransportUni => TransportScope::WebtransportUni,
            RateLimitApplyTo::WebtransportUniDownstream => {
                TransportScope::WebtransportUniDownstream
            }
            RateLimitApplyTo::WebtransportUniUpstream => TransportScope::WebtransportUniUpstream,
            RateLimitApplyTo::WebtransportDatagram => TransportScope::WebtransportDatagram,
            RateLimitApplyTo::WebtransportDatagramDownstream => {
                TransportScope::WebtransportDatagramDownstream
            }
            RateLimitApplyTo::WebtransportDatagramUpstream => {
                TransportScope::WebtransportDatagramUpstream
            }
        };
        if !out.contains(&parsed) {
            out.push(parsed);
        }
    }
    if out.is_empty() {
        out.push(TransportScope::Request);
    }
    out
}

fn normalized_groups_key(groups: &[String]) -> Option<String> {
    if groups.is_empty() {
        return None;
    }
    let mut groups = groups
        .iter()
        .map(|group| group.trim())
        .filter(|group| !group.is_empty())
        .collect::<Vec<_>>();
    if groups.is_empty() {
        return None;
    }
    groups.sort_unstable();
    groups.dedup();
    Some(groups.join(","))
}

fn text_key(value: Option<&str>, missing: &str) -> Arc<str> {
    Arc::<str>::from(
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(missing),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::{ActionConfig, ActionKind, ListenerMode};

    #[test]
    fn collect_profile_rejects_unknown_profile_name() {
        let listener = ListenerConfig {
            name: "forward".to_string(),
            mode: ListenerMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        };
        let profile = RateLimitProfileConfig {
            name: "known".to_string(),
            limit: RateLimitConfig {
                enabled: true,
                apply_to: vec![RateLimitApplyTo::Request],
                key: "user".to_string(),
                requests: Some(qpx_core::config::RateLimitRequestsConfig {
                    rps: Some(10),
                    burst: Some(10),
                    quota: None,
                }),
                traffic: None,
                sessions: None,
            },
        };
        let limiters = RateLimiters::from_config(&[listener], &[profile]);

        assert!(limiters
            .collect_profile(Some("missing"), TransportScope::Request)
            .is_err());
        assert!(limiters
            .collect_profile(Some("known"), TransportScope::Request)
            .is_ok());
        assert!(limiters
            .collect_profile(None, TransportScope::Request)
            .expect("no profile")
            .is_empty());
    }

    #[test]
    fn reserve_bytes_enforces_quota() {
        let limits = AppliedRateLimits {
            byte_quota_limiters: vec![Arc::new(QuotaLimiter::new(
                KeyKind::User,
                Duration::from_secs(60),
                None,
                Some(8),
            ))],
            ..Default::default()
        };
        let ctx = RateLimitContext {
            user: Some("alice".to_string()),
            ..Default::default()
        };

        assert_eq!(limits.reserve_bytes(&ctx, 4), Ok(Duration::ZERO));
        assert_eq!(limits.reserve_bytes(&ctx, 5), Err(()));
    }
}
