// Extracted from rate_limit.rs; public surface is re-exported by mod.rs.
use super::bucket::RateLimiter;
use super::concurrency::{ConcurrencyLimiter, ConcurrencyPermit};
use super::key::{KeyKind, RateLimitContext};
use super::quota::QuotaLimiter;
use anyhow::{Result, anyhow};
use qpx_core::config::{
    IngressEdgeConfig, RateLimitApplyTo, RateLimitConfig, RateLimitProfileConfig,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

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
pub(crate) struct CompiledRateLimitPlan {
    pub(crate) base: RateLimitSet,
    pub(crate) selected: RateLimitSet,
}

impl CompiledRateLimitPlan {
    pub(crate) fn from_sets(base: RateLimitSet, selected: RateLimitSet) -> Self {
        Self { base, selected }
    }

    pub(crate) fn collect(&self, scope: TransportScope) -> AppliedRateLimits {
        let mut out = AppliedRateLimits::default();
        out.extend_set(&self.base, scope);
        out.extend_set(&self.selected, scope);
        out
    }

    #[cfg(test)]
    pub(crate) fn is_empty_for_scope(&self, scope: TransportScope) -> bool {
        self.collect(scope).is_empty()
    }
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
    profiles: HashMap<String, RateLimitSet>,
}

impl RateLimiters {
    pub(crate) fn from_config<'a>(
        _listeners: impl IntoIterator<Item = &'a IngressEdgeConfig>,
        profiles: &[RateLimitProfileConfig],
    ) -> Self {
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

    pub(crate) fn collect_checked_plan_request(
        &self,
        plan: &CompiledRateLimitPlan,
        profile: Option<&str>,
        scope: TransportScope,
        ctx: &RateLimitContext,
        cost: u64,
    ) -> Result<RequestLimitAcquire> {
        let mut limits = plan.collect(scope);
        let retry_after = limits.merge_profile_and_check(self, profile, scope, ctx, cost)?;
        Ok(RequestLimitAcquire {
            limits,
            retry_after,
        })
    }

    #[cfg(feature = "http3")]
    pub(crate) fn collect_plan_with_profile(
        &self,
        plan: &CompiledRateLimitPlan,
        profile: Option<&str>,
        scope: TransportScope,
    ) -> Result<AppliedRateLimits> {
        let mut limits = plan.collect(scope);
        limits.extend_from(&self.collect_profile(profile, scope)?);
        Ok(limits)
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
