#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use super::TlsPassthroughRoute;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use super::compile::compile_upstream_pool;
use super::compile::refresh_dynamic_upstreams;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use super::selection::select_upstream_inner;
use super::selection::{
    cookie_affinity_seed, feed, feed_ip, fnv_offset, header_affinity_seed, query_affinity_seed,
};
use super::{
    CompiledPathRewrite, CompiledRegexPathRewrite, DynamicDiscovery, LoadBalanceStrategy,
    RetryBudgetRuntime, ReverseAffinityKey, ReverseAffinityRuntime, RoutePolicy, UpstreamPool,
};
use crate::http::body::Body;
use crate::reverse::health::{
    EndpointLifecycleRuntime, HealthCheckRuntime, PassiveHealthRuntime, UpstreamEndpoint,
    now_millis,
};
use crate::upstream::origin::OriginEndpoint;
use anyhow::Result;
use arc_swap::ArcSwap;
use hyper::Request;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use qpx_core::config::ReverseTlsPassthroughRouteConfig;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use qpx_core::config::UpstreamConfig;
use qpx_core::config::{PathRewriteConfig, ReverseRouteConfig};
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use qpx_core::prefilter::StringInterner;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use qpx_core::rules::RuleMatchContext;
use regex::Regex;
use std::collections::{HashMap, HashSet};
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use std::net::IpAddr;
use std::sync::Arc;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use tokio::sync::watch;
use tokio::time::Duration;
use tracing::warn;

mod http_route;

impl RetryBudgetRuntime {
    pub(in crate::reverse) fn new(retry_attempts: usize) -> Arc<Self> {
        let burst = retry_attempts.saturating_sub(1).max(1) as isize;
        Arc::new(Self {
            balance: AtomicIsize::new(burst),
            max_balance: burst.saturating_mul(8),
        })
    }

    pub(in crate::reverse) fn try_consume_retry(&self) -> bool {
        self.balance
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current > 0).then_some(current - 1)
            })
            .is_ok()
    }

    pub(in crate::reverse) fn record_success(&self) {
        let _ = self
            .balance
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some((current + 1).min(self.max_balance))
            });
    }
}

impl CompiledPathRewrite {
    pub(in crate::reverse) fn compile(raw: &PathRewriteConfig) -> Result<Self> {
        let regex = raw
            .regex
            .as_ref()
            .map(|r| -> Result<CompiledRegexPathRewrite> {
                Ok(CompiledRegexPathRewrite {
                    pattern: Regex::new(r.pattern.as_str())?,
                    replace: r.replace.clone(),
                })
            })
            .transpose()?;
        Ok(Self {
            strip_prefix: raw.strip_prefix.clone(),
            add_prefix: raw.add_prefix.clone(),
            regex,
        })
    }
}

impl ReverseAffinityRuntime {
    pub(in crate::reverse) fn from_config(
        config: Option<&qpx_core::config::ReverseAffinityConfig>,
    ) -> Result<Self> {
        let key = match config.map(|cfg| cfg.key.trim().to_ascii_lowercase()) {
            None => ReverseAffinityKey::SrcIp,
            Some(key) if key == "src_ip" => ReverseAffinityKey::SrcIp,
            Some(key) if key == "host" => ReverseAffinityKey::Host,
            Some(key) if key == "header" => ReverseAffinityKey::Header(Arc::<str>::from(
                config
                    .and_then(|cfg| cfg.header.as_deref())
                    .unwrap_or_default()
                    .trim(),
            )),
            Some(key) if key == "cookie" => ReverseAffinityKey::Cookie(Arc::<str>::from(
                config
                    .and_then(|cfg| cfg.cookie.as_deref())
                    .unwrap_or_default()
                    .trim(),
            )),
            Some(key) if key == "user" => ReverseAffinityKey::User,
            Some(key) if key == "tenant" => ReverseAffinityKey::Tenant,
            Some(key) if key == "query" => ReverseAffinityKey::Query(Arc::<str>::from(
                config
                    .and_then(|cfg| cfg.query.as_deref())
                    .unwrap_or_default()
                    .trim(),
            )),
            Some(other) => {
                return Err(anyhow::anyhow!("unknown reverse affinity key: {}", other));
            }
        };
        Ok(Self { key })
    }

    pub(in crate::reverse) fn seed_http(
        &self,
        conn: &crate::reverse::transport::ReverseConnInfo,
        host: &str,
        req: &Request<Body>,
        identity: &crate::policy_context::ResolvedIdentity,
    ) -> u64 {
        let mut hash = fnv_offset();
        match &self.key {
            ReverseAffinityKey::SrcIp => {
                hash = feed_ip(hash, conn.remote_addr.ip());
                feed(hash, host.as_bytes())
            }
            ReverseAffinityKey::Host => feed(hash, host.as_bytes()),
            ReverseAffinityKey::Header(name) => {
                header_affinity_seed(hash, req, name.as_ref(), host)
            }
            ReverseAffinityKey::Cookie(name) => {
                cookie_affinity_seed(hash, req, name.as_ref(), host)
            }
            ReverseAffinityKey::User => {
                feed(hash, identity.user.as_deref().unwrap_or(host).as_bytes())
            }
            ReverseAffinityKey::Tenant => {
                feed(hash, identity.tenant.as_deref().unwrap_or(host).as_bytes())
            }
            ReverseAffinityKey::Query(name) => query_affinity_seed(hash, req, name.as_ref(), host),
        }
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(in crate::reverse) fn seed_tls_passthrough(
        &self,
        remote_ip: IpAddr,
        sni: Option<&str>,
    ) -> u64 {
        let host = sni.unwrap_or("");
        let mut hash = fnv_offset();
        match &self.key {
            ReverseAffinityKey::Host => feed(hash, host.as_bytes()),
            _ => {
                hash = feed_ip(hash, remote_ip);
                feed(hash, host.as_bytes())
            }
        }
    }
}

impl UpstreamPool {
    pub(in crate::reverse) fn new(
        static_endpoints: Vec<Arc<UpstreamEndpoint>>,
        seed_endpoints: Vec<Arc<UpstreamEndpoint>>,
        discovery: Vec<DynamicDiscovery>,
        lifecycle: EndpointLifecycleRuntime,
    ) -> Arc<Self> {
        Arc::new(Self {
            static_endpoints: Arc::new(static_endpoints),
            endpoints: ArcSwap::from_pointee(seed_endpoints),
            discovery,
            lifecycle,
            discovery_started: AtomicBool::new(false),
        })
    }

    pub(in crate::reverse) fn endpoints(&self) -> Arc<Vec<Arc<UpstreamEndpoint>>> {
        self.endpoints.load_full()
    }

    pub(in crate::reverse) fn spawn_discovery(self: &Arc<Self>, mut shutdown: watch::Receiver<()>) {
        if self.discovery.is_empty() || self.discovery_started.swap(true, Ordering::Relaxed) {
            return;
        }
        let pool = self.clone();
        tokio::spawn(async move {
            let mut delay = Duration::ZERO;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    res = shutdown.changed() => {
                        if res.is_err() {
                            break;
                        }
                        continue;
                    }
                }
                match refresh_dynamic_upstreams(&pool.discovery).await {
                    Ok((resolved, next_delay)) => {
                        let combined = pool.reconcile_dynamic_endpoints(resolved);
                        pool.endpoints.store(Arc::new(combined));
                        delay = next_delay;
                    }
                    Err(err) => {
                        warn!(error = ?err, "reverse dynamic upstream discovery failed");
                        delay = pool
                            .discovery
                            .iter()
                            .map(|entry| Duration::from_millis(entry.config.interval_ms))
                            .min()
                            .unwrap_or_else(|| Duration::from_secs(30));
                    }
                }
            }
        });
    }

    pub(in crate::reverse) fn reconcile_dynamic_endpoints(
        &self,
        resolved: Vec<OriginEndpoint>,
    ) -> Vec<Arc<UpstreamEndpoint>> {
        let now_ms = now_millis();
        let static_labels = self
            .static_endpoints
            .iter()
            .map(|endpoint| endpoint.target.clone())
            .collect::<HashSet<_>>();
        let mut reusable = self
            .endpoints()
            .iter()
            .filter(|endpoint| !static_labels.contains(endpoint.target.as_str()))
            .map(|endpoint| (endpoint.target.clone(), endpoint.clone()))
            .collect::<HashMap<_, _>>();
        let mut combined = self.static_endpoints.as_ref().clone();
        for origin in resolved {
            let label = origin.label();
            if let Some(endpoint) = reusable.remove(label.as_str()) {
                endpoint.reactivate(&self.lifecycle);
                combined.push(endpoint);
            } else {
                let endpoint = Arc::new(UpstreamEndpoint::from_origin(origin));
                endpoint.begin_recovery_window(&self.lifecycle);
                combined.push(endpoint);
            }
        }
        for endpoint in reusable.into_values() {
            if endpoint.mark_draining(&self.lifecycle) && endpoint.should_retain_draining(now_ms) {
                combined.push(endpoint);
            }
        }
        combined
    }
}

#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
impl TlsPassthroughRoute {
    pub(in crate::reverse) fn from_config(
        config: ReverseTlsPassthroughRouteConfig,
        upstreams: &HashMap<&str, &UpstreamConfig>,
        interner: &mut StringInterner,
        compiled_route: &crate::runtime::CompiledTlsPassthroughRoute,
    ) -> Result<(Self, qpx_core::prefilter::MatchPrefilterHint)> {
        let _ = interner;
        let matcher = compiled_route.matcher.clone();
        let hint = compiled_route.hint.clone();
        let policy = RoutePolicy::from_tls_config(&config)?;
        let affinity = ReverseAffinityRuntime::from_config(config.affinity.as_ref())?;
        let upstreams =
            compile_upstream_pool(config.upstreams, upstreams, true, &policy.lifecycle)?;
        Ok((
            Self {
                matcher,
                upstreams,
                affinity,
                policy,
                rr_counter: AtomicUsize::new(0),
            },
            hint,
        ))
    }

    pub(in crate::reverse) fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }

    pub(in crate::reverse) fn select_upstream(
        &self,
        request_seed: u64,
        sticky_seed: u64,
    ) -> Option<Arc<UpstreamEndpoint>> {
        let endpoints = self.upstreams.endpoints();
        select_upstream_inner(
            endpoints.as_slice(),
            &self.policy,
            &self.rr_counter,
            request_seed,
            sticky_seed,
        )
    }

    pub(super) fn health_upstream_pools(&self) -> Vec<Arc<UpstreamPool>> {
        vec![self.upstreams.clone()]
    }
}

impl RoutePolicy {
    pub(in crate::reverse) fn from_http_config(config: &ReverseRouteConfig) -> Result<Self> {
        let (retry_attempts, retry_backoff_ms, retry_body_threshold_bytes) = config
            .resilience
            .as_ref()
            .map(resilience_retry_runtime)
            .unwrap_or((1, 0, 64 * 1024));
        let passive_health = config.resilience.as_ref().map(resilience_to_passive_health);
        let max_upstream_concurrency = config
            .resilience
            .as_ref()
            .and_then(|resilience| resilience.max_upstream_concurrency);
        Self::from_parts(RoutePolicyParts {
            lb: config.target.lb().unwrap_or("round_robin"),
            retry_attempts,
            retry_backoff_ms,
            retry_body_threshold_bytes,
            timeout_ms: config.timeout_ms,
            health_check: config.health_check.as_ref(),
            passive_health,
            lifecycle: config.lifecycle.as_ref(),
            max_upstream_concurrency,
        })
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(in crate::reverse) fn from_tls_config(
        config: &ReverseTlsPassthroughRouteConfig,
    ) -> Result<Self> {
        let (retry_attempts, retry_backoff_ms, retry_body_threshold_bytes) = config
            .resilience
            .as_ref()
            .map(resilience_retry_runtime)
            .unwrap_or((1, 0, 64 * 1024));
        let passive_health = config.resilience.as_ref().map(resilience_to_passive_health);
        let max_upstream_concurrency = config
            .resilience
            .as_ref()
            .and_then(|resilience| resilience.max_upstream_concurrency);
        Self::from_parts(RoutePolicyParts {
            lb: config.lb.as_str(),
            retry_attempts,
            retry_backoff_ms,
            retry_body_threshold_bytes,
            timeout_ms: config.timeout_ms,
            health_check: config.health_check.as_ref(),
            passive_health,
            lifecycle: config.lifecycle.as_ref(),
            max_upstream_concurrency,
        })
    }

    fn from_parts(parts: RoutePolicyParts<'_>) -> Result<Self> {
        let lb_lower = parts.lb.trim().to_ascii_lowercase();
        let lb = match lb_lower.as_str() {
            "round_robin" | "roundrobin" => LoadBalanceStrategy::RoundRobin,
            "random" => LoadBalanceStrategy::Random,
            "least_conn" | "least_connections" => LoadBalanceStrategy::LeastConnections,
            "consistent_hash" | "consistent-hash" => LoadBalanceStrategy::ConsistentHash,
            "sticky" | "sticky_ip" | "sticky-src-ip" => LoadBalanceStrategy::Sticky,
            other => return Err(anyhow::anyhow!("unknown lb strategy: {}", other)),
        };
        if parts.retry_attempts == 0 {
            return Err(anyhow::anyhow!("retry.attempts must be >= 1"));
        }
        let health = HealthCheckRuntime::from_config(parts.health_check);
        Ok(Self {
            lb,
            retry_attempts: parts.retry_attempts,
            retry_backoff: Duration::from_millis(parts.retry_backoff_ms),
            retry_body_threshold_bytes: parts.retry_body_threshold_bytes,
            retry_budget: RetryBudgetRuntime::new(parts.retry_attempts),
            timeout: Duration::from_millis(parts.timeout_ms.unwrap_or(30_000)),
            passive_health: parts.passive_health,
            lifecycle: EndpointLifecycleRuntime::from_config(parts.lifecycle),
            max_upstream_concurrency: parts.max_upstream_concurrency,
            health,
        })
    }
}

struct RoutePolicyParts<'a> {
    lb: &'a str,
    retry_attempts: usize,
    retry_backoff_ms: u64,
    retry_body_threshold_bytes: usize,
    timeout_ms: Option<u64>,
    health_check: Option<&'a qpx_core::config::HealthCheckConfig>,
    passive_health: Option<PassiveHealthRuntime>,
    lifecycle: Option<&'a qpx_core::config::EndpointLifecycleConfig>,
    max_upstream_concurrency: Option<usize>,
}

fn resilience_to_passive_health(
    resilience: &qpx_core::config::ResilienceConfig,
) -> PassiveHealthRuntime {
    let consecutive = resilience
        .outlier_detection
        .as_ref()
        .and_then(|cfg| cfg.consecutive_failures.as_ref());
    let latency = resilience
        .outlier_detection
        .as_ref()
        .and_then(|cfg| cfg.latency.as_ref());
    let ejection = resilience.ejection.as_ref();
    PassiveHealthRuntime {
        consecutive_5xx: consecutive.and_then(|cfg| cfg.http_5xx).unwrap_or_default(),
        consecutive_timeouts: consecutive.and_then(|cfg| cfg.timeouts).unwrap_or_default(),
        consecutive_connect_errors: consecutive
            .and_then(|cfg| cfg.connect_errors)
            .unwrap_or_default(),
        consecutive_resets: consecutive.and_then(|cfg| cfg.resets).unwrap_or_default(),
        max_ejection: Duration::from_millis(
            ejection
                .and_then(|cfg| cfg.max_ms.or(cfg.base_ms))
                .unwrap_or(30_000)
                .max(1),
        ),
        latency_threshold: latency
            .and_then(|cfg| cfg.p95_ms)
            .map(|threshold| Duration::from_millis(threshold.max(1))),
    }
}

fn resilience_retry_runtime(
    resilience: &qpx_core::config::ResilienceConfig,
) -> (usize, u64, usize) {
    resilience
        .retry
        .as_ref()
        .map(|retry| {
            (
                retry.attempts,
                retry.backoff_ms,
                retry.retry_body_threshold_bytes,
            )
        })
        .unwrap_or((1, 0, 64 * 1024))
}

pub(in crate::reverse) fn normalize_host_for_match(raw: &str) -> String {
    if let Ok(authority) = raw.parse::<http::uri::Authority>() {
        return authority.host().to_ascii_lowercase();
    }
    raw.to_ascii_lowercase()
}
