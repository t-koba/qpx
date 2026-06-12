use super::ConnectionPool;
use super::resolved::{EndpointConcurrencyPermit, ResolvedUpstreamProxy};
use crate::runtime::now_millis;
use crate::upstream::http1::{UpstreamProxyEndpoint, parse_upstream_proxy_endpoint};
use crate::upstream::origin::discover_origin_endpoints;
use anyhow::{Result, anyhow};
use arc_swap::ArcSwap;
use qpx_core::config::{ResilienceConfig, UpstreamConfig};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use tokio::time::Duration;
use tracing::warn;

const ADAPTIVE_MIN_SAMPLES: u32 = 8;
const ADAPTIVE_MAX_SAMPLES: u32 = 32;
const ADAPTIVE_FAILURE_RATE_NUM: u32 = 1;
const ADAPTIVE_FAILURE_RATE_DEN: u32 = 2;
const ADAPTIVE_LATENCY_MULTIPLIER: u64 = 2;
const ADAPTIVE_MAX_BACKOFF_SHIFT: u32 = 5;

#[derive(Debug, Clone)]
pub(super) struct PassiveHealthPolicy {
    pub(super) consecutive_5xx: u32,
    pub(super) consecutive_timeouts: u32,
    pub(super) consecutive_connect_errors: u32,
    pub(super) consecutive_resets: u32,
    pub(super) max_ejection: Duration,
    pub(super) latency_threshold: Option<Duration>,
}

impl PassiveHealthPolicy {
    fn from_resilience(config: Option<&ResilienceConfig>) -> Option<Self> {
        let cfg = config?;
        let consecutive = cfg
            .outlier_detection
            .as_ref()
            .and_then(|policy| policy.consecutive_failures.as_ref());
        let latency = cfg
            .outlier_detection
            .as_ref()
            .and_then(|policy| policy.latency.as_ref());
        let ejection = cfg.ejection.as_ref();
        let derived = Self {
            consecutive_5xx: consecutive
                .and_then(|policy| policy.http_5xx)
                .unwrap_or_default(),
            consecutive_timeouts: consecutive
                .and_then(|policy| policy.timeouts)
                .unwrap_or_default(),
            consecutive_connect_errors: consecutive
                .and_then(|policy| policy.connect_errors)
                .unwrap_or_default(),
            consecutive_resets: consecutive
                .and_then(|policy| policy.resets)
                .unwrap_or_default(),
            max_ejection: Duration::from_millis(
                ejection
                    .and_then(|policy| policy.max_ms.or(policy.base_ms))
                    .unwrap_or(30_000)
                    .max(1),
            ),
            latency_threshold: latency
                .and_then(|policy| policy.p95_ms)
                .map(|threshold| Duration::from_millis(threshold.max(1))),
        };
        if derived.consecutive_5xx == 0
            && derived.consecutive_timeouts == 0
            && derived.consecutive_connect_errors == 0
            && derived.consecutive_resets == 0
            && derived.latency_threshold.is_none()
        {
            return None;
        }
        Some(derived)
    }
}

#[derive(Debug, Clone)]
pub(super) struct DynamicDiscovery {
    base_upstream: Arc<str>,
    config: qpx_core::config::UpstreamDiscoveryConfig,
}

#[derive(Debug)]
pub(super) struct ManagedUpstreamEndpoint {
    pub(super) endpoint: UpstreamProxyEndpoint,
    unhealthy_until_ms: AtomicU64,
    passive_5xx: AtomicU32,
    passive_timeouts: AtomicU32,
    passive_connect_errors: AtomicU32,
    passive_resets: AtomicU32,
    adaptive_successes: AtomicU32,
    adaptive_failures: AtomicU32,
    adaptive_latency_total_ms: AtomicU64,
    adaptive_latency_samples: AtomicU32,
    ejection_backoff_shift: AtomicU32,
    pub(super) inflight: AtomicUsize,
}

impl ManagedUpstreamEndpoint {
    pub(super) fn new(endpoint: UpstreamProxyEndpoint) -> Self {
        Self {
            endpoint,
            unhealthy_until_ms: AtomicU64::new(0),
            passive_5xx: AtomicU32::new(0),
            passive_timeouts: AtomicU32::new(0),
            passive_connect_errors: AtomicU32::new(0),
            passive_resets: AtomicU32::new(0),
            adaptive_successes: AtomicU32::new(0),
            adaptive_failures: AtomicU32::new(0),
            adaptive_latency_total_ms: AtomicU64::new(0),
            adaptive_latency_samples: AtomicU32::new(0),
            ejection_backoff_shift: AtomicU32::new(0),
            inflight: AtomicUsize::new(0),
        }
    }

    pub(super) fn is_healthy(&self, now_ms: u64) -> bool {
        self.unhealthy_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    fn is_half_open(&self, now_ms: u64) -> bool {
        let unhealthy_until = self.unhealthy_until_ms.load(Ordering::Relaxed);
        unhealthy_until != 0 && unhealthy_until <= now_ms
    }

    pub(super) fn mark_passive_success(&self) {
        let recovered = self.unhealthy_until_ms.swap(0, Ordering::Relaxed) != 0;
        self.reset_passive_counters();
        self.note_adaptive_success();
        if recovered {
            super::metrics::probe_success();
        }
    }

    pub(super) fn mark_passive_failure(
        &self,
        policy: Option<&PassiveHealthPolicy>,
        kind: PassiveFailureKind,
    ) {
        let Some(policy) = policy else {
            return;
        };
        let threshold = match kind {
            PassiveFailureKind::Http5xx => policy.consecutive_5xx,
            PassiveFailureKind::Timeout => policy.consecutive_timeouts,
            PassiveFailureKind::ConnectError => policy.consecutive_connect_errors,
            PassiveFailureKind::Reset => policy.consecutive_resets,
        };
        if threshold == 0 {
            return;
        }
        self.reset_passive_counters_except(kind);
        let count = match kind {
            PassiveFailureKind::Http5xx => self.passive_5xx.fetch_add(1, Ordering::Relaxed),
            PassiveFailureKind::Timeout => self.passive_timeouts.fetch_add(1, Ordering::Relaxed),
            PassiveFailureKind::ConnectError => {
                self.passive_connect_errors.fetch_add(1, Ordering::Relaxed)
            }
            PassiveFailureKind::Reset => self.passive_resets.fetch_add(1, Ordering::Relaxed),
        }
        .saturating_add(1);
        let reason = passive_failure_reason(kind);
        self.note_adaptive_failure(policy.max_ejection);
        if count >= threshold {
            self.eject(policy.max_ejection, reason);
            self.reset_passive_counters();
        }
    }

    pub(super) fn mark_passive_latency(
        &self,
        policy: Option<&PassiveHealthPolicy>,
        elapsed: Duration,
    ) {
        let Some(policy) = policy else {
            return;
        };
        let Some(threshold) = policy.latency_threshold else {
            return;
        };
        self.note_adaptive_latency(policy.max_ejection, threshold, elapsed);
        if elapsed >= threshold {
            self.eject(policy.max_ejection, EjectionReason::Latency);
        }
    }

    fn eject(&self, duration: Duration, reason: EjectionReason) {
        let shift = self
            .ejection_backoff_shift
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some((current + 1).min(ADAPTIVE_MAX_BACKOFF_SHIFT))
            })
            .unwrap_or(0)
            .min(ADAPTIVE_MAX_BACKOFF_SHIFT);
        let scaled_ms = (duration.as_millis() as u64).saturating_mul(1u64 << shift);
        let until = now_millis().saturating_add(scaled_ms);
        self.unhealthy_until_ms.fetch_max(until, Ordering::Relaxed);
        self.reset_adaptive_stats();
        super::metrics::ejection(reason.as_label());
    }

    fn reset_passive_counters(&self) {
        self.passive_5xx.store(0, Ordering::Relaxed);
        self.passive_timeouts.store(0, Ordering::Relaxed);
        self.passive_connect_errors.store(0, Ordering::Relaxed);
        self.passive_resets.store(0, Ordering::Relaxed);
    }

    fn reset_passive_counters_except(&self, keep: PassiveFailureKind) {
        if keep != PassiveFailureKind::Http5xx {
            self.passive_5xx.store(0, Ordering::Relaxed);
        }
        if keep != PassiveFailureKind::Timeout {
            self.passive_timeouts.store(0, Ordering::Relaxed);
        }
        if keep != PassiveFailureKind::ConnectError {
            self.passive_connect_errors.store(0, Ordering::Relaxed);
        }
        if keep != PassiveFailureKind::Reset {
            self.passive_resets.store(0, Ordering::Relaxed);
        }
    }

    fn note_adaptive_success(&self) {
        self.adaptive_successes.fetch_add(1, Ordering::Relaxed);
        self.ejection_backoff_shift.store(0, Ordering::Relaxed);
        self.maybe_trim_adaptive_window();
    }

    fn note_adaptive_failure(&self, max_ejection: Duration) {
        let failures = self
            .adaptive_failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let successes = self.adaptive_successes.load(Ordering::Relaxed);
        let total = successes.saturating_add(failures);
        if total >= ADAPTIVE_MIN_SAMPLES
            && failures.saturating_mul(ADAPTIVE_FAILURE_RATE_DEN)
                >= total.saturating_mul(ADAPTIVE_FAILURE_RATE_NUM)
        {
            self.eject(max_ejection, EjectionReason::SuccessRate);
            return;
        }
        self.maybe_trim_adaptive_window();
    }

    fn note_adaptive_latency(
        &self,
        max_ejection: Duration,
        threshold: Duration,
        elapsed: Duration,
    ) {
        let sample = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        let samples = self
            .adaptive_latency_samples
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.adaptive_latency_total_ms
            .fetch_add(sample, Ordering::Relaxed);
        if samples < ADAPTIVE_MIN_SAMPLES {
            self.maybe_trim_adaptive_window();
            return;
        }
        let total_ms = self.adaptive_latency_total_ms.load(Ordering::Relaxed);
        let avg_ms = total_ms / u64::from(samples.max(1));
        let threshold_ms = threshold.as_millis().min(u128::from(u64::MAX)) as u64;
        if avg_ms >= threshold_ms.saturating_mul(ADAPTIVE_LATENCY_MULTIPLIER) {
            self.eject(max_ejection, EjectionReason::Latency);
        } else {
            self.maybe_trim_adaptive_window();
        }
    }

    fn maybe_trim_adaptive_window(&self) {
        let successes = self.adaptive_successes.load(Ordering::Relaxed);
        let failures = self.adaptive_failures.load(Ordering::Relaxed);
        if successes.saturating_add(failures) <= ADAPTIVE_MAX_SAMPLES {
            return;
        }
        self.adaptive_successes
            .store(successes / 2, Ordering::Relaxed);
        self.adaptive_failures
            .store(failures / 2, Ordering::Relaxed);
        self.adaptive_latency_samples
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current / 2)
            })
            .ok();
        self.adaptive_latency_total_ms
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current / 2)
            })
            .ok();
    }

    fn reset_adaptive_stats(&self) {
        self.adaptive_successes.store(0, Ordering::Relaxed);
        self.adaptive_failures.store(0, Ordering::Relaxed);
        self.adaptive_latency_total_ms.store(0, Ordering::Relaxed);
        self.adaptive_latency_samples.store(0, Ordering::Relaxed);
    }
}

fn passive_failure_reason(kind: PassiveFailureKind) -> EjectionReason {
    match kind {
        PassiveFailureKind::Http5xx => EjectionReason::Http5xx,
        PassiveFailureKind::Timeout => EjectionReason::Timeout,
        PassiveFailureKind::ConnectError => EjectionReason::ConnectError,
        PassiveFailureKind::Reset => EjectionReason::Reset,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PassiveFailureKind {
    Http5xx,
    Timeout,
    ConnectError,
    Reset,
}

#[derive(Debug, Clone, Copy)]
enum EjectionReason {
    Http5xx,
    Timeout,
    ConnectError,
    Reset,
    Latency,
    SuccessRate,
}

impl EjectionReason {
    fn as_label(self) -> &'static str {
        match self {
            Self::Http5xx => "http_5xx",
            Self::Timeout => "timeout",
            Self::ConnectError => "connect_error",
            Self::Reset => "reset",
            Self::Latency => "latency",
            Self::SuccessRate => "success_rate",
        }
    }
}

#[derive(Debug)]
pub(crate) struct UpstreamProxyCluster {
    pub(super) key: Arc<str>,
    pub(super) static_endpoints: Arc<Vec<Arc<ManagedUpstreamEndpoint>>>,
    pub(super) endpoints: ArcSwap<Vec<Arc<ManagedUpstreamEndpoint>>>,
    pub(super) discovery: Option<DynamicDiscovery>,
    pub(super) trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    pub(super) discovery_started: AtomicBool,
    pub(super) passive_health: Option<PassiveHealthPolicy>,
    pub(super) max_concurrency: Option<usize>,
    pub(super) rr_counter: AtomicUsize,
}

impl UpstreamProxyCluster {
    pub(super) fn from_config(cfg: &UpstreamConfig) -> Result<Arc<Self>> {
        let seed_endpoint = Arc::new(ManagedUpstreamEndpoint::new(parse_upstream_proxy_endpoint(
            cfg.url.as_str(),
        )?));
        let static_endpoints = if cfg.discovery.is_some() {
            Vec::new()
        } else {
            vec![seed_endpoint.clone()]
        };
        let seed_endpoints = vec![seed_endpoint];
        Ok(Arc::new(Self {
            key: Arc::<str>::from(cfg.name.as_str()),
            static_endpoints: Arc::new(static_endpoints),
            endpoints: ArcSwap::from_pointee(seed_endpoints),
            discovery: cfg.discovery.as_ref().map(|config| DynamicDiscovery {
                base_upstream: Arc::<str>::from(cfg.url.as_str()),
                config: config.clone(),
            }),
            trust: CompiledUpstreamTlsTrust::from_config(cfg.tls_trust.as_ref())?,
            discovery_started: AtomicBool::new(false),
            passive_health: PassiveHealthPolicy::from_resilience(cfg.resilience.as_ref()),
            max_concurrency: cfg
                .resilience
                .as_ref()
                .and_then(|resilience| resilience.max_upstream_concurrency)
                .map(|value| value.max(1)),
            rr_counter: AtomicUsize::new(0),
        }))
    }

    pub(crate) fn select(self: &Arc<Self>) -> Result<ResolvedUpstreamProxy> {
        self.spawn_discovery();
        let endpoints = self.endpoints.load_full();
        let now_ms = now_millis();
        let candidates = endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.is_healthy(now_ms)
                    && (!endpoint.is_half_open(now_ms)
                        || endpoint.inflight.load(Ordering::Relaxed) == 0)
                    && self
                        .max_concurrency
                        .is_none_or(|max| endpoint.inflight.load(Ordering::Relaxed) < max)
            })
            .cloned()
            .collect::<Vec<_>>();
        let endpoint = if candidates.is_empty() {
            return Err(anyhow!(
                "no healthy upstream proxy endpoints available for {}",
                self.key
            ));
        } else {
            let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
            candidates[idx].clone()
        };
        let permit = self.max_concurrency.map(|_| EndpointConcurrencyPermit {
            endpoint: endpoint.clone(),
        });
        if permit.is_some() {
            endpoint.inflight.fetch_add(1, Ordering::Relaxed);
        }
        Ok(ResolvedUpstreamProxy {
            key: self.key.clone(),
            endpoint,
            trust: self.trust.clone(),
            passive_health: self.passive_health.clone(),
            _permit: permit,
        })
    }

    fn spawn_discovery(self: &Arc<Self>) {
        let Some(discovery) = self.discovery.clone() else {
            return;
        };
        if self.discovery_started.swap(true, Ordering::Relaxed) {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut delay = Duration::ZERO;
            loop {
                tokio::time::sleep(delay).await;
                let Some(cluster) = weak.upgrade() else {
                    break;
                };
                match refresh_dynamic_endpoints(&discovery).await {
                    Ok((resolved, next_delay)) => {
                        if !resolved.is_empty() || !cluster.static_endpoints.is_empty() {
                            let combined = cluster.reconcile_dynamic_endpoints(resolved);
                            cluster.endpoints.store(Arc::new(combined));
                        }
                        delay = next_delay;
                    }
                    Err(err) => {
                        warn!(
                            error = ?err,
                            upstream = %cluster.key,
                            "forward dynamic upstream proxy discovery failed"
                        );
                        delay = Duration::from_millis(discovery.config.interval_ms.max(1));
                    }
                }
            }
        });
    }

    pub(super) fn reconcile_dynamic_endpoints(
        &self,
        resolved: Vec<UpstreamProxyEndpoint>,
    ) -> Vec<Arc<ManagedUpstreamEndpoint>> {
        let static_keys = self
            .static_endpoints
            .iter()
            .map(|endpoint| upstream_proxy_endpoint_identity(&endpoint.endpoint))
            .collect::<std::collections::HashSet<_>>();
        let mut reusable = self
            .endpoints
            .load_full()
            .iter()
            .filter(|endpoint| {
                !static_keys.contains(&upstream_proxy_endpoint_identity(&endpoint.endpoint))
            })
            .map(|endpoint| {
                (
                    upstream_proxy_endpoint_identity(&endpoint.endpoint),
                    endpoint.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut combined = self.static_endpoints.as_ref().clone();
        for endpoint in resolved {
            let key = upstream_proxy_endpoint_identity(&endpoint);
            if let Some(existing) = reusable.remove(&key) {
                combined.push(existing);
            } else {
                combined.push(Arc::new(ManagedUpstreamEndpoint::new(endpoint)));
            }
        }
        combined
    }
}

impl ConnectionPool<ResolvedUpstreamProxy> for Arc<UpstreamProxyCluster> {
    type Acquire = ();
    type Error = anyhow::Error;

    fn acquire_connection(&self, (): Self::Acquire) -> Result<ResolvedUpstreamProxy> {
        self.select()
    }
}

async fn refresh_dynamic_endpoints(
    discovery: &DynamicDiscovery,
) -> Result<(Vec<UpstreamProxyEndpoint>, Duration)> {
    let (origins, delay) =
        discover_origin_endpoints(discovery.base_upstream.as_ref(), &discovery.config).await?;
    let endpoints = origins
        .iter()
        .map(UpstreamProxyEndpoint::from_origin)
        .collect::<Result<Vec<_>>>()?;
    Ok((endpoints, delay))
}

fn upstream_proxy_endpoint_identity(endpoint: &UpstreamProxyEndpoint) -> String {
    let proxy_authorization = endpoint
        .proxy_authorization
        .as_ref()
        .map(|value| String::from_utf8_lossy(value.as_bytes()))
        .unwrap_or_default();
    format!(
        "{}|host={}|logical={}|auth={}",
        endpoint.cache_key(),
        endpoint.host,
        endpoint.logical_authority.as_deref().unwrap_or_default(),
        proxy_authorization
    )
}
