use crate::http::body::Body;
use crate::tls::CompiledUpstreamTlsTrust;
use crate::upstream::http1::{
    open_upstream_proxy_sender as open_proxy_sender_once, parse_upstream_proxy_endpoint,
    UpstreamProxyEndpoint, UpstreamProxyScheme,
};
use crate::upstream::origin::discover_origin_endpoints;
use crate::upstream::raw_http1::{send_http1_request_with_interim, Http1ResponseWithInterim};
use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use http::header::PROXY_AUTHORIZATION;
use hyper::{Request, Response, StatusCode};
use metrics::counter;
use qpx_core::config::{ResilienceConfig, UpstreamConfig};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{timeout, Duration, Instant};
use tracing::warn;
use url::Url;

type UpstreamProxySender = crate::http::common::Http1SendRequest;

static UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT: AtomicUsize = AtomicUsize::new(8);
const ADAPTIVE_MIN_SAMPLES: u32 = 8;
const ADAPTIVE_MAX_SAMPLES: u32 = 32;
const ADAPTIVE_FAILURE_RATE_NUM: u32 = 1;
const ADAPTIVE_FAILURE_RATE_DEN: u32 = 2;
const ADAPTIVE_LATENCY_MULTIPLIER: u64 = 2;
const ADAPTIVE_MAX_BACKOFF_SHIFT: u32 = 5;

pub(crate) fn set_upstream_proxy_max_concurrent_per_endpoint(value: usize) {
    UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT.store(value.max(1), Ordering::Relaxed);
}

fn upstream_proxy_max_concurrent_per_endpoint() -> usize {
    UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT
        .load(Ordering::Relaxed)
        .max(1)
}

struct UpstreamProxySlot {
    senders: Mutex<Vec<UpstreamProxySender>>,
    semaphore: Arc<Semaphore>,
}

type UpstreamProxySlotHandle = Arc<UpstreamProxySlot>;
type UpstreamProxyMap = HashMap<String, UpstreamProxySlotHandle>;
type UpstreamProxyPool = Arc<Mutex<UpstreamProxyMap>>;

fn upstream_proxy_pool() -> &'static UpstreamProxyPool {
    static POOL: OnceLock<UpstreamProxyPool> = OnceLock::new();
    POOL.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

#[derive(Debug, Clone)]
struct PassiveHealthPolicy {
    consecutive_5xx: u32,
    consecutive_timeouts: u32,
    consecutive_connect_errors: u32,
    consecutive_resets: u32,
    max_ejection: Duration,
    latency_threshold: Option<Duration>,
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
struct DynamicDiscovery {
    base_upstream: Arc<str>,
    config: qpx_core::config::UpstreamDiscoveryConfig,
}

#[derive(Debug)]
struct ManagedUpstreamEndpoint {
    endpoint: UpstreamProxyEndpoint,
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
    inflight: AtomicUsize,
}

impl ManagedUpstreamEndpoint {
    fn new(endpoint: UpstreamProxyEndpoint) -> Self {
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

    fn is_healthy(&self, now_ms: u64) -> bool {
        self.unhealthy_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    fn is_half_open(&self, now_ms: u64) -> bool {
        let unhealthy_until = self.unhealthy_until_ms.load(Ordering::Relaxed);
        unhealthy_until != 0 && unhealthy_until <= now_ms
    }

    fn mark_passive_success(&self) {
        let recovered = self.unhealthy_until_ms.swap(0, Ordering::Relaxed) != 0;
        self.reset_passive_counters();
        self.note_adaptive_success();
        if recovered {
            counter!(crate::runtime::metric_names()
                .forward_upstream_proxy_probe_success_total
                .clone())
            .increment(1);
        }
    }

    fn mark_passive_failure(&self, policy: Option<&PassiveHealthPolicy>, kind: PassiveFailureKind) {
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

    fn mark_passive_latency(&self, policy: Option<&PassiveHealthPolicy>, elapsed: Duration) {
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
        counter!(
            crate::runtime::metric_names()
                .forward_upstream_proxy_ejections_total
                .clone(),
            "reason" => reason.as_label()
        )
        .increment(1);
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
enum PassiveFailureKind {
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
    key: Arc<str>,
    static_endpoints: Arc<Vec<Arc<ManagedUpstreamEndpoint>>>,
    endpoints: ArcSwap<Vec<Arc<ManagedUpstreamEndpoint>>>,
    discovery: Option<DynamicDiscovery>,
    trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    discovery_started: AtomicBool,
    passive_health: Option<PassiveHealthPolicy>,
    max_concurrency: Option<usize>,
    rr_counter: AtomicUsize,
}

impl UpstreamProxyCluster {
    fn from_config(cfg: &UpstreamConfig) -> Result<Arc<Self>> {
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
                    Ok((dynamic, next_delay)) => {
                        if !dynamic.is_empty() || !cluster.static_endpoints.is_empty() {
                            let mut combined = cluster.static_endpoints.as_ref().clone();
                            combined.extend(dynamic);
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
}

async fn refresh_dynamic_endpoints(
    discovery: &DynamicDiscovery,
) -> Result<(Vec<Arc<ManagedUpstreamEndpoint>>, Duration)> {
    let (origins, delay) =
        discover_origin_endpoints(discovery.base_upstream.as_ref(), &discovery.config).await?;
    let endpoints = origins
        .iter()
        .map(UpstreamProxyEndpoint::from_origin)
        .map(|result| result.map(ManagedUpstreamEndpoint::new))
        .map(|result| result.map(Arc::new))
        .collect::<Result<Vec<_>>>()?;
    Ok((endpoints, delay))
}

struct EndpointConcurrencyPermit {
    endpoint: Arc<ManagedUpstreamEndpoint>,
}

impl Drop for EndpointConcurrencyPermit {
    fn drop(&mut self) {
        self.endpoint.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) struct ResolvedUpstreamProxy {
    key: Arc<str>,
    endpoint: Arc<ManagedUpstreamEndpoint>,
    trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    passive_health: Option<PassiveHealthPolicy>,
    _permit: Option<EndpointConcurrencyPermit>,
}

impl ResolvedUpstreamProxy {
    pub(crate) fn direct(raw: &str) -> Result<Self> {
        Ok(Self {
            key: Arc::<str>::from(raw),
            endpoint: Arc::new(ManagedUpstreamEndpoint::new(parse_upstream_proxy_endpoint(
                raw,
            )?)),
            trust: None,
            passive_health: None,
            _permit: None,
        })
    }

    pub(crate) fn key(&self) -> &str {
        self.key.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn label(&self) -> &str {
        self.key.as_ref()
    }

    pub(crate) fn endpoint(&self) -> &UpstreamProxyEndpoint {
        &self.endpoint.endpoint
    }

    pub(crate) fn trust(&self) -> Option<&CompiledUpstreamTlsTrust> {
        self.trust.as_deref()
    }

    pub(crate) fn mark_success(&self) {
        if self.passive_health.is_some() {
            self.endpoint.mark_passive_success();
        }
    }

    pub(crate) fn mark_http_response(&self, status: StatusCode, elapsed: Duration) {
        if status.is_server_error() {
            self.endpoint
                .mark_passive_failure(self.passive_health.as_ref(), PassiveFailureKind::Http5xx);
            return;
        }
        self.endpoint.mark_passive_success();
        self.endpoint
            .mark_passive_latency(self.passive_health.as_ref(), elapsed);
    }

    pub(crate) fn mark_timeout(&self) {
        self.endpoint
            .mark_passive_failure(self.passive_health.as_ref(), PassiveFailureKind::Timeout);
    }

    pub(crate) fn mark_connect_error(&self) {
        self.endpoint.mark_passive_failure(
            self.passive_health.as_ref(),
            PassiveFailureKind::ConnectError,
        );
    }

    pub(crate) fn mark_reset(&self) {
        self.endpoint
            .mark_passive_failure(self.passive_health.as_ref(), PassiveFailureKind::Reset);
    }
}

pub(crate) fn build_named_upstream_proxies(
    upstreams: &[UpstreamConfig],
) -> Result<HashMap<String, Arc<UpstreamProxyCluster>>> {
    let mut clusters = HashMap::new();
    for cfg in upstreams {
        let scheme = Url::parse(cfg.url.as_str())
            .ok()
            .map(|url| url.scheme().to_ascii_lowercase())
            .unwrap_or_default();
        if scheme != "http" && scheme != "https" {
            continue;
        }
        clusters.insert(cfg.name.clone(), UpstreamProxyCluster::from_config(cfg)?);
    }
    Ok(clusters)
}

pub async fn send_via_upstream_proxy(
    mut req: Request<Body>,
    upstream: &ResolvedUpstreamProxy,
    timeout_dur: Duration,
) -> Result<Response<Body>> {
    let endpoint = upstream.endpoint().clone();
    req.headers_mut().remove(PROXY_AUTHORIZATION);
    if let Some(value) = endpoint.proxy_authorization.as_ref() {
        req.headers_mut().insert(PROXY_AUTHORIZATION, value.clone());
    }
    let pool_key = endpoint.cache_key();

    let slot = {
        let pool = upstream_proxy_pool();
        let mut guard = pool.lock().await;
        guard
            .entry(pool_key.clone())
            .or_insert_with(|| {
                Arc::new(UpstreamProxySlot {
                    senders: Mutex::new(Vec::new()),
                    semaphore: Arc::new(Semaphore::new(
                        upstream_proxy_max_concurrent_per_endpoint(),
                    )),
                })
            })
            .clone()
    };

    let _permit = slot
        .semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| anyhow!("upstream proxy concurrency limiter closed"))?;

    let sender = { slot.senders.lock().await.pop() };
    let mut sender = match sender {
        Some(sender) => sender,
        None => match open_upstream_proxy_sender(&endpoint, timeout_dur, upstream.trust()).await {
            Ok(sender) => sender,
            Err(err) => {
                upstream.mark_connect_error();
                return Err(err);
            }
        },
    };
    let started = Instant::now();

    match timeout(timeout_dur, sender.send_request(req)).await {
        Ok(Ok(response)) => {
            let response = response.map(Body::from);
            upstream.mark_http_response(response.status(), started.elapsed());
            slot.senders.lock().await.push(sender);
            Ok(response)
        }
        Ok(Err(err)) => {
            upstream.mark_reset();
            Err(err.into())
        }
        Err(_) => {
            upstream.mark_timeout();
            Err(anyhow!("upstream proxy request timed out"))
        }
    }
}

pub async fn send_via_upstream_proxy_with_interim(
    mut req: Request<Body>,
    upstream: &ResolvedUpstreamProxy,
    timeout_dur: Duration,
) -> Result<Http1ResponseWithInterim> {
    let endpoint = upstream.endpoint().clone();
    req.headers_mut().remove(PROXY_AUTHORIZATION);
    if let Some(value) = endpoint.proxy_authorization.as_ref() {
        req.headers_mut().insert(PROXY_AUTHORIZATION, value.clone());
    }

    let started = Instant::now();
    let stream = match timeout(
        timeout_dur,
        open_upstream_proxy_stream(&endpoint, upstream.trust()),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            upstream.mark_connect_error();
            return Err(err);
        }
        Err(_) => {
            upstream.mark_timeout();
            return Err(anyhow!("upstream proxy request timed out"));
        }
    };

    match timeout(timeout_dur, send_http1_request_with_interim(stream, req)).await {
        Ok(Ok(response)) => {
            upstream.mark_http_response(response.response.status(), started.elapsed());
            Ok(response)
        }
        Ok(Err(err)) => {
            upstream.mark_reset();
            Err(err)
        }
        Err(_) => {
            upstream.mark_timeout();
            Err(anyhow!("upstream proxy request timed out"))
        }
    }
}

async fn open_upstream_proxy_sender(
    endpoint: &UpstreamProxyEndpoint,
    timeout_dur: Duration,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<UpstreamProxySender> {
    open_proxy_sender_once(endpoint, Some(timeout_dur), "upstream proxy pooled", trust).await
}

async fn open_upstream_proxy_stream(
    endpoint: &UpstreamProxyEndpoint,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<crate::tls::client::BoxTlsStream> {
    let tcp = TcpStream::connect(endpoint.authority.as_str()).await?;
    let _ = tcp.set_nodelay(true);
    match endpoint.scheme {
        UpstreamProxyScheme::Http => Ok(Box::new(tcp)),
        UpstreamProxyScheme::Https => {
            crate::tls::client::connect_tls_http1_with_options(
                endpoint.host.as_str(),
                tcp,
                true,
                trust,
            )
            .await
        }
    }
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PassiveHealthPolicy {
        PassiveHealthPolicy {
            consecutive_5xx: 1,
            consecutive_timeouts: 1,
            consecutive_connect_errors: 1,
            consecutive_resets: 1,
            max_ejection: Duration::from_secs(30),
            latency_threshold: None,
        }
    }

    #[test]
    fn cluster_skips_ejected_endpoint() {
        let first = Arc::new(ManagedUpstreamEndpoint::new(
            parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
        ));
        let second = Arc::new(ManagedUpstreamEndpoint::new(
            parse_upstream_proxy_endpoint("http://127.0.0.2:3128").expect("endpoint"),
        ));
        let cluster = Arc::new(UpstreamProxyCluster {
            key: Arc::<str>::from("corp"),
            static_endpoints: Arc::new(vec![first.clone(), second.clone()]),
            endpoints: ArcSwap::from_pointee(vec![first.clone(), second.clone()]),
            discovery: None,
            trust: None,
            discovery_started: AtomicBool::new(false),
            passive_health: Some(policy()),
            max_concurrency: None,
            rr_counter: AtomicUsize::new(0),
        });

        let first_pick = cluster.select().expect("first pick");
        assert_eq!(first_pick.endpoint().authority, "127.0.0.1:3128");
        first_pick.mark_connect_error();
        drop(first_pick);

        let second_pick = cluster.select().expect("second pick");
        assert_eq!(second_pick.endpoint().authority, "127.0.0.2:3128");
    }

    #[test]
    fn cluster_respects_max_concurrency() {
        let endpoint = Arc::new(ManagedUpstreamEndpoint::new(
            parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
        ));
        let cluster = Arc::new(UpstreamProxyCluster {
            key: Arc::<str>::from("corp"),
            static_endpoints: Arc::new(vec![endpoint.clone()]),
            endpoints: ArcSwap::from_pointee(vec![endpoint]),
            discovery: None,
            trust: None,
            discovery_started: AtomicBool::new(false),
            passive_health: None,
            max_concurrency: Some(1),
            rr_counter: AtomicUsize::new(0),
        });

        let first = cluster.select().expect("first selection");
        assert!(cluster.select().is_err());
        drop(first);
        assert!(cluster.select().is_ok());
    }

    #[test]
    fn cluster_adaptive_failure_rate_ejects_endpoint() {
        let endpoint = Arc::new(ManagedUpstreamEndpoint::new(
            parse_upstream_proxy_endpoint("http://127.0.0.1:3128").expect("endpoint"),
        ));
        let policy = PassiveHealthPolicy {
            consecutive_5xx: 100,
            consecutive_timeouts: 100,
            consecutive_connect_errors: 100,
            consecutive_resets: 100,
            max_ejection: Duration::from_secs(30),
            latency_threshold: None,
        };
        for _ in 0..4 {
            endpoint.mark_passive_success();
        }
        for _ in 0..4 {
            endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::ConnectError);
        }
        assert!(!endpoint.is_healthy(now_millis()));
    }
}
