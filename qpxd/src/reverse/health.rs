use crate::http::body::Body;
use anyhow::{anyhow, Result};
use hyper::header::HOST;
use hyper::{Request, StatusCode, Uri};
use metrics::counter;
use qpx_core::config::{EndpointLifecycleConfig, HealthCheckConfig, HttpHealthCheckConfig};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::Duration;
use url::Url;

use crate::upstream::origin::OriginEndpoint;
use crate::{tls::client::connect_tls_http1_with_options, tls::CompiledUpstreamTlsTrust};

const ADAPTIVE_MIN_SAMPLES: u32 = 8;
const ADAPTIVE_MAX_SAMPLES: u32 = 32;
const ADAPTIVE_FAILURE_RATE_NUM: u32 = 1;
const ADAPTIVE_FAILURE_RATE_DEN: u32 = 2;
const ADAPTIVE_LATENCY_MULTIPLIER: u64 = 2;
const ADAPTIVE_MAX_BACKOFF_SHIFT: u32 = 5;

#[derive(Debug, Clone)]
pub(super) struct HealthCheckRuntime {
    pub(super) interval: Duration,
    pub(super) timeout: Duration,
    pub(super) fail_threshold: u32,
    pub(super) cooldown: Duration,
    pub(super) http: Option<Arc<HttpHealthCheckRuntime>>,
}

#[derive(Debug, Clone)]
pub(super) struct HttpHealthCheckRuntime {
    pub(super) method: http::Method,
    pub(super) path: Arc<str>,
    pub(super) expected_status: Option<Arc<Vec<u16>>>,
}

#[derive(Debug, Clone)]
pub(super) struct PassiveHealthRuntime {
    pub(super) consecutive_5xx: u32,
    pub(super) consecutive_timeouts: u32,
    pub(super) consecutive_connect_errors: u32,
    pub(super) consecutive_resets: u32,
    pub(super) max_ejection: Duration,
    pub(super) latency_threshold: Option<Duration>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct EndpointLifecycleRuntime {
    pub(super) slow_start: Option<Duration>,
    pub(super) warmup: Option<Duration>,
    pub(super) drain_timeout: Option<Duration>,
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
    ActiveFailure,
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
            Self::ActiveFailure => "active_failure",
            Self::Http5xx => "http_5xx",
            Self::Timeout => "timeout",
            Self::ConnectError => "connect_error",
            Self::Reset => "reset",
            Self::Latency => "latency",
            Self::SuccessRate => "success_rate",
        }
    }
}

impl HealthCheckRuntime {
    pub(super) fn from_config(config: Option<&HealthCheckConfig>) -> Self {
        if let Some(cfg) = config {
            return Self {
                interval: Duration::from_millis(cfg.interval_ms),
                timeout: Duration::from_millis(cfg.timeout_ms),
                fail_threshold: cfg.fail_threshold.max(1),
                cooldown: Duration::from_millis(cfg.cooldown_ms),
                http: cfg
                    .http
                    .as_ref()
                    .map(|h| Arc::new(HttpHealthCheckRuntime::from_config(h))),
            };
        }
        Self {
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            fail_threshold: 3,
            cooldown: Duration::from_secs(30),
            http: None,
        }
    }
}

impl HttpHealthCheckRuntime {
    fn from_config(cfg: &HttpHealthCheckConfig) -> Self {
        let method = cfg
            .method
            .as_deref()
            .unwrap_or("HEAD")
            .trim()
            .to_ascii_uppercase();
        let method = if method == "GET" {
            http::Method::GET
        } else {
            http::Method::HEAD
        };
        let path = cfg.path.as_deref().unwrap_or("/").trim();
        let expected_status = cfg
            .expected_status
            .as_ref()
            .filter(|v| !v.is_empty())
            .map(|v| Arc::new(v.clone()));
        Self {
            method,
            path: Arc::<str>::from(if path.is_empty() { "/" } else { path }),
            expected_status,
        }
    }
}

impl EndpointLifecycleRuntime {
    pub(super) fn from_config(config: Option<&EndpointLifecycleConfig>) -> Self {
        let Some(cfg) = config else {
            return Self::default();
        };
        Self {
            slow_start: cfg
                .slow_start_ms
                .map(|value| Duration::from_millis(value.max(1))),
            warmup: cfg
                .warmup_ms
                .map(|value| Duration::from_millis(value.max(1))),
            drain_timeout: cfg
                .drain_timeout_ms
                .map(|value| Duration::from_millis(value.max(1))),
        }
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.slow_start.is_some() || self.warmup.is_some() || self.drain_timeout.is_some()
    }
}

#[derive(Debug)]
pub(super) struct UpstreamEndpoint {
    pub(super) target: String,
    pub(super) origin: OriginEndpoint,
    failures: AtomicU32,
    unhealthy_until_ms: AtomicU64,
    pub(super) inflight: AtomicUsize,
    passive_5xx: AtomicU32,
    passive_timeouts: AtomicU32,
    passive_connect_errors: AtomicU32,
    passive_resets: AtomicU32,
    adaptive_successes: AtomicU32,
    adaptive_failures: AtomicU32,
    adaptive_latency_total_ms: AtomicU64,
    adaptive_latency_samples: AtomicU32,
    ejection_backoff_shift: AtomicU32,
    recovery_start_ms: AtomicU64,
    warmup_until_ms: AtomicU64,
    drain_deadline_ms: AtomicU64,
}

impl UpstreamEndpoint {
    pub(super) fn new(target: String) -> Self {
        Self::from_origin(OriginEndpoint::direct(target))
    }

    pub(super) fn from_origin(origin: OriginEndpoint) -> Self {
        Self {
            target: origin.label(),
            origin,
            failures: AtomicU32::new(0),
            unhealthy_until_ms: AtomicU64::new(0),
            inflight: AtomicUsize::new(0),
            passive_5xx: AtomicU32::new(0),
            passive_timeouts: AtomicU32::new(0),
            passive_connect_errors: AtomicU32::new(0),
            passive_resets: AtomicU32::new(0),
            adaptive_successes: AtomicU32::new(0),
            adaptive_failures: AtomicU32::new(0),
            adaptive_latency_total_ms: AtomicU64::new(0),
            adaptive_latency_samples: AtomicU32::new(0),
            ejection_backoff_shift: AtomicU32::new(0),
            recovery_start_ms: AtomicU64::new(0),
            warmup_until_ms: AtomicU64::new(0),
            drain_deadline_ms: AtomicU64::new(0),
        }
    }

    pub(super) fn is_healthy(&self, now_ms: u64) -> bool {
        self.unhealthy_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    pub(super) fn is_half_open(&self, now_ms: u64) -> bool {
        let unhealthy_until = self.unhealthy_until_ms.load(Ordering::Relaxed);
        unhealthy_until != 0 && unhealthy_until <= now_ms
    }

    pub(super) fn mark_success(&self, lifecycle: &EndpointLifecycleRuntime) {
        let recovered = self.unhealthy_until_ms.swap(0, Ordering::Relaxed) != 0;
        self.failures.store(0, Ordering::Relaxed);
        self.reset_passive_counters();
        self.note_adaptive_success();
        if recovered {
            self.begin_recovery_window(lifecycle);
            counter!(crate::runtime::metric_names()
                .reverse_upstream_probe_success_total
                .clone())
            .increment(1);
        }
    }

    pub(super) fn mark_failure(&self, policy: &HealthCheckRuntime) {
        let fails = self
            .failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if fails >= policy.fail_threshold {
            self.eject(policy.cooldown, EjectionReason::ActiveFailure);
        }
    }

    pub(super) fn mark_passive_success(&self, lifecycle: &EndpointLifecycleRuntime) {
        let recovered = self.unhealthy_until_ms.swap(0, Ordering::Relaxed) != 0;
        self.reset_passive_counters();
        self.note_adaptive_success();
        if recovered {
            self.begin_recovery_window(lifecycle);
            counter!(crate::runtime::metric_names()
                .reverse_upstream_probe_success_total
                .clone())
            .increment(1);
        }
    }

    pub(super) fn mark_passive_failure(
        &self,
        policy: Option<&PassiveHealthRuntime>,
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
        self.note_adaptive_failure(policy.max_ejection, reason);
        if count >= threshold {
            self.eject(policy.max_ejection, reason);
            self.reset_passive_counters();
        }
    }

    pub(super) fn mark_passive_latency(
        &self,
        policy: Option<&PassiveHealthRuntime>,
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
        } else {
            self.reset_passive_counters();
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
                .reverse_upstream_ejections_total
                .clone(),
            "reason" => reason.as_label()
        )
        .increment(1);
    }

    pub(super) fn begin_recovery_window(&self, lifecycle: &EndpointLifecycleRuntime) {
        let now = now_millis();
        let warmup_until = lifecycle
            .warmup
            .map(|duration| now.saturating_add(duration.as_millis() as u64))
            .unwrap_or(0);
        self.warmup_until_ms.store(warmup_until, Ordering::Relaxed);
        let recovery_start = if lifecycle.slow_start.is_some() {
            warmup_until.max(now)
        } else {
            0
        };
        self.recovery_start_ms
            .store(recovery_start, Ordering::Relaxed);
    }

    pub(super) fn mark_draining(&self, lifecycle: &EndpointLifecycleRuntime) -> bool {
        let Some(timeout) = lifecycle.drain_timeout else {
            return false;
        };
        let until = now_millis().saturating_add(timeout.as_millis() as u64);
        self.drain_deadline_ms.fetch_max(until, Ordering::Relaxed);
        true
    }

    pub(super) fn reactivate(&self, lifecycle: &EndpointLifecycleRuntime) {
        let was_draining = self.drain_deadline_ms.swap(0, Ordering::Relaxed) != 0;
        if was_draining {
            self.begin_recovery_window(lifecycle);
        }
    }

    pub(super) fn is_draining(&self) -> bool {
        self.drain_deadline_ms.load(Ordering::Relaxed) != 0
    }

    pub(super) fn should_retain_draining(&self, now_ms: u64) -> bool {
        let drain_deadline = self.drain_deadline_ms.load(Ordering::Relaxed);
        drain_deadline != 0
            && (now_ms < drain_deadline || self.inflight.load(Ordering::Relaxed) > 0)
    }

    pub(super) fn warmup_until_ms(&self) -> u64 {
        self.warmup_until_ms.load(Ordering::Relaxed)
    }

    pub(super) fn recovery_start_ms(&self) -> u64 {
        self.recovery_start_ms.load(Ordering::Relaxed)
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

    fn note_adaptive_failure(&self, max_ejection: Duration, _reason: EjectionReason) {
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

pub(super) async fn probe_upstream(
    origin: &OriginEndpoint,
    http: Option<&HttpHealthCheckRuntime>,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<()> {
    if let Some(cfg) = http {
        let normalized = if origin.upstream.starts_with("ws://") {
            origin.upstream.replacen("ws://", "http://", 1)
        } else if origin.upstream.starts_with("wss://") {
            origin.upstream.replacen("wss://", "https://", 1)
        } else {
            origin.upstream.clone()
        };
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            let mut normalized_origin = origin.clone();
            normalized_origin.upstream = normalized;
            return probe_http(&normalized_origin, cfg, trust).await;
        }
    }
    let default_port = if origin.upstream.starts_with("http://") {
        80
    } else {
        443
    };
    let addr = origin.connect_authority(default_port)?;
    let _ = TcpStream::connect(addr).await?;
    Ok(())
}

async fn probe_http(
    origin: &OriginEndpoint,
    cfg: &HttpHealthCheckRuntime,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<()> {
    let url = Url::parse(origin.upstream.as_str())?;
    let scheme = url.scheme();
    match scheme {
        "http" => probe_http_plain(origin, &url, cfg).await,
        "https" => probe_http_tls(origin, &url, cfg, trust).await,
        other => Err(anyhow!("unsupported health check scheme: {}", other)),
    }
}

async fn probe_http_plain(
    origin: &OriginEndpoint,
    url: &Url,
    cfg: &HttpHealthCheckRuntime,
) -> Result<()> {
    let connect_authority = origin.connect_authority(80)?;
    let host_header = origin.host_header_authority(80)?;
    if !origin.uses_connect_override() {
        let uri = Uri::builder()
            .scheme("http")
            .authority(connect_authority.as_str())
            .path_and_query(cfg.path.as_ref())
            .build()?;
        let req = Request::builder()
            .method(cfg.method.clone())
            .uri(uri)
            .body(Body::empty())?;
        let resp = crate::http::common::request_with_shared_client(req).await?;
        return validate_probe_status(resp.status(), cfg);
    }
    let mut sender = crate::upstream::http1::open_http1_sender(
        connect_authority.as_str(),
        None,
        "reverse health check conn",
    )
    .await?;
    let req = Request::builder()
        .method(cfg.method.clone())
        .version(http::Version::HTTP_11)
        .uri(Uri::builder().path_and_query(cfg.path.as_ref()).build()?)
        .header(HOST, host_header.as_str())
        .body(Body::empty())?;
    let _ = url;
    let resp = sender.send_request(req).await?;
    validate_probe_status(resp.status(), cfg)
}

async fn probe_http_tls(
    origin: &OriginEndpoint,
    url: &Url,
    cfg: &HttpHealthCheckRuntime,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<()> {
    let _ = url;
    let authority = origin.host_header_authority(443)?;
    let addr = origin.connect_authority(443)?;
    let server_name = origin.tls_server_name()?;
    let tcp = TcpStream::connect(addr).await?;
    let tls = connect_tls_http1_with_options(server_name.as_str(), tcp, true, trust).await?;
    let (mut sender, conn) = crate::http::common::handshake_http1(tls).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri = Uri::builder().path_and_query(cfg.path.as_ref()).build()?;
    let req = Request::builder()
        .method(cfg.method.clone())
        .version(http::Version::HTTP_11)
        .uri(uri)
        .header(HOST, authority.as_str())
        .body(Body::empty())?;
    let resp = sender.send_request(req).await?;
    validate_probe_status(resp.status(), cfg)
}

fn validate_probe_status(status: StatusCode, cfg: &HttpHealthCheckRuntime) -> Result<()> {
    let code = status.as_u16();
    if let Some(expected) = cfg.expected_status.as_ref() {
        if expected.contains(&code) {
            return Ok(());
        }
        return Err(anyhow!("unexpected health check status: {}", code));
    }
    if status.is_success() || status.is_redirection() {
        return Ok(());
    }
    Err(anyhow!("unhealthy status: {}", code))
}

pub(super) fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passive_policy() -> PassiveHealthRuntime {
        PassiveHealthRuntime {
            consecutive_5xx: 100,
            consecutive_timeouts: 100,
            consecutive_connect_errors: 100,
            consecutive_resets: 100,
            max_ejection: Duration::from_secs(30),
            latency_threshold: Some(Duration::from_millis(10)),
        }
    }

    #[test]
    fn adaptive_failure_rate_ejects_endpoint() {
        let endpoint = UpstreamEndpoint::new("http://example".to_string());
        let policy = passive_policy();
        for _ in 0..4 {
            endpoint.mark_passive_success(&EndpointLifecycleRuntime::default());
        }
        for _ in 0..4 {
            endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::ConnectError);
        }
        assert!(!endpoint.is_healthy(now_millis()));
    }

    #[test]
    fn adaptive_latency_ejects_endpoint() {
        let endpoint = UpstreamEndpoint::new("http://example".to_string());
        let policy = passive_policy();
        for _ in 0..8 {
            endpoint.mark_passive_success(&EndpointLifecycleRuntime::default());
            endpoint.mark_passive_latency(Some(&policy), Duration::from_millis(25));
        }
        assert!(!endpoint.is_healthy(now_millis()));
    }
}
