use crate::upstream::health::{
    AdaptiveEjection, EjectionReason, LatencyWindow, PassiveFailureCounters, PassiveFailureKind,
};
use qpx_core::config::{EndpointLifecycleConfig, HealthCheckConfig, HttpHealthCheckConfig};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use tokio::time::Duration;

use crate::upstream::origin::OriginEndpoint;

mod probe;

pub(super) use self::probe::probe_upstream;
pub(super) use crate::runtime::now_millis;

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
    pub(super) ejection_base: Duration,
    pub(super) ejection_max: Duration,
    pub(super) latency_threshold: Option<Duration>,
    pub(super) latency_min_samples: u64,
}

#[derive(Debug, Clone, Default)]
pub(super) struct EndpointLifecycleRuntime {
    pub(super) slow_start: Option<Duration>,
    pub(super) warmup: Option<Duration>,
    pub(super) drain_timeout: Option<Duration>,
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
    passive: PassiveFailureCounters,
    adaptive: AdaptiveEjection,
    latency_window: LatencyWindow,
    recovery_start_ms: AtomicU64,
    warmup_until_ms: AtomicU64,
    drain_deadline_ms: AtomicU64,
    admission_state_active: AtomicBool,
}

impl UpstreamEndpoint {
    pub(super) fn new(target: String) -> Self {
        Self::from_origin(OriginEndpoint::direct(target))
    }

    pub(super) fn from_origin(origin: OriginEndpoint) -> Self {
        Self {
            target: origin.label().to_string(),
            origin,
            failures: AtomicU32::new(0),
            unhealthy_until_ms: AtomicU64::new(0),
            inflight: AtomicUsize::new(0),
            passive: PassiveFailureCounters::new(),
            adaptive: AdaptiveEjection::new(),
            latency_window: LatencyWindow::new(),
            recovery_start_ms: AtomicU64::new(0),
            warmup_until_ms: AtomicU64::new(0),
            drain_deadline_ms: AtomicU64::new(0),
            admission_state_active: AtomicBool::new(false),
        }
    }

    /// Hold one in-flight attempt count, released exactly once: explicitly
    /// at the normal completion point via [`InflightAttemptGuard::release`],
    /// or on drop for early returns, `?`, loop breaks, and task
    /// cancellation. Mirrors the acquire/release pairing of
    /// `EndpointConcurrencyPermit`, but the release point stays explicit so
    /// normal-path limit accounting is unchanged.
    pub(super) fn hold_inflight(self: &Arc<Self>) -> InflightAttemptGuard {
        self.inflight.fetch_add(1, Ordering::Relaxed);
        InflightAttemptGuard {
            endpoint: Some(Arc::clone(self)),
        }
    }

    pub(super) fn is_healthy(&self, now_ms: u64) -> bool {
        self.unhealthy_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    pub(super) fn is_half_open(&self, now_ms: u64) -> bool {
        let unhealthy_until = self.unhealthy_until_ms.load(Ordering::Relaxed);
        unhealthy_until != 0 && unhealthy_until <= now_ms
    }

    pub(super) fn has_time_dependent_admission_state(&self) -> bool {
        self.admission_state_active.load(Ordering::Acquire)
    }

    fn refresh_admission_state(&self) {
        let active = self.unhealthy_until_ms.load(Ordering::Relaxed) != 0
            || self.recovery_start_ms.load(Ordering::Relaxed) != 0
            || self.warmup_until_ms.load(Ordering::Relaxed) != 0
            || self.drain_deadline_ms.load(Ordering::Relaxed) != 0;
        self.admission_state_active.store(active, Ordering::Release);
    }

    pub(super) fn mark_success(&self, lifecycle: &EndpointLifecycleRuntime) {
        let recovered = self.unhealthy_until_ms.swap(0, Ordering::Relaxed) != 0;
        self.failures.store(0, Ordering::Relaxed);
        self.passive.reset_all();
        self.note_adaptive_success();
        if recovered {
            self.begin_recovery_window(lifecycle);
            super::metrics::upstream_probe_success();
        }
    }

    pub(super) fn mark_response_success(&self, lifecycle: &EndpointLifecycleRuntime) {
        if self.failures.load(Ordering::Relaxed) == 0 {
            return;
        }
        let recovered = self.unhealthy_until_ms.swap(0, Ordering::Relaxed) != 0;
        self.failures.store(0, Ordering::Relaxed);
        if recovered {
            self.begin_recovery_window(lifecycle);
            super::metrics::upstream_probe_success();
        }
    }

    pub(super) fn mark_failure(&self, policy: &HealthCheckRuntime) {
        self.mark_failure_at(policy, now_millis());
    }

    pub(super) fn mark_failure_at(&self, policy: &HealthCheckRuntime, now_ms: u64) {
        let fails = self
            .failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        if fails >= policy.fail_threshold {
            self.eject_at(policy.cooldown, None, EjectionReason::ActiveFailure, now_ms);
        }
    }

    pub(super) fn mark_passive_success(&self, lifecycle: &EndpointLifecycleRuntime) {
        let recovered = self.unhealthy_until_ms.swap(0, Ordering::Relaxed) != 0;
        self.passive.reset_all();
        self.note_adaptive_success();
        if recovered {
            self.begin_recovery_window(lifecycle);
            super::metrics::upstream_probe_success();
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
        self.passive.reset_except(kind);
        let count = self.passive.increment(kind);
        let reason = EjectionReason::from_passive_failure(kind);
        self.note_adaptive_failure(policy.ejection_base, policy.ejection_max, reason);
        if count >= threshold {
            self.eject(policy.ejection_base, Some(policy.ejection_max), reason);
            self.passive.reset_all();
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
        self.note_adaptive_latency(
            policy.ejection_base,
            policy.ejection_max,
            threshold,
            elapsed,
        );
        if self.latency_window.observe_and_meets_p95_threshold(
            elapsed,
            threshold,
            policy.latency_min_samples,
        ) {
            self.eject(
                policy.ejection_base,
                Some(policy.ejection_max),
                EjectionReason::Latency,
            );
        } else if elapsed < threshold {
            self.passive.reset_all();
        }
    }

    fn eject(&self, base: Duration, cap: Option<Duration>, reason: EjectionReason) {
        self.eject_at(base, cap, reason, now_millis());
    }

    fn eject_at(&self, base: Duration, cap: Option<Duration>, reason: EjectionReason, now_ms: u64) {
        let shift = self.adaptive.next_backoff_shift();
        let scaled_ms = (base.as_millis() as u64).saturating_mul(1u64 << shift);
        let scaled_ms = match cap {
            Some(cap) => scaled_ms.min(cap.as_millis().min(u128::from(u64::MAX)) as u64),
            None => scaled_ms,
        };
        let until = now_ms.saturating_add(scaled_ms);
        self.unhealthy_until_ms.fetch_max(until, Ordering::Relaxed);
        self.admission_state_active.store(true, Ordering::Release);
        self.adaptive.reset();
        super::metrics::upstream_ejection(reason.as_label());
    }

    pub(super) fn begin_recovery_window(&self, lifecycle: &EndpointLifecycleRuntime) {
        self.begin_recovery_window_at(lifecycle, now_millis());
    }

    pub(super) fn begin_recovery_window_at(
        &self,
        lifecycle: &EndpointLifecycleRuntime,
        now_ms: u64,
    ) {
        let now = now_ms;
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
        self.refresh_admission_state();
    }

    pub(super) fn mark_draining_at(
        &self,
        lifecycle: &EndpointLifecycleRuntime,
        now_ms: u64,
    ) -> bool {
        let Some(timeout) = lifecycle.drain_timeout else {
            return false;
        };
        let until = now_ms.saturating_add(timeout.as_millis() as u64).max(1);
        // Set the deadline only on the transition into draining. Renewing it
        // on every discovery refresh would keep removed endpoints past their
        // drain timeout whenever refreshes outpace it.
        let _ =
            self.drain_deadline_ms
                .compare_exchange(0, until, Ordering::Relaxed, Ordering::Relaxed);
        self.admission_state_active.store(true, Ordering::Release);
        true
    }

    pub(super) fn reactivate_at(&self, lifecycle: &EndpointLifecycleRuntime, now_ms: u64) {
        let was_draining = self.drain_deadline_ms.swap(0, Ordering::Relaxed) != 0;
        if was_draining {
            self.begin_recovery_window_at(lifecycle, now_ms);
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

    fn note_adaptive_success(&self) {
        self.adaptive.note_success();
        self.adaptive.maybe_trim();
    }

    fn note_adaptive_failure(
        &self,
        ejection_base: Duration,
        ejection_cap: Duration,
        _reason: EjectionReason,
    ) {
        if self.adaptive.note_failure() {
            self.eject(
                ejection_base,
                Some(ejection_cap),
                EjectionReason::SuccessRate,
            );
        } else {
            self.adaptive.maybe_trim();
        }
    }

    fn note_adaptive_latency(
        &self,
        ejection_base: Duration,
        ejection_cap: Duration,
        threshold: Duration,
        elapsed: Duration,
    ) {
        if self.adaptive.note_latency(elapsed, threshold) {
            self.eject(ejection_base, Some(ejection_cap), EjectionReason::Latency);
        } else {
            self.adaptive.maybe_trim();
        }
    }
}

/// Owns one in-flight attempt count on an endpoint; see
/// [`UpstreamEndpoint::hold_inflight`].
pub(super) struct InflightAttemptGuard {
    endpoint: Option<Arc<UpstreamEndpoint>>,
}

impl InflightAttemptGuard {
    pub(super) fn release(mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.inflight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl Drop for InflightAttemptGuard {
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.inflight.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::reverse::health::*;
    use crate::upstream::health::LATENCY_P95_DEFAULT_MIN_SAMPLES;
    use crate::upstream::health::PassiveFailureKind;

    fn passive_policy() -> PassiveHealthRuntime {
        PassiveHealthRuntime {
            consecutive_5xx: 100,
            consecutive_timeouts: 100,
            consecutive_connect_errors: 100,
            consecutive_resets: 100,
            ejection_base: Duration::from_secs(30),
            ejection_max: Duration::from_secs(30),
            latency_threshold: Some(Duration::from_millis(10)),
            latency_min_samples: LATENCY_P95_DEFAULT_MIN_SAMPLES,
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

    fn bounded_policy() -> PassiveHealthRuntime {
        PassiveHealthRuntime {
            consecutive_5xx: 1,
            consecutive_timeouts: 100,
            consecutive_connect_errors: 100,
            consecutive_resets: 100,
            ejection_base: Duration::from_millis(1_000),
            ejection_max: Duration::from_millis(5_000),
            latency_threshold: None,
            latency_min_samples: LATENCY_P95_DEFAULT_MIN_SAMPLES,
        }
    }

    fn latency_policy() -> PassiveHealthRuntime {
        PassiveHealthRuntime {
            consecutive_5xx: 100,
            consecutive_timeouts: 100,
            consecutive_connect_errors: 100,
            consecutive_resets: 100,
            ejection_base: Duration::from_millis(1_000),
            ejection_max: Duration::from_millis(5_000),
            latency_threshold: Some(Duration::from_millis(100)),
            latency_min_samples: LATENCY_P95_DEFAULT_MIN_SAMPLES,
        }
    }

    fn observe(endpoint: &UpstreamEndpoint, policy: &PassiveHealthRuntime, ms: u64) {
        endpoint.mark_passive_latency(Some(policy), Duration::from_millis(ms));
    }

    #[test]
    fn rare_latency_outlier_does_not_trip_p95() {
        let endpoint = UpstreamEndpoint::new("http://example".to_string());
        let policy = latency_policy();
        for _ in 0..99 {
            observe(&endpoint, &policy, 1);
        }
        observe(&endpoint, &policy, 101);
        assert!(
            endpoint.is_healthy(now_millis()),
            "single 101ms sample ejected an endpoint with p95 1ms"
        );
    }

    #[test]
    fn sustained_slow_latency_trips_p95() {
        let endpoint = UpstreamEndpoint::new("http://example".to_string());
        let policy = latency_policy();
        for _ in 0..100 {
            observe(&endpoint, &policy, 150);
        }
        assert!(!endpoint.is_healthy(now_millis()));
    }

    #[test]
    fn p95_waits_for_min_requests() {
        let endpoint = UpstreamEndpoint::new("http://example".to_string());
        let mut policy = latency_policy();
        policy.latency_min_samples = 10_000;
        for _ in 0..100 {
            observe(&endpoint, &policy, 150);
        }
        assert!(
            endpoint.is_healthy(now_millis()),
            "p95 ejected before min_requests observations"
        );
    }

    fn ejection_span_ms(endpoint: &UpstreamEndpoint) -> u64 {
        endpoint
            .unhealthy_until_ms
            .load(Ordering::Relaxed)
            .saturating_sub(now_millis())
    }

    #[test]
    fn passive_ejection_starts_at_base_and_never_exceeds_max() {
        let endpoint = UpstreamEndpoint::new("http://example".to_string());
        let policy = bounded_policy();
        endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::Http5xx);
        let first = ejection_span_ms(&endpoint);
        assert!(
            first <= 1_000,
            "first ejection {first}ms exceeds base_ms 1000"
        );
        endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::Http5xx);
        let second = ejection_span_ms(&endpoint);
        assert!(
            second > first,
            "backoff stalled: first {first}ms second {second}ms"
        );
        for _ in 0..8 {
            endpoint.mark_passive_failure(Some(&policy), PassiveFailureKind::Http5xx);
        }
        let worst = ejection_span_ms(&endpoint);
        assert!(worst <= 5_000, "ejection {worst}ms exceeds max_ms 5000");
    }

    #[test]
    fn response_success_keeps_the_clean_path_free_of_adaptive_updates() {
        let endpoint = UpstreamEndpoint::new("http://example".to_string());

        endpoint.mark_response_success(&EndpointLifecycleRuntime::default());

        assert_eq!(endpoint.adaptive.successes(), 0);
        assert!(!endpoint.has_time_dependent_admission_state());
        assert!(endpoint.is_healthy(now_millis()));
    }

    #[test]
    fn response_success_recovers_a_failed_endpoint() {
        let endpoint = UpstreamEndpoint::new("http://example".to_string());
        let policy = HealthCheckRuntime {
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            fail_threshold: 1,
            cooldown: Duration::from_secs(30),
            http: None,
        };
        endpoint.mark_failure(&policy);
        assert!(!endpoint.is_healthy(now_millis()));

        endpoint.mark_response_success(&EndpointLifecycleRuntime::default());

        assert!(endpoint.is_healthy(now_millis()));
        assert_eq!(endpoint.failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn mark_draining_sets_deadline_only_on_transition() {
        // The drain deadline must be fixed at the removal transition: a later
        // refresh must not renew it, or removed endpoints would never retire
        // while refreshes outpace the timeout. Uses a synthetic clock instead
        // of sleeping between the two marks.
        let lifecycle = EndpointLifecycleRuntime {
            slow_start: None,
            warmup: None,
            drain_timeout: Some(Duration::from_secs(10)),
        };
        let endpoint = UpstreamEndpoint::new("http://example".to_string());
        let marked_at = 1_000_000u64;
        assert!(endpoint.mark_draining_at(&lifecycle, marked_at));
        let first = endpoint.drain_deadline_ms.load(Ordering::Relaxed);
        assert_ne!(first, 0);
        assert!(endpoint.mark_draining_at(&lifecycle, marked_at.saturating_add(50)));
        let second = endpoint.drain_deadline_ms.load(Ordering::Relaxed);
        assert_eq!(
            first, second,
            "second mark_draining must not renew the drain deadline"
        );
        assert!(endpoint.should_retain_draining(first.saturating_sub(1)));
        assert!(!endpoint.should_retain_draining(first));
        assert!(!endpoint.should_retain_draining(first.saturating_add(1)));
    }
}

#[cfg(test)]
mod inflight_guard_tests {
    use super::*;

    #[test]
    fn inflight_guard_releases_on_explicit_release() {
        let endpoint = Arc::new(UpstreamEndpoint::new("http://example".to_string()));
        let guard = endpoint.hold_inflight();
        assert_eq!(endpoint.inflight.load(Ordering::Relaxed), 1);
        guard.release();
        assert_eq!(endpoint.inflight.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn inflight_guard_releases_on_drop() {
        let endpoint = Arc::new(UpstreamEndpoint::new("http://example".to_string()));
        {
            let _guard = endpoint.hold_inflight();
            assert_eq!(endpoint.inflight.load(Ordering::Relaxed), 1);
        }
        assert_eq!(endpoint.inflight.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn inflight_guard_releases_on_task_abort() {
        let endpoint = Arc::new(UpstreamEndpoint::new("http://example".to_string()));
        let (held_tx, held_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn({
            let endpoint = endpoint.clone();
            async move {
                let _guard = endpoint.hold_inflight();
                let _ = held_tx.send(());
                std::future::pending::<()>().await;
            }
        });
        held_rx.await.expect("guard held");
        assert_eq!(endpoint.inflight.load(Ordering::Relaxed), 1);
        task.abort();
        let _ = task.await;
        assert_eq!(endpoint.inflight.load(Ordering::Relaxed), 0);
    }
}
