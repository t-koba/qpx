use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use tokio::time::Duration;

/// Trailing per-endpoint latencies kept for the outlier p95. Bounded: one
/// slow request must not eject while the empirical p95 stays fast.
pub(crate) const LATENCY_P95_WINDOW: usize = 100;
/// Default requests observed before the trailing p95 can eject. A percentile
/// needs a full window; override with `outlier_detection.latency.min_requests`.
pub(crate) const LATENCY_P95_DEFAULT_MIN_SAMPLES: u64 = LATENCY_P95_WINDOW as u64;

/// Trim adaptive counters above the owner's sample bound. Only atomic mechanics
/// are shared; the bound and decisions about when to trim stay with each owner.
pub(crate) fn maybe_trim_adaptive_window(
    successes: &AtomicU32,
    failures: &AtomicU32,
    latency_total_ms: &AtomicU64,
    latency_samples: &AtomicU32,
    max_samples: u32,
) {
    let success_count = successes.load(Ordering::Relaxed);
    let failure_count = failures.load(Ordering::Relaxed);
    if success_count.saturating_add(failure_count) <= max_samples {
        return;
    }
    successes.store(success_count / 2, Ordering::Relaxed);
    failures.store(failure_count / 2, Ordering::Relaxed);
    latency_samples
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current / 2)
        })
        .ok();
    latency_total_ms
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current / 2)
        })
        .ok();
}

/// Clear adaptive counters when requested by the endpoint owner.
pub(crate) fn reset_adaptive_stats(
    successes: &AtomicU32,
    failures: &AtomicU32,
    latency_total_ms: &AtomicU64,
    latency_samples: &AtomicU32,
) {
    successes.store(0, Ordering::Relaxed);
    failures.store(0, Ordering::Relaxed);
    latency_total_ms.store(0, Ordering::Relaxed);
    latency_samples.store(0, Ordering::Relaxed);
}

// Passive failure kinds shared by forward-cluster and reverse endpoints.
// Only the kind discriminant and the consecutive-counter mechanics live here;
// thresholds, ejection, backoff, recovery, lifecycle, and all policy mapping
// stay with each endpoint owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassiveFailureKind {
    Http5xx,
    Timeout,
    ConnectError,
    Reset,
}

/// Per-endpoint consecutive passive-failure counters. Each owner keeps one
/// instance and still decides when to reset or increment; this helper owns
/// only the four atomics and the reset/increment mechanics.
#[derive(Debug)]
pub(crate) struct PassiveFailureCounters {
    http_5xx: AtomicU32,
    timeouts: AtomicU32,
    connect_errors: AtomicU32,
    resets: AtomicU32,
}

impl PassiveFailureCounters {
    pub(crate) fn new() -> Self {
        Self {
            http_5xx: AtomicU32::new(0),
            timeouts: AtomicU32::new(0),
            connect_errors: AtomicU32::new(0),
            resets: AtomicU32::new(0),
        }
    }

    pub(crate) fn reset_all(&self) {
        self.http_5xx.store(0, Ordering::Relaxed);
        self.timeouts.store(0, Ordering::Relaxed);
        self.connect_errors.store(0, Ordering::Relaxed);
        self.resets.store(0, Ordering::Relaxed);
    }

    pub(crate) fn reset_except(&self, keep: PassiveFailureKind) {
        if keep != PassiveFailureKind::Http5xx {
            self.http_5xx.store(0, Ordering::Relaxed);
        }
        if keep != PassiveFailureKind::Timeout {
            self.timeouts.store(0, Ordering::Relaxed);
        }
        if keep != PassiveFailureKind::ConnectError {
            self.connect_errors.store(0, Ordering::Relaxed);
        }
        if keep != PassiveFailureKind::Reset {
            self.resets.store(0, Ordering::Relaxed);
        }
    }

    pub(crate) fn increment(&self, kind: PassiveFailureKind) -> u32 {
        match kind {
            PassiveFailureKind::Http5xx => self.http_5xx.fetch_add(1, Ordering::Relaxed),
            PassiveFailureKind::Timeout => self.timeouts.fetch_add(1, Ordering::Relaxed),
            PassiveFailureKind::ConnectError => self.connect_errors.fetch_add(1, Ordering::Relaxed),
            PassiveFailureKind::Reset => self.resets.fetch_add(1, Ordering::Relaxed),
        }
        .saturating_add(1)
    }
}

/// Bounded trailing latency window shared by forward-cluster and reverse
/// endpoints. The surrounding health, ejection, and lifecycle policy stays
/// with each owner; only the window accumulation and p95 rank live here.
#[derive(Debug)]
pub(crate) struct LatencyWindow {
    samples_ms: Mutex<VecDeque<u64>>,
    total: AtomicU64,
}

impl LatencyWindow {
    pub(crate) fn new() -> Self {
        Self {
            samples_ms: Mutex::new(VecDeque::new()),
            total: AtomicU64::new(0),
        }
    }

    pub(crate) fn observe(&self, elapsed: Duration) {
        let sample = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        self.total.fetch_add(1, Ordering::Relaxed);
        let mut window = self
            .samples_ms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        window.push_back(sample);
        while window.len() > LATENCY_P95_WINDOW {
            window.pop_front();
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub(crate) fn p95_ms(&self) -> u64 {
        let window = self
            .samples_ms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let n = window.len();
        if n == 0 {
            return 0;
        }
        let mut sorted: Vec<u64> = window.iter().copied().collect();
        drop(window);
        let rank = (n as u64).saturating_mul(95).saturating_add(99) / 100;
        let rank = rank.clamp(1, n as u64) as usize;
        let (_, pivot, _) = sorted.select_nth_unstable(rank - 1);
        *pivot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_window_is_unchanged_at_or_below_bound() {
        for (success_count, failure_count) in [(0, 0), (7, 4), (15, 17)] {
            let successes = AtomicU32::new(success_count);
            let failures = AtomicU32::new(failure_count);
            let latency_total_ms = AtomicU64::new(101);
            let latency_samples = AtomicU32::new(37);
            maybe_trim_adaptive_window(
                &successes,
                &failures,
                &latency_total_ms,
                &latency_samples,
                32,
            );
            assert_eq!(successes.load(Ordering::Relaxed), success_count);
            assert_eq!(failures.load(Ordering::Relaxed), failure_count);
            assert_eq!(latency_total_ms.load(Ordering::Relaxed), 101);
            assert_eq!(latency_samples.load(Ordering::Relaxed), 37);
        }
    }

    #[test]
    fn adaptive_window_halves_all_counters_above_caller_bound() {
        for max_samples in [0, 16, 32] {
            let successes = AtomicU32::new(17);
            let failures = AtomicU32::new(18);
            let latency_total_ms = AtomicU64::new(101);
            let latency_samples = AtomicU32::new(36);
            maybe_trim_adaptive_window(
                &successes,
                &failures,
                &latency_total_ms,
                &latency_samples,
                max_samples,
            );
            assert_eq!(successes.load(Ordering::Relaxed), 8);
            assert_eq!(failures.load(Ordering::Relaxed), 9);
            assert_eq!(latency_total_ms.load(Ordering::Relaxed), 50);
            assert_eq!(latency_samples.load(Ordering::Relaxed), 18);
        }
    }

    #[test]
    fn adaptive_stats_reset_to_zero() {
        let successes = AtomicU32::new(17);
        let failures = AtomicU32::new(18);
        let latency_total_ms = AtomicU64::new(101);
        let latency_samples = AtomicU32::new(36);
        reset_adaptive_stats(&successes, &failures, &latency_total_ms, &latency_samples);
        assert_eq!(successes.load(Ordering::Relaxed), 0);
        assert_eq!(failures.load(Ordering::Relaxed), 0);
        assert_eq!(latency_total_ms.load(Ordering::Relaxed), 0);
        assert_eq!(latency_samples.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn empty_window_p95_is_zero() {
        let window = LatencyWindow::new();
        assert_eq!(window.total(), 0);
        assert_eq!(window.p95_ms(), 0);
    }

    #[test]
    fn window_is_bounded_but_count_is_cumulative() {
        let window = LatencyWindow::new();
        for _ in 0..(LATENCY_P95_WINDOW + 50) {
            window.observe(Duration::from_millis(7));
        }
        assert_eq!(window.total(), (LATENCY_P95_WINDOW + 50) as u64);
        let guarded = window
            .samples_ms
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(guarded.len(), LATENCY_P95_WINDOW);
    }

    #[test]
    fn count_never_resets_and_p95_tracks_trailing_window() {
        let window = LatencyWindow::new();
        for _ in 0..LATENCY_P95_WINDOW {
            window.observe(Duration::from_millis(1));
        }
        assert_eq!(window.total(), LATENCY_P95_WINDOW as u64);
        assert_eq!(window.p95_ms(), 1);
        for _ in 0..LATENCY_P95_WINDOW {
            window.observe(Duration::from_millis(50));
        }
        assert_eq!(window.total(), (2 * LATENCY_P95_WINDOW) as u64);
        assert_eq!(window.p95_ms(), 50);
    }

    #[test]
    fn passive_counters_track_kinds_independently() {
        let counters = PassiveFailureCounters::new();
        assert_eq!(counters.increment(PassiveFailureKind::Http5xx), 1);
        assert_eq!(counters.increment(PassiveFailureKind::Http5xx), 2);
        assert_eq!(counters.increment(PassiveFailureKind::Timeout), 1);
        counters.reset_except(PassiveFailureKind::Timeout);
        assert_eq!(counters.increment(PassiveFailureKind::Http5xx), 1);
        assert_eq!(counters.increment(PassiveFailureKind::Timeout), 2);
        counters.reset_all();
        assert_eq!(counters.increment(PassiveFailureKind::ConnectError), 1);
        assert_eq!(counters.increment(PassiveFailureKind::Reset), 1);
        assert_eq!(counters.increment(PassiveFailureKind::Timeout), 1);
        assert_eq!(counters.increment(PassiveFailureKind::Http5xx), 1);
    }
}
