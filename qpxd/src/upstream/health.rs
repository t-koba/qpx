use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Duration;

/// Trailing per-endpoint latencies kept for the outlier p95. Bounded: one
/// slow request must not eject while the empirical p95 stays fast.
pub(crate) const LATENCY_P95_WINDOW: usize = 100;
/// Default requests observed before the trailing p95 can eject. A percentile
/// needs a full window; override with `outlier_detection.latency.min_requests`.
pub(crate) const LATENCY_P95_DEFAULT_MIN_SAMPLES: u64 = LATENCY_P95_WINDOW as u64;

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
}
