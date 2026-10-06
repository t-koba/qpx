use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const SAMPLE_INTERVAL: u64 = 1024;

pub(crate) struct PhaseTimer {
    phase: &'static str,
    started: Option<Instant>,
}

impl PhaseTimer {
    pub(crate) fn begin(phase: &'static str, samples: &AtomicU64) -> Self {
        let sampled = tracing::enabled!(target: "qpx_perf_phase", tracing::Level::DEBUG)
            && samples
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(SAMPLE_INTERVAL);
        Self {
            phase,
            started: sampled.then(Instant::now),
        }
    }

    pub(crate) fn child(&self, phase: &'static str) -> Self {
        Self {
            phase,
            started: self.started.map(|_| Instant::now()),
        }
    }

    pub(crate) fn enter(&mut self, phase: &'static str) {
        if let Some(started) = self.started {
            let now = Instant::now();
            self.record(now.duration_since(started).as_nanos() as u64);
            self.started = Some(now);
        }
        self.phase = phase;
    }

    fn record(&self, elapsed_ns: u64) {
        tracing::debug!(target: "qpx_perf_phase", phase = self.phase,
            elapsed_ns, sample_interval = SAMPLE_INTERVAL,
            thread = ?std::thread::current().id(), "performance phase completed");
    }
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            self.record(started.elapsed().as_nanos() as u64);
        }
    }
}

macro_rules! phase_timer {
    ($phase:literal) => {{
        static SAMPLES: ::std::sync::atomic::AtomicU64 = ::std::sync::atomic::AtomicU64::new(0);
        $crate::perf_diagnostics::PhaseTimer::begin($phase, &SAMPLES)
    }};
}
pub(crate) use phase_timer;
