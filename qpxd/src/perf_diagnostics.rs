use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const SAMPLE_INTERVAL: u64 = 1024;

pub(crate) struct PhaseTimer {
    phase: &'static str,
    // Keep thread evidence out of unsampled request-state storage.
    started: Option<Box<StartedPhase>>,
}

struct StartedPhase {
    at: Instant,
    thread: std::thread::ThreadId,
}

impl PhaseTimer {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn is_sampled(&self) -> bool {
        self.started.is_some()
    }

    pub(crate) fn begin(phase: &'static str, samples: &AtomicU64) -> Self {
        let sampled = tracing::enabled!(target: "qpx_perf_phase", tracing::Level::DEBUG)
            && samples
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(SAMPLE_INTERVAL);
        Self {
            phase,
            started: sampled.then(|| {
                Box::new(StartedPhase {
                    at: Instant::now(),
                    thread: std::thread::current().id(),
                })
            }),
        }
    }
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        if let Some(started) = self.started.as_ref() {
            let completed_thread = std::thread::current().id();
            tracing::debug!(target: "qpx_perf_phase", phase = self.phase,
                elapsed_ns = started.at.elapsed().as_nanos() as u64,
                sample_interval = SAMPLE_INTERVAL,
                started_thread = ?started.thread,
                migrated = started.thread != completed_thread,
                thread = ?completed_thread, "performance phase completed");
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
