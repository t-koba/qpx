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
    polls: u64,
    pending_polls: u64,
    active_poll_ns: u64,
    max_active_poll_ns: u64,
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
                    polls: 0,
                    pending_polls: 0,
                    active_poll_ns: 0,
                    max_active_poll_ns: 0,
                })
            }),
        }
    }

    pub(crate) async fn observe_future<F: std::future::Future>(&mut self, future: F) -> F::Output {
        let Some(started) = self.started.as_mut() else {
            return future.await;
        };
        let mut future = Box::pin(future);
        std::future::poll_fn(|cx| {
            let at = Instant::now();
            let result = future.as_mut().poll(cx);
            let elapsed = at.elapsed().as_nanos() as u64;
            started.polls += 1;
            started.pending_polls += u64::from(result.is_pending());
            started.active_poll_ns += elapsed;
            started.max_active_poll_ns = started.max_active_poll_ns.max(elapsed);
            result
        })
        .await
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
                polls = started.polls, pending_polls = started.pending_polls,
                active_poll_ns = started.active_poll_ns,
                max_active_poll_ns = started.max_active_poll_ns,
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
