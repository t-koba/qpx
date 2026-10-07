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

    pub(crate) fn measure_sync<T>(&self, work: impl FnOnce() -> T) -> T {
        #[cfg(target_os = "linux")]
        if self.started.is_some() {
            let wall_started = Instant::now();
            let cpu_started = thread_cpu_ns();
            let result = work();
            let cpu_finished = thread_cpu_ns();
            let wall_ns = wall_started.elapsed().as_nanos();
            match cpu_started.and_then(|start| {
                cpu_finished.and_then(|end| {
                    end.checked_sub(start)
                        .filter(|cpu| u128::from(*cpu) <= wall_ns)
                        .ok_or_else(|| {
                            std::io::Error::other("synchronous phase CPU clock is inconsistent")
                        })
                })
            }) {
                Ok(cpu_ns) => tracing::debug!(target: "qpx_perf_phase", phase = self.phase,
                    elapsed_ns = wall_ns as u64, cpu_ns, sample_interval = SAMPLE_INTERVAL,
                    thread = ?std::thread::current().id(), "performance phase synchronous CPU sampled"),
                Err(error) => tracing::error!(target: "qpx_perf_phase", phase = self.phase,
                    error = %error, "performance phase CPU sampling failed"),
            }
            return result;
        }
        work()
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

#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> std::io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // The thread CPU clock brackets one synchronous closure without migration.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let seconds = u64::try_from(time.tv_sec)
        .map_err(|_| std::io::Error::other("thread CPU clock has negative seconds"))?;
    let nanoseconds = u64::try_from(time.tv_nsec)
        .ok()
        .filter(|value| *value < 1_000_000_000)
        .ok_or_else(|| std::io::Error::other("thread CPU clock has invalid nanoseconds"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| std::io::Error::other("thread CPU clock exceeds nanosecond range"))
}

macro_rules! phase_timer {
    ($phase:literal) => {{
        static SAMPLES: ::std::sync::atomic::AtomicU64 = ::std::sync::atomic::AtomicU64::new(0);
        $crate::perf_diagnostics::PhaseTimer::begin($phase, &SAMPLES)
    }};
}
pub(crate) use phase_timer;
