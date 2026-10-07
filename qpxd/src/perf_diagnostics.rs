use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::{sync::Arc, task::Wake};

const SAMPLE_INTERVAL: u64 = 1024;
static TCP_TIMELINE_ENABLED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
    std::env::var_os("QPX_PERF_NATIVE_IO_TIMELINE").as_deref() == Some(std::ffi::OsStr::new("1"))
});
#[cfg(target_os = "linux")]
static IO_SAMPLE_IDS: AtomicU64 = AtomicU64::new(1);

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
    notified_wait_ns: u64,
    before_notify_ns: u64,
    unnotified_wait_ns: u64,
    notified_resumptions: u64,
    io_sample_id: u64,
    first_notification_ns: u64,
    poll_cpu: Option<PollCpu>,
}

#[derive(Default)]
struct PollCpu {
    polls: u64,
    errors: u64,
    active_ns: u64,
    max_ns: u64,
    cpu_at_max_wall_ns: u64,
}

struct RecordedWake {
    at: Instant,
    first_notify_ns: AtomicU64,
    parent: std::task::Waker,
}

impl Wake for RecordedWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let _ = self.first_notify_ns.compare_exchange(
            0,
            self.at.elapsed().as_nanos() as u64 + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        // Forward every notification to the original task, including repeated wakes.
        self.parent.wake_by_ref();
    }
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
        Self::begin_sampled(phase, sampled)
    }

    pub(crate) fn begin_native_h2_connection() -> Self {
        Self::begin_sampled(
            "h2_connection_poll",
            *TCP_TIMELINE_ENABLED
                && tracing::enabled!(target: "qpx_perf_phase", tracing::Level::DEBUG),
        )
    }

    fn begin_sampled(phase: &'static str, sampled: bool) -> Self {
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
                    notified_wait_ns: 0,
                    before_notify_ns: 0,
                    unnotified_wait_ns: 0,
                    notified_resumptions: 0,
                    io_sample_id: 0,
                    first_notification_ns: 0,
                    poll_cpu: (cfg!(target_os = "linux") && phase == "h2_connection_poll")
                        .then(PollCpu::default),
                })
            }),
        }
    }

    pub(crate) fn record_native_tcp_identity<S: 'static>(
        &mut self,
        stream: &S,
    ) -> std::io::Result<()> {
        if !*TCP_TIMELINE_ENABLED || self.started.is_none() {
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            let socket = (stream as &dyn std::any::Any)
                .downcast_ref::<tokio::net::TcpStream>()
                .ok_or_else(|| std::io::Error::other("native I/O phase requires a TCP stream"))?;
            self.record_tcp_identity(socket)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "native I/O phase timeline requires Linux",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn record_tcp_identity(&mut self, socket: &tokio::net::TcpStream) -> std::io::Result<()> {
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        let started = self
            .started
            .as_mut()
            .ok_or_else(|| std::io::Error::other("native I/O identity requires a sampled phase"))?;
        let monotonic_before_ns = native_monotonic_ns()?;
        let phase_offset_ns = started.at.elapsed().as_nanos() as u64;
        let monotonic_after_ns = native_monotonic_ns()?;
        if monotonic_after_ns < monotonic_before_ns {
            return Err(std::io::Error::other(
                "native I/O monotonic clock regressed",
            ));
        }
        started.io_sample_id = IO_SAMPLE_IDS.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(target: "qpx_perf_phase", phase = self.phase,
            io_sample_id = started.io_sample_id, monotonic_before_ns, monotonic_after_ns,
            phase_offset_ns,
            local = %local, peer = %peer, "native TCP phase identity");
        Ok(())
    }

    pub(crate) async fn observe_future<F: std::future::Future>(&mut self, future: F) -> F::Output {
        let Some(started) = self.started.as_mut() else {
            return future.await;
        };
        let mut future = Box::pin(future);
        let mut pending: Option<(Arc<RecordedWake>, u64)> = None;
        std::future::poll_fn(|cx| {
            let poll_started = started.at.elapsed().as_nanos() as u64;
            if let Some((previous, pending_since)) = pending.take() {
                let notified = previous.first_notify_ns.load(Ordering::Relaxed);
                if notified > 0 && notified - 1 <= poll_started {
                    if started.first_notification_ns == 0 {
                        started.first_notification_ns = notified - 1;
                    }
                    let notification = (notified - 1).clamp(pending_since, poll_started);
                    started.before_notify_ns += notification - pending_since;
                    started.notified_wait_ns += poll_started - notification;
                    started.notified_resumptions += 1;
                } else {
                    started.unnotified_wait_ns += poll_started - pending_since;
                }
            }
            let probe = Arc::new(RecordedWake {
                at: started.at,
                first_notify_ns: AtomicU64::new(0),
                parent: cx.waker().clone(),
            });
            let waker = std::task::Waker::from(Arc::clone(&probe));
            let mut observed = std::task::Context::from_waker(&waker);
            let at = Instant::now();
            #[cfg(target_os = "linux")]
            let monotonic_before = started.poll_cpu.as_ref().map(|_| native_monotonic_ns());
            #[cfg(target_os = "linux")]
            let cpu_before = started.poll_cpu.as_ref().map(|_| native_thread_cpu_ns());
            let result = future.as_mut().poll(&mut observed);
            #[cfg(target_os = "linux")]
            let cpu_after = started.poll_cpu.as_ref().map(|_| native_thread_cpu_ns());
            let elapsed = at.elapsed().as_nanos() as u64;
            #[cfg(target_os = "linux")]
            let monotonic_after = started.poll_cpu.as_ref().map(|_| native_monotonic_ns());
            #[cfg(target_os = "linux")]
            if let (Some(before), Some(after), Some(cpu)) =
                (cpu_before, cpu_after, started.poll_cpu.as_mut())
            {
                let measured = before.and_then(|before| {
                    after.and_then(|after| {
                        after.checked_sub(before).ok_or_else(|| {
                            std::io::Error::other("performance phase thread CPU clock regressed")
                        })
                    })
                });
                match measured {
                    Ok(measured) => {
                        cpu.polls += 1;
                        cpu.active_ns += measured;
                        cpu.max_ns = cpu.max_ns.max(measured);
                        if elapsed >= 1_000_000 {
                            match monotonic_before.zip(monotonic_after) {
                                Some((Ok(begin), Ok(end))) if end >= begin => {
                                    // SAFETY: gettid has no arguments and returns this Linux thread.
                                    let native_tid = unsafe { libc::gettid() };
                                    tracing::debug!(target: "qpx_perf_phase", native_tid,
                                        monotonic_begin_ns = begin, monotonic_end_ns = end,
                                        wall_ns = elapsed, cpu_ns = measured,
                                        poll_index = started.polls,
                                        thread = ?std::thread::current().id(),
                                        "native H2 long poll interval");
                                }
                                clocks => {
                                    cpu.errors += 1;
                                    tracing::error!(target: "qpx_perf_phase", clocks = ?clocks,
                                        "native H2 poll interval clock failed");
                                }
                            }
                        }
                        if elapsed >= started.max_active_poll_ns {
                            cpu.cpu_at_max_wall_ns = measured;
                        }
                    }
                    Err(error) => {
                        cpu.errors += 1;
                        tracing::debug!(target: "qpx_perf_phase", error = ?error,
                            "performance phase CPU sampling failed");
                    }
                }
            }
            started.polls += 1;
            started.pending_polls += u64::from(result.is_pending());
            started.active_poll_ns += elapsed;
            started.max_active_poll_ns = started.max_active_poll_ns.max(elapsed);
            if result.is_pending() {
                pending = Some((probe, started.at.elapsed().as_nanos() as u64));
            }
            result
        })
        .await
    }
}

#[cfg(target_os = "linux")]
fn native_monotonic_ns() -> std::io::Result<u64> {
    native_clock_ns(libc::CLOCK_MONOTONIC)
}

#[cfg(target_os = "linux")]
fn native_thread_cpu_ns() -> std::io::Result<u64> {
    native_clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
}

#[cfg(target_os = "linux")]
fn native_clock_ns(clock_id: libc::clockid_t) -> std::io::Result<u64> {
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: callers provide a valid clock identifier and clock points to
    // initialized writable storage owned exclusively by this call.
    if unsafe { libc::clock_gettime(clock_id, &mut clock) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if !(0..1_000_000_000).contains(&clock.tv_nsec) {
        return Err(std::io::Error::other(
            "invalid performance diagnostic clock nanoseconds",
        ));
    }
    u64::try_from(clock.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(clock.tv_nsec as u64))
        .ok_or_else(|| std::io::Error::other("invalid performance diagnostic clock seconds"))
}

impl Drop for PhaseTimer {
    fn drop(&mut self) {
        if let Some(started) = self.started.as_ref() {
            let completed_thread = std::thread::current().id();
            tracing::debug!(target: "qpx_perf_phase", phase = self.phase,
                elapsed_ns = started.at.elapsed().as_nanos() as u64,
                sample_interval = if self.phase == "h2_connection_poll" { 1 } else { SAMPLE_INTERVAL },
                started_thread = ?started.thread,
                migrated = started.thread != completed_thread,
                polls = started.polls, pending_polls = started.pending_polls,
                active_poll_ns = started.active_poll_ns,
                max_active_poll_ns = started.max_active_poll_ns,
                notified_wait_ns = started.notified_wait_ns,
                before_notify_ns = started.before_notify_ns,
                unnotified_wait_ns = started.unnotified_wait_ns,
                notified_resumptions = started.notified_resumptions,
                io_sample_id = started.io_sample_id,
                first_notification_ns = started.first_notification_ns,
                poll_cpu_enabled = started.poll_cpu.is_some(),
                poll_cpu_samples = started.poll_cpu.as_ref().map_or(0, |cpu| cpu.polls),
                poll_cpu_errors = started.poll_cpu.as_ref().map_or(0, |cpu| cpu.errors),
                active_poll_cpu_ns = started.poll_cpu.as_ref().map_or(0, |cpu| cpu.active_ns),
                max_active_poll_cpu_ns = started.poll_cpu.as_ref().map_or(0, |cpu| cpu.max_ns),
                cpu_at_max_wall_poll_ns = started.poll_cpu.as_ref().map_or(0, |cpu| cpu.cpu_at_max_wall_ns),
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn sampled_future_forwards_real_tcp_readiness() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [1]);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            socket.write_all(b"ready").await.unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(&[1]).await.unwrap();
        let mut timer = PhaseTimer::begin_sampled("h2_connection_poll", true);
        #[cfg(target_os = "linux")]
        timer.record_tcp_identity(&client).unwrap();
        let mut response = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            timer.observe_future(client.read_exact(&mut response)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"ready");
        server.await.unwrap();
        let sample = timer.started.as_ref().unwrap();
        assert!(sample.pending_polls > 0);
        assert!(sample.notified_resumptions > 0);
        assert!(sample.before_notify_ns > 0);
        assert!(sample.first_notification_ns > 0);
        #[cfg(target_os = "linux")]
        {
            assert!(sample.io_sample_id > 0);
            let cpu = sample.poll_cpu.as_ref().expect("thread CPU evidence");
            assert_eq!(cpu.polls, sample.polls);
            assert_eq!(cpu.errors, 0);
            assert!(cpu.active_ns > 0);
            assert!(cpu.max_ns <= sample.max_active_poll_ns);
            assert!(cpu.active_ns <= sample.active_poll_ns);
        }
        assert!(
            sample.active_poll_ns
                + sample.before_notify_ns
                + sample.notified_wait_ns
                + sample.unnotified_wait_ns
                <= sample.at.elapsed().as_nanos() as u64
        );
    }
}
