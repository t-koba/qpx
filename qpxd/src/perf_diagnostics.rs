use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::{sync::Arc, task::Wake};

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
    notified_wait_ns: u64,
    before_notify_ns: u64,
    unnotified_wait_ns: u64,
    notified_resumptions: u64,
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
                })
            }),
        }
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
            let result = future.as_mut().poll(&mut observed);
            let elapsed = at.elapsed().as_nanos() as u64;
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
                notified_wait_ns = started.notified_wait_ns,
                before_notify_ns = started.before_notify_ns,
                unnotified_wait_ns = started.unnotified_wait_ns,
                notified_resumptions = started.notified_resumptions,
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
        let mut timer = PhaseTimer {
            phase: "tcp_readiness_test",
            started: Some(Box::new(StartedPhase {
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
            })),
        };
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
        assert!(
            sample.active_poll_ns
                + sample.before_notify_ns
                + sample.notified_wait_ns
                + sample.unnotified_wait_ns
                <= sample.at.elapsed().as_nanos() as u64
        );
    }
}
