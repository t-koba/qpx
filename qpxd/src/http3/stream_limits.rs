use anyhow::{Result, anyhow};
use http::HeaderMap;
use std::future::Future;
use tokio::time::{Duration, Instant, sleep_until, timeout};

pub(crate) async fn timeout_or_deadline<F, T>(
    future: F,
    operation_timeout: Duration,
    stream_deadline: Option<Instant>,
    timeout_message: &'static str,
    deadline_message: &'static str,
) -> Result<T>
where
    F: Future<Output = T>,
{
    let operation = timeout(operation_timeout, future);
    tokio::pin!(operation);
    if let Some(deadline) = stream_deadline {
        tokio::select! {
            _ = sleep_until(deadline) => Err(anyhow!(deadline_message)),
            result = &mut operation => result.map_err(|_| anyhow!(timeout_message)),
        }
    } else {
        operation.await.map_err(|_| anyhow!(timeout_message))
    }
}

pub(crate) fn response_stream_timeouts(
    headers: &HeaderMap,
    default_timeout: Duration,
    default_send_timeout: Duration,
    default_deadline: Option<Instant>,
    sse_policy: Option<qpx_core::config::SseStreamingPolicy>,
) -> (Duration, Duration, Option<Instant>) {
    let Some(policy) = sse_policy else {
        return (default_timeout, default_send_timeout, default_deadline);
    };
    if !crate::http::modules::is_event_stream_headers(headers) {
        return (default_timeout, default_send_timeout, default_deadline);
    }
    let idle = Duration::from_millis(policy.idle_timeout_ms.max(1));
    let deadline = if policy.max_stream_duration_ms == 0 {
        None
    } else {
        let duration_ms = policy
            .max_stream_duration_ms
            .min(qpx_core::config::MAX_SSE_STREAM_DURATION_MS);
        Instant::now().checked_add(Duration::from_millis(duration_ms))
    };
    (idle, default_send_timeout, deadline)
}
