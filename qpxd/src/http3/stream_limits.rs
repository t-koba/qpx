use anyhow::{Result, anyhow};
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
