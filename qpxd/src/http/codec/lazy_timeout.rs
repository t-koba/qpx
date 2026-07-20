use std::future::{Future, poll_fn};
use std::task::Poll;
use tokio::time::{Duration, error::Elapsed, timeout};

pub(crate) async fn timeout_after_pending<F>(
    duration: Duration,
    future: F,
) -> Result<F::Output, Elapsed>
where
    F: Future,
{
    timeout_after_pending_with(duration, future, || {}).await
}

pub(crate) async fn timeout_after_pending_with<F, P>(
    duration: Duration,
    future: F,
    on_pending: P,
) -> Result<F::Output, Elapsed>
where
    F: Future,
    P: FnOnce(),
{
    tokio::pin!(future);
    let ready = poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Ready(output) => Poll::Ready(Some(output)),
        Poll::Pending => Poll::Ready(None),
    })
    .await;
    match ready {
        Some(output) => Ok(output),
        None => {
            on_pending();
            timeout(duration, future).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn immediate_future_completes_without_a_timer() {
        let result = timeout_after_pending(Duration::ZERO, std::future::ready(42)).await;

        assert_eq!(result.expect("immediate result"), 42);
    }

    #[tokio::test]
    async fn pending_future_remains_timeout_protected() {
        let result =
            timeout_after_pending(Duration::from_millis(1), std::future::pending::<()>()).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn pending_hook_runs_only_after_the_first_pending_poll() {
        let pending_hook_calls = std::cell::Cell::new(0);
        let ready = timeout_after_pending_with(Duration::ZERO, std::future::ready(42), || {
            pending_hook_calls.set(pending_hook_calls.get() + 1);
        })
        .await;
        assert_eq!(ready.expect("immediate result"), 42);
        assert_eq!(pending_hook_calls.get(), 0);

        let pending = timeout_after_pending_with(
            Duration::from_millis(1),
            std::future::pending::<()>(),
            || pending_hook_calls.set(pending_hook_calls.get() + 1),
        )
        .await;
        assert!(pending.is_err());
        assert_eq!(pending_hook_calls.get(), 1);
    }
}
