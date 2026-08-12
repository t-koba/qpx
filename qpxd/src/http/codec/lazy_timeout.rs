use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::time::{Duration, Instant, Sleep, sleep};

#[derive(Debug)]
pub(crate) struct TimeoutElapsed;

struct TimeoutAfterPending<F, P> {
    future: F,
    duration: Duration,
    timer: Option<Sleep>,
    on_pending: P,
    completed: bool,
}

pub(crate) struct ReusablePendingTimeout<'a> {
    timer: Pin<&'a mut Sleep>,
}

struct TimeoutAfterPendingWithReusable<'a, 'timer, F, P> {
    future: F,
    duration: Duration,
    timeout: &'a mut ReusablePendingTimeout<'timer>,
    on_pending: P,
    armed: bool,
    completed: bool,
}

impl<'a> ReusablePendingTimeout<'a> {
    pub(crate) fn new(timer: Pin<&'a mut Sleep>) -> Self {
        Self { timer }
    }

    pub(crate) fn timeout_after_pending<F>(
        &mut self,
        duration: Duration,
        future: F,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>>
    where
        F: Future,
    {
        self.timeout_after_pending_with(duration, future, || {})
    }

    pub(crate) fn timeout_after_pending_with<F, P>(
        &mut self,
        duration: Duration,
        future: F,
        on_pending: P,
    ) -> impl Future<Output = Result<F::Output, TimeoutElapsed>>
    where
        F: Future,
        P: FnMut(),
    {
        TimeoutAfterPendingWithReusable {
            future,
            duration,
            timeout: self,
            on_pending,
            armed: false,
            completed: false,
        }
    }
}

pub(crate) fn timeout_after_pending<F>(
    duration: Duration,
    future: F,
) -> impl Future<Output = Result<F::Output, TimeoutElapsed>>
where
    F: Future,
{
    timeout_after_pending_with(duration, future, || {})
}

pub(crate) fn timeout_after_pending_with<F, P>(
    duration: Duration,
    future: F,
    on_pending: P,
) -> impl Future<Output = Result<F::Output, TimeoutElapsed>>
where
    F: Future,
    P: FnMut(),
{
    TimeoutAfterPending {
        future,
        duration,
        timer: None,
        on_pending,
        completed: false,
    }
}

impl<F, P> Future for TimeoutAfterPending<F, P>
where
    F: Future,
    P: FnMut(),
{
    type Output = Result<F::Output, TimeoutElapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: `future` is never moved after the wrapper is pinned. The other
        // fields are not structurally pinned and may be updated independently.
        let this = unsafe { self.get_unchecked_mut() };
        assert!(!this.completed, "timeout future polled after completion");
        // SAFETY: the wrapper owns `future` and never moves it while pinned.
        let future = unsafe { Pin::new_unchecked(&mut this.future) };
        if let Poll::Ready(output) = future.poll(cx) {
            this.completed = true;
            return Poll::Ready(Ok(output));
        }

        let timer = match this.timer.as_mut() {
            Some(timer) => timer,
            None => {
                (this.on_pending)();
                // Inserting the timer into an empty slot does not move a previously
                // pinned value. Once initialized, this field is never replaced.
                this.timer.insert(sleep(this.duration))
            }
        };
        // SAFETY: the timer is initialized only after the wrapper is pinned and
        // remains in the same field until the wrapper is dropped.
        if unsafe { Pin::new_unchecked(timer) }.poll(cx).is_ready() {
            this.completed = true;
            Poll::Ready(Err(TimeoutElapsed))
        } else {
            Poll::Pending
        }
    }
}

impl<F, P> Future for TimeoutAfterPendingWithReusable<'_, '_, F, P>
where
    F: Future,
    P: FnMut(),
{
    type Output = Result<F::Output, TimeoutElapsed>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: `future` is never moved after the wrapper is pinned. The other
        // fields are not structurally pinned and may be updated independently.
        let this = unsafe { self.get_unchecked_mut() };
        assert!(!this.completed, "timeout future polled after completion");
        // SAFETY: the wrapper owns `future` and never moves it while pinned.
        let future = unsafe { Pin::new_unchecked(&mut this.future) };
        if let Poll::Ready(output) = future.poll(cx) {
            this.completed = true;
            return Poll::Ready(Ok(output));
        }

        if !this.armed {
            (this.on_pending)();
            let deadline = Instant::now() + this.duration;
            this.timeout.timer.as_mut().reset(deadline);
            this.armed = true;
        }
        if this.timeout.timer.as_mut().poll(cx).is_ready() {
            this.completed = true;
            Poll::Ready(Err(TimeoutElapsed))
        } else {
            Poll::Pending
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

    #[tokio::test]
    async fn reusable_timeout_restarts_the_same_pinned_timer() {
        let timer = sleep(Duration::ZERO);
        tokio::pin!(timer);
        let timer_address = std::ptr::from_ref(timer.as_ref().get_ref());
        let mut timeout = ReusablePendingTimeout::new(timer.as_mut());
        let ready = timeout
            .timeout_after_pending(Duration::ZERO, std::future::ready(42))
            .await;
        assert_eq!(ready.expect("immediate result"), 42);

        let first = timeout
            .timeout_after_pending(Duration::from_millis(1), std::future::pending::<()>())
            .await;
        assert!(first.is_err());
        assert_eq!(
            std::ptr::from_ref(timeout.timer.as_ref().get_ref()),
            timer_address
        );

        let second = timeout
            .timeout_after_pending(Duration::from_millis(1), std::future::pending::<()>())
            .await;
        assert!(second.is_err());
        assert_eq!(
            std::ptr::from_ref(timeout.timer.as_ref().get_ref()),
            timer_address
        );
    }
}
