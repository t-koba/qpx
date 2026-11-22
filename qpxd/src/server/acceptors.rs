use anyhow::{Result, anyhow};
use futures_util::future::select_all;
use tokio::task::JoinHandle;

/// Awaits listener acceptors and reports the first failure without waiting for the others.
pub(crate) async fn join_acceptor_tasks(
    tasks: Vec<JoinHandle<Result<()>>>,
    listener_kind: &str,
) -> Result<()> {
    let mut tasks = tasks;
    while !tasks.is_empty() {
        let (joined, _index, remaining) = select_all(tasks).await;
        tasks = remaining;
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                for task in tasks {
                    task.abort();
                }
                return Err(err);
            }
            Err(err) => {
                for task in tasks {
                    task.abort();
                }
                return Err(anyhow!("{listener_kind} acceptor task failed: {err}"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::join_acceptor_tasks;
    use anyhow::{Result, anyhow};
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn successful_acceptor_tasks_join() -> Result<()> {
        let task: JoinHandle<Result<()>> = tokio::spawn(async { Ok(()) });
        join_acceptor_tasks(vec![task], "test").await
    }

    #[tokio::test]
    async fn child_error_is_returned_without_join_context() {
        let task: JoinHandle<Result<()>> = tokio::spawn(async { Err(anyhow!("child failure")) });
        let error = join_acceptor_tasks(vec![task], "test")
            .await
            .expect_err("child error must propagate");
        assert_eq!(error.to_string(), "child failure");
    }

    #[tokio::test]
    async fn join_error_keeps_listener_context() {
        let task: JoinHandle<Result<()>> = tokio::spawn(async { std::future::pending().await });
        task.abort();
        let error = join_acceptor_tasks(vec![task], "test")
            .await
            .expect_err("cancelled task must fail the join");
        assert!(
            error
                .to_string()
                .starts_with("test acceptor task failed: task ")
        );
        assert!(error.to_string().ends_with(" was cancelled"));
    }

    #[tokio::test]
    async fn later_acceptor_error_is_not_hidden_by_an_active_first_acceptor() {
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let active: JoinHandle<Result<()>> = tokio::spawn(async move {
            let _ = release_rx.await;
            Ok(())
        });
        let failed: JoinHandle<Result<()>> = tokio::spawn(async { Err(anyhow!("child failure")) });

        let joined = timeout(
            Duration::from_millis(200),
            join_acceptor_tasks(vec![active, failed], "test"),
        )
        .await
        .expect("a failed acceptor must be reported while an earlier acceptor is active");
        let error = joined.expect_err("child error must propagate");
        assert_eq!(error.to_string(), "child failure");
        drop(release_tx);
    }
}
