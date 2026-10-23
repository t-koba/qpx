use anyhow::{Result, anyhow};
use tokio::task::JoinHandle;

/// Awaits listener acceptors in their configured order and preserves their errors.
pub(crate) async fn join_acceptor_tasks(
    tasks: Vec<JoinHandle<Result<()>>>,
    listener_kind: &str,
) -> Result<()> {
    for task in tasks {
        task.await
            .map_err(|err| anyhow!("{listener_kind} acceptor task failed: {err}"))??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::join_acceptor_tasks;
    use anyhow::{Result, anyhow};
    use tokio::task::JoinHandle;

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
}
