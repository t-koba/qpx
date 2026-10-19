use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

/// Wait for connection capacity, retrying false shutdown updates and stopping on
/// a true update or channel closure. Semaphore closure remains an error.
pub(crate) async fn acquire_connection_permit(
    semaphore: &Arc<Semaphore>,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<Option<OwnedSemaphorePermit>> {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(None);
                }
            }
            permit = semaphore.clone().acquire_owned() => return Ok(Some(permit?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::poll;

    #[tokio::test]
    async fn false_shutdown_update_retries_until_permit_is_available() {
        let semaphore = Arc::new(Semaphore::new(0));
        let (sender, mut shutdown) = watch::channel(false);
        let acquisition = acquire_connection_permit(&semaphore, &mut shutdown);
        tokio::pin!(acquisition);
        assert!(poll!(&mut acquisition).is_pending());
        sender.send(false).unwrap();
        assert!(poll!(&mut acquisition).is_pending());
        semaphore.add_permits(1);
        let permit = acquisition.await.unwrap().unwrap();
        assert_eq!(semaphore.available_permits(), 0);
        drop(permit);
        assert_eq!(semaphore.available_permits(), 1);
    }
}
