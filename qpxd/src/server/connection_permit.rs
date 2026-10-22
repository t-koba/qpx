use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tracing::warn;

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

/// Accept the next TCP stream after acquiring one connection permit.
///
/// Shutdown updates and listener errors preserve the acceptor's retry/stop
/// behavior while ensuring every accepted stream carries its capacity permit.
pub(crate) async fn accept_tcp_with_connection_permit(
    listener: &TcpListener,
    semaphore: &Arc<Semaphore>,
    shutdown: &mut watch::Receiver<bool>,
    accept_error_message: &'static str,
) -> Result<Option<(OwnedSemaphorePermit, TcpStream, SocketAddr)>> {
    loop {
        let Some(permit) = acquire_connection_permit(semaphore, shutdown).await? else {
            return Ok(None);
        };
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    None
                } else {
                    continue;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok(accepted) => Some(accepted),
                Err(err) => {
                    warn!(error = ?err, "{accept_error_message}");
                    continue;
                }
            }
        };
        let Some((stream, remote_addr)) = accepted else {
            return Ok(None);
        };
        return Ok(Some((permit, stream, remote_addr)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::poll;

    #[tokio::test]
    async fn accepted_stream_carries_its_connection_permit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let semaphore = Arc::new(Semaphore::new(1));
        let (_sender, mut shutdown) = watch::channel(false);
        let client = tokio::spawn(TcpStream::connect(address));

        let accepted = accept_tcp_with_connection_permit(
            &listener,
            &semaphore,
            &mut shutdown,
            "test accept failed",
        )
        .await
        .unwrap()
        .unwrap();
        let (permit, stream, remote_addr) = accepted;
        assert_eq!(
            remote_addr,
            client.await.unwrap().unwrap().local_addr().unwrap()
        );
        assert_eq!(stream.peer_addr().unwrap(), remote_addr);
        assert_eq!(semaphore.available_permits(), 0);
        drop(permit);
        assert_eq!(semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn shutdown_while_waiting_to_accept_releases_the_permit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let semaphore = Arc::new(Semaphore::new(1));
        let (sender, mut shutdown) = watch::channel(false);
        sender.send(true).unwrap();

        let accepted = accept_tcp_with_connection_permit(
            &listener,
            &semaphore,
            &mut shutdown,
            "test accept failed",
        )
        .await
        .unwrap();
        assert!(accepted.is_none());
        assert_eq!(semaphore.available_permits(), 1);
    }

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
