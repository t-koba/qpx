use crate::server::control::SidecarControl;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Semaphore, watch};
use tracing::warn;

/// Runs the qpx-h3 connection accept loop shared by forward and reverse H3.
/// The callers retain their listener setup and policy; this owner only admits
/// connections and holds each capacity permit for the connection lifetime.
pub(crate) async fn serve_qpx_h3_endpoint<H: qpx_h3::RequestHandler>(
    endpoint: quinn::Endpoint,
    listen_addr: SocketAddr,
    handler: H,
    connection_semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<SidecarControl>,
    connection_failure_message: &'static str,
) -> Result<()> {
    loop {
        let connecting = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            connecting = endpoint.accept() => connecting,
        };
        let Some(connecting) = connecting else {
            break;
        };
        let permit = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            permit = connection_semaphore.clone().acquire_owned() => Some(permit?),
        };
        let Some(permit) = permit else {
            break;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) =
                qpx_h3::serve_connection(connecting, listen_addr.port(), handler).await
            {
                warn!(error = ?err, "{connection_failure_message}");
            }
        });
    }

    Ok(())
}
