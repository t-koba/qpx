use super::{
    H3ConnInfo, H3ConnectKind, H3DatagramDispatch, H3RequestHandler, ScheduledH3Stream,
    classify_h3_connect_kind, request_priority, run_priority_scheduler,
};
use crate::server::control::SidecarControl;
use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc, watch};
use tracing::{info, warn};

pub(crate) async fn serve_endpoint<H: H3RequestHandler>(
    endpoint: quinn::Endpoint,
    dst_port: u16,
    handler: H,
    label: &str,
    connection_semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<SidecarControl>,
) -> Result<()> {
    info!(label = %label, "HTTP/3 listener starting");
    loop {
        let connecting = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || shutdown.borrow().should_stop() {
                    None
                } else {
                    continue;
                }
            }
            connecting = endpoint.accept() => connecting
        };
        let Some(connecting) = connecting else {
            break;
        };
        let handler = handler.clone();
        let label = label.to_string();
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
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = serve_connection(connecting, dst_port, handler).await {
                warn!(label = %label, error = ?err, "HTTP/3 connection failed");
            }
        });
    }
    Ok(())
}

fn extract_tls_sni(conn: &quinn::Connection) -> Option<Arc<str>> {
    conn.handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hs| hs.server_name.clone())
        .map(Arc::<str>::from)
}

#[cfg(feature = "tls-rustls")]
fn extract_peer_certificates(conn: &quinn::Connection) -> Option<Arc<Vec<Vec<u8>>>> {
    let identity = conn.peer_identity()?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    Some(Arc::new(
        certs
            .iter()
            .map(|cert| cert.as_ref().to_vec())
            .collect::<Vec<_>>(),
    ))
}

async fn serve_connection<H: H3RequestHandler>(
    connecting: quinn::Incoming,
    dst_port: u16,
    handler: H,
) -> Result<()> {
    let limits = handler.limits();
    let stream_semaphore = Arc::new(Semaphore::new(
        limits.max_concurrent_streams_per_connection.max(1),
    ));
    let connection = connecting.await?;
    let conn_info = H3ConnInfo {
        remote_addr: connection.remote_address(),
        dst_port,
        tls_sni: extract_tls_sni(&connection),
        #[cfg(feature = "tls-rustls")]
        peer_certificates: extract_peer_certificates(&connection),
    };
    let mut builder = ::h3::server::builder();
    builder
        // Keep response trailer/FIN sequencing deterministic. GREASE frames are
        // optional, and sending one after trailers has exposed platform-specific
        // trailer-drain flakes in the h3 client used by the e2e tests.
        .send_grease(false)
        .enable_extended_connect(handler.enable_extended_connect())
        .enable_datagram(handler.enable_datagram());
    let mut h3_conn = builder
        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
        .await?;

    let datagram_dispatch = if handler.enable_datagram() {
        use h3_datagram::datagram_handler::HandleDatagramsExt as _;

        let dispatch = Arc::new(H3DatagramDispatch::new(limits.datagram_channel_capacity));
        let reader = h3_conn.get_datagram_reader();
        let dispatch_task = dispatch.clone();
        tokio::spawn(async move {
            dispatch_task.run(reader).await;
        });
        Some(dispatch)
    } else {
        None
    };

    let scheduler_capacity = limits
        .max_concurrent_streams_per_connection
        .saturating_mul(4)
        .max(1);
    let (scheduler_tx, scheduler_rx) = mpsc::channel(scheduler_capacity);
    let scheduler = tokio::spawn(run_priority_scheduler(
        scheduler_rx,
        stream_semaphore.clone(),
        handler.clone(),
        conn_info.clone(),
        limits.clone(),
    ));

    while let Some(resolver) = h3_conn.accept().await? {
        let (req_head, req_stream) = resolver.resolve_request().await?;
        let connect_kind = (req_head.method() == ::http::Method::CONNECT)
            .then(|| classify_h3_connect_kind(req_head.extensions().get().cloned()));
        let stream_id = req_stream.id();
        let (datagrams, disabled_datagram_registration) =
            match (datagram_dispatch.as_ref(), connect_kind) {
                (Some(dispatch), Some(H3ConnectKind::ConnectUdp))
                | (
                    Some(dispatch),
                    Some(H3ConnectKind::Extended(::h3::ext::Protocol::WEB_TRANSPORT)),
                ) => {
                    use h3_datagram::datagram_handler::HandleDatagramsExt as _;
                    let sender = h3_conn.get_datagram_sender(stream_id);
                    (
                        Some(dispatch.register_stream(stream_id, sender).await),
                        None,
                    )
                }
                (Some(dispatch), _) => (
                    None,
                    Some(dispatch.register_stream_without_datagrams(stream_id).await),
                ),
                (None, _) => (None, None),
            };
        let priority = request_priority(req_head.headers());
        if scheduler_tx
            .send(ScheduledH3Stream {
                req_head,
                req_stream,
                datagrams,
                disabled_datagram_registration,
                priority,
            })
            .await
            .is_err()
        {
            break;
        }
    }
    drop(scheduler_tx);
    let _ = scheduler.await;
    Ok(())
}
