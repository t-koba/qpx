use bytes::Buf;
use bytes::Bytes;
use h3::error::Code;
use h3::error::connection_error_creators::CloseStream;
use h3::error::internal_error::InternalConnectionError;
use h3::quic::StreamId;
use metrics::{counter, histogram};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

pub(crate) type H3DatagramSender =
    h3_datagram::datagram_handler::DatagramSender<h3_quinn::datagram::SendDatagramHandler, Bytes>;
pub(crate) type H3DatagramReader =
    h3_datagram::datagram_handler::DatagramReader<h3_quinn::datagram::RecvDatagramHandler>;

#[derive(Clone)]
enum DatagramRoute {
    Enabled(mpsc::Sender<Bytes>),
    Disabled,
}

pub(crate) struct H3DatagramDispatch {
    streams: Mutex<HashMap<StreamId, DatagramRoute>>,
    channel_capacity: usize,
}

impl H3DatagramDispatch {
    pub(crate) fn new(channel_capacity: usize) -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            channel_capacity,
        }
    }

    pub(crate) async fn register_stream(
        self: &Arc<Self>,
        stream_id: StreamId,
        sender: H3DatagramSender,
    ) -> H3StreamDatagrams {
        let (tx, rx) = mpsc::channel(self.channel_capacity.max(1));
        {
            let mut guard = self.streams.lock().await;
            guard.insert(stream_id, DatagramRoute::Enabled(tx));
        }
        H3StreamDatagrams {
            sender,
            receiver: rx,
            _registration: DatagramRegistration {
                dispatch: self.clone(),
                stream_id,
            },
        }
    }

    pub(crate) async fn register_stream_without_datagrams(
        self: &Arc<Self>,
        stream_id: StreamId,
    ) -> DatagramRegistration {
        self.streams
            .lock()
            .await
            .insert(stream_id, DatagramRoute::Disabled);
        DatagramRegistration {
            dispatch: self.clone(),
            stream_id,
        }
    }

    async fn unregister(&self, stream_id: StreamId) {
        let mut guard = self.streams.lock().await;
        guard.remove(&stream_id);
    }

    pub(crate) async fn run(self: Arc<Self>, mut reader: H3DatagramReader) {
        loop {
            match reader.read_datagram().await {
                Ok(datagram) => {
                    let stream_id = datagram.stream_id();
                    let mut payload = datagram.into_payload();
                    let bytes = payload.copy_to_bytes(payload.remaining());
                    let route = { self.streams.lock().await.get(&stream_id).cloned() };
                    match route {
                        Some(DatagramRoute::Enabled(tx)) => {
                            let len = bytes.len() as u64;
                            record_datagram_channel_utilization(&tx);
                            match tx.try_send(bytes) {
                                Ok(()) => {
                                    counter!(
                                        "qpx_datagram_received_total",
                                        "transport" => "h3",
                                        "listener" => "unknown"
                                    )
                                    .increment(1);
                                    counter!(
                                        "qpx_datagram_received_bytes_total",
                                        "transport" => "h3",
                                        "listener" => "unknown"
                                    )
                                    .increment(len);
                                }
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    counter!(
                                        "qpx_datagram_dropped_total",
                                        "transport" => "h3",
                                        "listener" => "unknown",
                                        "reason" => "channel_full"
                                    )
                                    .increment(1);
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {}
                            }
                        }
                        Some(DatagramRoute::Disabled) => {
                            counter!(
                                "qpx_datagram_dropped_total",
                                "transport" => "h3",
                                "listener" => "unknown",
                                "reason" => "disabled"
                            )
                            .increment(1);
                            let _ = reader.handle_connection_error_on_stream(
                                InternalConnectionError::new(
                                    Code::H3_DATAGRAM_ERROR,
                                    "datagram received for stream without datagram semantics"
                                        .to_string(),
                                ),
                            );
                            break;
                        }
                        None => {
                            counter!(
                                "qpx_datagram_dropped_total",
                                "transport" => "h3",
                                "listener" => "unknown",
                                "reason" => "unknown_stream"
                            )
                            .increment(1);
                        }
                    }
                }
                Err(err) => {
                    warn!(error = ?err, "HTTP/3 datagram reader stopped");
                    break;
                }
            }
        }
    }
}

fn record_datagram_channel_utilization(tx: &mpsc::Sender<Bytes>) {
    let max = tx.max_capacity();
    if max == 0 {
        return;
    }
    let used = max.saturating_sub(tx.capacity());
    histogram!(
        "qpx_datagram_channel_utilization",
        "transport" => "h3",
        "listener" => "unknown"
    )
    .record(used as f64 / max as f64);
}

pub(crate) struct H3StreamDatagrams {
    pub(crate) sender: H3DatagramSender,
    pub(crate) receiver: mpsc::Receiver<Bytes>,
    _registration: DatagramRegistration,
}

pub(crate) struct DatagramRegistration {
    dispatch: Arc<H3DatagramDispatch>,
    stream_id: StreamId,
}

impl Drop for DatagramRegistration {
    fn drop(&mut self) {
        let dispatch = self.dispatch.clone();
        let stream_id = self.stream_id;
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            dispatch.unregister(stream_id).await;
        });
    }
}
