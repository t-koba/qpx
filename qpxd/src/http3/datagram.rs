use bytes::Bytes;
use h3::error::Code;
use h3::error::connection_error_creators::CloseStream;
use h3::error::internal_error::InternalConnectionError;
use h3::quic::StreamId;
use metrics::{counter, histogram};
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tracing::warn;

pub(crate) type H3DatagramSender =
    h3_datagram::datagram_handler::DatagramSender<h3_quinn::datagram::SendDatagramHandler, Bytes>;
pub(crate) type H3DatagramReader =
    h3_datagram::datagram_handler::DatagramReader<h3_quinn::datagram::RecvDatagramHandler>;

const DATAGRAM_ROUTE_SHARDS: usize = 64;

#[derive(Clone)]
enum DatagramRoute {
    Enabled(mpsc::Sender<Bytes>),
    Disabled,
}

pub(crate) struct H3DatagramDispatch {
    streams: Vec<RwLock<HashMap<StreamId, DatagramRoute>>>,
    channel_capacity: usize,
    utilization_samples: AtomicU64,
}

impl H3DatagramDispatch {
    pub(crate) fn new(channel_capacity: usize) -> Self {
        Self {
            streams: (0..DATAGRAM_ROUTE_SHARDS)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
            channel_capacity,
            utilization_samples: AtomicU64::new(0),
        }
    }

    fn shard(&self, stream_id: &StreamId) -> &RwLock<HashMap<StreamId, DatagramRoute>> {
        let mut hasher = DefaultHasher::new();
        stream_id.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % self.streams.len();
        &self.streams[idx]
    }

    fn should_record_utilization(&self) -> bool {
        self.utilization_samples
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(64)
    }

    pub(crate) async fn register_stream(
        self: &Arc<Self>,
        stream_id: StreamId,
        sender: H3DatagramSender,
    ) -> H3StreamDatagrams {
        let (tx, rx) = mpsc::channel(self.channel_capacity.max(1));
        self.shard(&stream_id)
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(stream_id, DatagramRoute::Enabled(tx.clone()));
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
        self.shard(&stream_id)
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(stream_id, DatagramRoute::Disabled);
        DatagramRegistration {
            dispatch: self.clone(),
            stream_id,
        }
    }

    async fn unregister(&self, stream_id: StreamId) {
        self.shard(&stream_id)
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&stream_id);
    }

    pub(crate) async fn run(self: Arc<Self>, mut reader: H3DatagramReader) {
        loop {
            match reader.read_datagram().await {
                Ok(datagram) => {
                    let stream_id = datagram.stream_id();
                    let payload = datagram.into_payload();
                    let route = self
                        .shard(&stream_id)
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get(&stream_id)
                        .cloned();
                    match route {
                        Some(DatagramRoute::Enabled(tx)) => {
                            let len = payload.len() as u64;
                            if self.should_record_utilization() {
                                record_datagram_channel_utilization(&tx);
                            }
                            if tx.capacity() == 0 {
                                counter!(
                                    "qpx_datagram_dropped_total",
                                    "transport" => "h3",
                                    "listener" => "unknown",
                                    "reason" => "channel_full"
                                )
                                .increment(1);
                                continue;
                            }
                            match tx.try_send(payload) {
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
