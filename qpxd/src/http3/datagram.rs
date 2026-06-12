use crate::http3::metrics;
use arc_swap::ArcSwap;
use bytes::Bytes;
use h3::error::Code;
use h3::error::connection_error_creators::CloseStream;
use h3::error::internal_error::InternalConnectionError;
use h3::quic::StreamId;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
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
    streams: Vec<DatagramRouteShard>,
    channel_capacity: usize,
    utilization_samples: AtomicU64,
}

struct DatagramRouteShard {
    routes: ArcSwap<HashMap<StreamId, DatagramRoute>>,
    write_lock: Mutex<()>,
}

impl DatagramRouteShard {
    fn new() -> Self {
        Self {
            routes: ArcSwap::from_pointee(HashMap::new()),
            write_lock: Mutex::new(()),
        }
    }
}

impl H3DatagramDispatch {
    pub(crate) fn new(channel_capacity: usize) -> Self {
        Self {
            streams: (0..DATAGRAM_ROUTE_SHARDS)
                .map(|_| DatagramRouteShard::new())
                .collect(),
            channel_capacity,
            utilization_samples: AtomicU64::new(0),
        }
    }

    fn shard_idx(&self, stream_id: &StreamId) -> usize {
        qpx_http::sharding::modulo(stream_id, self.streams.len())
    }

    fn route(&self, stream_id: &StreamId) -> Option<DatagramRoute> {
        let shard = &self.streams[self.shard_idx(stream_id)];
        shard.routes.load().get(stream_id).cloned()
    }

    fn insert_route(&self, stream_id: StreamId, route: DatagramRoute) {
        let idx = self.shard_idx(&stream_id);
        let shard = &self.streams[idx];
        let _guard = shard
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut routes = (**shard.routes.load()).clone();
        routes.insert(stream_id, route);
        shard.routes.store(Arc::new(routes));
    }

    fn remove_route(&self, stream_id: StreamId) {
        let idx = self.shard_idx(&stream_id);
        let shard = &self.streams[idx];
        let _guard = shard
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut routes = (**shard.routes.load()).clone();
        routes.remove(&stream_id);
        shard.routes.store(Arc::new(routes));
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
        self.insert_route(stream_id, DatagramRoute::Enabled(tx.clone()));
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
        self.insert_route(stream_id, DatagramRoute::Disabled);
        DatagramRegistration {
            dispatch: self.clone(),
            stream_id,
        }
    }

    async fn unregister(&self, stream_id: StreamId) {
        self.remove_route(stream_id);
    }

    pub(crate) async fn run(self: Arc<Self>, mut reader: H3DatagramReader) {
        loop {
            match reader.read_datagram().await {
                Ok(datagram) => {
                    let stream_id = datagram.stream_id();
                    let payload = datagram.into_payload();
                    let route = self.route(&stream_id);
                    match route {
                        Some(DatagramRoute::Enabled(tx)) => {
                            let len = payload.len() as u64;
                            if self.should_record_utilization() {
                                metrics::h3_datagram_channel_utilization(&tx);
                            }
                            if tx.capacity() == 0 {
                                metrics::h3_datagram_drop("channel_full");
                                continue;
                            }
                            match tx.try_send(payload) {
                                Ok(()) => {
                                    metrics::h3_datagram_received(len);
                                }
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    metrics::h3_datagram_drop("channel_full");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {}
                            }
                        }
                        Some(DatagramRoute::Disabled) => {
                            metrics::h3_datagram_drop("disabled");
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
                            metrics::h3_datagram_drop("unknown_stream");
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
