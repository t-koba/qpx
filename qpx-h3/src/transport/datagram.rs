use crate::H3Result as Result;
use crate::protocol::{H3_DATAGRAM_ERROR, encode_varint, read_varint_slice};
use crate::transport::metrics;
use anyhow::anyhow;
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

const DATAGRAM_ROUTE_SHARDS: usize = 64;

/// Sender for HTTP/3 DATAGRAM frames associated with a stream.
pub struct DatagramSender {
    conn: quinn::Connection,
    prefix: Bytes,
}

impl DatagramSender {
    fn new(conn: quinn::Connection, stream_id: u64) -> Result<Self> {
        let prefix = datagram_prefix_for_stream(stream_id)?;
        Ok(Self { conn, prefix })
    }

    /// Returns the encoded DATAGRAM stream prefix.
    pub fn datagram_prefix(&self) -> Bytes {
        self.prefix.clone()
    }

    /// Sends a datagram that already includes the encoded prefix.
    pub fn send_prefixed_datagram(&mut self, datagram: Bytes, payload_len: usize) -> Result<()> {
        self.conn
            .send_datagram(datagram)
            .map_err(|err| anyhow!("failed to send QUIC datagram: {err}"))?;
        metrics::datagram_sent(payload_len);
        Ok(())
    }

    /// Sends an unprefixed datagram payload using caller-provided scratch storage.
    pub fn send_unprefixed_datagram_with_scratch(
        &mut self,
        payload: Bytes,
        scratch: &mut BytesMut,
    ) -> Result<()> {
        metrics::datagram_prefix_copy(payload.len());
        scratch.clear();
        scratch.reserve(self.prefix.len() + payload.len());
        scratch.extend_from_slice(self.prefix.as_ref());
        scratch.extend_from_slice(payload.as_ref());
        let datagram = scratch.split().freeze();
        self.conn
            .send_datagram(datagram)
            .map_err(|err| anyhow!("failed to send QUIC datagram: {err}"))?;
        metrics::datagram_sent(payload.len());
        Ok(())
    }
}

fn datagram_prefix_for_stream(stream_id: u64) -> Result<Bytes> {
    if !stream_id.is_multiple_of(4) {
        return Err(anyhow!("datagram stream id must be divisible by 4").into());
    }
    let quarter_stream = stream_id / 4;
    Ok(Bytes::from(encode_varint(quarter_stream)?))
}

/// DATAGRAM sender and receiver pair for one stream.
pub struct StreamDatagrams {
    /// DATAGRAM sender.
    pub sender: DatagramSender,
    /// DATAGRAM receiver.
    pub receiver: mpsc::Receiver<Bytes>,
    _registration: DatagramRegistration,
}

#[derive(Clone)]
enum DatagramRoute {
    Enabled(mpsc::Sender<Bytes>),
    Disabled,
}

pub(crate) struct DatagramDispatch {
    conn: quinn::Connection,
    streams: Vec<DatagramRouteShard>,
    channel_capacity: usize,
    utilization_samples: AtomicU64,
}

struct DatagramRouteShard {
    routes: ArcSwap<HashMap<u64, DatagramRoute>>,
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

impl DatagramDispatch {
    pub(crate) fn new(conn: quinn::Connection, channel_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            conn,
            streams: (0..DATAGRAM_ROUTE_SHARDS)
                .map(|_| DatagramRouteShard::new())
                .collect(),
            channel_capacity,
            utilization_samples: AtomicU64::new(0),
        })
    }

    fn shard_idx(&self, stream_id: u64) -> usize {
        crate::sharding::modulo_u64(stream_id, self.streams.len())
    }

    fn route(&self, stream_id: u64) -> Option<DatagramRoute> {
        let shard = &self.streams[self.shard_idx(stream_id)];
        shard.routes.load().get(&stream_id).cloned()
    }

    fn insert_route(&self, stream_id: u64, route: DatagramRoute) {
        let idx = self.shard_idx(stream_id);
        let shard = &self.streams[idx];
        let _guard = shard
            .write_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut routes = (**shard.routes.load()).clone();
        routes.insert(stream_id, route);
        shard.routes.store(Arc::new(routes));
    }

    fn remove_route(&self, stream_id: u64) {
        let idx = self.shard_idx(stream_id);
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
        stream_id: u64,
    ) -> Result<StreamDatagrams> {
        self.register_stream_with_capacity(stream_id, self.channel_capacity)
            .await
    }

    pub(crate) async fn register_stream_with_capacity(
        self: &Arc<Self>,
        stream_id: u64,
        channel_capacity: usize,
    ) -> Result<StreamDatagrams> {
        let sender = DatagramSender::new(self.conn.clone(), stream_id)?;
        let (tx, rx) = mpsc::channel(channel_capacity.max(1));
        self.insert_route(stream_id, DatagramRoute::Enabled(tx.clone()));
        Ok(StreamDatagrams {
            sender,
            receiver: rx,
            _registration: DatagramRegistration {
                dispatch: self.clone(),
                stream_id,
            },
        })
    }

    pub(crate) async fn register_stream_without_datagrams(
        self: &Arc<Self>,
        stream_id: u64,
    ) -> DatagramRegistration {
        self.insert_route(stream_id, DatagramRoute::Disabled);
        DatagramRegistration {
            dispatch: self.clone(),
            stream_id,
        }
    }

    async fn unregister(&self, stream_id: u64) {
        self.remove_route(stream_id);
    }

    pub(crate) async fn run(self: Arc<Self>) {
        loop {
            let datagram = match self.conn.read_datagram().await {
                Ok(datagram) => datagram,
                Err(err) => {
                    tracing::warn!(error = ?err, "qpx-h3 datagram reader stopped");
                    break;
                }
            };
            let (quarter_stream, used) = match read_varint_slice(datagram.as_ref()) {
                Ok(parsed) => parsed,
                Err(err) => {
                    close_datagram_connection(&self.conn, err.to_string());
                    break;
                }
            };
            if quarter_stream >= (1u64 << 60) {
                close_datagram_connection(&self.conn, "quarter stream id exceeds RFC 9297 limit");
                break;
            }
            let Some(stream_id) = quarter_stream.checked_mul(4) else {
                close_datagram_connection(&self.conn, "quarter stream id multiplication overflow");
                break;
            };
            let payload = datagram.slice(used..);
            let route = self.route(stream_id);
            match route {
                Some(DatagramRoute::Enabled(tx)) => {
                    let len = payload.len() as u64;
                    if self.should_record_utilization() {
                        record_datagram_channel_utilization(&tx);
                    }
                    match tx.try_send(payload) {
                        Ok(()) => {
                            metrics::datagram_received(len);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            metrics::datagram_dropped("channel_full");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {}
                    }
                }
                Some(DatagramRoute::Disabled) => {
                    metrics::datagram_dropped("disabled");
                    close_datagram_connection(
                        &self.conn,
                        "datagram received for stream without datagram semantics",
                    );
                    break;
                }
                None => {
                    metrics::datagram_dropped("unknown_stream");
                }
            }
        }
    }
}

fn record_datagram_channel_utilization(tx: &mpsc::Sender<Bytes>) {
    metrics::datagram_channel_utilization(tx);
}

pub(crate) struct DatagramRegistration {
    dispatch: Arc<DatagramDispatch>,
    stream_id: u64,
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

fn close_datagram_connection(conn: &quinn::Connection, message: impl AsRef<str>) {
    if let Ok(code) = quinn::VarInt::from_u64(H3_DATAGRAM_ERROR) {
        conn.close(code, message.as_ref().as_bytes());
    }
}
