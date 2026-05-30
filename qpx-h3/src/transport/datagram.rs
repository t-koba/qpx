use crate::protocol::{H3_DATAGRAM_ERROR, encode_varint, read_varint_slice};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use metrics::{counter, histogram};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

const DATAGRAM_ROUTE_SHARDS: usize = 64;

pub struct DatagramSender {
    conn: quinn::Connection,
    stream_id: u64,
}

impl DatagramSender {
    fn new(conn: quinn::Connection, stream_id: u64) -> Self {
        Self { conn, stream_id }
    }

    pub fn datagram_prefix(&self) -> Result<Bytes> {
        if !self.stream_id.is_multiple_of(4) {
            return Err(anyhow!("datagram stream id must be divisible by 4"));
        }
        let quarter_stream = self.stream_id / 4;
        Ok(Bytes::from(encode_varint(quarter_stream)?))
    }

    pub fn send_prefixed_datagram(&mut self, datagram: Bytes, payload_len: usize) -> Result<()> {
        self.conn
            .send_datagram(datagram)
            .map_err(|err| anyhow!("failed to send QUIC datagram: {err}"))?;
        self.record_datagram_sent(payload_len);
        Ok(())
    }

    pub fn send_datagram(&mut self, payload: Bytes) -> Result<()> {
        let prefix = self.datagram_prefix()?;
        let mut out = bytes::BytesMut::with_capacity(prefix.len() + payload.len());
        out.extend_from_slice(prefix.as_ref());
        out.extend_from_slice(payload.as_ref());
        self.conn
            .send_datagram(out.freeze())
            .map_err(|err| anyhow!("failed to send QUIC datagram: {err}"))?;
        self.record_datagram_sent(payload.len());
        Ok(())
    }

    fn record_datagram_sent(&self, payload_len: usize) {
        counter!(
            "qpx_datagram_sent_total",
            "transport" => "qpx_h3",
            "listener" => "unknown"
        )
        .increment(1);
        counter!(
            "qpx_datagram_sent_bytes_total",
            "transport" => "qpx_h3",
            "listener" => "unknown"
        )
        .increment(payload_len as u64);
    }
}

pub struct StreamDatagrams {
    pub sender: DatagramSender,
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
    streams: Vec<RwLock<HashMap<u64, DatagramRoute>>>,
    channel_capacity: usize,
    utilization_samples: AtomicU64,
}

impl DatagramDispatch {
    pub(crate) fn new(conn: quinn::Connection, channel_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            conn,
            streams: (0..DATAGRAM_ROUTE_SHARDS)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
            channel_capacity,
            utilization_samples: AtomicU64::new(0),
        })
    }

    fn shard(&self, stream_id: u64) -> &RwLock<HashMap<u64, DatagramRoute>> {
        &self.streams[(stream_id as usize) % self.streams.len()]
    }

    fn should_record_utilization(&self) -> bool {
        self.utilization_samples
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(64)
    }

    pub(crate) async fn register_stream(self: &Arc<Self>, stream_id: u64) -> StreamDatagrams {
        self.register_stream_with_capacity(stream_id, self.channel_capacity)
            .await
    }

    pub(crate) async fn register_stream_with_capacity(
        self: &Arc<Self>,
        stream_id: u64,
        channel_capacity: usize,
    ) -> StreamDatagrams {
        let (tx, rx) = mpsc::channel(channel_capacity.max(1));
        self.shard(stream_id)
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(stream_id, DatagramRoute::Enabled(tx.clone()));
        StreamDatagrams {
            sender: DatagramSender::new(self.conn.clone(), stream_id),
            receiver: rx,
            _registration: DatagramRegistration {
                dispatch: self.clone(),
                stream_id,
            },
        }
    }

    pub(crate) async fn register_stream_without_datagrams(
        self: &Arc<Self>,
        stream_id: u64,
    ) -> DatagramRegistration {
        self.shard(stream_id)
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(stream_id, DatagramRoute::Disabled);
        DatagramRegistration {
            dispatch: self.clone(),
            stream_id,
        }
    }

    async fn unregister(&self, stream_id: u64) {
        self.shard(stream_id)
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&stream_id);
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
            let route = self
                .shard(stream_id)
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
                    match tx.try_send(payload) {
                        Ok(()) => {
                            counter!(
                                "qpx_datagram_received_total",
                                "transport" => "qpx_h3",
                                "listener" => "unknown"
                            )
                            .increment(1);
                            counter!(
                                "qpx_datagram_received_bytes_total",
                                "transport" => "qpx_h3",
                                "listener" => "unknown"
                            )
                            .increment(len);
                        }
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            counter!(
                                "qpx_datagram_dropped_total",
                                "transport" => "qpx_h3",
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
                        "transport" => "qpx_h3",
                        "listener" => "unknown",
                        "reason" => "disabled"
                    )
                    .increment(1);
                    close_datagram_connection(
                        &self.conn,
                        "datagram received for stream without datagram semantics",
                    );
                    break;
                }
                None => {
                    counter!(
                        "qpx_datagram_dropped_total",
                        "transport" => "qpx_h3",
                        "listener" => "unknown",
                        "reason" => "unknown_stream"
                    )
                    .increment(1);
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
        "transport" => "qpx_h3",
        "listener" => "unknown"
    )
    .record(used as f64 / max as f64);
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
