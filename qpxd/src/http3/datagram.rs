use bytes::Buf;
use bytes::Bytes;
use h3::error::connection_error_creators::CloseStream;
use h3::error::internal_error::InternalConnectionError;
use h3::error::Code;
use h3::quic::StreamId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
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
                            let _ = tx.try_send(bytes);
                        }
                        Some(DatagramRoute::Disabled) => {
                            let _ = reader.handle_connection_error_on_stream(
                                InternalConnectionError::new(
                                    Code::H3_DATAGRAM_ERROR,
                                    "datagram received for stream without datagram semantics"
                                        .to_string(),
                                ),
                            );
                            break;
                        }
                        None => {}
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
