use crate::protocol::{
    FRAME_DATA, FRAME_HEADERS, H3_DATAGRAM_ERROR, H3_FRAME_UNEXPECTED, H3_MESSAGE_ERROR,
    H3_REQUEST_CANCELLED, encode_varint, read_varint_slice, validate_message_stream_frame,
    write_frame,
};
use crate::qpack::{HeaderDecodeError, QpackConnection, encode_response_head, encode_trailers};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use metrics::{counter, histogram};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

const WEBTRANSPORT_STREAM_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug)]
struct ResponseSendState {
    response_started: bool,
    final_sent: bool,
    body_allowed: bool,
    head_request: bool,
}

#[derive(Debug)]
pub struct RequestStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    stream_id: u64,
    qpack: QpackConnection,
    read_timeout: Duration,
    max_frame_payload_bytes: usize,
    pending_trailers: Option<http::HeaderMap>,
    closed: bool,
    response_state: Option<ResponseSendState>,
}

impl RequestStream {
    pub(crate) fn new_client_request(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        stream_id: u64,
        qpack: QpackConnection,
        read_timeout: Duration,
        max_frame_payload_bytes: usize,
    ) -> Self {
        Self {
            send,
            recv,
            stream_id,
            qpack,
            read_timeout,
            max_frame_payload_bytes,
            pending_trailers: None,
            closed: false,
            response_state: None,
        }
    }

    pub(crate) fn new_server_response(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        stream_id: u64,
        qpack: QpackConnection,
        read_timeout: Duration,
        max_frame_payload_bytes: usize,
        request_method: http::Method,
    ) -> Self {
        Self {
            send,
            recv,
            stream_id,
            qpack,
            read_timeout,
            max_frame_payload_bytes,
            pending_trailers: None,
            closed: false,
            response_state: Some(ResponseSendState {
                response_started: false,
                final_sent: false,
                body_allowed: true,
                head_request: request_method == http::Method::HEAD,
            }),
        }
    }

    pub fn id(&self) -> u64 {
        self.stream_id
    }

    pub(crate) async fn send_headers(&mut self, payload: &[u8]) -> Result<()> {
        write_frame(&mut self.send, FRAME_HEADERS, payload).await
    }

    pub async fn send_response_head(&mut self, response: &http::Response<()>) -> Result<()> {
        let mut response = response.clone();
        let Some(state) = self.response_state.as_mut() else {
            return Err(anyhow!(
                "HTTP/3 response HEADERS can only be sent by server response streams"
            ));
        };
        if state.final_sent {
            return Err(anyhow!("HTTP/3 final response HEADERS already sent"));
        }
        let body_allowed = crate::response::sanitize_streaming_response_head_for_h3(&mut response)?;
        state.response_started = true;
        if let Some(body_allowed) = body_allowed {
            state.final_sent = true;
            state.body_allowed = body_allowed && !state.head_request;
        }
        let payload = encode_response_head(&response);
        self.send_headers(&payload).await
    }

    pub async fn send_full_response(
        &mut self,
        head: &http::Response<()>,
        body: &[u8],
        trailers: Option<&http::HeaderMap>,
    ) -> Result<()> {
        self.send_response_head(head).await?;
        if !body.is_empty() {
            self.send_data(Bytes::copy_from_slice(body)).await?;
        }
        if let Some(trailers) = trailers {
            self.send_trailers(trailers).await?;
        }
        self.finish().await
    }

    pub async fn send_trailers(&mut self, trailers: &http::HeaderMap) -> Result<()> {
        let mut trailers = trailers.clone();
        if let Some(state) = self.response_state.as_ref() {
            if !state.final_sent {
                return Err(anyhow!(
                    "HTTP/3 trailers cannot precede final response HEADERS"
                ));
            }
            if !state.body_allowed {
                return Err(anyhow!("HTTP/3 trailers are not allowed for this response"));
            }
            crate::response::sanitize_trailers_for_h3(&mut trailers)?;
        }
        let payload = encode_trailers(&trailers);
        self.send_headers(&payload).await
    }

    pub async fn send_data(&mut self, payload: Bytes) -> Result<()> {
        if let Some(state) = self.response_state.as_ref() {
            if !state.final_sent {
                return Err(anyhow!("HTTP/3 DATA cannot precede final response HEADERS"));
            }
            if !state.body_allowed {
                return Err(anyhow!("HTTP/3 DATA is not allowed for this response"));
            }
        }
        write_frame(&mut self.send, FRAME_DATA, payload.as_ref()).await
    }

    pub async fn finish(&mut self) -> Result<()> {
        if let Some(state) = self.response_state.as_ref()
            && state.response_started
            && !state.final_sent
        {
            return Err(anyhow!(
                "HTTP/3 response ended without final response HEADERS"
            ));
        }
        self.send.finish()?;
        Ok(())
    }

    pub async fn recv_data(&mut self) -> Result<Option<Bytes>> {
        if self.closed {
            return Ok(None);
        }
        loop {
            let Some(frame) = self.recv_frame().await? else {
                self.closed = true;
                return Ok(None);
            };
            if self.pending_trailers.is_some() {
                abort_bidi_stream(&mut self.send, &mut self.recv, H3_FRAME_UNEXPECTED);
                return Err(anyhow!("received HTTP/3 frame after trailers"));
            }
            match frame.ty {
                FRAME_DATA => return Ok(Some(frame.payload)),
                FRAME_HEADERS => {
                    match self
                        .qpack
                        .decode_trailers(self.stream_id, frame.payload.as_ref(), self.read_timeout)
                        .await
                    {
                        Ok(trailers) => self.pending_trailers = Some(trailers),
                        Err(err) => {
                            abort_bidi_stream(&mut self.send, &mut self.recv, err.code());
                            return Err(anyhow!(err.to_string()));
                        }
                    }
                    continue;
                }
                _ => {
                    if let Err(close) = validate_message_stream_frame(frame.ty) {
                        abort_bidi_stream(&mut self.send, &mut self.recv, close.code);
                        return Err(anyhow!(close.message));
                    }
                }
            }
        }
    }

    pub async fn recv_trailers(&mut self) -> Result<Option<http::HeaderMap>> {
        if self.pending_trailers.is_some() {
            return Ok(self.pending_trailers.take());
        }
        while !self.closed {
            if self.recv_data().await?.is_some() {
                continue;
            }
        }
        Ok(self.pending_trailers.take())
    }

    pub fn split(self) -> (RequestSendStream, RequestRecvStream) {
        (
            RequestSendStream {
                send: self.send,
                stream_id: self.stream_id,
                response_state: self.response_state,
            },
            RequestRecvStream {
                recv: self.recv,
                stream_id: self.stream_id,
                qpack: self.qpack,
                read_timeout: self.read_timeout,
                max_frame_payload_bytes: self.max_frame_payload_bytes,
                pending_trailers: self.pending_trailers,
                closed: self.closed,
            },
        )
    }

    pub(crate) async fn recv_frame(&mut self) -> Result<Option<crate::protocol::Frame>> {
        crate::protocol::read_frame(&mut self.recv, self.max_frame_payload_bytes).await
    }

    pub(crate) fn abort_with_code(&mut self, code: u64) {
        abort_bidi_stream(&mut self.send, &mut self.recv, code);
    }

    pub fn stop_receiving_request_body(&mut self) {
        stop_recv_stream(&mut self.recv, H3_REQUEST_CANCELLED);
        self.closed = true;
    }

    pub fn abort_message_stream(&mut self) {
        abort_bidi_stream(&mut self.send, &mut self.recv, H3_MESSAGE_ERROR);
        self.closed = true;
    }

    pub(crate) async fn decode_response_head(
        &self,
        payload: &[u8],
    ) -> std::result::Result<http::Response<()>, HeaderDecodeError> {
        Ok(self
            .qpack
            .decode_response_head(self.stream_id, payload, self.read_timeout)
            .await?
            .response)
    }

    pub(crate) fn send_mut(&mut self) -> &mut quinn::SendStream {
        &mut self.send
    }
}

#[derive(Debug)]
pub struct RequestSendStream {
    send: quinn::SendStream,
    stream_id: u64,
    response_state: Option<ResponseSendState>,
}

impl RequestSendStream {
    pub fn id(&self) -> u64 {
        self.stream_id
    }

    pub async fn send_data(&mut self, payload: Bytes) -> Result<()> {
        if let Some(state) = self.response_state.as_ref() {
            if !state.final_sent {
                return Err(anyhow!("HTTP/3 DATA cannot precede final response HEADERS"));
            }
            if !state.body_allowed {
                return Err(anyhow!("HTTP/3 DATA is not allowed for this response"));
            }
        }
        write_frame(&mut self.send, FRAME_DATA, payload.as_ref()).await
    }

    pub(crate) async fn send_headers(&mut self, payload: &[u8]) -> Result<()> {
        write_frame(&mut self.send, FRAME_HEADERS, payload).await
    }

    pub async fn send_trailers(&mut self, trailers: &http::HeaderMap) -> Result<()> {
        let mut trailers = trailers.clone();
        if let Some(state) = self.response_state.as_ref() {
            if !state.final_sent {
                return Err(anyhow!(
                    "HTTP/3 trailers cannot precede final response HEADERS"
                ));
            }
            if !state.body_allowed {
                return Err(anyhow!("HTTP/3 trailers are not allowed for this response"));
            }
            crate::response::sanitize_trailers_for_h3(&mut trailers)?;
        }
        let payload = encode_trailers(&trailers);
        self.send_headers(&payload).await
    }

    pub async fn finish(&mut self) -> Result<()> {
        if let Some(state) = self.response_state.as_ref()
            && state.response_started
            && !state.final_sent
        {
            return Err(anyhow!(
                "HTTP/3 response ended without final response HEADERS"
            ));
        }
        self.send.finish()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RequestRecvStream {
    recv: quinn::RecvStream,
    stream_id: u64,
    qpack: QpackConnection,
    read_timeout: Duration,
    max_frame_payload_bytes: usize,
    pending_trailers: Option<http::HeaderMap>,
    closed: bool,
}

impl RequestRecvStream {
    pub fn id(&self) -> u64 {
        self.stream_id
    }

    pub async fn recv_data(&mut self) -> Result<Option<Bytes>> {
        if self.closed {
            return Ok(None);
        }
        loop {
            let Some(frame) =
                crate::protocol::read_frame(&mut self.recv, self.max_frame_payload_bytes).await?
            else {
                self.closed = true;
                return Ok(None);
            };
            if self.pending_trailers.is_some() {
                stop_recv_stream(&mut self.recv, H3_FRAME_UNEXPECTED);
                return Err(anyhow!("received HTTP/3 frame after trailers"));
            }
            match frame.ty {
                FRAME_DATA => return Ok(Some(frame.payload)),
                FRAME_HEADERS => {
                    match self
                        .qpack
                        .decode_trailers(self.stream_id, frame.payload.as_ref(), self.read_timeout)
                        .await
                    {
                        Ok(trailers) => self.pending_trailers = Some(trailers),
                        Err(err) => {
                            stop_recv_stream(&mut self.recv, err.code());
                            return Err(anyhow!(err.to_string()));
                        }
                    }
                    continue;
                }
                _ => {
                    if let Err(close) = validate_message_stream_frame(frame.ty) {
                        stop_recv_stream(&mut self.recv, close.code);
                        return Err(anyhow!(close.message));
                    }
                }
            }
        }
    }

    pub async fn recv_trailers(&mut self) -> Result<Option<http::HeaderMap>> {
        if self.pending_trailers.is_some() {
            return Ok(self.pending_trailers.take());
        }
        while !self.closed {
            if self.recv_data().await?.is_some() {
                continue;
            }
        }
        Ok(self.pending_trailers.take())
    }
}

fn stop_recv_stream(recv: &mut quinn::RecvStream, code: u64) {
    if let Ok(code) = quinn::VarInt::from_u64(code) {
        let _ = recv.stop(code);
    }
}

fn abort_bidi_stream(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream, code: u64) {
    stop_recv_stream(recv, code);
    if let Ok(code) = quinn::VarInt::from_u64(code) {
        let _ = send.reset(code);
    }
}

#[derive(Debug)]
pub struct BidiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl BidiStream {
    pub(crate) fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    pub(crate) fn abort_with_code(mut self, code: u64) {
        abort_bidi_stream(&mut self.send, &mut self.recv, code);
    }

    pub fn split(self) -> (StreamSend, StreamRecv) {
        (
            StreamSend { send: self.send },
            StreamRecv { recv: self.recv },
        )
    }
}

#[derive(Debug)]
pub struct StreamSend {
    send: quinn::SendStream,
}

impl StreamSend {
    pub async fn send_chunk(&mut self, payload: Bytes) -> Result<()> {
        self.send.write_all(payload.as_ref()).await?;
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct StreamRecv {
    recv: quinn::RecvStream,
}

impl StreamRecv {
    pub async fn recv_chunk(&mut self) -> Result<Option<Bytes>> {
        Ok(self
            .recv
            .read_chunk(WEBTRANSPORT_STREAM_CHUNK_BYTES, true)
            .await?
            .map(|chunk| chunk.bytes))
    }
}

#[derive(Debug)]
pub struct UniRecvStream {
    recv: quinn::RecvStream,
}

impl UniRecvStream {
    pub(crate) fn new(recv: quinn::RecvStream) -> Self {
        Self { recv }
    }

    pub(crate) fn stop_with_code(mut self, code: u64) {
        stop_recv_stream(&mut self.recv, code);
    }

    pub async fn recv_chunk(&mut self) -> Result<Option<Bytes>> {
        Ok(self
            .recv
            .read_chunk(WEBTRANSPORT_STREAM_CHUNK_BYTES, true)
            .await?
            .map(|chunk| chunk.bytes))
    }
}

#[derive(Debug)]
pub struct UniSendStream {
    send: quinn::SendStream,
}

impl UniSendStream {
    pub(crate) fn new(send: quinn::SendStream) -> Self {
        Self { send }
    }

    pub async fn send_chunk(&mut self, payload: Bytes) -> Result<()> {
        self.send.write_all(payload.as_ref()).await?;
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<()> {
        self.send.finish()?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct OpenStreams {
    conn: quinn::Connection,
}

impl OpenStreams {
    pub(crate) fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    pub async fn open_webtransport_bidi(&mut self, session_id: u64) -> Result<BidiStream> {
        let (mut send, recv) = self.conn.open_bi().await?;
        send.write_all(&encode_varint(crate::protocol::STREAM_WEBTRANSPORT_BIDI)?)
            .await?;
        send.write_all(&encode_varint(session_id)?).await?;
        Ok(BidiStream::new(send, recv))
    }

    pub async fn open_webtransport_uni(&mut self, session_id: u64) -> Result<UniSendStream> {
        let mut send = self.conn.open_uni().await?;
        send.write_all(&encode_varint(crate::protocol::STREAM_WEBTRANSPORT_UNI)?)
            .await?;
        send.write_all(&encode_varint(session_id)?).await?;
        Ok(UniSendStream::new(send))
    }
}

#[derive(Debug)]
pub struct DatagramSender {
    conn: quinn::Connection,
    stream_id: u64,
}

impl DatagramSender {
    fn new(conn: quinn::Connection, stream_id: u64) -> Self {
        Self { conn, stream_id }
    }

    pub fn send_datagram(&mut self, payload: Bytes) -> Result<()> {
        if !self.stream_id.is_multiple_of(4) {
            return Err(anyhow!("datagram stream id must be divisible by 4"));
        }
        let quarter_stream = self.stream_id / 4;
        let mut out = encode_varint(quarter_stream)?;
        out.extend_from_slice(payload.as_ref());
        self.conn
            .send_datagram(Bytes::from(out))
            .map_err(|err| anyhow!("failed to send QUIC datagram: {err}"))?;
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
        .increment(payload.len() as u64);
        Ok(())
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
    streams: Mutex<HashMap<u64, DatagramRoute>>,
    channel_capacity: usize,
}

impl DatagramDispatch {
    pub(crate) fn new(conn: quinn::Connection, channel_capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            conn,
            streams: Mutex::new(HashMap::new()),
            channel_capacity,
        })
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
        {
            let mut guard = self.streams.lock().await;
            guard.insert(stream_id, DatagramRoute::Enabled(tx));
        }
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
        self.streams
            .lock()
            .await
            .insert(stream_id, DatagramRoute::Disabled);
        DatagramRegistration {
            dispatch: self.clone(),
            stream_id,
        }
    }

    async fn unregister(&self, stream_id: u64) {
        self.streams.lock().await.remove(&stream_id);
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
            let route = { self.streams.lock().await.get(&stream_id).cloned() };
            match route {
                Some(DatagramRoute::Enabled(tx)) => {
                    let len = payload.len() as u64;
                    record_datagram_channel_utilization(&tx);
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
