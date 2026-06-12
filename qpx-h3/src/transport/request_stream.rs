use crate::H3Result as Result;
use crate::protocol::{
    FRAME_DATA, FRAME_HEADERS, H3_FRAME_UNEXPECTED, H3_MESSAGE_ERROR, H3_REQUEST_CANCELLED,
    read_varint, validate_message_stream_frame, write_frame,
};
use crate::qpack::{QpackConnection, encode_response_head, encode_trailers};
use anyhow::anyhow;
use bytes::Bytes;
use std::time::Duration;
use tokio::time::timeout;

use super::{
    MESSAGE_DATA_CHUNK_BYTES, RequestRecvStream, RequestSendStream, RequestStreamConfig,
    ResponseSendState, abort_bidi_stream, declared_response_body_length,
    enforce_body_content_length_complete, enforce_body_frame,
    enforce_response_content_length_complete, enforce_response_content_length_send,
    max_message_frame_payload_bytes, stop_recv_stream,
};

/// Combined HTTP/3 request stream.
pub struct RequestStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    stream_id: u64,
    qpack: QpackConnection,
    read_timeout: Duration,
    max_frame_payload_bytes: usize,
    max_non_data_frame_payload_bytes: usize,
    max_field_section_bytes: usize,
    max_request_body_bytes: Option<usize>,
    declared_request_body_bytes: Option<u64>,
    received_request_body_bytes: usize,
    receives_response_body: bool,
    response_head_received: bool,
    declared_response_body_bytes: Option<u64>,
    received_response_body_bytes: usize,
    response_head_request: bool,
    pending_data_frame_bytes: usize,
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
        config: RequestStreamConfig,
        request_method: http::Method,
    ) -> Self {
        Self {
            send,
            recv,
            stream_id,
            qpack,
            read_timeout: config.read_timeout,
            max_frame_payload_bytes: config.max_frame_payload_bytes,
            max_non_data_frame_payload_bytes: config.max_non_data_frame_payload_bytes,
            max_field_section_bytes: config.max_field_section_bytes,
            max_request_body_bytes: None,
            declared_request_body_bytes: None,
            received_request_body_bytes: 0,
            receives_response_body: true,
            response_head_received: false,
            declared_response_body_bytes: None,
            received_response_body_bytes: 0,
            response_head_request: request_method == http::Method::HEAD,
            pending_data_frame_bytes: 0,
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
        config: RequestStreamConfig,
        request_method: http::Method,
        declared_request_body_bytes: Option<u64>,
    ) -> Self {
        Self {
            send,
            recv,
            stream_id,
            qpack,
            read_timeout: config.read_timeout,
            max_frame_payload_bytes: config.max_frame_payload_bytes,
            max_non_data_frame_payload_bytes: config.max_non_data_frame_payload_bytes,
            max_field_section_bytes: config.max_field_section_bytes,
            max_request_body_bytes: config.max_request_body_bytes,
            declared_request_body_bytes,
            received_request_body_bytes: 0,
            receives_response_body: false,
            response_head_received: false,
            declared_response_body_bytes: None,
            received_response_body_bytes: 0,
            response_head_request: false,
            pending_data_frame_bytes: 0,
            pending_trailers: None,
            closed: false,
            response_state: Some(ResponseSendState {
                response_started: false,
                final_sent: false,
                body_allowed: true,
                head_request: request_method == http::Method::HEAD,
                declared_content_length: None,
                sent_body_bytes: 0,
            }),
        }
    }

    /// Returns the QUIC stream id.
    pub fn id(&self) -> u64 {
        self.stream_id
    }

    pub(crate) async fn send_headers(&mut self, payload: &[u8]) -> Result<()> {
        write_frame(&mut self.send, FRAME_HEADERS, payload).await
    }

    /// Sends response headers.
    pub async fn send_response_head(&mut self, response: &http::Response<()>) -> Result<()> {
        let mut response = response.clone();
        let Some(state) = self.response_state.as_mut() else {
            return Err(anyhow!(
                "HTTP/3 response HEADERS can only be sent by server response streams"
            )
            .into());
        };
        if state.final_sent {
            return Err(anyhow!("HTTP/3 final response HEADERS already sent").into());
        }
        let body_allowed = crate::response::sanitize_streaming_response_head_for_h3(&mut response)?;
        state.response_started = true;
        if let Some(body_allowed) = body_allowed {
            state.final_sent = true;
            state.body_allowed = body_allowed && !state.head_request;
            state.declared_content_length = if state.body_allowed {
                crate::response::parse_content_length(response.headers())?
            } else {
                None
            };
        }
        let payload = encode_response_head(&response);
        self.send_headers(&payload).await
    }

    /// Sends a complete response.
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

    /// Sends response trailers.
    pub async fn send_trailers(&mut self, trailers: &http::HeaderMap) -> Result<()> {
        let mut trailers = trailers.clone();
        if let Some(state) = self.response_state.as_ref() {
            if !state.final_sent {
                return Err(
                    anyhow!("HTTP/3 trailers cannot precede final response HEADERS").into(),
                );
            }
            if !state.body_allowed {
                return Err(anyhow!("HTTP/3 trailers are not allowed for this response").into());
            }
            enforce_response_content_length_complete(state)?;
            crate::response::sanitize_trailers_for_h3(&mut trailers)?;
        }
        let payload = encode_trailers(&trailers);
        self.send_headers(&payload).await
    }

    /// Sends one DATA frame.
    pub async fn send_data(&mut self, payload: Bytes) -> Result<()> {
        if let Some(state) = self.response_state.as_ref() {
            if !state.final_sent {
                return Err(anyhow!("HTTP/3 DATA cannot precede final response HEADERS").into());
            }
            if !state.body_allowed {
                return Err(anyhow!("HTTP/3 DATA is not allowed for this response").into());
            }
        }
        if let Some(state) = self.response_state.as_mut() {
            enforce_response_content_length_send(state, payload.len())?;
        }
        write_frame(&mut self.send, FRAME_DATA, payload.as_ref()).await
    }

    /// Finishes the stream.
    pub async fn finish(&mut self) -> Result<()> {
        if let Some(state) = self.response_state.as_ref()
            && state.response_started
            && !state.final_sent
        {
            return Err(anyhow!("HTTP/3 response ended without final response HEADERS").into());
        }
        if let Some(state) = self.response_state.as_ref() {
            enforce_response_content_length_complete(state)?;
        }
        self.send.finish()?;
        Ok(())
    }

    /// Receives one DATA frame payload.
    pub async fn recv_data(&mut self) -> Result<Option<Bytes>> {
        if self.closed {
            return Ok(None);
        }
        loop {
            if let Some(chunk) = self.read_pending_data_chunk().await? {
                return Ok(Some(chunk));
            }
            let Some((ty, len)) = self.read_next_frame_header().await? else {
                self.closed = true;
                self.enforce_received_content_length_complete()?;
                return Ok(None);
            };
            if self.pending_trailers.is_some() {
                abort_bidi_stream(&mut self.send, &mut self.recv, H3_FRAME_UNEXPECTED);
                return Err(anyhow!("received HTTP/3 frame after trailers").into());
            }
            match ty {
                FRAME_DATA => {
                    if let Err(err) = self.enforce_received_data_frame_len(len) {
                        abort_bidi_stream(&mut self.send, &mut self.recv, H3_MESSAGE_ERROR);
                        return Err(err);
                    }
                    self.pending_data_frame_bytes = len;
                    if let Some(chunk) = self.read_pending_data_chunk().await? {
                        return Ok(Some(chunk));
                    }
                }
                FRAME_HEADERS => {
                    match self
                        .qpack
                        .decode_trailers_from_reader(
                            self.stream_id,
                            &mut self.recv,
                            len,
                            self.read_timeout,
                        )
                        .await
                    {
                        Ok(trailers) => self.pending_trailers = Some(trailers),
                        Err(err) => {
                            abort_bidi_stream(&mut self.send, &mut self.recv, err.code());
                            return Err(anyhow!(err.to_string()).into());
                        }
                    }
                    if let Err(err) = self.enforce_received_content_length_complete() {
                        abort_bidi_stream(&mut self.send, &mut self.recv, H3_MESSAGE_ERROR);
                        return Err(err);
                    }
                    continue;
                }
                _ => {
                    if let Err(close) = validate_message_stream_frame(ty) {
                        abort_bidi_stream(&mut self.send, &mut self.recv, close.code);
                        return Err(anyhow!(close.message).into());
                    }
                    self.discard_frame_payload(len).await?;
                }
            }
        }
    }

    fn enforce_received_data_frame_len(&mut self, len: usize) -> Result<()> {
        if self.receives_response_body {
            if !self.response_head_received {
                return Err(anyhow!(
                    "HTTP/3 response DATA cannot be received before response HEADERS"
                )
                .into());
            }
            enforce_body_frame(
                None,
                self.declared_response_body_bytes,
                &mut self.received_response_body_bytes,
                len,
                "response",
            )
        } else {
            enforce_body_frame(
                self.max_request_body_bytes,
                self.declared_request_body_bytes,
                &mut self.received_request_body_bytes,
                len,
                "request",
            )
        }
    }

    fn enforce_received_content_length_complete(&self) -> Result<()> {
        if self.receives_response_body {
            enforce_body_content_length_complete(
                self.declared_response_body_bytes,
                self.received_response_body_bytes,
                "response",
            )
        } else {
            enforce_body_content_length_complete(
                self.declared_request_body_bytes,
                self.received_request_body_bytes,
                "request",
            )
        }
    }

    /// Receives trailers, if present.
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

    /// Splits the stream into send and receive halves.
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
                max_non_data_frame_payload_bytes: self.max_non_data_frame_payload_bytes,
                max_field_section_bytes: self.max_field_section_bytes,
                max_request_body_bytes: self.max_request_body_bytes,
                declared_request_body_bytes: self.declared_request_body_bytes,
                received_request_body_bytes: self.received_request_body_bytes,
                receives_response_body: self.receives_response_body,
                response_head_received: self.response_head_received,
                declared_response_body_bytes: self.declared_response_body_bytes,
                received_response_body_bytes: self.received_response_body_bytes,
                pending_data_frame_bytes: self.pending_data_frame_bytes,
                pending_trailers: self.pending_trailers,
                closed: self.closed,
            },
        )
    }

    async fn read_next_frame_header(&mut self) -> Result<Option<(u64, usize)>> {
        let Some(ty) = read_varint(&mut self.recv).await? else {
            return Ok(None);
        };
        let len = read_varint(&mut self.recv)
            .await?
            .ok_or_else(|| anyhow!("truncated frame length"))?;
        let max_payload_bytes = max_message_frame_payload_bytes(
            ty,
            self.max_frame_payload_bytes,
            self.max_non_data_frame_payload_bytes,
            self.max_field_section_bytes,
        );
        if len > max_payload_bytes as u64 {
            return Err(anyhow!(
                "HTTP/3 frame 0x{ty:x} payload length {len} exceeds limit {max_payload_bytes}"
            )
            .into());
        }
        Ok(Some((ty, len as usize)))
    }

    async fn discard_frame_payload(&mut self, len: usize) -> Result<()> {
        let mut remaining = len;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let want = remaining.min(buf.len());
            timeout(self.read_timeout, self.recv.read_exact(&mut buf[..want]))
                .await
                .map_err(|_| anyhow!("timed out discarding frame payload"))??;
            remaining -= want;
        }
        Ok(())
    }

    async fn read_pending_data_chunk(&mut self) -> Result<Option<Bytes>> {
        if self.pending_data_frame_bytes == 0 {
            return Ok(None);
        }
        let want = self.pending_data_frame_bytes.min(MESSAGE_DATA_CHUNK_BYTES);
        let chunk = timeout(self.read_timeout, self.recv.read_chunk(want, true))
            .await
            .map_err(|_| anyhow!("timed out reading DATA frame payload"))??
            .ok_or_else(|| anyhow!("truncated DATA frame payload"))?;
        if chunk.bytes.is_empty() {
            return Err(anyhow!("truncated DATA frame payload").into());
        }
        self.pending_data_frame_bytes = self
            .pending_data_frame_bytes
            .saturating_sub(chunk.bytes.len());
        Ok(Some(chunk.bytes))
    }

    pub(crate) async fn recv_response_head(&mut self) -> Result<Option<http::Response<()>>> {
        loop {
            let Some((ty, len)) = self.read_next_frame_header().await? else {
                self.closed = true;
                self.enforce_received_content_length_complete()?;
                return Ok(None);
            };
            if ty == FRAME_DATA {
                self.abort_with_code(H3_FRAME_UNEXPECTED);
                return Err(
                    anyhow!("received DATA before response HEADERS on HTTP/3 stream").into(),
                );
            }
            if let Err(close) = validate_message_stream_frame(ty) {
                self.abort_with_code(close.code);
                return Err(anyhow!(close.message).into());
            }
            if ty != FRAME_HEADERS {
                self.discard_frame_payload(len).await?;
                continue;
            }
            let decoded = self
                .qpack
                .decode_response_head_from_reader(
                    self.stream_id,
                    &mut self.recv,
                    len,
                    self.read_timeout,
                )
                .await
                .map_err(|err| {
                    self.abort_with_code(err.code());
                    anyhow!(err.to_string())
                })?;
            self.response_head_received = true;
            self.declared_response_body_bytes =
                declared_response_body_length(&decoded.response, self.response_head_request)?;
            self.received_response_body_bytes = 0;
            return Ok(Some(decoded.response));
        }
    }

    pub(crate) fn abort_with_code(&mut self, code: u64) {
        abort_bidi_stream(&mut self.send, &mut self.recv, code);
    }

    /// Stops receiving request body bytes.
    pub fn stop_receiving_request_body(&mut self) {
        stop_recv_stream(&mut self.recv, H3_REQUEST_CANCELLED);
        self.closed = true;
    }

    /// Aborts the message stream.
    pub fn abort_message_stream(&mut self) {
        abort_bidi_stream(&mut self.send, &mut self.recv, H3_MESSAGE_ERROR);
        self.closed = true;
    }

    pub(crate) fn send_mut(&mut self) -> &mut quinn::SendStream {
        &mut self.send
    }
}
