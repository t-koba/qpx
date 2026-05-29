use crate::protocol::{
    FRAME_DATA, FRAME_HEADERS, H3_FRAME_UNEXPECTED, H3_MESSAGE_ERROR, H3_REQUEST_CANCELLED,
    read_varint, validate_message_stream_frame, write_frame,
};
use crate::qpack::{QpackConnection, encode_response_head, encode_trailers};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use std::time::Duration;
use tokio::time::timeout;

use super::{
    MESSAGE_DATA_CHUNK_BYTES, ResponseSendState, enforce_body_content_length_complete,
    enforce_body_frame, enforce_response_content_length_complete,
    enforce_response_content_length_send, max_message_frame_payload_bytes, stop_recv_stream,
};

pub struct RequestSendStream {
    pub(super) send: quinn::SendStream,
    pub(super) stream_id: u64,
    pub(super) response_state: Option<ResponseSendState>,
}

impl RequestSendStream {
    pub fn id(&self) -> u64 {
        self.stream_id
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
            state.declared_content_length = if state.body_allowed {
                crate::response::parse_content_length(response.headers())?
            } else {
                None
            };
        }
        let payload = encode_response_head(&response);
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
        if let Some(state) = self.response_state.as_mut() {
            enforce_response_content_length_send(state, payload.len())?;
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
            enforce_response_content_length_complete(state)?;
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
        if let Some(state) = self.response_state.as_ref() {
            enforce_response_content_length_complete(state)?;
        }
        self.send.finish()?;
        Ok(())
    }

    pub fn abort_message_stream(&mut self) {
        if let Ok(code) = quinn::VarInt::from_u64(H3_MESSAGE_ERROR) {
            let _ = self.send.reset(code);
        }
    }
}

#[derive(Debug)]
pub struct RequestRecvStream {
    pub(super) recv: quinn::RecvStream,
    pub(super) stream_id: u64,
    pub(super) qpack: QpackConnection,
    pub(super) read_timeout: Duration,
    pub(super) max_frame_payload_bytes: usize,
    pub(super) max_non_data_frame_payload_bytes: usize,
    pub(super) max_field_section_bytes: usize,
    pub(super) max_request_body_bytes: Option<usize>,
    pub(super) declared_request_body_bytes: Option<u64>,
    pub(super) received_request_body_bytes: usize,
    pub(super) receives_response_body: bool,
    pub(super) response_head_received: bool,
    pub(super) declared_response_body_bytes: Option<u64>,
    pub(super) received_response_body_bytes: usize,
    pub(super) pending_data_frame_bytes: usize,
    pub(super) pending_trailers: Option<http::HeaderMap>,
    pub(super) closed: bool,
}

impl RequestRecvStream {
    pub fn id(&self) -> u64 {
        self.stream_id
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
            ));
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
            return Err(anyhow!("truncated DATA frame payload"));
        }
        self.pending_data_frame_bytes = self
            .pending_data_frame_bytes
            .saturating_sub(chunk.bytes.len());
        Ok(Some(chunk.bytes))
    }

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
                stop_recv_stream(&mut self.recv, H3_FRAME_UNEXPECTED);
                return Err(anyhow!("received HTTP/3 frame after trailers"));
            }
            match ty {
                FRAME_DATA => {
                    if let Err(err) = self.enforce_received_data_frame_len(len) {
                        stop_recv_stream(&mut self.recv, H3_MESSAGE_ERROR);
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
                            stop_recv_stream(&mut self.recv, err.code());
                            return Err(anyhow!(err.to_string()));
                        }
                    }
                    if let Err(err) = self.enforce_received_content_length_complete() {
                        stop_recv_stream(&mut self.recv, H3_MESSAGE_ERROR);
                        return Err(err);
                    }
                    continue;
                }
                _ => {
                    if let Err(close) = validate_message_stream_frame(ty) {
                        stop_recv_stream(&mut self.recv, close.code);
                        return Err(anyhow!(close.message));
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
                ));
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

    pub fn abort_message_stream(&mut self) {
        stop_recv_stream(&mut self.recv, H3_MESSAGE_ERROR);
        self.closed = true;
    }

    pub fn stop_receiving_request_body(&mut self) {
        stop_recv_stream(&mut self.recv, H3_REQUEST_CANCELLED);
        self.closed = true;
    }
}
