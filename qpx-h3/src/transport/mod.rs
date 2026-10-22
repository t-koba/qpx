use crate::H3Result as Result;
use crate::protocol::{FRAME_DATA, FRAME_HEADERS, read_varint, write_frame};
use anyhow::anyhow;
use std::time::Duration;
use tokio::time::timeout;

mod datagram;
mod metrics;
mod request_stream;
mod split;
mod streams;

#[cfg(test)]
mod tests;

pub(crate) use datagram::DatagramDispatch;
pub use datagram::StreamDatagrams;
pub use request_stream::RequestStream;
pub use split::{RequestRecvStream, RequestSendStream};
pub use streams::{BidiStream, OpenStreams, StreamRecv, StreamSend, UniRecvStream, UniSendStream};

const MESSAGE_DATA_CHUNK_BYTES: usize = 64 * 1024;
const WEBTRANSPORT_STREAM_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestStreamConfig {
    pub(crate) read_timeout: Duration,
    pub(crate) max_frame_payload_bytes: usize,
    pub(crate) max_non_data_frame_payload_bytes: usize,
    pub(crate) max_field_section_bytes: usize,
    pub(crate) max_request_body_bytes: Option<usize>,
}

#[derive(Debug)]
pub(super) struct ResponseSendState {
    response_started: bool,
    final_sent: bool,
    body_allowed: bool,
    head_request: bool,
    declared_content_length: Option<u64>,
    sent_body_bytes: u64,
}

use crate::qpack::encode_response_head;
use crate::qpack::encode_trailers;
use bytes::Bytes;

/// Sends the response head of an HTTP/3 request stream.
///
/// The rules here are the ones every HTTP/3 response follows: the head
/// comes first, a body may follow only if the head allows one, and the
/// declared length must match what is sent.
pub(super) async fn send_response_head(
    send: &mut quinn::SendStream,
    response_state: &mut Option<ResponseSendState>,
    response: &http::Response<()>,
) -> Result<()> {
    let mut response = response.clone();
    let Some(state) = response_state.as_mut() else {
        return Err(
            anyhow!("HTTP/3 response HEADERS can only be sent by server response streams").into(),
        );
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
    send_headers(send, &payload).await
}

/// Sends one DATA frame of an HTTP/3 response.
pub(super) async fn send_response_data(
    send: &mut quinn::SendStream,
    response_state: &mut Option<ResponseSendState>,
    payload: Bytes,
) -> Result<()> {
    if let Some(state) = response_state.as_ref() {
        if !state.final_sent {
            return Err(anyhow!("HTTP/3 DATA cannot precede final response HEADERS").into());
        }
        if !state.body_allowed {
            return Err(anyhow!("HTTP/3 DATA is not allowed for this response").into());
        }
    }
    if let Some(state) = response_state.as_mut() {
        enforce_response_content_length_send(state, payload.len())?;
    }
    write_frame(send, FRAME_DATA, payload.as_ref()).await
}

/// Sends the response trailers of an HTTP/3 request stream.
pub(super) async fn send_response_trailers(
    send: &mut quinn::SendStream,
    response_state: &mut Option<ResponseSendState>,
    trailers: &http::HeaderMap,
) -> Result<()> {
    let mut trailers = trailers.clone();
    if let Some(state) = response_state.as_ref() {
        if !state.final_sent {
            return Err(anyhow!("HTTP/3 trailers cannot precede final response HEADERS").into());
        }
        if !state.body_allowed {
            return Err(anyhow!("HTTP/3 trailers are not allowed for this response").into());
        }
        enforce_response_content_length_complete(state)?;
        crate::response::sanitize_trailers_for_h3(&mut trailers)?;
    }
    let payload = encode_trailers(&trailers);
    send_headers(send, &payload).await
}

/// Finishes an HTTP/3 response stream.
pub(super) async fn finish_response(
    send: &mut quinn::SendStream,
    response_state: &Option<ResponseSendState>,
) -> Result<()> {
    if let Some(state) = response_state.as_ref()
        && state.response_started
        && !state.final_sent
    {
        return Err(anyhow!("HTTP/3 response ended without final response HEADERS").into());
    }
    if let Some(state) = response_state.as_ref() {
        enforce_response_content_length_complete(state)?;
    }
    send.finish()?;
    Ok(())
}

/// The limits that decide how large a frame's payload may be.
#[derive(Debug, Clone, Copy)]
pub(super) struct FramePayloadLimits {
    pub(super) max_frame_payload_bytes: usize,
    pub(super) max_non_data_frame_payload_bytes: usize,
    pub(super) max_field_section_bytes: usize,
}

/// Reads the header of the next frame on an HTTP/3 stream.
///
/// The header is the frame's type and its payload length, and a frame whose
/// payload is larger than its limit is refused before any of it is read.
pub(super) async fn read_next_frame_header(
    recv: &mut quinn::RecvStream,
    limits: FramePayloadLimits,
) -> Result<Option<(u64, usize)>> {
    let Some(ty) = read_varint(recv).await? else {
        return Ok(None);
    };
    let len = read_varint(recv)
        .await?
        .ok_or_else(|| anyhow!("truncated frame length"))?;
    let max_payload_bytes = max_message_frame_payload_bytes(
        ty,
        limits.max_frame_payload_bytes,
        limits.max_non_data_frame_payload_bytes,
        limits.max_field_section_bytes,
    );
    if len > max_payload_bytes as u64 {
        return Err(anyhow!(
            "HTTP/3 frame 0x{ty:x} payload length {len} exceeds limit {max_payload_bytes}"
        )
        .into());
    }
    Ok(Some((ty, len as usize)))
}

/// Discards a frame's payload without reading it into memory.
pub(super) async fn discard_frame_payload(
    recv: &mut quinn::RecvStream,
    read_timeout: Duration,
    len: usize,
) -> Result<()> {
    let mut remaining = len;
    let mut buf = [0u8; 8192];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        timeout(read_timeout, recv.read_exact(&mut buf[..want]))
            .await
            .map_err(|_| anyhow!("timed out discarding frame payload"))??;
        remaining -= want;
    }
    Ok(())
}

/// Writes one HEADERS frame.
pub(super) async fn send_headers(send: &mut quinn::SendStream, payload: &[u8]) -> Result<()> {
    write_frame(send, FRAME_HEADERS, payload).await
}

fn enforce_body_frame(
    max_request_body_bytes: Option<usize>,
    declared_content_length: Option<u64>,
    received_body_bytes: &mut usize,
    next_len: usize,
    message_name: &'static str,
) -> Result<()> {
    *received_body_bytes = received_body_bytes
        .checked_add(next_len)
        .ok_or_else(|| anyhow!("HTTP/3 {message_name} body size overflow"))?;
    if let Some(max_request_body_bytes) = max_request_body_bytes
        && *received_body_bytes > max_request_body_bytes
    {
        return Err(anyhow!(
            "HTTP/3 request body exceeds max_request_body_bytes ({max_request_body_bytes})"
        )
        .into());
    }
    if let Some(declared_content_length) = declared_content_length
        && *received_body_bytes as u64 > declared_content_length
    {
        return Err(anyhow!(
            "HTTP/3 {message_name} body exceeds Content-Length: Content-Length={declared_content_length}, received={}",
            *received_body_bytes
        ).into());
    }
    Ok(())
}

fn enforce_body_content_length_complete(
    declared_content_length: Option<u64>,
    received_body_bytes: usize,
    message_name: &'static str,
) -> Result<()> {
    let Some(declared_content_length) = declared_content_length else {
        return Ok(());
    };
    if received_body_bytes as u64 != declared_content_length {
        return Err(anyhow!(
            "HTTP/3 {message_name} body length mismatch: Content-Length={declared_content_length}, received={received_body_bytes}"
        ).into());
    }
    Ok(())
}

fn declared_response_body_length(
    response: &http::Response<()>,
    head_request: bool,
) -> Result<Option<u64>> {
    let declared = crate::response::parse_content_length(response.headers())?;
    if head_request
        || response.status().is_informational()
        || response.status() == http::StatusCode::NO_CONTENT
        || response.status() == http::StatusCode::RESET_CONTENT
        || response.status() == http::StatusCode::NOT_MODIFIED
    {
        Ok(Some(0))
    } else {
        Ok(declared)
    }
}

fn enforce_response_content_length_send(
    state: &mut ResponseSendState,
    next_len: usize,
) -> Result<()> {
    state.sent_body_bytes = state
        .sent_body_bytes
        .checked_add(next_len as u64)
        .ok_or_else(|| anyhow!("HTTP/3 response body size overflow"))?;
    if let Some(declared) = state.declared_content_length
        && state.sent_body_bytes > declared
    {
        return Err(anyhow!(
            "HTTP/3 response body exceeds Content-Length: Content-Length={declared}, sent={}",
            state.sent_body_bytes
        )
        .into());
    }
    Ok(())
}

fn enforce_response_content_length_complete(state: &ResponseSendState) -> Result<()> {
    if let Some(declared) = state.declared_content_length
        && state.sent_body_bytes != declared
    {
        return Err(anyhow!(
            "HTTP/3 response body length mismatch: Content-Length={declared}, sent={}",
            state.sent_body_bytes
        )
        .into());
    }
    Ok(())
}

fn max_message_frame_payload_bytes(
    ty: u64,
    max_data_frame_payload_bytes: usize,
    max_non_data_frame_payload_bytes: usize,
    max_field_section_bytes: usize,
) -> usize {
    match ty {
        FRAME_DATA => max_data_frame_payload_bytes,
        FRAME_HEADERS => max_field_section_bytes,
        _ => max_non_data_frame_payload_bytes,
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
