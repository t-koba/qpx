use crate::protocol::{FRAME_DATA, FRAME_HEADERS};
use anyhow::{Result, anyhow};
use std::time::Duration;

mod datagram;
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
        ));
    }
    if let Some(declared_content_length) = declared_content_length
        && *received_body_bytes as u64 > declared_content_length
    {
        return Err(anyhow!(
            "HTTP/3 {message_name} body exceeds Content-Length: Content-Length={declared_content_length}, received={}",
            *received_body_bytes
        ));
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
        ));
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
        ));
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
        ));
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
