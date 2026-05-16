mod codec;
mod decode;
mod dynamic_table;
mod encode;
mod encoder;
mod errors;
mod static_table;

#[cfg(test)]
mod tests;

use crate::qpack_fields::{append_header, validate_h3_response_field, validate_h3_trailer_field};
use anyhow::Result;
use bytes::{Buf, BytesMut};
use decode::pseudo_value_to_string;
use dynamic_table::DecoderState;
use errors::FieldDecodeError;
use http::HeaderMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Notify};
use tokio::time::timeout;

pub(crate) use crate::qpack_fields::validate_h3_regular_field;
pub(crate) use decode::decode_request_head_from_fields;
pub(crate) use encode::{encode_request_head, encode_response_head, encode_trailers};
pub(crate) use encoder::fuzz_qpack_decoder;
pub(crate) use errors::HeaderDecodeError;

#[cfg(test)]
use codec::{encode_header_prefix, encode_prefixed_int, encode_string};
#[cfg(test)]
use encoder::{decode_field_section_prefix, decode_required_insert_count};
#[cfg(test)]
use static_table::{STATIC_TABLE, static_field};

pub(crate) const DEFAULT_DYNAMIC_TABLE_CAPACITY: usize = 4096;
pub(crate) const DEFAULT_MAX_BLOCKED_STREAMS: u64 = 16;
pub(crate) const DEFAULT_ENCODER_STREAM_BUFFER_BYTES: usize = 1024 * 1024;
const HEADER_ENTRY_OVERHEAD: u64 = 32;

#[derive(Debug)]
pub(crate) struct DecodedRequestHead {
    pub(crate) request: http::Request<()>,
    pub(crate) protocol: Option<String>,
}

#[derive(Debug)]
struct DecodedFields {
    fields: Vec<(String, Vec<u8>)>,
    dynamic_ref: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedResponseHead {
    pub(crate) response: http::Response<()>,
}

#[derive(Debug)]
pub(crate) enum EncoderStreamError {
    Closed(String),
    Invalid(String),
}

impl EncoderStreamError {
    fn closed(message: impl Into<String>) -> Self {
        Self::Closed(message.into())
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

impl std::fmt::Display for EncoderStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(message) | Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for EncoderStreamError {}

#[derive(Clone)]
pub(crate) struct QpackConnection {
    state: Arc<Mutex<DecoderState>>,
    decoder_send: Arc<Mutex<quinn::SendStream>>,
    notify: Arc<Notify>,
    max_encoder_stream_buffer_bytes: usize,
    encoder_stream_read_timeout: Duration,
}

impl std::fmt::Debug for QpackConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QpackConnection").finish_non_exhaustive()
    }
}

impl QpackConnection {
    pub(crate) fn new(
        decoder_send: quinn::SendStream,
        max_table_capacity: usize,
        max_blocked_streams: u64,
        max_field_section_size: u64,
        max_encoder_stream_buffer_bytes: usize,
        encoder_stream_read_timeout: Duration,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(DecoderState::new(
                max_table_capacity,
                max_blocked_streams,
                max_field_section_size,
            ))),
            decoder_send: Arc::new(Mutex::new(decoder_send)),
            notify: Arc::new(Notify::new()),
            max_encoder_stream_buffer_bytes,
            encoder_stream_read_timeout,
        }
    }

    pub(crate) async fn process_encoder_stream(
        &self,
        mut recv: quinn::RecvStream,
    ) -> std::result::Result<(), EncoderStreamError> {
        let mut buffer = BytesMut::new();
        loop {
            match timeout(
                self.encoder_stream_read_timeout,
                recv.read_chunk(self.max_encoder_stream_buffer_bytes.max(1), true),
            )
            .await
            .map_err(|_| EncoderStreamError::closed("QPACK encoder stream read timed out"))?
            .map_err(|err| EncoderStreamError::closed(err.to_string()))?
            {
                Some(chunk) => {
                    let next_len =
                        buffer.len().checked_add(chunk.bytes.len()).ok_or_else(|| {
                            EncoderStreamError::invalid("QPACK encoder stream buffer overflow")
                        })?;
                    if next_len > self.max_encoder_stream_buffer_bytes {
                        return Err(EncoderStreamError::invalid(format!(
                            "QPACK encoder stream buffer length {next_len} exceeds limit {}",
                            self.max_encoder_stream_buffer_bytes
                        )));
                    }
                    buffer.extend_from_slice(chunk.bytes.as_ref());
                }
                None => {
                    return Err(EncoderStreamError::closed(
                        "peer closed QPACK encoder stream",
                    ));
                }
            }

            loop {
                let (consumed, inserted_delta) = {
                    let mut state = self.state.lock().await;
                    match state
                        .process_encoder_chunk(buffer.as_ref())
                        .map_err(|err| EncoderStreamError::invalid(err.to_string()))?
                    {
                        Some(result) => result,
                        None => break,
                    }
                };
                buffer.advance(consumed);
                if inserted_delta != 0 {
                    self.send_decoder_instruction(&codec::encode_insert_count_increment(
                        inserted_delta,
                    ))
                    .await
                    .map_err(|err| EncoderStreamError::invalid(err.to_string()))?;
                    self.notify.notify_waiters();
                }
            }
        }
    }

    pub(crate) async fn decode_request_head(
        &self,
        stream_id: u64,
        payload: &[u8],
        wait_timeout: Duration,
    ) -> std::result::Result<DecodedRequestHead, HeaderDecodeError> {
        let fields = self
            .decode_field_lines(stream_id, payload, wait_timeout)
            .await?;
        decode_request_head_from_fields(fields)
    }

    pub(crate) async fn decode_response_head(
        &self,
        stream_id: u64,
        payload: &[u8],
        wait_timeout: Duration,
    ) -> std::result::Result<DecodedResponseHead, HeaderDecodeError> {
        let fields = self
            .decode_field_lines(stream_id, payload, wait_timeout)
            .await?;
        let mut status = None;
        let mut headers = HeaderMap::new();
        let mut regular_seen = false;

        for (name, value) in fields {
            let is_pseudo = name.starts_with(':');
            if is_pseudo && regular_seen {
                return Err(HeaderDecodeError::message(format!(
                    "pseudo header {name} appeared after a regular header"
                )));
            }
            match name.as_str() {
                ":status" => {
                    if status.is_some() {
                        return Err(HeaderDecodeError::message(
                            "duplicate :status pseudo header",
                        ));
                    }
                    let value = pseudo_value_to_string(&name, value)?;
                    status = Some(
                        http::StatusCode::from_u16(value.parse::<u16>().map_err(|_| {
                            HeaderDecodeError::message("invalid :status pseudo header")
                        })?)
                        .map_err(|err| HeaderDecodeError::message(err.to_string()))?,
                    );
                }
                other if other.starts_with(':') => {
                    return Err(HeaderDecodeError::message(format!(
                        "unsupported pseudo header {other}"
                    )));
                }
                _ => {
                    regular_seen = true;
                    validate_h3_response_field(&name, &value)?;
                    append_header(&mut headers, &name, &value)
                        .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
                }
            }
        }

        let mut response = http::Response::builder()
            .status(status.ok_or_else(|| HeaderDecodeError::message("missing :status"))?)
            .body(())
            .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
        *response.headers_mut() = headers;
        Ok(DecodedResponseHead { response })
    }

    pub(crate) async fn decode_trailers(
        &self,
        stream_id: u64,
        payload: &[u8],
        wait_timeout: Duration,
    ) -> std::result::Result<HeaderMap, HeaderDecodeError> {
        let fields = self
            .decode_field_lines(stream_id, payload, wait_timeout)
            .await?;
        let mut trailers = HeaderMap::new();
        for (name, value) in fields {
            if name.starts_with(':') {
                return Err(HeaderDecodeError::message(
                    "trailers must not contain pseudo headers",
                ));
            }
            validate_h3_trailer_field(&name, &value)?;
            append_header(&mut trailers, &name, &value)
                .map_err(|err| HeaderDecodeError::message(err.to_string()))?;
        }
        Ok(trailers)
    }

    async fn decode_field_lines(
        &self,
        stream_id: u64,
        payload: &[u8],
        wait_timeout: Duration,
    ) -> std::result::Result<Vec<(String, Vec<u8>)>, HeaderDecodeError> {
        let mut blocked_registered = false;
        let (fields, needs_ack) = loop {
            let outcome = {
                let mut state = self.state.lock().await;
                match state.decode_field_lines(payload) {
                    Ok(decoded) => break (decoded.fields, decoded.dynamic_ref),
                    Err(FieldDecodeError::MissingRefs(required_refs)) => {
                        if !blocked_registered {
                            state
                                .register_blocked_stream(stream_id)
                                .map_err(HeaderDecodeError::qpack)?;
                            blocked_registered = true;
                        }
                        Ok::<_, HeaderDecodeError>(required_refs)
                    }
                    Err(FieldDecodeError::DecompressionFailed(message)) => {
                        if blocked_registered {
                            state.unregister_blocked_stream(stream_id);
                        }
                        return Err(HeaderDecodeError::qpack(message));
                    }
                }
            };
            let required_refs = outcome?;
            if timeout(wait_timeout, self.notify.notified()).await.is_err() {
                if blocked_registered {
                    self.state.lock().await.unregister_blocked_stream(stream_id);
                }
                return Err(HeaderDecodeError::qpack(format!(
                    "timed out waiting for QPACK dynamic state ({required_refs} refs)"
                )));
            }
        };
        if blocked_registered {
            self.state.lock().await.unregister_blocked_stream(stream_id);
        }

        if needs_ack {
            self.send_decoder_instruction(&codec::encode_header_ack(stream_id))
                .await
                .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?;
        }
        Ok(fields)
    }

    async fn send_decoder_instruction(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        let mut send = self.decoder_send.lock().await;
        send.write_all(payload).await?;
        send.flush().await?;
        Ok(())
    }
}
