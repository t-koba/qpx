use super::codec;
use super::dynamic_table::DecoderState;
use super::encoder_stream::{EncoderStreamBuffer, EncoderStreamError};
use super::field_reader::FieldPayloadReader;
use super::fields::{
    DecodedField, FieldSink, RequestHeadSink, ResponseHeadSink, TrailerSink, push_decoded_field,
};
use super::static_table::static_field;
use super::{
    DECODER_INSTRUCTION_QUEUE_DEPTH, DecodedRequestHead, DecodedResponseHead, HeaderDecodeError,
};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::HeaderMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::time::timeout;

#[derive(Clone)]
pub(crate) struct QpackConnection {
    state: Arc<Mutex<DecoderState>>,
    decoder_instructions: mpsc::Sender<Bytes>,
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
        let (decoder_instructions, decoder_instruction_rx) =
            mpsc::channel(DECODER_INSTRUCTION_QUEUE_DEPTH);
        tokio::spawn(decoder_instruction_writer(
            decoder_send,
            decoder_instruction_rx,
        ));
        Self {
            state: Arc::new(Mutex::new(DecoderState::new(
                max_table_capacity,
                max_blocked_streams,
                max_field_section_size,
            ))),
            decoder_instructions,
            notify: Arc::new(Notify::new()),
            max_encoder_stream_buffer_bytes,
            encoder_stream_read_timeout,
        }
    }

    pub(crate) async fn process_encoder_stream(
        &self,
        mut recv: quinn::RecvStream,
    ) -> std::result::Result<(), EncoderStreamError> {
        let mut buffered = EncoderStreamBuffer::new(self.max_encoder_stream_buffer_bytes);
        loop {
            let chunk = match timeout(
                self.encoder_stream_read_timeout,
                recv.read_chunk(self.max_encoder_stream_buffer_bytes.max(1), true),
            )
            .await
            .map_err(|_| EncoderStreamError::closed("QPACK encoder stream read timed out"))?
            .map_err(|err| EncoderStreamError::closed(err.to_string()))?
            {
                Some(chunk) => chunk.bytes,
                None => {
                    return Err(EncoderStreamError::closed(
                        "peer closed QPACK encoder stream",
                    ));
                }
            };

            buffered.push(chunk)?;
            let mut decoder_instructions = Vec::new();
            while let Some(instruction) = buffered.parse_next_instruction()? {
                let inserted_delta = self
                    .state
                    .lock()
                    .await
                    .apply_encoder_instruction(instruction)
                    .map_err(|err| EncoderStreamError::invalid(err.to_string()))?;
                if inserted_delta > 0 {
                    decoder_instructions.push(Bytes::from(codec::encode_insert_count_increment(
                        inserted_delta,
                    )));
                    self.notify.notify_waiters();
                }
            }
            for instruction in decoder_instructions {
                self.send_decoder_instruction(instruction)
                    .await
                    .map_err(|err| EncoderStreamError::invalid(err.to_string()))?;
            }
        }
    }

    pub(crate) async fn decode_request_head_from_reader(
        &self,
        stream_id: u64,
        reader: &mut quinn::RecvStream,
        len: usize,
        wait_timeout: Duration,
    ) -> std::result::Result<DecodedRequestHead, HeaderDecodeError> {
        self.decode_field_section_from_reader(
            stream_id,
            reader,
            len,
            wait_timeout,
            RequestHeadSink::default(),
        )
        .await
    }

    pub(crate) async fn decode_response_head_from_reader(
        &self,
        stream_id: u64,
        reader: &mut quinn::RecvStream,
        len: usize,
        wait_timeout: Duration,
    ) -> std::result::Result<DecodedResponseHead, HeaderDecodeError> {
        self.decode_field_section_from_reader(
            stream_id,
            reader,
            len,
            wait_timeout,
            ResponseHeadSink::default(),
        )
        .await
    }

    pub(crate) async fn decode_trailers_from_reader(
        &self,
        stream_id: u64,
        reader: &mut quinn::RecvStream,
        len: usize,
        wait_timeout: Duration,
    ) -> std::result::Result<HeaderMap, HeaderDecodeError> {
        self.decode_field_section_from_reader(
            stream_id,
            reader,
            len,
            wait_timeout,
            TrailerSink::default(),
        )
        .await
    }

    async fn decode_field_section_from_reader<S>(
        &self,
        stream_id: u64,
        reader: &mut quinn::RecvStream,
        len: usize,
        wait_timeout: Duration,
        mut sink: S,
    ) -> std::result::Result<S::Output, HeaderDecodeError>
    where
        S: FieldSink,
    {
        let mut reader = FieldPayloadReader::new(reader, len, wait_timeout);
        let (_, encoded_insert_count) = reader.read_prefixed_int(8).await?;
        let (sign_bit, delta_base) = reader.read_prefixed_int(7).await?;
        let mut blocked_registered = false;
        let prefix = loop {
            let result = {
                let mut state = self.state.lock().await;
                let prefix = state
                    .decode_field_section_prefix_values(
                        encoded_insert_count as usize,
                        sign_bit,
                        delta_base as usize,
                    )
                    .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?;
                if prefix.required_insert_count <= state.total_inserted() {
                    break prefix;
                }
                if !blocked_registered {
                    state
                        .register_blocked_stream(stream_id)
                        .map_err(HeaderDecodeError::qpack)?;
                    blocked_registered = true;
                }
                Ok::<_, HeaderDecodeError>(prefix.required_insert_count)
            };
            let required_refs = result?;
            if timeout(wait_timeout, self.notify.notified()).await.is_err() {
                if blocked_registered {
                    self.state.lock().await.unregister_blocked_stream(stream_id);
                }
                return Err(HeaderDecodeError::qpack(format!(
                    "timed out waiting for QPACK dynamic state ({required_refs} refs)"
                )));
            }
        };

        let (max_field_section_size, dynamic_snapshot) = {
            let state = self.state.lock().await;
            (
                state.max_field_section_size(),
                state.dynamic_table_snapshot(),
            )
        };
        let mut field_section_size = 0u64;
        while reader.remaining() != 0 {
            let first = reader.read_u8().await?;
            if (first & 0x80) != 0 {
                let (flags, index) = reader.read_prefixed_int_after_first(first, 6).await?;
                let field = match flags {
                    0b11 => {
                        let (name, value) = static_field(index as usize).ok_or_else(|| {
                            HeaderDecodeError::qpack(format!(
                                "unknown static QPACK table index {index}"
                            ))
                        })?;
                        DecodedField::static_field(name, value)
                    }
                    0b10 => {
                        let (name, value) = dynamic_snapshot
                            .get_relative_from_base_shared(prefix.base, index as usize)
                            .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?;
                        DecodedField::shared(name, value)
                    }
                    _ => {
                        return Err(HeaderDecodeError::qpack(format!(
                            "invalid indexed QPACK field flags {flags:#b}"
                        )));
                    }
                };
                push_decoded_field(
                    &mut sink,
                    &mut field_section_size,
                    field,
                    max_field_section_size,
                )?;
                continue;
            }
            if (first & 0xf0) == 0x10 {
                let (flags, index) = reader.read_prefixed_int_after_first(first, 4).await?;
                if flags != 0b0001 {
                    return Err(HeaderDecodeError::qpack(format!(
                        "invalid post-base indexed QPACK flags {flags:#b}"
                    )));
                }
                let (name, value) = dynamic_snapshot
                    .get_post_base_shared(prefix.base, index as usize)
                    .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?;
                let field = DecodedField::shared(name, value);
                push_decoded_field(
                    &mut sink,
                    &mut field_section_size,
                    field,
                    max_field_section_size,
                )?;
                continue;
            }
            if (first & 0xc0) == 0x40 {
                let (flags, index) = reader.read_prefixed_int_after_first(first, 4).await?;
                let value = reader.read_string(8).await?;
                let field = match flags {
                    flag if (flag & 0b0101) == 0b0101 => {
                        let (name, _) = static_field(index as usize).ok_or_else(|| {
                            HeaderDecodeError::qpack(format!(
                                "unknown static QPACK name index {index}"
                            ))
                        })?;
                        DecodedField::owned(name.to_string(), value)
                    }
                    flag if (flag & 0b0101) == 0b0100 => {
                        let (name, _) = dynamic_snapshot
                            .get_relative_from_base_shared(prefix.base, index as usize)
                            .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?;
                        DecodedField::owned(name.to_string(), value)
                    }
                    _ => {
                        return Err(HeaderDecodeError::qpack(format!(
                            "invalid QPACK name-reference flags {flags:#b}"
                        )));
                    }
                };
                push_decoded_field(
                    &mut sink,
                    &mut field_section_size,
                    field,
                    max_field_section_size,
                )?;
                continue;
            }
            if (first & 0xf0) == 0x00 {
                let (flags, index) = reader.read_prefixed_int_after_first(first, 3).await?;
                if flags != 0 {
                    return Err(HeaderDecodeError::qpack(format!(
                        "invalid QPACK post-base name-reference flags {flags:#b}"
                    )));
                }
                let (name, _) = dynamic_snapshot
                    .get_post_base_shared(prefix.base, index as usize)
                    .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?;
                let value = reader.read_string(8).await?;
                let field = DecodedField::owned(name.to_string(), value);
                push_decoded_field(
                    &mut sink,
                    &mut field_section_size,
                    field,
                    max_field_section_size,
                )?;
                continue;
            }
            if (first & 0xe0) == 0x20 {
                let name = reader.read_string_after_first(first, 4).await?;
                let value = reader.read_string(8).await?;
                let field = DecodedField::owned(
                    String::from_utf8(name.to_vec())
                        .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?,
                    value,
                );
                push_decoded_field(
                    &mut sink,
                    &mut field_section_size,
                    field,
                    max_field_section_size,
                )?;
                continue;
            }
            return Err(HeaderDecodeError::qpack(format!(
                "unsupported QPACK field representation: 0x{first:02x}"
            )));
        }

        if blocked_registered {
            self.state.lock().await.unregister_blocked_stream(stream_id);
        }
        if prefix.required_insert_count != 0 {
            self.send_decoder_instruction(Bytes::from(codec::encode_header_ack(stream_id)))
                .await
                .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?;
        }
        sink.finish()
    }

    async fn send_decoder_instruction(&self, payload: Bytes) -> Result<()> {
        if payload.is_empty() {
            return Ok(());
        }
        self.decoder_instructions
            .send(payload)
            .await
            .map_err(|_| anyhow!("QPACK decoder instruction stream closed"))?;
        Ok(())
    }
}

async fn decoder_instruction_writer(mut send: quinn::SendStream, mut rx: mpsc::Receiver<Bytes>) {
    while let Some(first) = rx.recv().await {
        if send.write_all(first.as_ref()).await.is_err() {
            break;
        }
        let mut written = first.len();
        while let Ok(next) = rx.try_recv() {
            written = written.saturating_add(next.len());
            if send.write_all(next.as_ref()).await.is_err() {
                return;
            }
            if written >= 16 * 1024 {
                break;
            }
        }
    }
}
