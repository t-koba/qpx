use super::errors::HeaderDecodeError;
use bytes::{Buf, Bytes};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::timeout;

const FIELD_SECTION_READ_CHUNK_BYTES: usize = 16 * 1024;

pub(super) struct FieldPayloadReader<'a> {
    reader: &'a mut quinn::RecvStream,
    stream_remaining: usize,
    buffers: VecDeque<Bytes>,
    buffered_len: usize,
    timeout: Duration,
}

impl<'a> FieldPayloadReader<'a> {
    pub(super) fn new(reader: &'a mut quinn::RecvStream, len: usize, timeout: Duration) -> Self {
        Self {
            reader,
            stream_remaining: len,
            buffers: VecDeque::new(),
            buffered_len: 0,
            timeout,
        }
    }
}

impl FieldPayloadReader<'_> {
    pub(super) fn remaining(&self) -> usize {
        self.stream_remaining + self.buffered_len
    }

    async fn refill(&mut self) -> std::result::Result<(), HeaderDecodeError> {
        if self.buffered_len != 0 {
            return Ok(());
        }
        if self.stream_remaining == 0 {
            return Err(HeaderDecodeError::qpack("truncated QPACK field section"));
        }
        let want = self.stream_remaining.min(FIELD_SECTION_READ_CHUNK_BYTES);
        let chunk = timeout(self.timeout, self.reader.read_chunk(want, true))
            .await
            .map_err(|_| HeaderDecodeError::qpack("timed out reading QPACK field section"))?
            .map_err(|err| HeaderDecodeError::qpack(err.to_string()))?
            .ok_or_else(|| HeaderDecodeError::qpack("truncated QPACK field section"))?;
        if chunk.bytes.is_empty() {
            return Err(HeaderDecodeError::qpack("truncated QPACK field section"));
        }
        self.stream_remaining = self.stream_remaining.saturating_sub(chunk.bytes.len());
        self.buffered_len += chunk.bytes.len();
        self.buffers.push_back(chunk.bytes);
        Ok(())
    }

    pub(super) async fn read_u8(&mut self) -> std::result::Result<u8, HeaderDecodeError> {
        self.refill().await?;
        let front = self
            .buffers
            .front_mut()
            .ok_or_else(|| HeaderDecodeError::qpack("truncated QPACK field section"))?;
        let byte = front[0];
        front.advance(1);
        self.buffered_len -= 1;
        if front.is_empty() {
            self.buffers.pop_front();
        }
        Ok(byte)
    }

    async fn read_exact_bytes(
        &mut self,
        len: usize,
    ) -> std::result::Result<Bytes, HeaderDecodeError> {
        if len > self.remaining() {
            return Err(HeaderDecodeError::qpack("truncated QPACK string literal"));
        }
        self.refill().await?;
        if let Some(front) = self.buffers.front_mut()
            && front.len() >= len
        {
            let out = front.split_to(len);
            self.buffered_len -= len;
            if front.is_empty() {
                self.buffers.pop_front();
            }
            return Ok(out);
        }
        let mut out = vec![0u8; len];
        let mut written = 0usize;
        while written < len {
            self.refill().await?;
            let front = self
                .buffers
                .front_mut()
                .ok_or_else(|| HeaderDecodeError::qpack("truncated QPACK string literal"))?;
            let take = (len - written).min(front.len());
            out[written..written + take].copy_from_slice(&front[..take]);
            front.advance(take);
            self.buffered_len -= take;
            if front.is_empty() {
                self.buffers.pop_front();
            }
            written += take;
        }
        Ok(Bytes::from(out))
    }

    pub(super) async fn read_prefixed_int(
        &mut self,
        prefix_bits: u8,
    ) -> std::result::Result<(u8, u64), HeaderDecodeError> {
        let first = self.read_u8().await?;
        self.read_prefixed_int_after_first(first, prefix_bits).await
    }

    pub(super) async fn read_prefixed_int_after_first(
        &mut self,
        first: u8,
        prefix_bits: u8,
    ) -> std::result::Result<(u8, u64), HeaderDecodeError> {
        let (flags, mask) = if prefix_bits == 8 {
            (0, u8::MAX)
        } else {
            (first >> prefix_bits, ((1u16 << prefix_bits) - 1) as u8)
        };
        let mut value = (first & mask) as u64;
        if value < mask as u64 {
            return Ok((flags, value));
        }
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8().await?;
            value = value
                .checked_add(((byte & 0x7f) as u64) << shift)
                .ok_or_else(|| HeaderDecodeError::qpack("prefixed integer overflow"))?;
            if (byte & 0x80) == 0 {
                return Ok((flags, value));
            }
            shift += 7;
            if shift > 56 {
                return Err(HeaderDecodeError::qpack("prefixed integer overflow"));
            }
        }
    }

    pub(super) async fn read_string(
        &mut self,
        total_bits: u8,
    ) -> std::result::Result<Bytes, HeaderDecodeError> {
        let first = self.read_u8().await?;
        self.read_string_after_first(first, total_bits).await
    }

    pub(super) async fn read_string_after_first(
        &mut self,
        first: u8,
        total_bits: u8,
    ) -> std::result::Result<Bytes, HeaderDecodeError> {
        let (flags, len) = self
            .read_prefixed_int_after_first(first, total_bits - 1)
            .await?;
        let raw = self.read_exact_bytes(len as usize).await?;
        if (flags & 0x1) == 0 {
            return Ok(raw);
        }
        crate::huffman::decode(&raw)
            .map(Bytes::from)
            .map_err(|err| HeaderDecodeError::qpack(err.to_string()))
    }
}
