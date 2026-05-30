use super::encoder::EncoderInstruction;
use bytes::{Buf, Bytes};
use std::collections::VecDeque;

#[derive(Debug)]
pub(crate) enum EncoderStreamError {
    Closed(String),
    Invalid(String),
}

impl EncoderStreamError {
    pub(super) fn closed(message: impl Into<String>) -> Self {
        Self::Closed(message.into())
    }

    pub(super) fn invalid(message: impl Into<String>) -> Self {
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

pub(super) struct EncoderStreamBuffer {
    chunks: VecDeque<Bytes>,
    buffered_len: usize,
    max_buffered_len: usize,
}

impl EncoderStreamBuffer {
    pub(super) fn new(max_buffered_len: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            buffered_len: 0,
            max_buffered_len,
        }
    }

    pub(super) fn push(&mut self, chunk: Bytes) -> std::result::Result<(), EncoderStreamError> {
        if chunk.is_empty() {
            return Ok(());
        }
        self.buffered_len = self
            .buffered_len
            .checked_add(chunk.len())
            .ok_or_else(|| EncoderStreamError::invalid("QPACK encoder stream buffer overflow"))?;
        if self.buffered_len > self.max_buffered_len {
            return Err(EncoderStreamError::invalid(format!(
                "QPACK encoder stream buffer length {} exceeds limit {}",
                self.buffered_len, self.max_buffered_len
            )));
        }
        self.chunks.push_back(chunk);
        Ok(())
    }

    pub(super) fn parse_next_instruction(
        &mut self,
    ) -> std::result::Result<Option<EncoderInstruction>, EncoderStreamError> {
        let mut cursor = EncoderStreamCursor {
            chunks: &self.chunks,
            buffered_len: self.len(),
            offset: 0,
        };
        let Some(first) = cursor.peek_byte(0) else {
            return Ok(None);
        };
        let instruction = if (first & 0x80) != 0 {
            let Some((flags, index)) = cursor.read_prefixed_int(6)? else {
                return Ok(None);
            };
            if (flags & 0b10) != 0b10 {
                return Err(EncoderStreamError::invalid(format!(
                    "invalid QPACK insert-with-name-reference flags {flags:#b}"
                )));
            }
            let Some(value) = cursor.read_string(8)? else {
                return Ok(None);
            };
            if (flags & 0b01) != 0 {
                EncoderInstruction::InsertWithStaticName {
                    index: index as usize,
                    value,
                }
            } else {
                EncoderInstruction::InsertWithDynamicName {
                    index: index as usize,
                    value,
                }
            }
        } else if (first & 0x40) != 0 {
            let Some(name) = cursor.read_string(6)? else {
                return Ok(None);
            };
            let Some(value) = cursor.read_string(8)? else {
                return Ok(None);
            };
            EncoderInstruction::InsertWithoutName {
                name: String::from_utf8(name)
                    .map_err(|err| EncoderStreamError::invalid(err.to_string()))?,
                value,
            }
        } else if (first & 0xe0) == 0x00 {
            let Some((flags, index)) = cursor.read_prefixed_int(5)? else {
                return Ok(None);
            };
            if flags != 0 {
                return Err(EncoderStreamError::invalid(format!(
                    "invalid QPACK duplicate flags {flags:#b}"
                )));
            }
            EncoderInstruction::Duplicate(index as usize)
        } else if (first & 0x20) != 0 {
            let Some((flags, size)) = cursor.read_prefixed_int(5)? else {
                return Ok(None);
            };
            if flags != 0b001 {
                return Err(EncoderStreamError::invalid(format!(
                    "invalid QPACK dynamic table size-update flags {flags:#b}"
                )));
            }
            EncoderInstruction::SetDynamicTableCapacity(size as usize)
        } else {
            return Err(EncoderStreamError::invalid(format!(
                "unsupported QPACK encoder instruction: 0x{first:02x}"
            )));
        };
        self.advance_front(cursor.offset);
        Ok(Some(instruction))
    }

    fn len(&self) -> usize {
        self.buffered_len
    }

    fn advance_front(&mut self, consumed: usize) {
        if consumed == 0 {
            return;
        }
        let Some(mut front) = self.chunks.pop_front() else {
            return;
        };
        let consumed = consumed.min(front.len());
        self.buffered_len = self.buffered_len.saturating_sub(consumed);
        front.advance(consumed);
        if !front.is_empty() {
            self.chunks.push_front(front);
        }
    }
}

struct EncoderStreamCursor<'a> {
    chunks: &'a VecDeque<Bytes>,
    buffered_len: usize,
    offset: usize,
}

impl EncoderStreamCursor<'_> {
    fn read_prefixed_int(
        &mut self,
        prefix_bits: u8,
    ) -> std::result::Result<Option<(u8, u64)>, EncoderStreamError> {
        let Some(first) = self.peek_byte(0) else {
            return Ok(None);
        };
        let (flags, mask) = if prefix_bits == 8 {
            (0, u8::MAX)
        } else {
            (first >> prefix_bits, ((1u16 << prefix_bits) - 1) as u8)
        };
        let mut value = u64::from(first & mask);
        let mut consumed = 1usize;
        if value < u64::from(mask) {
            self.offset += consumed;
            return Ok(Some((flags, value)));
        }
        let mut shift = 0u32;
        loop {
            let Some(byte) = self.peek_byte(consumed) else {
                return Ok(None);
            };
            value += u64::from(byte & 0x7f) << shift;
            consumed += 1;
            if (byte & 0x80) == 0 {
                self.offset += consumed;
                return Ok(Some((flags, value)));
            }
            shift += 7;
            if shift > 56 {
                return Err(EncoderStreamError::invalid(
                    "QPACK encoder stream prefixed integer overflow",
                ));
            }
        }
    }

    fn read_string(
        &mut self,
        total_bits: u8,
    ) -> std::result::Result<Option<Vec<u8>>, EncoderStreamError> {
        let start = self.offset;
        let Some((flags, len)) = self.read_prefixed_int(total_bits - 1)? else {
            self.offset = start;
            return Ok(None);
        };
        let len = usize::try_from(len)
            .map_err(|_| EncoderStreamError::invalid("QPACK encoder string length overflow"))?;
        if self.buffered_len.saturating_sub(self.offset) < len {
            self.offset = start;
            return Ok(None);
        }
        let raw = self.read_bytes(len);
        if (flags & 0x1) == 0 {
            return Ok(Some(raw));
        }
        crate::huffman::decode(&raw)
            .map(Some)
            .map_err(|err| EncoderStreamError::invalid(err.to_string()))
    }

    fn read_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut offset = self.offset;
        let mut remaining = len;
        for chunk in self.chunks {
            if offset >= chunk.len() {
                offset -= chunk.len();
                continue;
            }
            let take = remaining.min(chunk.len() - offset);
            out.extend_from_slice(&chunk[offset..offset + take]);
            remaining -= take;
            offset = 0;
            if remaining == 0 {
                break;
            }
        }
        self.offset += len;
        out
    }

    fn peek_byte(&self, relative_offset: usize) -> Option<u8> {
        let mut offset = self.offset.checked_add(relative_offset)?;
        if offset >= self.buffered_len {
            return None;
        }
        for chunk in self.chunks {
            if offset < chunk.len() {
                return Some(chunk[offset]);
            }
            offset -= chunk.len();
        }
        None
    }
}
