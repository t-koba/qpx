#[cfg(any(test, feature = "http3"))]
use anyhow::{Result, anyhow};
#[cfg(any(test, feature = "http3"))]
use bytes::{Bytes, BytesMut};
#[cfg(any(test, feature = "http3"))]
use std::collections::VecDeque;

#[cfg(any(test, feature = "http3"))]
#[derive(Debug, Default)]
pub(crate) struct CapsuleBuffer {
    chunks: VecDeque<Bytes>,
    len: usize,
}

#[cfg(any(test, feature = "http3"))]
impl CapsuleBuffer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn push(&mut self, bytes: Bytes, max_bytes: usize) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let new_len = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| anyhow!("CONNECT-UDP capsule buffer length overflow"))?;
        if new_len > max_bytes {
            return Err(anyhow!(
                "CONNECT-UDP capsule buffer exceeded max_capsule_buffer_bytes={} (current={new_len})",
                max_bytes
            ));
        }
        self.len = new_len;
        self.chunks.push_back(bytes);
        Ok(())
    }

    pub(crate) fn take_next(&mut self) -> Result<Option<(u64, Bytes)>> {
        let (capsule_type, type_len) = match self.peek_varint(0) {
            Some(v) => v,
            None => return Ok(None),
        };
        let (capsule_len, len_len) = match self.peek_varint(type_len) {
            Some(v) => v,
            None => return Ok(None),
        };
        let capsule_len =
            usize::try_from(capsule_len).map_err(|_| anyhow!("capsule length exceeds usize"))?;
        let payload_offset = type_len + len_len;
        let total = payload_offset
            .checked_add(capsule_len)
            .ok_or_else(|| anyhow!("capsule length overflow"))?;
        if self.len < total {
            return Ok(None);
        }
        self.discard(payload_offset);
        Ok(Some((capsule_type, self.take_bytes(capsule_len))))
    }

    fn peek_varint(&self, offset: usize) -> Option<(u64, usize)> {
        let first = self.peek_byte(offset)?;
        let prefix = first >> 6;
        let len = match prefix {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        if self.len < offset.checked_add(len)? {
            return None;
        }
        let mut value = u64::from(first & 0x3f);
        for idx in 1..len {
            value = (value << 8) | u64::from(self.peek_byte(offset + idx)?);
        }
        Some((value, len))
    }

    fn peek_byte(&self, mut offset: usize) -> Option<u8> {
        if offset >= self.len {
            return None;
        }
        for chunk in &self.chunks {
            if offset < chunk.len() {
                return Some(chunk[offset]);
            }
            offset -= chunk.len();
        }
        None
    }

    fn discard(&mut self, mut len: usize) {
        debug_assert!(len <= self.len);
        self.len -= len;
        while len > 0 {
            let front_len = self.chunks.front().map_or(0, Bytes::len);
            if front_len <= len {
                self.chunks.pop_front();
                len -= front_len;
            } else {
                if let Some(front) = self.chunks.front_mut() {
                    *front = front.slice(len..);
                }
                break;
            }
        }
    }

    fn take_bytes(&mut self, len: usize) -> Bytes {
        debug_assert!(len <= self.len);
        if len == 0 {
            return Bytes::new();
        }
        if let Some(front) = self.chunks.front_mut()
            && len <= front.len()
        {
            let out = front.slice(..len);
            if len == front.len() {
                self.chunks.pop_front();
            } else {
                *front = front.slice(len..);
            }
            self.len -= len;
            return out;
        }

        let mut out = BytesMut::with_capacity(len);
        let mut remaining = len;
        while remaining > 0 {
            let Some(front) = self.chunks.pop_front() else {
                break;
            };
            if front.len() <= remaining {
                out.extend_from_slice(front.as_ref());
                remaining -= front.len();
            } else {
                out.extend_from_slice(&front[..remaining]);
                self.chunks.push_front(front.slice(remaining..));
                remaining = 0;
            }
        }
        self.len -= len;
        out.freeze()
    }
}

#[cfg(any(test, feature = "http3"))]
pub(crate) fn encode_datagram_capsule_header(value_len: usize) -> Result<Bytes> {
    let mut capsule = Vec::with_capacity(9);
    encode_quic_varint(0, &mut capsule)?; // DATAGRAM capsule type
    encode_quic_varint(value_len as u64, &mut capsule)?;
    Ok(Bytes::from(capsule))
}

#[cfg(any(test, feature = "http3"))]
pub(crate) fn encode_datagram_capsule_context_header(payload_len: usize) -> Result<Bytes> {
    let value_len = payload_len
        .checked_add(1)
        .ok_or_else(|| anyhow!("CONNECT-UDP DATAGRAM capsule length overflow"))?;
    let mut capsule = Vec::with_capacity(10);
    encode_quic_varint(0, &mut capsule)?; // DATAGRAM capsule type
    encode_quic_varint(value_len as u64, &mut capsule)?;
    encode_quic_varint(0, &mut capsule)?; // context id
    Ok(Bytes::from(capsule))
}

#[cfg(test)]
pub(crate) fn encode_datagram_capsule(payload: &[u8]) -> Result<Bytes> {
    let header = encode_datagram_capsule_context_header(payload.len())?;
    let mut capsule = BytesMut::with_capacity(header.len() + payload.len());
    capsule.extend_from_slice(header.as_ref());
    capsule.extend_from_slice(payload);
    Ok(capsule.freeze())
}

pub(crate) fn decode_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let prefix = first >> 6;
    let len = match prefix {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for b in &buf[1..len] {
        value = (value << 8) | u64::from(*b);
    }
    Some((value, len))
}

#[cfg(any(test, feature = "http3"))]
pub(crate) fn encode_quic_varint(value: u64, out: &mut Vec<u8>) -> Result<()> {
    if value <= 63 {
        out.push(value as u8);
        return Ok(());
    }
    if value <= 16_383 {
        out.push(((value >> 8) as u8) | 0x40);
        out.push((value & 0xff) as u8);
        return Ok(());
    }
    if value <= 1_073_741_823 {
        out.push(((value >> 24) as u8) | 0x80);
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
        return Ok(());
    }
    if value <= 4_611_686_018_427_387_903 {
        out.push(((value >> 56) as u8) | 0xc0);
        out.push(((value >> 48) & 0xff) as u8);
        out.push(((value >> 40) & 0xff) as u8);
        out.push(((value >> 32) & 0xff) as u8);
        out.push(((value >> 24) & 0xff) as u8);
        out.push(((value >> 16) & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push((value & 0xff) as u8);
        return Ok(());
    }
    Err(anyhow!("quic varint too large"))
}

#[cfg(test)]
mod tests {
    use crate::http3::capsule::*;

    #[test]
    fn capsule_buffer_limit_rejects_growth_past_cap() {
        let mut buf = CapsuleBuffer::new();
        buf.push(Bytes::from_static(&[1, 2, 3]), 4)
            .expect("within cap");
        assert!(buf.push(Bytes::from_static(&[4, 5]), 4).is_err());
    }

    #[test]
    fn quic_varint_roundtrip_samples() {
        let samples = [
            0u64,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ];
        for value in samples {
            let mut encoded = Vec::new();
            encode_quic_varint(value, &mut encoded).expect("encode");
            let (decoded, consumed) = decode_quic_varint(&encoded).expect("decode");
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn datagram_capsule_encode_decode_roundtrip() {
        let payload = b"hello-udp";
        let capsule = encode_datagram_capsule(payload).expect("capsule");
        let mut buf = CapsuleBuffer::new();
        buf.push(capsule, 1024).expect("push");
        let (capsule_type, value) = buf.take_next().expect("parse").expect("one");
        assert_eq!(capsule_type, 0);
        assert!(buf.is_empty());
        let (context_id, offset) = decode_quic_varint(value.as_ref()).expect("context");
        assert_eq!(context_id, 0);
        assert_eq!(&value[offset..], payload);
    }

    #[test]
    fn datagram_capsule_split_payload_only_copies_when_needed() {
        let payload = b"split-payload";
        let capsule = encode_datagram_capsule(payload).expect("capsule");
        let split = capsule.len() - 3;
        let mut buf = CapsuleBuffer::new();
        buf.push(capsule.slice(..split), 1024).expect("first");
        assert!(buf.take_next().expect("partial").is_none());
        buf.push(capsule.slice(split..), 1024).expect("second");
        let (_, value) = buf.take_next().expect("parse").expect("one");
        let (_, offset) = decode_quic_varint(value.as_ref()).expect("context");
        assert_eq!(&value[offset..], payload);
        assert!(buf.is_empty());
    }
}
