use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};

pub(crate) fn append_capsule_chunk(
    buf: &mut BytesMut,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<()> {
    let new_len = buf
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| anyhow!("CONNECT-UDP capsule buffer length overflow"))?;
    if new_len > max_bytes {
        return Err(anyhow!(
            "CONNECT-UDP capsule buffer exceeded max_capsule_buffer_bytes={} (current={new_len})",
            max_bytes
        ));
    }
    buf.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn take_next_capsule(buf: &mut BytesMut) -> Result<Option<(u64, Bytes)>> {
    let (capsule_type, type_len) = match decode_quic_varint(buf.as_ref()) {
        Some(v) => v,
        None => return Ok(None),
    };
    let (capsule_len, len_len) = match decode_quic_varint(&buf[type_len..]) {
        Some(v) => v,
        None => return Ok(None),
    };
    let capsule_len =
        usize::try_from(capsule_len).map_err(|_| anyhow!("capsule length exceeds usize"))?;
    let payload_offset = type_len + len_len;
    let total = payload_offset
        .checked_add(capsule_len)
        .ok_or_else(|| anyhow!("capsule length overflow"))?;
    if buf.len() < total {
        return Ok(None);
    }
    let payload = Bytes::copy_from_slice(&buf[payload_offset..total]);
    buf.advance(total);
    Ok(Some((capsule_type, payload)))
}

pub(crate) fn encode_datagram_capsule(payload: &[u8]) -> Result<Bytes> {
    let mut value = Vec::with_capacity(1 + payload.len());
    encode_quic_varint(0, &mut value)?; // context id
    value.extend_from_slice(payload);

    let mut capsule = Vec::with_capacity(2 + value.len());
    encode_quic_varint(0, &mut capsule)?; // DATAGRAM capsule type
    encode_quic_varint(value.len() as u64, &mut capsule)?;
    capsule.extend_from_slice(&value);
    Ok(Bytes::from(capsule))
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
    use super::*;

    #[test]
    fn capsule_buffer_limit_rejects_growth_past_cap() {
        let mut buf = BytesMut::new();
        append_capsule_chunk(&mut buf, &[1, 2, 3], 4).expect("within cap");
        assert!(append_capsule_chunk(&mut buf, &[4, 5], 4).is_err());
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
        let mut buf = BytesMut::from(capsule.as_ref());
        let (capsule_type, value) = take_next_capsule(&mut buf).expect("parse").expect("one");
        assert_eq!(capsule_type, 0);
        assert!(buf.is_empty());
        let (context_id, offset) = decode_quic_varint(value.as_ref()).expect("context");
        assert_eq!(context_id, 0);
        assert_eq!(&value[offset..], payload);
    }
}
