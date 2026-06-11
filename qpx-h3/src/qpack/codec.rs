use crate::H3Result as Result;
use crate::huffman;
use anyhow::anyhow;

pub(super) fn encode_header_prefix(
    out: &mut Vec<u8>,
    required_insert_count: usize,
    base: usize,
    max_table_capacity: usize,
) {
    if max_table_capacity == 0 || required_insert_count == 0 {
        encode_prefixed_int(out, 8, 0, 0);
        encode_prefixed_int(out, 7, 0, 0);
        return;
    }

    let max_entries = max_table_capacity / 32;
    let encoded_insert_count = required_insert_count % (2 * max_entries) + 1;
    let (sign_bit, delta_base) = if required_insert_count > base {
        (1, required_insert_count - base - 1)
    } else {
        (0, base - required_insert_count)
    };
    encode_prefixed_int(out, 8, 0, encoded_insert_count as u64);
    encode_prefixed_int(out, 7, sign_bit, delta_base as u64);
}

pub(super) fn encode_string(out: &mut Vec<u8>, total_bits: u8, flags: u8, value: &[u8]) {
    encode_prefixed_int(out, total_bits - 1, flags << 1, value.len() as u64);
    out.extend_from_slice(value);
}

pub(super) fn encode_header_ack(stream_id: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_prefixed_int(&mut out, 7, 0b1, stream_id);
    out
}

pub(super) fn encode_insert_count_increment(increment: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_prefixed_int(&mut out, 6, 0, increment);
    out
}

pub(super) fn decode_string(cursor: &mut &[u8], total_bits: u8) -> Result<Vec<u8>> {
    Ok(
        try_decode_string(cursor, total_bits)?
            .ok_or_else(|| anyhow!("truncated string literal"))?,
    )
}

pub(super) fn try_decode_string(cursor: &mut &[u8], total_bits: u8) -> Result<Option<Vec<u8>>> {
    let original = *cursor;
    let Some((flags, len)) = try_decode_prefixed_int(cursor, total_bits - 1)? else {
        *cursor = original;
        return Ok(None);
    };
    let len = len as usize;
    if cursor.len() < len {
        *cursor = original;
        return Ok(None);
    }
    let (raw, rest) = cursor.split_at(len);
    *cursor = rest;
    if (flags & 0x1) == 0 {
        return Ok(Some(raw.to_vec()));
    }
    Ok(Some(huffman::decode(raw)?))
}

pub(super) fn decode_prefixed_int(cursor: &mut &[u8], prefix_bits: u8) -> Result<(u8, u64)> {
    Ok(
        try_decode_prefixed_int(cursor, prefix_bits)?
            .ok_or_else(|| anyhow!("truncated integer"))?,
    )
}

pub(super) fn try_decode_prefixed_int(
    cursor: &mut &[u8],
    prefix_bits: u8,
) -> Result<Option<(u8, u64)>> {
    let Some(first) = cursor.first().copied() else {
        return Ok(None);
    };
    let (flags, mask) = if prefix_bits == 8 {
        (0, u8::MAX)
    } else {
        (first >> prefix_bits, ((1u16 << prefix_bits) - 1) as u8)
    };
    let mut value = (first & mask) as u64;
    let mut offset = 1usize;
    if value < mask as u64 {
        *cursor = &cursor[offset..];
        return Ok(Some((flags, value)));
    }
    let mut shift = 0u32;
    while offset < cursor.len() {
        let byte = cursor[offset];
        value += ((byte & 0x7f) as u64) << shift;
        offset += 1;
        if (byte & 0x80) == 0 {
            *cursor = &cursor[offset..];
            return Ok(Some((flags, value)));
        }
        shift += 7;
        if shift > 56 {
            return Err(anyhow!("prefixed integer overflow").into());
        }
    }
    Ok(None)
}

pub(super) fn encode_prefixed_int(out: &mut Vec<u8>, prefix_bits: u8, flags: u8, value: u64) {
    let mask = if prefix_bits == 8 {
        u8::MAX
    } else {
        ((1u16 << prefix_bits) - 1) as u8
    };
    if value < mask as u64 {
        let prefix = if prefix_bits == 8 {
            0
        } else {
            flags << prefix_bits
        };
        out.push(prefix | value as u8);
        return;
    }
    let prefix = if prefix_bits == 8 {
        0
    } else {
        flags << prefix_bits
    };
    out.push(prefix | mask);
    let mut remaining = value - mask as u64;
    while remaining >= 128 {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8);
}
