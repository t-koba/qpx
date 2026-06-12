use super::codec::decode_prefixed_int;
use super::dynamic_table::{DecoderState, DynamicTable};
use super::errors::FieldDecodeError;
use super::static_table::static_field;
use super::{DEFAULT_DYNAMIC_TABLE_CAPACITY, DEFAULT_MAX_BLOCKED_STREAMS, HEADER_ENTRY_OVERHEAD};
use crate::H3Result as Result;
use anyhow::anyhow;

pub(super) enum EncoderInstruction {
    SetDynamicTableCapacity(usize),
    InsertWithStaticName { index: usize, value: Vec<u8> },
    InsertWithDynamicName { index: usize, value: Vec<u8> },
    InsertWithoutName { name: String, value: Vec<u8> },
    Duplicate(usize),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct FieldSectionPrefix {
    pub(super) required_insert_count: usize,
    pub(super) base: usize,
}

pub(super) fn decode_field_section_prefix(
    cursor: &mut &[u8],
    total_inserted: usize,
    max_table_capacity: usize,
) -> std::result::Result<FieldSectionPrefix, FieldDecodeError> {
    let encoded_insert_count = decode_prefixed_int(cursor, 8)
        .map_err(FieldDecodeError::from)?
        .1 as usize;
    let (sign_bit, delta_base) = decode_prefixed_int(cursor, 7).map_err(FieldDecodeError::from)?;
    let delta_base = delta_base as usize;
    let required_insert_count =
        decode_required_insert_count(encoded_insert_count, total_inserted, max_table_capacity)?;
    let base = if required_insert_count == 0 {
        0
    } else if sign_bit == 0 {
        required_insert_count
            .checked_add(delta_base)
            .ok_or_else(|| FieldDecodeError::decompression_failed("QPACK base overflow"))?
    } else {
        required_insert_count
            .checked_sub(delta_base + 1)
            .ok_or_else(|| FieldDecodeError::decompression_failed("invalid QPACK base index"))?
    };
    Ok(FieldSectionPrefix {
        required_insert_count,
        base,
    })
}

pub(super) fn decode_required_insert_count(
    encoded_insert_count: usize,
    total_inserted: usize,
    max_table_capacity: usize,
) -> std::result::Result<usize, FieldDecodeError> {
    if encoded_insert_count == 0 {
        return Ok(0);
    }
    let max_entries = max_table_capacity / 32;
    if max_entries == 0 {
        return Err(FieldDecodeError::decompression_failed(
            "dynamic QPACK references require non-zero table capacity",
        ));
    }

    let full_range = max_entries
        .checked_mul(2)
        .ok_or_else(|| FieldDecodeError::decompression_failed("QPACK full range overflow"))?;
    if encoded_insert_count > full_range {
        return Err(FieldDecodeError::decompression_failed(
            "QPACK encoded insert count exceeds full range",
        ));
    }
    let mut required = encoded_insert_count
        .checked_sub(1)
        .ok_or_else(|| FieldDecodeError::decompression_failed("invalid QPACK insert count"))?;
    let mut wrapped = total_inserted % full_range;
    let required_window = required
        .checked_add(max_entries)
        .ok_or_else(|| FieldDecodeError::decompression_failed("QPACK insert count overflow"))?;
    if wrapped >= required_window {
        required = required
            .checked_add(full_range)
            .ok_or_else(|| FieldDecodeError::decompression_failed("QPACK insert count overflow"))?;
    } else if wrapped
        .checked_add(max_entries)
        .ok_or_else(|| FieldDecodeError::decompression_failed("QPACK insert count overflow"))?
        < required
    {
        wrapped = wrapped
            .checked_add(full_range)
            .ok_or_else(|| FieldDecodeError::decompression_failed("QPACK insert count overflow"))?;
    }
    let decoded = required
        .checked_add(total_inserted)
        .and_then(|value| value.checked_sub(wrapped))
        .ok_or_else(|| FieldDecodeError::decompression_failed("invalid QPACK insert count"))?;
    if decoded == 0 {
        return Err(FieldDecodeError::decompression_failed(
            "non-zero QPACK encoded insert count decoded to zero",
        ));
    }
    Ok(decoded)
}

pub(super) fn track_field_section_size(
    total: &mut u64,
    field: &(String, Vec<u8>),
    limit: u64,
) -> std::result::Result<(), FieldDecodeError> {
    let field_size = field
        .0
        .len()
        .checked_add(field.1.len())
        .and_then(|value| value.checked_add(HEADER_ENTRY_OVERHEAD as usize))
        .ok_or_else(|| FieldDecodeError::decompression_failed("field section size overflow"))?;
    *total = total
        .checked_add(field_size as u64)
        .ok_or_else(|| FieldDecodeError::decompression_failed("field section size overflow"))?;
    if *total > limit {
        return Err(FieldDecodeError::decompression_failed(format!(
            "field section size {} exceeds advertised limit {limit}",
            *total
        )));
    }
    Ok(())
}

pub(super) fn apply_encoder_instruction(
    table: &mut DynamicTable,
    instruction: EncoderInstruction,
) -> Result<()> {
    match instruction {
        EncoderInstruction::SetDynamicTableCapacity(size) => table.set_max_size(size),
        EncoderInstruction::InsertWithStaticName { index, value } => {
            let (name, _) = static_field(index)
                .ok_or_else(|| anyhow!("unknown static QPACK name index {index}"))?;
            table.insert(name.to_string(), value)
        }
        EncoderInstruction::InsertWithDynamicName { index, value } => {
            let (name, _) = table.get_latest_relative(index)?;
            table.insert(name, value)
        }
        EncoderInstruction::InsertWithoutName { name, value } => table.insert(name, value),
        EncoderInstruction::Duplicate(index) => table.duplicate_latest_relative(index),
    }
}

pub(crate) fn fuzz_qpack_decoder(data: &[u8]) {
    let state = DecoderState::new(
        DEFAULT_DYNAMIC_TABLE_CAPACITY,
        DEFAULT_MAX_BLOCKED_STREAMS,
        u64::MAX,
    );
    if let Ok(decoded) = state.decode_field_lines(data) {
        let _ = (decoded.fields.len(), decoded.dynamic_ref);
    }
}
