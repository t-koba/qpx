use super::codec::{decode_prefixed_int, decode_string};
use super::encoder::{
    apply_encoder_instruction, decode_field_section_prefix, parse_encoder_instruction,
    track_field_section_size,
};
use super::errors::FieldDecodeError;
use super::static_table::static_field;
use super::{DecodedFields, HEADER_ENTRY_OVERHEAD};
use anyhow::{Result, anyhow};
use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone)]
struct DynamicEntry {
    name: String,
    value: Vec<u8>,
    size: usize,
}

impl DynamicEntry {
    fn new(name: String, value: Vec<u8>) -> Self {
        let size = name.len() + value.len() + HEADER_ENTRY_OVERHEAD as usize;
        Self { name, value, size }
    }
}

#[derive(Debug)]
pub(super) struct DynamicTable {
    entries: VecDeque<DynamicEntry>,
    inserted: usize,
    dropped: usize,
    current_size: usize,
    max_size: usize,
    max_capacity: usize,
}

impl DynamicTable {
    fn new(max_capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            inserted: 0,
            dropped: 0,
            current_size: 0,
            max_size: 0,
            max_capacity,
        }
    }

    pub(super) fn total_inserted(&self) -> usize {
        self.inserted
    }

    pub(super) fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    pub(super) fn set_max_size(&mut self, new_size: usize) -> Result<()> {
        if new_size > self.max_capacity {
            return Err(anyhow!(
                "QPACK dynamic table size {new_size} exceeds advertised capacity {}",
                self.max_capacity
            ));
        }
        self.max_size = new_size;
        self.evict_to_limit(0)?;
        Ok(())
    }

    pub(super) fn insert(&mut self, name: String, value: Vec<u8>) -> Result<()> {
        let entry = DynamicEntry::new(name, value);
        if entry.size > self.max_size {
            return Err(anyhow!(
                "QPACK dynamic entry size {} exceeds current table capacity {}",
                entry.size,
                self.max_size
            ));
        }
        self.evict_to_limit(entry.size)?;
        self.current_size += entry.size;
        self.entries.push_back(entry);
        self.inserted += 1;
        Ok(())
    }

    pub(super) fn duplicate_latest_relative(&mut self, index: usize) -> Result<()> {
        let (name, value) = self.get_latest_relative(index)?;
        self.insert(name, value)
    }

    fn get_relative_from_base(&self, base: usize, index: usize) -> Result<(String, Vec<u8>)> {
        let absolute = base
            .checked_sub(index)
            .ok_or_else(|| anyhow!("invalid QPACK relative index {index} for base {base}"))?;
        self.get_absolute(absolute)
    }

    fn get_post_base(&self, base: usize, index: usize) -> Result<(String, Vec<u8>)> {
        let absolute = base
            .checked_add(index)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| anyhow!("QPACK post-base index overflow"))?;
        self.get_absolute(absolute)
    }

    pub(super) fn get_latest_relative(&self, index: usize) -> Result<(String, Vec<u8>)> {
        let absolute = self
            .inserted
            .checked_sub(index)
            .ok_or_else(|| anyhow!("invalid QPACK latest-relative index {index}"))?;
        self.get_absolute(absolute)
    }

    fn get_absolute(&self, absolute: usize) -> Result<(String, Vec<u8>)> {
        if absolute == 0 || absolute <= self.dropped || absolute > self.inserted {
            return Err(anyhow!("invalid QPACK absolute index {absolute}"));
        }
        let position = absolute - self.dropped - 1;
        let entry = self
            .entries
            .get(position)
            .ok_or_else(|| anyhow!("missing QPACK dynamic entry {absolute}"))?;
        Ok((entry.name.clone(), entry.value.clone()))
    }

    fn evict_to_limit(&mut self, additional: usize) -> Result<()> {
        while self.current_size + additional > self.max_size {
            let Some(entry) = self.entries.pop_front() else {
                return Err(anyhow!("QPACK dynamic table eviction underflow"));
            };
            self.current_size -= entry.size;
            self.dropped += 1;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct DecoderState {
    pub(super) table: DynamicTable,
    max_blocked_streams: u64,
    max_field_section_size: u64,
    blocked_streams: HashSet<u64>,
}

impl DecoderState {
    pub(super) fn new(
        max_table_capacity: usize,
        max_blocked_streams: u64,
        max_field_section_size: u64,
    ) -> Self {
        Self {
            table: DynamicTable::new(max_table_capacity),
            max_blocked_streams,
            max_field_section_size,
            blocked_streams: HashSet::new(),
        }
    }

    pub(super) fn register_blocked_stream(
        &mut self,
        stream_id: u64,
    ) -> std::result::Result<(), String> {
        if self.blocked_streams.insert(stream_id)
            && self.blocked_streams.len() as u64 > self.max_blocked_streams
        {
            self.blocked_streams.remove(&stream_id);
            return Err(format!(
                "QPACK blocked stream limit exceeded: advertised={}, stream_id={stream_id}",
                self.max_blocked_streams
            ));
        }
        Ok(())
    }

    pub(super) fn unregister_blocked_stream(&mut self, stream_id: u64) {
        self.blocked_streams.remove(&stream_id);
    }

    pub(super) fn decode_field_lines(
        &self,
        payload: &[u8],
    ) -> Result<DecodedFields, FieldDecodeError> {
        let mut cursor = payload;
        let prefix = decode_field_section_prefix(
            &mut cursor,
            self.table.total_inserted(),
            self.table.max_capacity(),
        )?;
        if prefix.required_insert_count > self.table.total_inserted() {
            return Err(FieldDecodeError::MissingRefs(prefix.required_insert_count));
        }

        let mut out = Vec::new();
        let mut field_section_size = 0u64;
        while !cursor.is_empty() {
            let first = cursor[0];
            if (first & 0x80) != 0 {
                let (flags, index) = decode_prefixed_int(&mut cursor, 6)?;
                let field = match flags {
                    0b11 => {
                        let (name, value) = static_field(index as usize).ok_or_else(|| {
                            FieldDecodeError::decompression_failed(format!(
                                "unknown static QPACK table index {index}"
                            ))
                        })?;
                        (name.to_string(), value.as_bytes().to_vec())
                    }
                    0b10 => self
                        .table
                        .get_relative_from_base(prefix.base, index as usize)
                        .map_err(FieldDecodeError::from)?,
                    _ => {
                        return Err(FieldDecodeError::decompression_failed(format!(
                            "invalid indexed QPACK field flags {flags:#b}"
                        )));
                    }
                };
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            if (first & 0xf0) == 0x10 {
                let (flags, index) = decode_prefixed_int(&mut cursor, 4)?;
                if flags != 0b0001 {
                    return Err(FieldDecodeError::decompression_failed(format!(
                        "invalid post-base indexed QPACK flags {flags:#b}"
                    )));
                }
                let field = self
                    .table
                    .get_post_base(prefix.base, index as usize)
                    .map_err(FieldDecodeError::from)?;
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            if (first & 0xc0) == 0x40 {
                let (flags, index) = decode_prefixed_int(&mut cursor, 4)?;
                let value = decode_string(&mut cursor, 8)?;
                let field = match flags {
                    flag if (flag & 0b0101) == 0b0101 => {
                        let (name, _) = static_field(index as usize).ok_or_else(|| {
                            FieldDecodeError::decompression_failed(format!(
                                "unknown static QPACK name index {index}"
                            ))
                        })?;
                        (name.to_string(), value)
                    }
                    flag if (flag & 0b0101) == 0b0100 => {
                        let (name, _) = self
                            .table
                            .get_relative_from_base(prefix.base, index as usize)
                            .map_err(FieldDecodeError::from)?;
                        (name, value)
                    }
                    _ => {
                        return Err(FieldDecodeError::decompression_failed(format!(
                            "invalid QPACK name-reference flags {flags:#b}"
                        )));
                    }
                };
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            if (first & 0xf0) == 0x00 {
                let (flags, index) = decode_prefixed_int(&mut cursor, 3)?;
                if flags != 0 {
                    return Err(FieldDecodeError::decompression_failed(format!(
                        "invalid QPACK post-base name-reference flags {flags:#b}"
                    )));
                }
                let (name, _) = self
                    .table
                    .get_post_base(prefix.base, index as usize)
                    .map_err(FieldDecodeError::from)?;
                let value = decode_string(&mut cursor, 8)?;
                let field = (name, value);
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            if (first & 0xe0) == 0x20 {
                let name = decode_string(&mut cursor, 4)?;
                let value = decode_string(&mut cursor, 8)?;
                let field = (
                    String::from_utf8(name)
                        .map_err(|err| FieldDecodeError::decompression_failed(err.to_string()))?,
                    value,
                );
                track_field_section_size(
                    &mut field_section_size,
                    &field,
                    self.max_field_section_size,
                )?;
                out.push(field);
                continue;
            }
            return Err(FieldDecodeError::decompression_failed(format!(
                "unsupported QPACK field representation: 0x{first:02x}"
            )));
        }

        Ok(DecodedFields {
            fields: out,
            dynamic_ref: prefix.required_insert_count != 0,
        })
    }

    pub(super) fn process_encoder_chunk(&mut self, payload: &[u8]) -> Result<Option<(usize, u64)>> {
        let mut cursor = payload;
        let mut consumed = 0usize;
        let inserted_before = self.table.total_inserted();

        while !cursor.is_empty() {
            let before = cursor.len();
            let Some(instruction) = parse_encoder_instruction(&mut cursor)? else {
                break;
            };
            apply_encoder_instruction(&mut self.table, instruction)?;
            consumed += before - cursor.len();
        }

        if consumed == 0 {
            return Ok(None);
        }
        let inserted_delta = (self.table.total_inserted() - inserted_before) as u64;
        Ok(Some((consumed, inserted_delta)))
    }
}
