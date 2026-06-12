use crate::H3Result as Result;
use anyhow::anyhow;
use std::collections::HashSet;
use tokio::io::{AsyncRead, AsyncReadExt};

#[cfg(test)]
use super::read_varint_slice;
use super::{
    SETTING_ENABLE_CONNECT_PROTOCOL, SETTING_ENABLE_WEBTRANSPORT, SETTING_H3_DATAGRAM,
    SETTING_MAX_FIELD_SECTION_SIZE, SETTING_QPACK_MAX_BLOCKED_STREAMS,
    SETTING_QPACK_MAX_TABLE_CAPACITY, SETTING_WEBTRANSPORT_MAX_SESSIONS,
};

#[derive(Debug, Clone)]
pub(crate) struct PeerSettings {
    pub(crate) enable_extended_connect: bool,
    pub(crate) enable_datagram: bool,
    pub(crate) enable_webtransport: bool,
    pub(crate) qpack_max_table_capacity: u64,
    pub(crate) qpack_max_blocked_streams: u64,
    pub(crate) max_field_section_size: u64,
    pub(crate) max_webtransport_sessions: u64,
}

impl Default for PeerSettings {
    fn default() -> Self {
        Self {
            enable_extended_connect: false,
            enable_datagram: false,
            enable_webtransport: false,
            qpack_max_table_capacity: 0,
            qpack_max_blocked_streams: 0,
            max_field_section_size: u64::MAX,
            max_webtransport_sessions: 0,
        }
    }
}
#[cfg(test)]
pub(crate) fn decode_settings_frame(payload: &[u8]) -> Result<PeerSettings> {
    let mut cursor = payload;
    let mut seen = HashSet::new();
    let mut settings = PeerSettings::default();
    while !cursor.is_empty() {
        let (id, used_id) = read_varint_slice(cursor)?;
        cursor = &cursor[used_id..];
        let (value, used_value) = read_varint_slice(cursor)?;
        cursor = &cursor[used_value..];
        if !seen.insert(id) {
            return Err(anyhow!("duplicate SETTINGS parameter 0x{id:x}").into());
        }
        apply_settings_parameter(&mut settings, id, value)?;
    }
    Ok(settings)
}

pub(crate) async fn decode_settings_frame_from_reader<R>(
    reader: &mut R,
    len: u64,
    max_payload_bytes: usize,
) -> Result<PeerSettings>
where
    R: AsyncRead + Unpin,
{
    if len > max_payload_bytes as u64 {
        return Err(anyhow!(
            "HTTP/3 SETTINGS payload length {len} exceeds limit {max_payload_bytes}"
        )
        .into());
    }
    let mut remaining = len;
    let mut seen = HashSet::new();
    let mut settings = PeerSettings::default();
    while remaining > 0 {
        let id = read_varint_from_payload(reader, &mut remaining, "SETTINGS parameter id").await?;
        let value =
            read_varint_from_payload(reader, &mut remaining, "SETTINGS parameter value").await?;
        if !seen.insert(id) {
            return Err(anyhow!("duplicate SETTINGS parameter 0x{id:x}").into());
        }
        apply_settings_parameter(&mut settings, id, value)?;
    }
    Ok(settings)
}

pub(super) async fn read_varint_from_payload<R>(
    reader: &mut R,
    remaining: &mut u64,
    label: &str,
) -> Result<u64>
where
    R: AsyncRead + Unpin,
{
    if *remaining == 0 {
        return Err(anyhow!("truncated {label}").into());
    }
    let first = reader.read_u8().await?;
    *remaining -= 1;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    let needed = (len - 1) as u64;
    if *remaining < needed {
        return Err(anyhow!("truncated {label}").into());
    }
    let mut value = (first & 0x3f) as u64;
    for _ in 1..len {
        value = (value << 8) | reader.read_u8().await? as u64;
        *remaining -= 1;
    }
    Ok(value)
}

fn apply_settings_parameter(settings: &mut PeerSettings, id: u64, value: u64) -> Result<()> {
    match id {
        SETTING_QPACK_MAX_TABLE_CAPACITY => settings.qpack_max_table_capacity = value,
        SETTING_QPACK_MAX_BLOCKED_STREAMS => settings.qpack_max_blocked_streams = value,
        SETTING_MAX_FIELD_SECTION_SIZE => settings.max_field_section_size = value,
        SETTING_ENABLE_CONNECT_PROTOCOL => {
            if value > 1 {
                return Err(anyhow!("SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1").into());
            }
            settings.enable_extended_connect = value == 1;
        }
        SETTING_H3_DATAGRAM => {
            if value > 1 {
                return Err(anyhow!("SETTINGS_H3_DATAGRAM must be 0 or 1").into());
            }
            settings.enable_datagram = value == 1;
        }
        SETTING_ENABLE_WEBTRANSPORT => {
            if value > 1 {
                return Err(anyhow!("SETTINGS_ENABLE_WEBTRANSPORT must be 0 or 1").into());
            }
            settings.enable_webtransport = value == 1;
        }
        SETTING_WEBTRANSPORT_MAX_SESSIONS => settings.max_webtransport_sessions = value,
        0x2..=0x5 => {
            return Err(anyhow!(
                "reserved HTTP/2 SETTINGS parameter 0x{id:x} is invalid in HTTP/3"
            )
            .into());
        }
        _ => {}
    }
    Ok(())
}
