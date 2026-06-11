use crate::H3Result as Result;
use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

mod control;
mod settings;

pub(crate) use control::{
    ConnectionClose, PeerControlState, control_frame_payload_is_known,
    validate_message_stream_frame,
};
#[cfg(test)]
pub(crate) use control::{
    MAX_BUFFERED_PRIORITY_UPDATES, parse_priority, validate_control_stream_frame,
};
pub use control::{PriorityUpdates, StreamPriority};
#[cfg(test)]
pub(crate) use settings::decode_settings_frame;
pub(crate) use settings::{PeerSettings, decode_settings_frame_from_reader};

pub(crate) const FRAME_DATA: u64 = 0x0;
pub(crate) const FRAME_HEADERS: u64 = 0x1;
const FRAME_PRIORITY: u64 = 0x2;
pub(crate) const FRAME_CANCEL_PUSH: u64 = 0x3;
pub(crate) const FRAME_SETTINGS: u64 = 0x4;
pub(crate) const FRAME_PUSH_PROMISE: u64 = 0x5;
const FRAME_PING: u64 = 0x6;
pub(crate) const FRAME_GOAWAY: u64 = 0x7;
const FRAME_WINDOW_UPDATE: u64 = 0x8;
const FRAME_CONTINUATION: u64 = 0x9;
pub(crate) const FRAME_MAX_PUSH_ID: u64 = 0xd;
const FRAME_PAYLOAD_READ_CHUNK_BYTES: usize = 64 * 1024;
pub(crate) const FRAME_PRIORITY_UPDATE_REQUEST: u64 = 0xf0700;
pub(crate) const FRAME_PRIORITY_UPDATE_PUSH: u64 = 0xf0701;
pub(crate) const STREAM_CONTROL: u64 = 0x0;
pub(crate) const STREAM_PUSH: u64 = 0x1;
pub(crate) const STREAM_QPACK_ENCODER: u64 = 0x2;
pub(crate) const STREAM_QPACK_DECODER: u64 = 0x3;
pub(crate) const STREAM_WEBTRANSPORT_BIDI: u64 = 0x41;
pub(crate) const STREAM_WEBTRANSPORT_UNI: u64 = 0x54;

pub(crate) const SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
pub(crate) const SETTING_QPACK_MAX_BLOCKED_STREAMS: u64 = 0x7;
pub(crate) const SETTING_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
pub(crate) const SETTING_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
pub(crate) const SETTING_H3_DATAGRAM: u64 = 0x33;
pub(crate) const SETTING_ENABLE_WEBTRANSPORT: u64 = 0x2b603742;
pub(crate) const SETTING_WEBTRANSPORT_MAX_SESSIONS: u64 = 0x2b603743;

pub(crate) const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x101;
pub(crate) const H3_STREAM_CREATION_ERROR: u64 = 0x103;
pub(crate) const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
pub(crate) const H3_FRAME_UNEXPECTED: u64 = 0x105;
pub(crate) const H3_FRAME_ERROR: u64 = 0x106;
pub(crate) const H3_EXCESSIVE_LOAD: u64 = 0x107;
pub(crate) const H3_ID_ERROR: u64 = 0x108;
pub(crate) const H3_SETTINGS_ERROR: u64 = 0x109;
pub(crate) const H3_MISSING_SETTINGS: u64 = 0x10a;
pub(crate) const H3_REQUEST_CANCELLED: u64 = 0x10c;
pub(crate) const H3_MESSAGE_ERROR: u64 = 0x10e;
pub(crate) const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
pub(crate) const QPACK_ENCODER_STREAM_ERROR: u64 = 0x201;
pub(crate) const H3_DATAGRAM_ERROR: u64 = 0x33;

pub(crate) async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<u64>> {
    let first = match reader.read_u8().await {
        Ok(value) => value,
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let prefix = first >> 6;
    let len = 1usize << prefix;
    let mut value = (first & 0x3f) as u64;
    for _ in 1..len {
        value = (value << 8) | reader.read_u8().await? as u64;
    }
    Ok(Some(value))
}

pub(crate) fn read_varint_slice(input: &[u8]) -> Result<(u64, usize)> {
    let first = *input
        .first()
        .ok_or_else(|| anyhow!("unexpected end of varint"))?;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    if input.len() < len {
        return Err(anyhow!("truncated varint").into());
    }
    let mut value = (first & 0x3f) as u64;
    for byte in &input[1..len] {
        value = (value << 8) | *byte as u64;
    }
    Ok((value, len))
}

pub(crate) async fn write_varint<W: AsyncWrite + Unpin>(writer: &mut W, value: u64) -> Result<()> {
    let buf = encode_varint(value)?;
    writer.write_all(&buf).await?;
    Ok(())
}

pub(crate) fn encode_varint(value: u64) -> Result<Vec<u8>> {
    if value < (1 << 6) {
        return Ok(vec![value as u8]);
    }
    if value < (1 << 14) {
        return Ok(vec![
            0x40 | ((value >> 8) as u8 & 0x3f),
            (value & 0xff) as u8,
        ]);
    }
    if value < (1 << 30) {
        return Ok(vec![
            0x80 | ((value >> 24) as u8 & 0x3f),
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]);
    }
    if value < (1 << 62) {
        return Ok(vec![
            0xc0 | ((value >> 56) as u8 & 0x3f),
            ((value >> 48) & 0xff) as u8,
            ((value >> 40) & 0xff) as u8,
            ((value >> 32) & 0xff) as u8,
            ((value >> 24) & 0xff) as u8,
            ((value >> 16) & 0xff) as u8,
            ((value >> 8) & 0xff) as u8,
            (value & 0xff) as u8,
        ]);
    }
    Err(anyhow!("value exceeds QUIC varint range").into())
}

pub(crate) fn push_varint(buf: &mut Vec<u8>, value: u64) {
    match encode_varint(value) {
        Ok(encoded) => buf.extend_from_slice(&encoded),
        Err(_) => debug_assert!(false, "value exceeds QUIC varint range"),
    }
}

#[cfg(test)]
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_payload_bytes: usize,
) -> Result<()> {
    let Some(ty) = read_varint(reader).await? else {
        return Ok(());
    };
    let len = read_varint(reader)
        .await?
        .ok_or_else(|| anyhow!("truncated frame length"))?;
    if len > max_payload_bytes as u64 {
        return Err(anyhow!(
            "HTTP/3 frame 0x{ty:x} payload length {len} exceeds limit {max_payload_bytes}"
        )
        .into());
    }
    discard_frame_payload(reader, len, max_payload_bytes).await
}

pub(crate) async fn read_frame_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(u64, u64)>> {
    let Some(ty) = read_varint(reader).await? else {
        return Ok(None);
    };
    let len = read_varint(reader)
        .await?
        .ok_or_else(|| anyhow!("truncated frame length"))?;
    Ok(Some((ty, len)))
}

pub(crate) async fn discard_frame_payload<R: AsyncRead + Unpin>(
    reader: &mut R,
    len: u64,
    max_payload_bytes: usize,
) -> Result<()> {
    if len > max_payload_bytes as u64 {
        return Err(
            anyhow!("HTTP/3 frame payload length {len} exceeds limit {max_payload_bytes}").into(),
        );
    }
    let mut remaining = len as usize;
    let mut buf = [0u8; FRAME_PAYLOAD_READ_CHUNK_BYTES];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        reader.read_exact(&mut buf[..want]).await?;
        remaining -= want;
    }
    Ok(())
}

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ty: u64,
    payload: &[u8],
) -> Result<()> {
    write_varint(writer, ty).await?;
    write_varint(writer, payload.len() as u64).await?;
    writer.write_all(payload).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
