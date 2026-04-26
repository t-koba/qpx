use anyhow::{anyhow, Result};
use bytes::Bytes;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, Notify};

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

pub(crate) const H3_STREAM_CREATION_ERROR: u64 = 0x103;
pub(crate) const H3_CLOSED_CRITICAL_STREAM: u64 = 0x104;
pub(crate) const H3_FRAME_UNEXPECTED: u64 = 0x105;
pub(crate) const H3_FRAME_ERROR: u64 = 0x106;
pub(crate) const H3_ID_ERROR: u64 = 0x108;
pub(crate) const H3_SETTINGS_ERROR: u64 = 0x109;
pub(crate) const H3_MISSING_SETTINGS: u64 = 0x10a;
pub(crate) const H3_MESSAGE_ERROR: u64 = 0x10e;
pub(crate) const QPACK_DECOMPRESSION_FAILED: u64 = 0x200;
pub(crate) const QPACK_ENCODER_STREAM_ERROR: u64 = 0x201;
pub(crate) const H3_DATAGRAM_ERROR: u64 = 0x33;

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

#[derive(Debug, Clone)]
pub(crate) struct ConnectionClose {
    pub(crate) code: u64,
    pub(crate) message: String,
}

impl ConnectionClose {
    pub(crate) fn new(code: u64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Default)]
struct PeerControlInner {
    control_stream_seen: bool,
    settings_seen: bool,
    encoder_stream_seen: bool,
    decoder_stream_seen: bool,
    max_push_id: Option<u64>,
    goaway_id: Option<u64>,
    settings: Option<PeerSettings>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PeerControlState {
    inner: Arc<Mutex<PeerControlInner>>,
    notify: Arc<Notify>,
}

impl PeerControlState {
    pub(crate) async fn register_control_stream(&self) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if inner.control_stream_seen {
            return Err(ConnectionClose::new(
                H3_STREAM_CREATION_ERROR,
                "received duplicate HTTP/3 control stream",
            ));
        }
        inner.control_stream_seen = true;
        Ok(())
    }

    pub(crate) async fn register_settings(
        &self,
        settings: PeerSettings,
    ) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if inner.settings_seen {
            return Err(ConnectionClose::new(
                H3_FRAME_UNEXPECTED,
                "received duplicate HTTP/3 SETTINGS frame",
            ));
        }
        inner.settings_seen = true;
        inner.settings = Some(settings);
        drop(inner);
        self.notify.notify_waiters();
        Ok(())
    }

    pub(crate) async fn settings_snapshot(&self) -> Option<PeerSettings> {
        self.inner.lock().await.settings.clone()
    }

    pub(crate) async fn register_encoder_stream(&self) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if inner.encoder_stream_seen {
            return Err(ConnectionClose::new(
                H3_STREAM_CREATION_ERROR,
                "received duplicate QPACK encoder stream",
            ));
        }
        inner.encoder_stream_seen = true;
        Ok(())
    }

    pub(crate) async fn register_decoder_stream(&self) -> std::result::Result<(), ConnectionClose> {
        let mut inner = self.inner.lock().await;
        if inner.decoder_stream_seen {
            return Err(ConnectionClose::new(
                H3_STREAM_CREATION_ERROR,
                "received duplicate QPACK decoder stream",
            ));
        }
        inner.decoder_stream_seen = true;
        Ok(())
    }

    pub(crate) async fn wait_for_settings(&self) -> PeerSettings {
        loop {
            if let Some(settings) = self.settings_snapshot().await {
                return settings;
            }
            self.notify.notified().await;
        }
    }

    pub(crate) async fn goaway_id(&self) -> Option<u64> {
        self.inner.lock().await.goaway_id
    }

    pub(crate) async fn handle_control_frame(
        &self,
        frame_ty: u64,
        payload: &[u8],
        endpoint_is_client: bool,
    ) -> std::result::Result<(), ConnectionClose> {
        validate_control_stream_frame(frame_ty, endpoint_is_client)?;
        match frame_ty {
            FRAME_CANCEL_PUSH => {
                let push_id = parse_single_varint_payload(payload, "CANCEL_PUSH")?;
                let inner = self.inner.lock().await;
                let Some(max_push_id) = inner.max_push_id else {
                    return Err(ConnectionClose::new(
                        H3_ID_ERROR,
                        "received CANCEL_PUSH before MAX_PUSH_ID established push space",
                    ));
                };
                if push_id > max_push_id {
                    return Err(ConnectionClose::new(
                        H3_ID_ERROR,
                        format!(
                            "received CANCEL_PUSH for push id {push_id} beyond MAX_PUSH_ID {max_push_id}"
                        ),
                    ));
                }
                Ok(())
            }
            FRAME_GOAWAY => {
                let goaway_id = parse_single_varint_payload(payload, "GOAWAY")?;
                if endpoint_is_client && goaway_id % 4 != 0 {
                    return Err(ConnectionClose::new(
                        H3_ID_ERROR,
                        format!("received GOAWAY with non-client-bidi stream id {goaway_id}"),
                    ));
                }
                let mut inner = self.inner.lock().await;
                if let Some(previous) = inner.goaway_id {
                    if goaway_id > previous {
                        return Err(ConnectionClose::new(
                            H3_ID_ERROR,
                            format!(
                                "received GOAWAY id {goaway_id} greater than previous {previous}"
                            ),
                        ));
                    }
                }
                inner.goaway_id = Some(goaway_id);
                Ok(())
            }
            FRAME_MAX_PUSH_ID => {
                let max_push_id = parse_single_varint_payload(payload, "MAX_PUSH_ID")?;
                let mut inner = self.inner.lock().await;
                if let Some(previous) = inner.max_push_id {
                    if max_push_id < previous {
                        return Err(ConnectionClose::new(
                            H3_ID_ERROR,
                            format!(
                                "received MAX_PUSH_ID {max_push_id} lower than previous {previous}"
                            ),
                        ));
                    }
                }
                inner.max_push_id = Some(max_push_id);
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

pub(crate) fn validate_control_stream_frame(
    frame_ty: u64,
    endpoint_is_client: bool,
) -> std::result::Result<(), ConnectionClose> {
    match frame_ty {
        FRAME_CANCEL_PUSH | FRAME_GOAWAY => Ok(()),
        FRAME_MAX_PUSH_ID if !endpoint_is_client => Ok(()),
        FRAME_SETTINGS => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            "received duplicate HTTP/3 SETTINGS frame",
        )),
        FRAME_DATA | FRAME_HEADERS | FRAME_PUSH_PROMISE | FRAME_MAX_PUSH_ID => {
            Err(ConnectionClose::new(
                H3_FRAME_UNEXPECTED,
                format!("HTTP/3 frame type 0x{frame_ty:x} is not permitted on this control stream"),
            ))
        }
        ty if is_reserved_http2_frame_type(ty) => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            format!("HTTP/2 frame type 0x{frame_ty:x} is reserved in HTTP/3"),
        )),
        _ => Ok(()),
    }
}

pub(crate) fn validate_message_stream_frame(
    frame_ty: u64,
) -> std::result::Result<(), ConnectionClose> {
    match frame_ty {
        FRAME_CANCEL_PUSH | FRAME_SETTINGS | FRAME_GOAWAY | FRAME_MAX_PUSH_ID
        | FRAME_PUSH_PROMISE => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            format!("HTTP/3 frame type 0x{frame_ty:x} is not permitted on a message stream"),
        )),
        ty if is_reserved_http2_frame_type(ty) => Err(ConnectionClose::new(
            H3_FRAME_UNEXPECTED,
            format!("HTTP/2 frame type 0x{frame_ty:x} is reserved in HTTP/3"),
        )),
        _ => Ok(()),
    }
}

fn is_reserved_http2_frame_type(frame_ty: u64) -> bool {
    matches!(
        frame_ty,
        FRAME_PRIORITY | FRAME_PING | FRAME_WINDOW_UPDATE | FRAME_CONTINUATION
    )
}

fn parse_single_varint_payload(
    payload: &[u8],
    frame_name: &str,
) -> std::result::Result<u64, ConnectionClose> {
    let (value, used) = read_varint_slice(payload).map_err(|err| {
        ConnectionClose::new(
            H3_FRAME_ERROR,
            format!("malformed {frame_name} payload: {err}"),
        )
    })?;
    if used != payload.len() {
        return Err(ConnectionClose::new(
            H3_FRAME_ERROR,
            format!("{frame_name} payload contained trailing bytes"),
        ));
    }
    Ok(value)
}

#[derive(Debug)]
pub(crate) struct Frame {
    pub(crate) ty: u64,
    pub(crate) payload: Bytes,
}

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
        return Err(anyhow!("truncated varint"));
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
    Err(anyhow!("value exceeds QUIC varint range"))
}

pub(crate) fn push_varint(buf: &mut Vec<u8>, value: u64) {
    let encoded = encode_varint(value).expect("valid varint");
    buf.extend_from_slice(&encoded);
}

pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_payload_bytes: usize,
) -> Result<Option<Frame>> {
    read_frame_with_limit(reader, |_| max_payload_bytes).await
}

pub(crate) async fn read_frame_with_limit<R, F>(
    reader: &mut R,
    max_payload_for_type: F,
) -> Result<Option<Frame>>
where
    R: AsyncRead + Unpin,
    F: FnOnce(u64) -> usize,
{
    let Some(ty) = read_varint(reader).await? else {
        return Ok(None);
    };
    let len = read_varint(reader)
        .await?
        .ok_or_else(|| anyhow!("truncated frame length"))?;
    let max_payload_bytes = max_payload_for_type(ty);
    if len > max_payload_bytes as u64 {
        return Err(anyhow!(
            "HTTP/3 frame 0x{ty:x} payload length {len} exceeds limit {max_payload_bytes}"
        ));
    }
    let len = len as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Some(Frame {
        ty,
        payload: Bytes::from(payload),
    }))
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
            return Err(anyhow!("duplicate SETTINGS parameter 0x{id:x}"));
        }
        match id {
            SETTING_QPACK_MAX_TABLE_CAPACITY => settings.qpack_max_table_capacity = value,
            SETTING_QPACK_MAX_BLOCKED_STREAMS => settings.qpack_max_blocked_streams = value,
            SETTING_MAX_FIELD_SECTION_SIZE => settings.max_field_section_size = value,
            SETTING_ENABLE_CONNECT_PROTOCOL => {
                if value > 1 {
                    return Err(anyhow!("SETTINGS_ENABLE_CONNECT_PROTOCOL must be 0 or 1"));
                }
                settings.enable_extended_connect = value == 1;
            }
            SETTING_H3_DATAGRAM => {
                if value > 1 {
                    return Err(anyhow!("SETTINGS_H3_DATAGRAM must be 0 or 1"));
                }
                settings.enable_datagram = value == 1;
            }
            SETTING_ENABLE_WEBTRANSPORT => {
                if value > 1 {
                    return Err(anyhow!("SETTINGS_ENABLE_WEBTRANSPORT must be 0 or 1"));
                }
                settings.enable_webtransport = value == 1;
            }
            SETTING_WEBTRANSPORT_MAX_SESSIONS => settings.max_webtransport_sessions = value,
            0x2..=0x5 => {
                return Err(anyhow!(
                    "reserved HTTP/2 SETTINGS parameter 0x{id:x} is invalid in HTTP/3"
                ));
            }
            _ => {}
        }
    }
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_settings_frame, encode_varint, push_varint, read_frame, read_varint_slice,
        validate_control_stream_frame, validate_message_stream_frame, PeerControlState,
        FRAME_CANCEL_PUSH, FRAME_DATA, FRAME_GOAWAY, FRAME_MAX_PUSH_ID, FRAME_PING,
        FRAME_PUSH_PROMISE, FRAME_WINDOW_UPDATE, H3_FRAME_ERROR, H3_FRAME_UNEXPECTED, H3_ID_ERROR,
    };

    #[test]
    fn quic_varint_roundtrip() {
        for value in [0, 63, 64, 15293, 16383, 16384, 1_000_000, (1 << 30) - 1] {
            let encoded = encode_varint(value).unwrap();
            let (decoded, used) = read_varint_slice(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(used, encoded.len());
        }
    }

    #[test]
    fn settings_reject_reserved_http2_identifiers() {
        let mut payload = Vec::new();
        push_varint(&mut payload, 0x2);
        push_varint(&mut payload, 1);
        let err = decode_settings_frame(payload.as_slice()).unwrap_err();
        assert!(
            err.to_string()
                .contains("reserved HTTP/2 SETTINGS parameter 0x2"),
            "{err}"
        );
    }

    #[test]
    fn control_stream_rejects_data_frames() {
        let err = validate_control_stream_frame(FRAME_DATA, false).unwrap_err();
        assert_eq!(err.code, H3_FRAME_UNEXPECTED);
    }

    #[test]
    fn client_control_stream_rejects_max_push_id() {
        let err = validate_control_stream_frame(FRAME_MAX_PUSH_ID, true).unwrap_err();
        assert_eq!(err.code, H3_FRAME_UNEXPECTED);
        assert!(validate_control_stream_frame(FRAME_GOAWAY, true).is_ok());
    }

    #[test]
    fn message_stream_rejects_control_only_frames() {
        let err = validate_message_stream_frame(FRAME_CANCEL_PUSH).unwrap_err();
        assert_eq!(err.code, H3_FRAME_UNEXPECTED);
        let err = validate_message_stream_frame(FRAME_PUSH_PROMISE).unwrap_err();
        assert_eq!(err.code, H3_FRAME_UNEXPECTED);
        let err = validate_message_stream_frame(FRAME_WINDOW_UPDATE).unwrap_err();
        assert_eq!(err.code, H3_FRAME_UNEXPECTED);
        let err = validate_control_stream_frame(FRAME_PING, false).unwrap_err();
        assert_eq!(err.code, H3_FRAME_UNEXPECTED);
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_payload_before_allocation() {
        let mut input = [FRAME_DATA as u8, 5u8].as_slice();
        let err = read_frame(&mut input, 4).await.unwrap_err();
        assert!(
            err.to_string().contains("exceeds limit 4"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn control_state_rejects_malformed_goaway_payload() {
        let state = PeerControlState::default();
        let err = state
            .handle_control_frame(FRAME_GOAWAY, &[0x40], true)
            .await
            .unwrap_err();
        assert_eq!(err.code, H3_FRAME_ERROR);
    }

    #[tokio::test]
    async fn control_state_enforces_goaway_monotonicity() {
        let state = PeerControlState::default();
        state
            .handle_control_frame(FRAME_GOAWAY, &[0x00], true)
            .await
            .unwrap();
        let err = state
            .handle_control_frame(FRAME_GOAWAY, &[0x04], true)
            .await
            .unwrap_err();
        assert_eq!(err.code, H3_ID_ERROR);
    }

    #[tokio::test]
    async fn control_state_enforces_max_push_id_monotonicity() {
        let state = PeerControlState::default();
        state
            .handle_control_frame(FRAME_MAX_PUSH_ID, &[0x05], false)
            .await
            .unwrap();
        let err = state
            .handle_control_frame(FRAME_MAX_PUSH_ID, &[0x04], false)
            .await
            .unwrap_err();
        assert_eq!(err.code, H3_ID_ERROR);
    }
}
