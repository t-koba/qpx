use anyhow::{anyhow, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const EVENT_PREFACE_LINE: &str = "QPX-EVENT/1";
pub const STREAM_PREFACE_LINE: &str = "QPX-STREAM/1";

const CAPTURE_WIRE_MAGIC: [u8; 4] = *b"QPXE";
const CAPTURE_WIRE_VERSION: u8 = 1;
const CAPTURE_WIRE_HEADER_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CapturePlane {
    ClientProxyEncrypted,
    ProxyServerEncrypted,
    ClientServerPlaintext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureEvent {
    pub session_id: String,
    pub timestamp_unix_nanos: u64,
    pub plane: CapturePlane,
    pub direction: CaptureDirection,
    pub client: String,
    pub server: String,
    pub payload: Bytes,
}

impl CaptureEvent {
    pub fn new(
        session_id: String,
        plane: CapturePlane,
        direction: CaptureDirection,
        client: String,
        server: String,
        payload: &[u8],
    ) -> Self {
        Self {
            session_id,
            timestamp_unix_nanos: unix_timestamp_nanos(),
            plane,
            direction,
            client,
            server,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    pub fn payload_bytes(&self) -> &[u8] {
        self.payload.as_ref()
    }

    pub fn encode_wire(&self, out: &mut Vec<u8>) -> Result<()> {
        let session = self.session_id.as_bytes();
        let client = self.client.as_bytes();
        let server = self.server.as_bytes();
        let payload = self.payload.as_ref();

        for (label, bytes) in [
            ("session_id", session),
            ("client", client),
            ("server", server),
            ("payload", payload),
        ] {
            if bytes.len() > u32::MAX as usize {
                return Err(anyhow!("capture event {} too large", label));
            }
        }

        let total_len =
            CAPTURE_WIRE_HEADER_LEN + session.len() + client.len() + server.len() + payload.len();
        out.clear();
        out.reserve(total_len);

        out.extend_from_slice(&CAPTURE_WIRE_MAGIC);
        out.push(CAPTURE_WIRE_VERSION);
        out.push(plane_to_u8(&self.plane));
        out.push(direction_to_u8(&self.direction));
        out.push(0); // reserved
        out.extend_from_slice(&self.timestamp_unix_nanos.to_le_bytes());
        out.extend_from_slice(&(session.len() as u32).to_le_bytes());
        out.extend_from_slice(&(client.len() as u32).to_le_bytes());
        out.extend_from_slice(&(server.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        debug_assert_eq!(out.len(), CAPTURE_WIRE_HEADER_LEN);

        out.extend_from_slice(session);
        out.extend_from_slice(client);
        out.extend_from_slice(server);
        out.extend_from_slice(payload);
        Ok(())
    }

    pub fn decode_wire(buf: Bytes) -> Result<Self> {
        if buf.len() < CAPTURE_WIRE_HEADER_LEN {
            return Err(anyhow!("capture event truncated (len={})", buf.len()));
        }
        if buf[0..4] != CAPTURE_WIRE_MAGIC {
            return Err(anyhow!("invalid capture event magic"));
        }
        if buf[4] != CAPTURE_WIRE_VERSION {
            return Err(anyhow!("unsupported capture event version"));
        }

        let plane = plane_from_u8(buf[5])?;
        let direction = direction_from_u8(buf[6])?;
        let timestamp_unix_nanos = u64::from_le_bytes(buf[8..16].try_into().expect("ts bytes"));

        let session_len = u32::from_le_bytes(buf[16..20].try_into().expect("session_len")) as usize;
        let client_len = u32::from_le_bytes(buf[20..24].try_into().expect("client_len")) as usize;
        let server_len = u32::from_le_bytes(buf[24..28].try_into().expect("server_len")) as usize;
        let payload_len = u32::from_le_bytes(buf[28..32].try_into().expect("payload_len")) as usize;

        let total_len =
            CAPTURE_WIRE_HEADER_LEN + session_len + client_len + server_len + payload_len;
        if total_len != buf.len() {
            return Err(anyhow!(
                "capture event length mismatch (expected={} actual={})",
                total_len,
                buf.len()
            ));
        }

        let mut offset = CAPTURE_WIRE_HEADER_LEN;
        let session_bytes = &buf[offset..offset + session_len];
        offset += session_len;
        let client_bytes = &buf[offset..offset + client_len];
        offset += client_len;
        let server_bytes = &buf[offset..offset + server_len];
        offset += server_len;
        let payload_start = offset;
        let payload_end = payload_start + payload_len;

        let session_id = std::str::from_utf8(session_bytes)
            .map_err(|_| anyhow!("capture event session_id is not utf-8"))?
            .to_string();
        let client = std::str::from_utf8(client_bytes)
            .map_err(|_| anyhow!("capture event client is not utf-8"))?
            .to_string();
        let server = std::str::from_utf8(server_bytes)
            .map_err(|_| anyhow!("capture event server is not utf-8"))?
            .to_string();

        Ok(Self {
            session_id,
            timestamp_unix_nanos,
            plane,
            direction,
            client,
            server,
            payload: buf.slice(payload_start..payload_end),
        })
    }
}

fn plane_to_u8(plane: &CapturePlane) -> u8 {
    match plane {
        CapturePlane::ClientProxyEncrypted => 0,
        CapturePlane::ProxyServerEncrypted => 1,
        CapturePlane::ClientServerPlaintext => 2,
    }
}

fn plane_from_u8(v: u8) -> Result<CapturePlane> {
    match v {
        0 => Ok(CapturePlane::ClientProxyEncrypted),
        1 => Ok(CapturePlane::ProxyServerEncrypted),
        2 => Ok(CapturePlane::ClientServerPlaintext),
        other => Err(anyhow!("invalid capture plane: {}", other)),
    }
}

fn direction_to_u8(dir: &CaptureDirection) -> u8 {
    match dir {
        CaptureDirection::ClientToServer => 0,
        CaptureDirection::ServerToClient => 1,
    }
}

fn direction_from_u8(v: u8) -> Result<CaptureDirection> {
    match v {
        0 => Ok(CaptureDirection::ClientToServer),
        1 => Ok(CaptureDirection::ServerToClient),
        other => Err(anyhow!("invalid capture direction: {}", other)),
    }
}

pub fn unix_timestamp_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_event_wire_roundtrip() -> Result<()> {
        let event = CaptureEvent {
            session_id: "sess-1".to_string(),
            timestamp_unix_nanos: 1234567890,
            plane: CapturePlane::ClientProxyEncrypted,
            direction: CaptureDirection::ClientToServer,
            client: "127.0.0.1:1".to_string(),
            server: "127.0.0.1:2".to_string(),
            payload: Bytes::from_static(b"hello"),
        };
        let mut buf = Vec::new();
        event.encode_wire(&mut buf)?;
        let decoded = CaptureEvent::decode_wire(Bytes::from(buf))?;
        assert_eq!(decoded, event);
        Ok(())
    }
}
