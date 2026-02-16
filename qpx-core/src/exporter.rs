use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const EVENT_PREFACE_LINE: &str = "QPX-EVENT/1";
pub const STREAM_PREFACE_LINE: &str = "QPX-STREAM/1";

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureEvent {
    pub session_id: String,
    pub timestamp_unix_nanos: u64,
    pub plane: CapturePlane,
    pub direction: CaptureDirection,
    pub client: String,
    pub server: String,
    pub payload_base64: String,
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
            payload_base64: BASE64.encode(payload),
        }
    }

    pub fn payload(&self) -> Result<Vec<u8>, base64::DecodeError> {
        BASE64.decode(self.payload_base64.as_bytes())
    }
}

pub fn unix_timestamp_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
