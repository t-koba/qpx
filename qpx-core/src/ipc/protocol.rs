use bytes::{BufMut, BytesMut};
use std::io;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAGIC: &[u8; 4] = b"QPXI";
pub const VERSION: u8 = 1;
const MAX_IPC_FRAME_BYTES: usize = 10 * 1024 * 1024;
const IPC_FRAME_READ_CHUNK_BYTES: usize = 64 * 1024;

type Result<T> = std::result::Result<T, IpcProtocolError>;

#[derive(Debug, Error)]
pub enum IpcProtocolError {
    #[error("failed to encode IPC frame payload")]
    Encode(#[source] serde_json::Error),
    #[error("failed to decode IPC frame payload")]
    Decode(#[source] serde_json::Error),
    #[error("IPC I/O error")]
    Io(#[from] io::Error),
    #[error("invalid IPC magic")]
    InvalidMagic,
    #[error("unsupported IPC version")]
    UnsupportedVersion,
    #[error("IPC payload too large")]
    PayloadTooLarge,
}

pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    data: &T,
) -> Result<()> {
    let payload = serde_json::to_vec(data).map_err(IpcProtocolError::Encode)?;
    let mut buf = BytesMut::with_capacity(9 + payload.len());
    buf.put_slice(MAGIC);
    buf.put_u8(VERSION);
    buf.put_u32_le(payload.len() as u32);
    buf.put_slice(&payload);
    writer.write_all(&buf).await?;
    Ok(())
}

pub async fn read_frame<R: tokio::io::AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    reader: &mut R,
) -> Result<T> {
    let mut header = [0u8; 9];
    reader.read_exact(&mut header).await?;
    if &header[0..4] != MAGIC {
        return Err(IpcProtocolError::InvalidMagic);
    }
    if header[4] != VERSION {
        return Err(IpcProtocolError::UnsupportedVersion);
    }
    let len = u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if len > MAX_IPC_FRAME_BYTES {
        return Err(IpcProtocolError::PayloadTooLarge);
    }
    let mut payload = Vec::with_capacity(len.min(IPC_FRAME_READ_CHUNK_BYTES));
    while payload.len() < len {
        let remaining = len - payload.len();
        let chunk_len = remaining.min(IPC_FRAME_READ_CHUNK_BYTES);
        let start = payload.len();
        payload.resize(start + chunk_len, 0);
        reader.read_exact(&mut payload[start..]).await?;
    }
    let meta = serde_json::from_slice(&payload).map_err(IpcProtocolError::Decode)?;
    Ok(meta)
}

#[doc(hidden)]
pub fn fuzz_decode_ipc_meta_frame(buf: &[u8]) {
    if buf.len() < 9 {
        return;
    }
    if &buf[0..4] != MAGIC || buf[4] != VERSION {
        return;
    }
    let len = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;
    if len > MAX_IPC_FRAME_BYTES {
        return;
    }
    let Some(end) = 9usize.checked_add(len) else {
        return;
    };
    let Some(payload) = buf.get(9..end) else {
        return;
    };
    let _ = serde_json::from_slice::<crate::ipc::meta::IpcRequestMeta>(payload);
    let _ = serde_json::from_slice::<crate::ipc::meta::IpcResponseMeta>(payload);
}
