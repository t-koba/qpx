use anyhow::{Result, anyhow};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const MAGIC: &[u8; 4] = b"QPXI";
pub const VERSION: u8 = 1;
const MAX_IPC_FRAME_BYTES: usize = 10 * 1024 * 1024;
const IPC_FRAME_READ_CHUNK_BYTES: usize = 64 * 1024;

pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin, T: serde::Serialize>(
    writer: &mut W,
    data: &T,
) -> Result<()> {
    let payload = serde_json::to_vec(data)?;
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
        return Err(anyhow!("Invalid IPC magic"));
    }
    if header[4] != VERSION {
        return Err(anyhow!("Unsupported IPC version"));
    }
    let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
    if len > MAX_IPC_FRAME_BYTES {
        return Err(anyhow!("IPC payload too large"));
    }
    let mut payload = Vec::with_capacity(len.min(IPC_FRAME_READ_CHUNK_BYTES));
    while payload.len() < len {
        let remaining = len - payload.len();
        let chunk_len = remaining.min(IPC_FRAME_READ_CHUNK_BYTES);
        let start = payload.len();
        payload.resize(start + chunk_len, 0);
        reader.read_exact(&mut payload[start..]).await?;
    }
    let meta = serde_json::from_slice(&payload)?;
    Ok(meta)
}
