use super::super::frame::{BrokerFrame, decode_frame_bytes, encode_frame_parts};
use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use std::io::{ErrorKind, IoSlice};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_BROKER_FRAME_BYTES: usize = 4 * 1024 * 1024;
const BROKER_FRAME_READ_CHUNK_BYTES: usize = 64 * 1024;

pub(super) async fn write_frame_no_flush<W>(write_half: &mut W, frame: &BrokerFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = encode_frame_parts(frame)?;
    let len = (encoded.len() as u32).to_be_bytes();
    write_all_vectored(
        write_half,
        &[
            len.as_slice(),
            encoded.header.as_slice(),
            encoded.payload.as_ref(),
        ],
    )
    .await
    .context("failed to write broker frame")?;
    Ok(())
}

async fn write_all_vectored<W>(writer: &mut W, parts: &[&[u8]]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut part_index = 0usize;
    let mut part_offset = 0usize;
    while part_index < parts.len() {
        while part_index < parts.len() && part_offset == parts[part_index].len() {
            part_index += 1;
            part_offset = 0;
        }
        if part_index >= parts.len() {
            break;
        }

        let mut slices = Vec::with_capacity(parts.len() - part_index);
        slices.push(IoSlice::new(&parts[part_index][part_offset..]));
        for part in &parts[part_index + 1..] {
            if !part.is_empty() {
                slices.push(IoSlice::new(part));
            }
        }

        let mut written = writer.write_vectored(&slices).await?;
        if written == 0 {
            return Err(std::io::Error::new(
                ErrorKind::WriteZero,
                "failed to write broker frame",
            ));
        }
        while written > 0 && part_index < parts.len() {
            let remaining = parts[part_index].len() - part_offset;
            if written < remaining {
                part_offset += written;
                written = 0;
            } else {
                written -= remaining;
                part_index += 1;
                part_offset = 0;
            }
        }
    }
    Ok(())
}

pub(super) async fn read_frame<R>(read_half: &mut R) -> Result<Option<BrokerFrame>>
where
    R: AsyncRead + Unpin,
{
    let len = match read_half.read_u32().await {
        Ok(len) => len as usize,
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("failed to read broker frame length"),
    };
    if len > MAX_BROKER_FRAME_BYTES {
        return Err(anyhow!(
            "broker frame length {} exceeds maximum {}",
            len,
            MAX_BROKER_FRAME_BYTES
        ));
    }
    let mut buf = Vec::with_capacity(len.min(BROKER_FRAME_READ_CHUNK_BYTES));
    while buf.len() < len {
        let remaining = len - buf.len();
        let chunk_len = remaining.min(BROKER_FRAME_READ_CHUNK_BYTES);
        let start = buf.len();
        buf.resize(start + chunk_len, 0);
        read_half
            .read_exact(&mut buf[start..])
            .await
            .context("failed to read broker frame payload")?;
    }
    decode_frame_bytes(Bytes::from(buf)).map(Some)
}

#[cfg(test)]
mod tests {
    use crate::http3::quinn_socket::tasks::io::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    pub(super) async fn read_frame_rejects_oversized_length_before_allocation() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_u32((MAX_BROKER_FRAME_BYTES as u32).saturating_add(1))
            .await
            .expect("write length");
        drop(client);

        let err = read_frame(&mut server).await.expect_err("oversized frame");
        assert!(err.to_string().contains("exceeds maximum"));
    }
}
