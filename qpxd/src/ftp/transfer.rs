use super::control::{BasicFtpClient, FtpDeadline};
use super::{FTP_RESPONSE_STREAM_CHANNEL_CAPACITY, OperationTimedOut, ResponseBodyTooLarge};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use qpx_http::body::Body;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::timeout;
use tracing::warn;

pub(super) struct FtpDataTransfer {
    pub(super) client: BasicFtpClient,
    pub(super) data: TcpStream,
    pub(super) finalize_context: &'static str,
}

#[derive(Clone, Copy)]
pub(super) enum FtpResponseTransform {
    Raw,
    Listing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FtpBodyStreamOutcome {
    Complete,
    DownstreamClosed,
}
#[cfg(test)]
pub(super) fn normalize_ftp_listing_body(raw: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    for mut line in raw.split(|byte| *byte == b'\n') {
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(b'\n');
        }
        out.extend_from_slice(line);
    }
    out
}

pub(super) fn spawn_ftp_response_body(
    transfer: FtpDataTransfer,
    transform: FtpResponseTransform,
    max_download_bytes: usize,
    permit: OwnedSemaphorePermit,
) -> Result<Body> {
    let (sender, body) = Body::channel_with_capacity(FTP_RESPONSE_STREAM_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        // Hold the FTP concurrency permit until the response body has finished streaming.
        let _permit = permit;
        if let Err(err) =
            stream_ftp_response_body(transfer, transform, max_download_bytes, sender).await
        {
            warn!(error = ?err, "FTP response streaming failed");
        }
    });
    Ok(body)
}

async fn stream_ftp_response_body(
    transfer: FtpDataTransfer,
    transform: FtpResponseTransform,
    max_download_bytes: usize,
    mut sender: qpx_http::body::Sender,
) -> Result<()> {
    let FtpDataTransfer {
        mut client,
        mut data,
        finalize_context,
    } = transfer;
    let result = match transform {
        FtpResponseTransform::Raw => {
            stream_raw_ftp_data(&mut data, max_download_bytes, client.deadline, &mut sender).await
        }
        FtpResponseTransform::Listing => {
            stream_listing_ftp_data(&mut data, max_download_bytes, client.deadline, &mut sender)
                .await
        }
    };
    drop(data);
    match result {
        Ok(FtpBodyStreamOutcome::Complete) => {
            client.expect_reply(&[226, 250], finalize_context).await?;
        }
        Ok(FtpBodyStreamOutcome::DownstreamClosed) => {}
        Err(err) => return Err(err),
    }
    Ok(())
}

async fn stream_raw_ftp_data(
    reader: &mut TcpStream,
    max_bytes: usize,
    deadline: FtpDeadline,
    sender: &mut qpx_http::body::Sender,
) -> Result<FtpBodyStreamOutcome> {
    let mut sent = 0usize;
    let mut chunk = BytesMut::with_capacity(16 * 1024);
    loop {
        chunk.clear();
        let read = timeout(deadline.remaining()?, reader.read_buf(&mut chunk))
            .await
            .map_err(|_| anyhow::Error::new(OperationTimedOut))??;
        if read == 0 {
            return Ok(FtpBodyStreamOutcome::Complete);
        }
        sent = checked_ftp_download_size(sent, read, max_bytes)?;
        if sender.send_data(chunk.split().freeze()).await.is_err() {
            return Ok(FtpBodyStreamOutcome::DownstreamClosed);
        }
        chunk.reserve(16 * 1024);
    }
}

async fn stream_listing_ftp_data(
    reader: &mut TcpStream,
    max_bytes: usize,
    deadline: FtpDeadline,
    sender: &mut qpx_http::body::Sender,
) -> Result<FtpBodyStreamOutcome> {
    let mut seen = 0usize;
    let mut emitted = false;
    let mut line = Vec::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = read_ftp_data_chunk(reader, &mut chunk, deadline).await?;
        if read == 0 {
            if flush_ftp_listing_line(sender, &mut line, &mut emitted)
                .await?
                .is_err()
            {
                return Ok(FtpBodyStreamOutcome::DownstreamClosed);
            }
            return Ok(FtpBodyStreamOutcome::Complete);
        }
        seen = checked_ftp_download_size(seen, read, max_bytes)?;
        for byte in &chunk[..read] {
            if *byte == b'\n' {
                if flush_ftp_listing_line(sender, &mut line, &mut emitted)
                    .await?
                    .is_err()
                {
                    return Ok(FtpBodyStreamOutcome::DownstreamClosed);
                }
            } else {
                line.push(*byte);
            }
        }
    }
}

async fn flush_ftp_listing_line(
    sender: &mut qpx_http::body::Sender,
    line: &mut Vec<u8>,
    emitted: &mut bool,
) -> Result<Result<(), ()>> {
    if line.ends_with(b"\r") {
        line.pop();
    }
    if line.is_empty() {
        return Ok(Ok(()));
    }
    let mut out = Vec::with_capacity(line.len() + usize::from(*emitted));
    if *emitted {
        out.push(b'\n');
    }
    out.extend_from_slice(line);
    line.clear();
    *emitted = true;
    Ok(sender.send_data(Bytes::from(out)).await.map_err(|_| ()))
}

async fn read_ftp_data_chunk(
    reader: &mut TcpStream,
    buf: &mut [u8],
    deadline: FtpDeadline,
) -> Result<usize> {
    timeout(deadline.remaining()?, reader.read(buf))
        .await
        .map_err(|_| anyhow::Error::new(OperationTimedOut))?
        .map_err(Into::into)
}

fn checked_ftp_download_size(current: usize, read: usize, max_bytes: usize) -> Result<usize> {
    let next = current
        .checked_add(read)
        .ok_or_else(|| anyhow!("ftp response body length overflow"))?;
    if next > max_bytes {
        return Err(anyhow::Error::new(ResponseBodyTooLarge(max_bytes)));
    }
    Ok(next)
}
