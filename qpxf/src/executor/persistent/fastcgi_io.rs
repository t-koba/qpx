use super::pool::BoxedIo;
use super::send_limited_chunk;
use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

pub(super) const FCGI_BEGIN_REQUEST: u8 = 1;
pub(super) const FCGI_ABORT_REQUEST: u8 = 2;
pub(super) const FCGI_END_REQUEST: u8 = 3;
pub(super) const FCGI_PARAMS: u8 = 4;
pub(super) const FCGI_STDIN: u8 = 5;
pub(super) const FCGI_STDOUT: u8 = 6;
pub(super) const FCGI_STDERR: u8 = 7;
const FCGI_RESPONDER: u16 = 1;
const FCGI_REQUEST_ID: u16 = 1;
const FCGI_REQUEST_COMPLETE: u8 = 0;
const FCGI_CANT_MPX_CONN: u8 = 1;
pub(super) const FCGI_OVERLOADED: u8 = 2;
const FCGI_UNKNOWN_ROLE: u8 = 3;

struct FastCgiRecord {
    record_type: u8,
    request_id: u16,
    content: Bytes,
}

pub(super) struct FastCgiOutputLimits {
    pub(super) stdout: usize,
    pub(super) stderr: usize,
}

pub(super) struct FastCgiOutputChannels {
    pub(super) stdout: mpsc::Sender<Bytes>,
    pub(super) stderr: mpsc::Sender<Bytes>,
}

pub(super) struct FastCgiStreamingStdin {
    pub(super) env: Vec<(String, String)>,
    pub(super) stdin_rx: mpsc::Receiver<Bytes>,
    pub(super) expected_stdin_bytes: Option<usize>,
    pub(super) max_stdin_bytes: usize,
    pub(super) output_limits: FastCgiOutputLimits,
    pub(super) output_channels: FastCgiOutputChannels,
}

#[cfg(test)]
pub(super) async fn run_fastcgi_on_stream(
    stream: &mut BoxedIo,
    env: Vec<(String, String)>,
    body: Bytes,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> Result<(Bytes, Bytes)> {
    write_fastcgi_begin(stream).await?;
    let params = encode_fastcgi_params(env)?;
    for chunk in params.chunks(u16::MAX as usize) {
        write_fastcgi_record(stream, FCGI_PARAMS, chunk).await?;
    }
    write_fastcgi_record(stream, FCGI_PARAMS, &[]).await?;
    for chunk in body.chunks(u16::MAX as usize) {
        write_fastcgi_record(stream, FCGI_STDIN, chunk).await?;
    }
    write_fastcgi_record(stream, FCGI_STDIN, &[]).await?;

    let mut stdout = BytesMut::new();
    let mut stderr = BytesMut::new();
    loop {
        let Some(record) = read_fastcgi_record(stream).await? else {
            return Err(anyhow!(
                "fastcgi backend closed connection before end request"
            ));
        };
        if record.request_id != FCGI_REQUEST_ID {
            return Err(anyhow!(
                "fastcgi backend returned record for unexpected request id {}",
                record.request_id
            ));
        }
        match record.record_type {
            FCGI_STDOUT => {
                append_limited(&mut stdout, &record.content, max_stdout_bytes, "stdout")?
            }
            FCGI_STDERR => {
                append_limited(&mut stderr, &record.content, max_stderr_bytes, "stderr")?
            }
            FCGI_END_REQUEST => {
                validate_fastcgi_end_request(&record.content)?;
                break;
            }
            FCGI_ABORT_REQUEST => return Err(anyhow!("fastcgi backend aborted request")),
            _ => {}
        }
    }
    Ok((stdout.freeze(), stderr.freeze()))
}

pub(super) async fn run_fastcgi_on_stream_streaming_stdin(
    stream: &mut BoxedIo,
    request: FastCgiStreamingStdin,
) -> Result<()> {
    write_fastcgi_begin(stream).await?;
    let params = encode_fastcgi_params(request.env)?;
    for chunk in params.chunks(u16::MAX as usize) {
        write_fastcgi_record(stream, FCGI_PARAMS, chunk).await?;
    }
    write_fastcgi_record(stream, FCGI_PARAMS, &[]).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write_body = async {
        write_fastcgi_stdin_rx(
            &mut writer,
            request.stdin_rx,
            request.expected_stdin_bytes,
            request.max_stdin_bytes,
        )
        .await?;
        write_fastcgi_record(&mut writer, FCGI_STDIN, &[]).await?;
        Ok::<_, anyhow::Error>(())
    };
    let read_response = read_fastcgi_streaming_response(
        &mut reader,
        request.output_limits.stdout,
        request.output_limits.stderr,
        request.output_channels.stdout,
        request.output_channels.stderr,
    );
    let _ = tokio::try_join!(write_body, read_response)?;
    Ok(())
}

async fn write_fastcgi_stdin_rx(
    stream: &mut (impl AsyncWrite + Unpin + ?Sized),
    mut stdin_rx: mpsc::Receiver<Bytes>,
    expected_stdin_bytes: Option<usize>,
    max_stdin_bytes: usize,
) -> Result<()> {
    let mut seen = 0usize;
    while let Some(chunk) = stdin_rx.recv().await {
        seen = seen.saturating_add(chunk.len());
        if seen > max_stdin_bytes {
            return Err(anyhow!("fastcgi backend stdin exceeds configured limit"));
        }
        if expected_stdin_bytes.is_some_and(|expected| seen > expected) {
            return Err(anyhow!(
                "fastcgi backend stdin exceeds declared content-length"
            ));
        }
        for part in chunk.chunks(u16::MAX as usize) {
            write_fastcgi_record(stream, FCGI_STDIN, part).await?;
        }
    }
    if let Some(expected) = expected_stdin_bytes
        && seen != expected
    {
        return Err(anyhow!(
            "fastcgi backend stdin length mismatch: declared {}, received {}",
            expected,
            seen
        ));
    }
    Ok(())
}

async fn write_fastcgi_begin(stream: &mut BoxedIo) -> Result<()> {
    let mut content = [0u8; 8];
    content[0..2].copy_from_slice(&FCGI_RESPONDER.to_be_bytes());
    content[2] = 1;
    write_fastcgi_record(stream, FCGI_BEGIN_REQUEST, &content).await
}

async fn write_fastcgi_record<W>(stream: &mut W, record_type: u8, content: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let content_len = u16::try_from(content.len()).context("fastcgi record too large")?;
    let padding_len = (8 - (content.len() % 8)) % 8;
    let header = [
        1,
        record_type,
        0,
        1,
        (content_len >> 8) as u8,
        content_len as u8,
        padding_len as u8,
        0,
    ];
    stream.write_all(&header).await?;
    stream.write_all(content).await?;
    if padding_len > 0 {
        stream.write_all(&[0u8; 8][..padding_len]).await?;
    }
    Ok(())
}

async fn read_fastcgi_record<R>(stream: &mut R) -> Result<Option<FastCgiRecord>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0u8; 8];
    match stream.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let record_type = header[1];
    let request_id = u16::from_be_bytes([header[2], header[3]]);
    let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let padding_len = header[6] as usize;
    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content).await?;
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        stream.read_exact(&mut padding).await?;
    }
    Ok(Some(FastCgiRecord {
        record_type,
        request_id,
        content: Bytes::from(content),
    }))
}

async fn read_fastcgi_streaming_response<R>(
    stream: &mut R,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
    stdout_tx: mpsc::Sender<Bytes>,
    stderr_tx: mpsc::Sender<Bytes>,
) -> Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut stdout_bytes = 0usize;
    let mut stderr_bytes = 0usize;
    loop {
        let Some(record) = read_fastcgi_record(stream).await? else {
            return Err(anyhow!(
                "fastcgi backend closed connection before end request"
            ));
        };
        if record.request_id != FCGI_REQUEST_ID {
            return Err(anyhow!(
                "fastcgi backend returned record for unexpected request id {}",
                record.request_id
            ));
        }
        match record.record_type {
            FCGI_STDOUT => {
                send_limited_chunk(
                    &stdout_tx,
                    record.content,
                    &mut stdout_bytes,
                    max_stdout_bytes,
                    "stdout",
                )
                .await?
            }
            FCGI_STDERR => {
                send_limited_chunk(
                    &stderr_tx,
                    record.content,
                    &mut stderr_bytes,
                    max_stderr_bytes,
                    "stderr",
                )
                .await?
            }
            FCGI_END_REQUEST => {
                validate_fastcgi_end_request(&record.content)?;
                return Ok(());
            }
            FCGI_ABORT_REQUEST => return Err(anyhow!("fastcgi backend aborted request")),
            _ => {}
        }
    }
}

pub(super) fn validate_fastcgi_end_request(content: &[u8]) -> Result<()> {
    if content.len() != 8 {
        return Err(anyhow!(
            "fastcgi END_REQUEST body length must be 8, got {}",
            content.len()
        ));
    }
    let app_status = u32::from_be_bytes([content[0], content[1], content[2], content[3]]);
    let protocol_status = content[4];
    match protocol_status {
        FCGI_REQUEST_COMPLETE => Ok(()),
        FCGI_CANT_MPX_CONN => Err(anyhow!(
            "fastcgi backend cannot multiplex connections (app_status={app_status})"
        )),
        FCGI_OVERLOADED => Err(anyhow!(
            "fastcgi backend overloaded (app_status={app_status})"
        )),
        FCGI_UNKNOWN_ROLE => Err(anyhow!(
            "fastcgi backend does not support responder role (app_status={app_status})"
        )),
        other => Err(anyhow!(
            "fastcgi backend returned unknown protocol status {other} (app_status={app_status})"
        )),
    }
}

pub(super) fn encode_fastcgi_params(env: Vec<(String, String)>) -> Result<Bytes> {
    let mut out = BytesMut::new();
    for (name, value) in env {
        encode_fastcgi_len(&mut out, name.len())?;
        encode_fastcgi_len(&mut out, value.len())?;
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    Ok(out.freeze())
}

fn encode_fastcgi_len(out: &mut BytesMut, len: usize) -> Result<()> {
    if len < 128 {
        out.extend_from_slice(&[len as u8]);
    } else {
        let len = u32::try_from(len).context("fastcgi param too large")? | 0x8000_0000;
        out.extend_from_slice(&len.to_be_bytes());
    }
    Ok(())
}

#[cfg(test)]
fn append_limited(out: &mut BytesMut, chunk: &[u8], limit: usize, label: &str) -> Result<()> {
    if out.len().saturating_add(chunk.len()) > limit {
        return Err(anyhow!(
            "persistent backend {label} exceeds configured limit"
        ));
    }
    out.extend_from_slice(chunk);
    Ok(())
}
