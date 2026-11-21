use super::pool::connect_backend;
use super::stream_read_limited;
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

pub(super) enum PersistentStdinBody {
    Memory(Bytes),
}

impl PersistentStdinBody {
    pub(super) async fn write_to<W>(&self, writer: &mut W) -> Result<()>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        match self {
            Self::Memory(body) => writer.write_all(body).await.map_err(Into::into),
        }
    }
}

pub(super) async fn ensure_unknown_scgi_stdin_is_empty(
    rx: &mut mpsc::Receiver<Bytes>,
) -> Result<()> {
    while let Some(chunk) = rx.recv().await {
        if !chunk.is_empty() {
            return Err(anyhow!(
                "scgi backend requires Content-Length for non-empty stdin"
            ));
        }
    }
    Ok(())
}
pub(super) async fn run_scgi_streaming(
    address: &str,
    env: Vec<(String, String)>,
    content_length: usize,
    body: PersistentStdinBody,
    max_stdout_bytes: usize,
    stdout_tx: mpsc::Sender<Bytes>,
) -> Result<()> {
    let mut stream = connect_backend(address).await?;
    write_scgi_request_headers(&mut stream, env, content_length).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write_body = async {
        body.write_to(&mut writer).await?;
        writer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let read_stdout = stream_read_limited(&mut reader, max_stdout_bytes, "stdout", stdout_tx);
    tokio::try_join!(write_body, read_stdout)?;
    Ok(())
}

pub(super) async fn run_scgi_streaming_stdin(
    address: &str,
    env: Vec<(String, String)>,
    stdin_rx: mpsc::Receiver<Bytes>,
    expected_stdin_bytes: usize,
    max_stdin_bytes: usize,
    max_stdout_bytes: usize,
    stdout_tx: mpsc::Sender<Bytes>,
) -> Result<()> {
    let mut stream = connect_backend(address).await?;
    write_scgi_request_headers(&mut stream, env, expected_stdin_bytes).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write_body = async {
        write_stdin_rx_to_writer(
            stdin_rx,
            &mut writer,
            expected_stdin_bytes,
            max_stdin_bytes,
            "scgi",
        )
        .await?;
        writer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let read_stdout = stream_read_limited(&mut reader, max_stdout_bytes, "stdout", stdout_tx);
    tokio::try_join!(write_body, read_stdout)?;
    Ok(())
}
async fn write_scgi_request_headers<W>(
    writer: &mut W,
    env: Vec<(String, String)>,
    content_length: usize,
) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut headers = BytesMut::new();
    push_scgi_pair(&mut headers, "CONTENT_LENGTH", content_length.to_string());
    push_scgi_pair(&mut headers, "SCGI", "1");
    for (name, value) in env {
        if name == "CONTENT_LENGTH" || name == "SCGI" {
            continue;
        }
        push_scgi_pair(&mut headers, name, value);
    }
    let prefix = format!("{}:", headers.len());
    writer.write_all(prefix.as_bytes()).await?;
    writer.write_all(&headers).await?;
    writer.write_all(b",").await?;
    Ok(())
}

fn push_scgi_pair(headers: &mut BytesMut, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    headers.extend_from_slice(name.as_ref());
    headers.extend_from_slice(b"\0");
    headers.extend_from_slice(value.as_ref());
    headers.extend_from_slice(b"\0");
}

async fn write_stdin_rx_to_writer<W>(
    mut stdin_rx: mpsc::Receiver<Bytes>,
    writer: &mut W,
    expected_stdin_bytes: usize,
    max_stdin_bytes: usize,
    label: &str,
) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut seen = 0usize;
    while let Some(chunk) = stdin_rx.recv().await {
        seen = seen.saturating_add(chunk.len());
        if seen > max_stdin_bytes {
            return Err(anyhow!(
                "persistent backend {label} stdin exceeds configured limit"
            ));
        }
        if seen > expected_stdin_bytes {
            return Err(anyhow!(
                "persistent backend {label} stdin exceeds declared content-length"
            ));
        }
        writer.write_all(&chunk).await?;
    }
    if seen != expected_stdin_bytes {
        return Err(anyhow!(
            "persistent backend {label} stdin length mismatch: declared {}, received {}",
            expected_stdin_bytes,
            seen
        ));
    }
    Ok(())
}
