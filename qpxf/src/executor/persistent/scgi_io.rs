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
    body: PersistentStdinBody,
    max_stdout_bytes: usize,
    stdout_tx: mpsc::Sender<Bytes>,
) -> Result<()> {
    let mut stream = connect_backend(address).await?;
    let mut headers = BytesMut::new();
    for (name, value) in env {
        headers.extend_from_slice(name.as_bytes());
        headers.extend_from_slice(b"\0");
        headers.extend_from_slice(value.as_bytes());
        headers.extend_from_slice(b"\0");
    }
    let prefix = format!("{}:", headers.len());
    stream.write_all(prefix.as_bytes()).await?;
    stream.write_all(&headers).await?;
    stream.write_all(b",").await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write_body = async {
        body.write_to(&mut writer).await?;
        writer.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    };
    let read_stdout = stream_read_limited(&mut reader, max_stdout_bytes, "stdout", stdout_tx);
    let _ = tokio::try_join!(write_body, read_stdout)?;
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
    let mut headers = BytesMut::new();
    for (name, value) in env {
        headers.extend_from_slice(name.as_bytes());
        headers.extend_from_slice(b"\0");
        headers.extend_from_slice(value.as_bytes());
        headers.extend_from_slice(b"\0");
    }
    let prefix = format!("{}:", headers.len());
    stream.write_all(prefix.as_bytes()).await?;
    stream.write_all(&headers).await?;
    stream.write_all(b",").await?;
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
    let _ = tokio::try_join!(write_body, read_stdout)?;
    Ok(())
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
