use crate::exporter::ExportSession;
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Duration};

async fn copy_one_way<R, W>(
    mut reader: R,
    mut writer: W,
    session: Option<ExportSession>,
    client_to_server: bool,
    idle_timeout: Option<Duration>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match idle_timeout {
            Some(dur) => timeout(dur, reader.read(&mut buf)).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel read timed out")
            })??,
            None => reader.read(&mut buf).await?,
        };
        if n == 0 {
            match idle_timeout {
                Some(dur) => timeout(dur, writer.shutdown()).await.map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel shutdown timed out")
                })??,
                None => writer.shutdown().await?,
            }
            return Ok(total);
        }
        match idle_timeout {
            Some(dur) => timeout(dur, writer.write_all(&buf[..n]))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel write timed out")
                })??,
            None => writer.write_all(&buf[..n]).await?,
        }
        if let Some(session) = &session {
            session.emit_encrypted_pair(client_to_server, &buf[..n]);
        }
        total = total.saturating_add(n as u64);
    }
}

pub async fn copy_bidirectional_with_export_and_idle<A, B>(
    a: A,
    b: B,
    session: Option<ExportSession>,
    idle_timeout: Option<Duration>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_reader, a_writer) = tokio::io::split(a);
    let (b_reader, b_writer) = tokio::io::split(b);

    let a_to_b_session = session.clone();
    let b_to_a_session = session;

    let _ = tokio::try_join!(
        copy_one_way(a_reader, b_writer, a_to_b_session, true, idle_timeout),
        copy_one_way(b_reader, a_writer, b_to_a_session, false, idle_timeout),
    )?;
    Ok(())
}
