use anyhow::{Context, Result};
#[cfg(windows)]
use std::io::ErrorKind;
#[cfg(windows)]
use std::net::{SocketAddr, TcpStream as StdTcpStream};
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
#[cfg(windows)]
use tokio::io::AsyncReadExt;
#[cfg(any(unix, windows))]
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(windows)]
use tokio::net::TcpStream as TokioTcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(unix)]
pub(crate) type QuinnBrokerStream = StdUnixStream;

#[cfg(windows)]
pub(crate) type QuinnBrokerStream = StdTcpStream;

#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub(crate) struct QuinnBrokerStream;

pub(super) enum TokioQuinnBrokerStream {
    #[cfg(unix)]
    Unix(UnixStream),
    #[cfg(windows)]
    Tcp(TokioTcpStream),
}

impl AsyncRead for TokioQuinnBrokerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(windows)]
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TokioQuinnBrokerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(windows)]
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(windows)]
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(windows)]
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(super) fn unix_stream_into_owned_fd(stream: QuinnBrokerStream) -> OwnedFd {
    let raw = stream.into_raw_fd();
    // SAFETY: into_raw_fd transfers ownership from the stream, so constructing OwnedFd
    // from the same raw descriptor preserves exactly one owner.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

#[cfg(unix)]
pub(super) fn adopt_unix_stream(fd: i32) -> Result<QuinnBrokerStream> {
    // SAFETY: the handoff manifest only contains descriptors produced by
    // unix_stream_into_owned_fd in this module, and take_from_env consumes each fd once.
    let stream = unsafe { QuinnBrokerStream::from_raw_fd(fd) };
    stream
        .set_nonblocking(true)
        .context("failed to set inherited QUIC broker stream nonblocking")?;
    Ok(stream)
}

#[cfg(windows)]
pub(super) fn connect_windows_broker(addr: &str, token: &str) -> Result<QuinnBrokerStream> {
    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid QUIC broker rendezvous addr {addr}"))?;
    let deadline = std::time::Instant::now() + crate::windows_handoff::HANDOFF_WAIT_TIMEOUT;
    loop {
        match StdTcpStream::connect(addr) {
            Ok(mut stream) => {
                write_broker_token(&mut stream, token)?;
                stream
                    .set_nonblocking(true)
                    .context("failed to set inherited QUIC broker tcp stream nonblocking")?;
                return Ok(stream);
            }
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                if std::time::Instant::now() >= deadline {
                    return Err(err)
                        .with_context(|| format!("timed out connecting QUIC broker {addr}"));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(err) => {
                return Err(err).with_context(|| format!("failed to connect QUIC broker {addr}"));
            }
        }
    }
}

pub(super) fn tokio_broker_stream_from_std(
    stream: QuinnBrokerStream,
) -> Result<TokioQuinnBrokerStream> {
    #[cfg(unix)]
    {
        Ok(TokioQuinnBrokerStream::Unix(UnixStream::from_std(stream)?))
    }

    #[cfg(windows)]
    {
        Ok(TokioQuinnBrokerStream::Tcp(TokioTcpStream::from_std(
            stream,
        )?))
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = stream;
        Err(anyhow::anyhow!(
            "QUIC broker handoff is unsupported on this platform"
        ))
    }
}

#[cfg(windows)]
fn write_broker_token(stream: &mut StdTcpStream, token: &str) -> Result<()> {
    let bytes = token.as_bytes();
    let len = u16::try_from(bytes.len()).context("broker token too long")?;
    std::io::Write::write_all(stream, &len.to_be_bytes())
        .context("failed to write broker token length")?;
    std::io::Write::write_all(stream, bytes).context("failed to write broker token")?;
    std::io::Write::flush(stream).ok();
    Ok(())
}

#[cfg(windows)]
pub(super) async fn read_broker_token(stream: &mut TokioTcpStream, expected: &str) -> Result<()> {
    const MAX_BROKER_TOKEN_LEN: usize = 512;
    let len = stream
        .read_u16()
        .await
        .context("failed to read broker token length")? as usize;
    if len == 0 || len > MAX_BROKER_TOKEN_LEN {
        return Err(anyhow!("invalid broker token length {len}"));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("failed to read broker token")?;
    if buf != expected.as_bytes() {
        return Err(anyhow!("broker token mismatch"));
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn remaining_handoff_wait(deadline: std::time::Instant) -> Result<std::time::Duration> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| anyhow!("timed out waiting for broker handoff"))
}
