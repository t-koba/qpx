use async_trait::async_trait;
#[cfg(feature = "http3-backend-h3")]
use bytes::Buf;
use bytes::Bytes;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TUNNEL_CHUNK_BYTES: usize = 16 * 1024;

#[async_trait]
pub(crate) trait TunnelHalf: Send {
    async fn recv(&mut self) -> io::Result<Option<Bytes>>;
}

#[async_trait]
pub(crate) trait TunnelHalfWrite: Send {
    async fn send(&mut self, data: Bytes) -> io::Result<()>;
    async fn shutdown(&mut self) -> io::Result<()>;
}

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) struct PrefixedTunnelHalf<R> {
    prefix: Option<Bytes>,
    inner: R,
}

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
impl<R> PrefixedTunnelHalf<R> {
    pub(crate) fn new(inner: R, prefix: Bytes) -> Self {
        Self {
            prefix: (!prefix.is_empty()).then_some(prefix),
            inner,
        }
    }
}

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
#[async_trait]
impl<R> TunnelHalf for PrefixedTunnelHalf<R>
where
    R: TunnelHalf + Send,
{
    async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        if let Some(prefix) = self.prefix.take() {
            return Ok(Some(prefix));
        }
        self.inner.recv().await
    }
}

#[async_trait]
impl<T> TunnelHalf for tokio::io::ReadHalf<T>
where
    T: AsyncRead + Unpin + Send,
{
    async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        let mut buf = vec![0u8; TUNNEL_CHUNK_BYTES];
        let n = self.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.truncate(n);
        Ok(Some(Bytes::from(buf)))
    }
}

#[async_trait]
impl<T> TunnelHalfWrite for tokio::io::WriteHalf<T>
where
    T: AsyncWrite + Unpin + Send,
{
    async fn send(&mut self, data: Bytes) -> io::Result<()> {
        self.write_all(data.as_ref()).await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        AsyncWriteExt::shutdown(self).await
    }
}

#[cfg(feature = "http3-backend-h3")]
#[async_trait]
impl TunnelHalf for ::h3::server::RequestStream<h3_quinn::RecvStream, Bytes> {
    async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        h3_recv_data(self.recv_data().await)
    }
}

#[cfg(feature = "http3-backend-h3")]
#[async_trait]
impl TunnelHalfWrite for ::h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes> {
    async fn send(&mut self, data: Bytes) -> io::Result<()> {
        h3_result(self.send_data(data).await)
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        h3_result(self.finish().await)
    }
}

#[cfg(feature = "http3-backend-h3")]
#[async_trait]
impl TunnelHalf for ::h3::client::RequestStream<h3_quinn::RecvStream, Bytes> {
    async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        h3_recv_data(self.recv_data().await)
    }
}

#[cfg(feature = "http3-backend-h3")]
#[async_trait]
impl TunnelHalfWrite for ::h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes> {
    async fn send(&mut self, data: Bytes) -> io::Result<()> {
        h3_result(self.send_data(data).await)
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        h3_result(self.finish().await)
    }
}

#[cfg(feature = "http3-backend-qpx")]
#[async_trait]
impl TunnelHalf for qpx_h3::RequestRecvStream {
    async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        qpx_result(self.recv_data().await)
    }
}

#[cfg(feature = "http3-backend-qpx")]
#[async_trait]
impl TunnelHalfWrite for qpx_h3::RequestSendStream {
    async fn send(&mut self, data: Bytes) -> io::Result<()> {
        qpx_result(self.send_data(data).await)
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        qpx_result(self.finish().await)
    }
}

#[cfg(feature = "http3-backend-qpx")]
#[async_trait]
impl TunnelHalf for qpx_h3::StreamRecv {
    async fn recv(&mut self) -> io::Result<Option<Bytes>> {
        qpx_result(self.recv_chunk().await)
    }
}

#[cfg(feature = "http3-backend-qpx")]
#[async_trait]
impl TunnelHalfWrite for qpx_h3::StreamSend {
    async fn send(&mut self, data: Bytes) -> io::Result<()> {
        qpx_result(self.send_chunk(data).await)
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        qpx_result(self.finish().await)
    }
}

#[cfg(feature = "http3-backend-h3")]
fn h3_recv_data(
    result: std::result::Result<Option<impl Buf>, ::h3::error::StreamError>,
) -> io::Result<Option<Bytes>> {
    let Some(mut chunk) = result.map_err(io_other)? else {
        return Ok(None);
    };
    Ok(Some(chunk.copy_to_bytes(chunk.remaining())))
}

#[cfg(feature = "http3-backend-h3")]
fn h3_result<T>(result: std::result::Result<T, ::h3::error::StreamError>) -> io::Result<T> {
    result.map_err(io_other)
}

#[cfg(feature = "http3-backend-qpx")]
fn qpx_result<T>(result: anyhow::Result<T>) -> io::Result<T> {
    result.map_err(io_other)
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
fn io_other(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(err.to_string())
}
