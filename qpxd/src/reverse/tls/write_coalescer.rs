use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const DIRECT_WRITE_THRESHOLD: usize = 4 * 1024;
const COALESCED_WRITE_CAPACITY: usize = 16 * 1024;

/// Coalesces adjacent small writes while preserving direct vectored I/O for bulk data.
pub(in crate::reverse) struct AdaptiveWriteCoalescer<T> {
    inner: T,
    buffered: Vec<u8>,
    written: usize,
}

impl<T> AdaptiveWriteCoalescer<T> {
    pub(in crate::reverse) fn new(inner: T) -> Self {
        Self {
            inner,
            buffered: Vec::new(),
            written: 0,
        }
    }
}

impl<T> AdaptiveWriteCoalescer<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.buffered.len() {
            let count =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.buffered[self.written..]))?;
            if count == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to drain coalesced write buffer",
                )));
            }
            self.written += count;
        }
        self.buffered.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_write_with_pending(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let pending = &self.buffered[self.written..];
            if pending.is_empty() {
                self.buffered.clear();
                self.written = 0;
                return Pin::new(&mut self.inner).poll_write(cx, buffer);
            }
            let buffers = [IoSlice::new(pending), IoSlice::new(buffer)];
            let count = ready!(Pin::new(&mut self.inner).poll_write_vectored(cx, &buffers))?;
            if count == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to drain coalesced write buffer",
                )));
            }
            if count <= pending.len() {
                self.written += count;
                continue;
            }
            let consumed = count - pending.len();
            self.buffered.clear();
            self.written = 0;
            return Poll::Ready(Ok(consumed));
        }
    }

    fn poll_write_vectored_with_pending(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let first = buffers
            .iter()
            .find(|buffer| !buffer.is_empty())
            .map(|buffer| buffer.as_ref())
            .unwrap_or_default();
        loop {
            let pending = &self.buffered[self.written..];
            if pending.is_empty() {
                self.buffered.clear();
                self.written = 0;
                return Pin::new(&mut self.inner).poll_write_vectored(cx, buffers);
            }
            let combined = [IoSlice::new(pending), IoSlice::new(first)];
            let count = ready!(Pin::new(&mut self.inner).poll_write_vectored(cx, &combined))?;
            if count == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to drain coalesced write buffer",
                )));
            }
            if count <= pending.len() {
                self.written += count;
                continue;
            }
            let consumed = count - pending.len();
            self.buffered.clear();
            self.written = 0;
            return Poll::Ready(Ok(consumed));
        }
    }

    fn can_buffer(&self, bytes: usize) -> bool {
        bytes < DIRECT_WRITE_THRESHOLD
            && self
                .buffered
                .len()
                .checked_add(bytes)
                .is_some_and(|total| total <= COALESCED_WRITE_CAPACITY)
    }

    fn buffer_slices(&mut self, slices: &[IoSlice<'_>], bytes: usize) {
        self.buffered.reserve(bytes);
        for slice in slices {
            self.buffered.extend_from_slice(slice);
        }
    }
}

impl<T> AsyncRead for AdaptiveWriteCoalescer<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buffer)
    }
}

impl<T> AsyncWrite for AdaptiveWriteCoalescer<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.can_buffer(buffer.len()) {
            this.buffered.reserve(buffer.len());
            this.buffered.extend_from_slice(buffer);
            return Poll::Ready(Ok(buffer.len()));
        }
        if buffer.len() < DIRECT_WRITE_THRESHOLD {
            ready!(this.poll_drain(cx))?;
            this.buffered.reserve(buffer.len());
            this.buffered.extend_from_slice(buffer);
            Poll::Ready(Ok(buffer.len()))
        } else {
            this.poll_write_with_pending(cx, buffer)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        let bytes = buffers
            .iter()
            .try_fold(0usize, |total, buffer| total.checked_add(buffer.len()))
            .unwrap_or(usize::MAX);
        if bytes == 0 {
            return Poll::Ready(Ok(0));
        }
        if this.can_buffer(bytes) {
            this.buffer_slices(buffers, bytes);
            return Poll::Ready(Ok(bytes));
        }
        if bytes < DIRECT_WRITE_THRESHOLD {
            ready!(this.poll_drain(cx))?;
            this.buffer_slices(buffers, bytes);
            Poll::Ready(Ok(bytes))
        } else {
            this.poll_write_vectored_with_pending(cx, buffers)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AdaptiveWriteCoalescer, DIRECT_WRITE_THRESHOLD};
    use std::io::IoSlice;
    use std::pin::Pin;
    use std::task::Poll;
    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{Duration, timeout};

    async fn connected_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn buffers_small_writes_until_flush() {
        let (mut client, server) = connected_tcp_pair().await;
        let mut writer = AdaptiveWriteCoalescer::new(server);
        writer.write_all(b"small").await.unwrap();

        let mut received = [0u8; 5];
        assert!(
            timeout(Duration::from_millis(20), client.read_exact(&mut received))
                .await
                .is_err()
        );

        writer.flush().await.unwrap();
        timeout(Duration::from_secs(1), client.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"small");
    }

    #[tokio::test]
    async fn drains_small_writes_before_direct_bulk_write() {
        let (mut client, server) = connected_tcp_pair().await;
        let mut writer = AdaptiveWriteCoalescer::new(server);
        writer.write_all(b"head").await.unwrap();
        let bulk = vec![b'x'; DIRECT_WRITE_THRESHOLD];
        writer.write_all(&bulk).await.unwrap();

        let mut received = vec![0u8; 4 + bulk.len()];
        timeout(Duration::from_secs(1), client.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..4], b"head");
        assert_eq!(&received[4..], bulk);
    }

    #[tokio::test]
    async fn coalesces_vectored_small_writes_without_reordering() {
        let (mut client, server) = connected_tcp_pair().await;
        let mut writer = AdaptiveWriteCoalescer::new(server);
        let buffers = [IoSlice::new(b"one"), IoSlice::new(b"two")];
        let written = std::future::poll_fn(|cx| {
            let result = Pin::new(&mut writer).poll_write_vectored(cx, &buffers);
            match result {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
        .unwrap();
        assert_eq!(written, 6);
        writer.shutdown().await.unwrap();

        let mut received = Vec::new();
        timeout(Duration::from_secs(1), client.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"onetwo");
    }
}
