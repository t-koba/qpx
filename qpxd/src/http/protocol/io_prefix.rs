use bytes::{Bytes, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// An IO wrapper that "unreads" a prefix before delegating to the inner IO.
///
/// This is used when we must inspect bytes from a stream (e.g. PROXYv2 metadata, TLS ClientHello)
/// but still want downstream consumers to see the original byte stream.
pub struct PrefixedIo<I> {
    inner: I,
    prefix: Bytes,
    pos: usize,
}

impl<I> PrefixedIo<I> {
    pub fn new(inner: I, prefix: Bytes) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }

    pub fn into_inner_with_leading_prefix(self, leading: Bytes) -> (I, Bytes) {
        let remaining = self.prefix.slice(self.pos..);
        if remaining.is_empty() {
            return (self.inner, leading);
        }
        if leading.is_empty() {
            return (self.inner, remaining);
        }
        let mut combined = BytesMut::with_capacity(leading.len() + remaining.len());
        combined.extend_from_slice(&leading);
        combined.extend_from_slice(&remaining);
        (self.inner, combined.freeze())
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for PrefixedIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() && buf.remaining() > 0 {
            let available = &self.prefix[self.pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_prefix_is_combined_with_unread_existing_prefix() {
        let prefixed = PrefixedIo {
            inner: 7_u8,
            prefix: Bytes::from_static(b"abcdef"),
            pos: 2,
        };

        let (inner, prefix) = prefixed.into_inner_with_leading_prefix(Bytes::from_static(b"12"));

        assert_eq!(inner, 7);
        assert_eq!(prefix, b"12cdef"[..]);
    }
}
