//! Leaf HTTP/1 client primitives shared across crates. The qpxd-specific helpers
//! (shared client, upstream-proxy resolution) remain in `qpxd`.

use crate::body::Body;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

/// HTTP/1 client send-request handle over the shared [`Body`] type.
pub type Http1SendRequest = hyper::client::conn::http1::SendRequest<Body>;

/// Performs an HTTP/1 client handshake over `io`, returning the send-request
/// handle and the connection driver future.
pub async fn handshake_http1<T>(
    io: T,
) -> Result<
    (
        Http1SendRequest,
        hyper::client::conn::http1::Connection<TokioIo<T>, Body>,
    ),
    hyper::Error,
>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await
}
