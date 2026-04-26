use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn handshake_http2<T>(
    io: T,
) -> Result<(
    hyper::client::conn::http2::SendRequest<BoxBody<Bytes, Infallible>>,
    hyper::client::conn::http2::Connection<TokioIo<T>, BoxBody<Bytes, Infallible>, TokioExecutor>,
)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Ok(
        hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(io))
            .await?,
    )
}
