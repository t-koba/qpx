use anyhow::{Result, anyhow};
use bytes::BytesMut;
use hyper::header::{CONTENT_LENGTH, HeaderMap};
use hyper::{Request, Response, StatusCode};
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_http::body::Body;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncWrite};

mod body;
mod io;
mod request;
mod response;
#[cfg(test)]
mod tests;

const MAX_HEADER_BYTES: usize = 128 * 1024;
const INITIAL_READ_BUF_SIZE: usize = 2 * 1024;
const READ_BUF_SIZE: usize = 64 * 1024;
const MAX_CHUNKED_BODY_BYTES: u64 = 1024 * 1024 * 1024;
const RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT: tokio::time::Duration =
    tokio::time::Duration::from_secs(30);

#[derive(Debug, Clone)]
pub(crate) struct InterimResponseHead {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
}

pub(crate) struct Http1ResponseWithInterim {
    pub(crate) interim: Vec<InterimResponseHead>,
    pub(crate) response: Response<Body>,
    pub(crate) upstream_cert: Option<UpstreamCertificateInfo>,
}

type RecycleFn<S> = dyn Fn(S, BytesMut) + Send + Sync;

#[derive(Clone)]
pub(crate) struct Http1ConnectionRecycler<S> {
    recycle: Arc<RecycleFn<S>>,
}

impl<S> Http1ConnectionRecycler<S> {
    pub(crate) fn new<F>(recycle: F) -> Self
    where
        F: Fn(S, BytesMut) + Send + Sync + 'static,
    {
        Self {
            recycle: Arc::new(recycle),
        }
    }

    fn recycle(&self, stream: S, read_buf: BytesMut) {
        (self.recycle)(stream, read_buf);
    }
}

pub(crate) async fn idle_connection_closed_or_dirty<S>(stream: &mut S) -> bool
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0_u8; 1];
    let mut read_buf = ReadBuf::new(&mut byte);
    poll_fn(
        |cx| match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(true),
            Poll::Ready(Err(_)) => Poll::Ready(true),
            Poll::Pending => Poll::Ready(false),
        },
    )
    .await
}

pub(crate) async fn send_http1_request_with_interim<S>(
    stream: S,
    req: Request<Body>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_http1_request_with_interim_inner(
        stream,
        BytesMut::with_capacity(INITIAL_READ_BUF_SIZE),
        req,
        None,
    )
    .await
}

pub(crate) async fn send_http1_request_with_interim_reusable<S>(
    stream: S,
    read_buf: BytesMut,
    req: Request<Body>,
    recycler: Http1ConnectionRecycler<S>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_http1_request_with_interim_inner(stream, read_buf, req, Some(recycler)).await
}

async fn send_http1_request_with_interim_inner<S>(
    mut stream: S,
    read_buf: BytesMut,
    req: Request<Body>,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request_method = req.method().clone();
    request::write_http1_request(&mut stream, req).await?;
    let (interim, final_head, buffered_body) =
        response::read_response_head_with_interim(&mut stream, read_buf, &request_method).await?;
    let response = response::build_response(stream, final_head, buffered_body, recycler);
    Ok(Http1ResponseWithInterim {
        interim,
        response,
        upstream_cert: None,
    })
}

fn parse_declared_content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut parsed = None::<u64>;
    for value in headers.get_all(CONTENT_LENGTH).iter() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid content-length header"))?;
        for part in raw.split(',') {
            let len = part
                .trim()
                .parse::<u64>()
                .map_err(|_| anyhow!("invalid content-length value: {}", part.trim()))?;
            match parsed {
                Some(existing) if existing != len => {
                    return Err(anyhow!("conflicting content-length values"));
                }
                Some(_) => {}
                None => parsed = Some(len),
            }
        }
    }
    Ok(parsed)
}
