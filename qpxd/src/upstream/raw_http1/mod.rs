use anyhow::{Result, anyhow};
use bytes::BytesMut;
use hyper::header::{CONTENT_LENGTH, HeaderMap};
use hyper::{Request, Response, StatusCode};
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_http::body::Body;
use std::fmt;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

mod body;
mod io;
mod raw_head;
mod request;
mod response;
#[cfg(test)]
mod tests;

pub(crate) use request::{is_bodyless_http1_request, serialize_bodyless_http1_request};

const MAX_HEADER_BYTES: usize = 128 * 1024;
const INITIAL_READ_BUF_SIZE: usize = 2 * 1024;
pub(crate) const READ_BUF_SIZE: usize = 512 * 1024;
const MAX_EMITTED_BODY_FRAME_SIZE: usize = READ_BUF_SIZE;
const MAX_CHUNKED_BODY_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT: tokio::time::Duration =
    tokio::time::Duration::from_secs(30);

#[derive(Debug)]
pub(crate) struct UpstreamConnectionClosed;

impl fmt::Display for UpstreamConnectionClosed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("upstream connection closed unexpectedly")
    }
}

impl std::error::Error for UpstreamConnectionClosed {}

pub(crate) use raw_head::{RawHttp1BodyFraming, RawHttp1ResponseHead};

#[derive(Debug, Clone)]
pub(crate) struct InterimResponseHead {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
}

pub(crate) struct Http1ResponseWithInterim {
    pub(crate) interim: Vec<InterimResponseHead>,
    pub(crate) response: Response<Body>,
    pub(crate) upstream_cert: Option<UpstreamCertificateInfo>,
    pub(crate) response_finalized: bool,
}

pub(crate) struct RawHttp1ResponseRelay<S> {
    pub(crate) interim: Vec<InterimResponseHead>,
    pub(crate) version: http::Version,
    pub(crate) status: StatusCode,
    pub(crate) raw: Arc<RawHttp1ResponseHead>,
    pub(crate) stream: Option<S>,
    pub(crate) read_buf: BytesMut,
    pub(crate) write_buf: BytesMut,
    pub(crate) recycler: Option<Http1ConnectionRecycler<S>>,
}

pub(crate) struct SerializedHttp1HeadSendError {
    error: anyhow::Error,
    write_buf: BytesMut,
}

impl SerializedHttp1HeadSendError {
    pub(crate) fn into_parts(self) -> (anyhow::Error, BytesMut) {
        (self.error, self.write_buf)
    }
}

impl<S> RawHttp1ResponseRelay<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    pub(crate) fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn supports_direct_relay(&self, max_response_body_bytes: usize) -> bool {
        self.status != StatusCode::SWITCHING_PROTOCOLS
            && match self.raw.framing() {
                RawHttp1BodyFraming::Empty => true,
                RawHttp1BodyFraming::ContentLength(length) => {
                    length <= max_response_body_bytes as u64
                }
                RawHttp1BodyFraming::Chunked | RawHttp1BodyFraming::CloseDelimited => false,
            }
    }

    pub(crate) fn finalize(&mut self, request_version: http::Version, proxy_name: &str) {
        if self.raw.is_finalized() {
            return;
        }
        Arc::make_mut(&mut self.raw).finalize(request_version, proxy_name);
    }

    pub(crate) fn into_http_response(self) -> Result<Http1ResponseWithInterim> {
        let Self {
            interim,
            version,
            status,
            raw,
            stream,
            read_buf,
            write_buf,
            recycler,
        } = self;
        let stream = stream.ok_or_else(|| anyhow!("raw HTTP/1 relay stream is unavailable"))?;
        let response = response::build_raw_response(
            stream,
            response::RawParsedResponseHead {
                version,
                status,
                raw,
            },
            read_buf,
            write_buf,
            recycler,
        );
        Ok(Http1ResponseWithInterim {
            interim,
            response,
            upstream_cert: None,
            response_finalized: false,
        })
    }

    pub(crate) fn into_materialized_http_response(self) -> Result<Http1ResponseWithInterim> {
        let Self {
            interim,
            version,
            status,
            raw,
            stream,
            read_buf,
            write_buf,
            recycler,
        } = self;
        let stream = stream.ok_or_else(|| anyhow!("raw HTTP/1 relay stream is unavailable"))?;
        let response = response::build_materialized_raw_response(
            stream,
            response::RawParsedResponseHead {
                version,
                status,
                raw,
            },
            read_buf,
            write_buf,
            recycler,
        )?;
        Ok(Http1ResponseWithInterim {
            interim,
            response,
            upstream_cert: None,
            response_finalized: true,
        })
    }
}

pub(crate) trait Http1RecycleTarget<S>: Send + Sync {
    fn recycle(&self, stream: S, read_buf: BytesMut, write_buf: BytesMut);
}

impl<S, F> Http1RecycleTarget<S> for F
where
    F: Fn(S, BytesMut, BytesMut) + Send + Sync,
{
    fn recycle(&self, stream: S, read_buf: BytesMut, write_buf: BytesMut) {
        self(stream, read_buf, write_buf);
    }
}

#[derive(Clone)]
pub(crate) struct Http1ConnectionRecycler<S> {
    target: Arc<dyn Http1RecycleTarget<S>>,
}

impl<S> Http1ConnectionRecycler<S> {
    pub(crate) fn new<F>(recycle: F) -> Self
    where
        F: Fn(S, BytesMut, BytesMut) + Send + Sync + 'static,
    {
        Self {
            target: Arc::new(recycle),
        }
    }

    pub(crate) fn from_target<T>(target: Arc<T>) -> Self
    where
        T: Http1RecycleTarget<S> + 'static,
    {
        Self { target }
    }

    pub(crate) fn recycle(&self, stream: S, read_buf: BytesMut, write_buf: BytesMut) {
        self.target.recycle(stream, read_buf, write_buf);
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
        BytesMut::with_capacity(512),
        req,
        None,
    )
    .await
}

pub(crate) async fn send_http1_request_with_interim_reusable<S>(
    stream: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    req: Request<Body>,
    recycler: Http1ConnectionRecycler<S>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_http1_request_with_interim_inner(stream, read_buf, write_buf, req, Some(recycler)).await
}

pub(crate) async fn send_http1_request_with_interim_reusable_raw_response<S>(
    stream: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    req: Request<Body>,
    request_version: http::Version,
    proxy_name: &str,
    recycler: Http1ConnectionRecycler<S>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_http1_request_with_interim_raw_response_inner(
        stream,
        read_buf,
        write_buf,
        req,
        request_version,
        proxy_name,
        Some(recycler),
    )
    .await
}

pub(crate) async fn send_prepared_http1_head_with_interim_reusable_raw_response<S>(
    mut stream: S,
    read_buf: BytesMut,
    write_buf: BytesMut,
    request_method: &http::Method,
    request_head: &[u8],
    proxy_name: &str,
    recycler: Http1ConnectionRecycler<S>,
) -> Result<RawHttp1ResponseRelay<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    stream.write_all(request_head).await?;
    let (interim, final_head, buffered_body) =
        response::read_finalized_raw_response_head_with_interim(
            &mut stream,
            read_buf,
            request_method,
            http::Version::HTTP_11,
            proxy_name,
        )
        .await?;
    Ok(RawHttp1ResponseRelay {
        interim,
        version: final_head.version,
        status: final_head.status,
        raw: final_head.raw,
        stream: Some(stream),
        read_buf: buffered_body,
        write_buf,
        recycler: Some(recycler),
    })
}

pub(crate) async fn send_serialized_http1_head_with_interim_reusable_raw_response<S>(
    mut stream: S,
    read_buf: BytesMut,
    mut write_buf: BytesMut,
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    recycler: Http1ConnectionRecycler<S>,
) -> std::result::Result<RawHttp1ResponseRelay<S>, SerializedHttp1HeadSendError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Err(error) = stream.write_all(&write_buf).await {
        return Err(SerializedHttp1HeadSendError {
            error: error.into(),
            write_buf,
        });
    }
    // The reverse fast path wraps this entire operation in the route deadline.
    // Avoid registering a second timer for the same response-head wait.
    let result = response::read_finalized_raw_response_head_with_interim_under_external_deadline(
        &mut stream,
        read_buf,
        request_method,
        request_version,
        proxy_name,
    )
    .await;
    let (interim, final_head, buffered_body) = match result {
        Ok(response) => response,
        Err(error) => {
            return Err(SerializedHttp1HeadSendError { error, write_buf });
        }
    };
    write_buf.clear();
    Ok(RawHttp1ResponseRelay {
        interim,
        version: final_head.version,
        status: final_head.status,
        raw: final_head.raw,
        stream: Some(stream),
        read_buf: buffered_body,
        write_buf,
        recycler: Some(recycler),
    })
}

async fn send_http1_request_with_interim_inner<S>(
    mut stream: S,
    read_buf: BytesMut,
    mut write_buf: BytesMut,
    req: Request<Body>,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request_method = req.method().clone();
    request::write_http1_request(&mut stream, req, &mut write_buf).await?;
    let (interim, final_head, buffered_body) =
        response::read_response_head_with_interim(&mut stream, read_buf, &request_method).await?;
    let response = response::build_response(stream, final_head, buffered_body, write_buf, recycler);
    Ok(Http1ResponseWithInterim {
        interim,
        response,
        upstream_cert: None,
        response_finalized: false,
    })
}

async fn send_http1_request_with_interim_raw_response_inner<S>(
    mut stream: S,
    read_buf: BytesMut,
    mut write_buf: BytesMut,
    req: Request<Body>,
    request_version: http::Version,
    proxy_name: &str,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request_method = req.method().clone();
    request::write_prepared_bodyless_http1_request(&mut stream, req, &mut write_buf).await?;
    let (interim, final_head, buffered_body) =
        response::read_finalized_raw_response_head_with_interim(
            &mut stream,
            read_buf,
            &request_method,
            request_version,
            proxy_name,
        )
        .await?;
    let response =
        response::build_raw_response(stream, final_head, buffered_body, write_buf, recycler);
    Ok(Http1ResponseWithInterim {
        interim,
        response,
        upstream_cert: None,
        response_finalized: false,
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
