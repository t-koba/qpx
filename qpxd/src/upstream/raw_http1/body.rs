use super::response::ResponseBodyKind;
use super::{
    Http1ConnectionRecycler, MAX_CHUNKED_BODY_BYTES, MAX_HEADER_BYTES,
    RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT, READ_BUF_SIZE,
};
use crate::http::codec::h1_common::{find_crlf, parse_header_map};
use bytes::{Buf, Bytes, BytesMut};
use http_body::Frame;
use qpx_http::body::BodyError;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Duration, Sleep};

enum BodyState {
    ContentLength {
        remaining: u64,
    },
    CloseDelimited,
    Chunked {
        state: ChunkState,
        total_body_bytes: u64,
    },
    Done,
}

enum ChunkState {
    Size,
    Data { remaining: usize },
    CrLf,
    Trailers,
}

pub(super) struct Http1ResponseBody<S> {
    stream: Option<S>,
    buf: BytesMut,
    state: BodyState,
    recycler: Option<Http1ConnectionRecycler<S>>,
    read_timeout: Duration,
    read_timer: Option<Pin<Box<Sleep>>>,
}

impl<S> Http1ResponseBody<S> {
    pub(super) fn new(
        stream: S,
        prefix: BytesMut,
        kind: ResponseBodyKind,
        recycler: Option<Http1ConnectionRecycler<S>>,
    ) -> Self {
        let state = match kind {
            ResponseBodyKind::Empty => BodyState::Done,
            ResponseBodyKind::ContentLength(remaining) => BodyState::ContentLength { remaining },
            ResponseBodyKind::CloseDelimited => BodyState::CloseDelimited,
            ResponseBodyKind::Chunked => BodyState::Chunked {
                state: ChunkState::Size,
                total_body_bytes: 0,
            },
        };
        Self {
            stream: Some(stream),
            buf: prefix,
            state,
            recycler,
            read_timeout: RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
            read_timer: None,
        }
    }

    fn finish(&mut self) {
        let Some(stream) = self.stream.take() else {
            return;
        };
        if self.buf.is_empty()
            && let Some(recycler) = self.recycler.take()
        {
            recycler.recycle(stream);
        }
    }

    fn discard(&mut self) {
        self.stream.take();
        self.recycler.take();
    }

    fn body_error(message: impl Into<String>) -> BodyError {
        BodyError::new(message)
    }
}

impl<S> Drop for Http1ResponseBody<S> {
    fn drop(&mut self) {
        self.discard();
    }
}

impl<S> http_body::Body for Http1ResponseBody<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        loop {
            match &mut this.state {
                BodyState::ContentLength { remaining } => {
                    if *remaining == 0 {
                        this.state = BodyState::Done;
                        this.finish();
                        return Poll::Ready(None);
                    }
                    if !this.buf.is_empty() {
                        let take = this.buf.len().min(*remaining as usize).min(READ_BUF_SIZE);
                        *remaining -= take as u64;
                        return Poll::Ready(Some(Ok(Frame::data(
                            this.buf.split_to(take).freeze(),
                        ))));
                    }
                    match poll_read_with_timeout(this, cx) {
                        Poll::Ready(Ok(0)) => {
                            this.state = BodyState::Done;
                            this.discard();
                            return Poll::Ready(Some(Err(Self::body_error(
                                "upstream response closed before content-length completed",
                            ))));
                        }
                        Poll::Ready(Ok(_)) => {}
                        Poll::Ready(Err(err)) => {
                            this.state = BodyState::Done;
                            this.discard();
                            return Poll::Ready(Some(Err(err)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                BodyState::CloseDelimited => {
                    if !this.buf.is_empty() {
                        let take = this.buf.len().min(READ_BUF_SIZE);
                        return Poll::Ready(Some(Ok(Frame::data(
                            this.buf.split_to(take).freeze(),
                        ))));
                    }
                    match poll_read_with_timeout(this, cx) {
                        Poll::Ready(Ok(0)) => {
                            this.state = BodyState::Done;
                            this.discard();
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Ok(_)) => {}
                        Poll::Ready(Err(err)) => {
                            this.state = BodyState::Done;
                            this.discard();
                            return Poll::Ready(Some(Err(err)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                BodyState::Chunked {
                    state,
                    total_body_bytes,
                } => match state {
                    ChunkState::Size => {
                        if let Some(idx) = find_crlf(&this.buf) {
                            let mut line = this.buf.split_to(idx + 2);
                            line.truncate(idx);
                            let size = parse_chunk_size(&line)?;
                            *total_body_bytes =
                                total_body_bytes.checked_add(size as u64).ok_or_else(|| {
                                    Self::body_error("chunked response body size overflow")
                                })?;
                            if *total_body_bytes > MAX_CHUNKED_BODY_BYTES {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(Self::body_error(format!(
                                    "chunked response body exceeds hard cap of {} bytes",
                                    MAX_CHUNKED_BODY_BYTES
                                )))));
                            }
                            *state = if size == 0 {
                                ChunkState::Trailers
                            } else {
                                ChunkState::Data { remaining: size }
                            };
                            continue;
                        }
                        if this.buf.len() >= MAX_HEADER_BYTES {
                            this.state = BodyState::Done;
                            this.discard();
                            return Poll::Ready(Some(Err(Self::body_error(
                                "HTTP/1 chunk-size line exceeded configured limit",
                            ))));
                        }
                        match poll_read_with_timeout(this, cx) {
                            Poll::Ready(Ok(0)) => {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(Self::body_error(
                                    "upstream connection closed before chunk-size line completed",
                                ))));
                            }
                            Poll::Ready(Ok(_)) => {}
                            Poll::Ready(Err(err)) => {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(err)));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    ChunkState::Data { remaining } => {
                        if *remaining == 0 {
                            *state = ChunkState::CrLf;
                            continue;
                        }
                        if !this.buf.is_empty() {
                            let take = this.buf.len().min(*remaining).min(READ_BUF_SIZE);
                            *remaining -= take;
                            return Poll::Ready(Some(Ok(Frame::data(
                                this.buf.split_to(take).freeze(),
                            ))));
                        }
                        match poll_read_with_timeout(this, cx) {
                            Poll::Ready(Ok(0)) => {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(Self::body_error(
                                    "peer connection closed before chunk payload completed",
                                ))));
                            }
                            Poll::Ready(Ok(_)) => {}
                            Poll::Ready(Err(err)) => {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(err)));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    ChunkState::CrLf => {
                        if this.buf.len() >= 2 {
                            if &this.buf[..2] != b"\r\n" {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(Self::body_error(
                                    "chunk payload missing trailing CRLF",
                                ))));
                            }
                            this.buf.advance(2);
                            *state = ChunkState::Size;
                            continue;
                        }
                        match poll_read_with_timeout(this, cx) {
                            Poll::Ready(Ok(0)) => {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(Self::body_error(
                                    "upstream connection closed before chunk CRLF completed",
                                ))));
                            }
                            Poll::Ready(Ok(_)) => {}
                            Poll::Ready(Err(err)) => {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(err)));
                            }
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    ChunkState::Trailers => {
                        let mut headers = [httparse::EMPTY_HEADER; 128];
                        match httparse::parse_headers(this.buf.as_ref(), &mut headers) {
                            Ok(httparse::Status::Complete((consumed, parsed))) => {
                                let trailers = if parsed.is_empty() {
                                    None
                                } else {
                                    match parse_header_map(parsed) {
                                        Ok(headers) => Some(headers),
                                        Err(err) => {
                                            this.state = BodyState::Done;
                                            this.discard();
                                            return Poll::Ready(Some(Err(Self::body_error(
                                                err.to_string(),
                                            ))));
                                        }
                                    }
                                };
                                this.buf.advance(consumed);
                                this.state = BodyState::Done;
                                this.finish();
                                if let Some(trailers) = trailers {
                                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                                }
                                return Poll::Ready(None);
                            }
                            Ok(httparse::Status::Partial) => {
                                if this.buf.len() >= MAX_HEADER_BYTES {
                                    this.state = BodyState::Done;
                                    this.discard();
                                    return Poll::Ready(Some(Err(Self::body_error(
                                        "HTTP/1 trailer block exceeded configured limit",
                                    ))));
                                }
                                match poll_read_with_timeout(this, cx) {
                                    Poll::Ready(Ok(0)) => {
                                        this.state = BodyState::Done;
                                        this.discard();
                                        return Poll::Ready(Some(Err(Self::body_error(
                                            "upstream connection closed before trailers completed",
                                        ))));
                                    }
                                    Poll::Ready(Ok(_)) => {}
                                    Poll::Ready(Err(err)) => {
                                        this.state = BodyState::Done;
                                        this.discard();
                                        return Poll::Ready(Some(Err(err)));
                                    }
                                    Poll::Pending => return Poll::Pending,
                                }
                            }
                            Err(err) => {
                                this.state = BodyState::Done;
                                this.discard();
                                return Poll::Ready(Some(Err(Self::body_error(err.to_string()))));
                            }
                        }
                    }
                },
                BodyState::Done => return Poll::Ready(None),
            }
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = http_body::SizeHint::new();
        if let BodyState::ContentLength { remaining } = self.state {
            hint.set_exact(remaining);
        }
        hint
    }
}

fn poll_read_with_timeout<S>(
    body: &mut Http1ResponseBody<S>,
    cx: &mut Context<'_>,
) -> Poll<Result<usize, BodyError>>
where
    S: AsyncRead + Unpin,
{
    let Some(stream) = body.stream.as_mut() else {
        return Poll::Ready(Ok(0));
    };
    if body.read_timer.is_none() {
        body.read_timer = Some(Box::pin(tokio::time::sleep(body.read_timeout)));
    }
    body.buf.reserve(READ_BUF_SIZE);
    match tokio_util::io::poll_read_buf(Pin::new(stream), cx, &mut body.buf) {
        Poll::Ready(Ok(n)) => {
            body.read_timer = None;
            Poll::Ready(Ok(n))
        }
        Poll::Ready(Err(err)) => {
            body.read_timer = None;
            Poll::Ready(Err(BodyError::new(err.to_string())))
        }
        Poll::Pending => {
            if let Some(timer) = body.read_timer.as_mut()
                && timer.as_mut().poll(cx).is_ready()
            {
                body.read_timer = None;
                return Poll::Ready(Err(BodyError::new(
                    "raw HTTP/1 upstream body read timed out",
                )));
            }
            Poll::Pending
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, BodyError> {
    let size_token = line
        .split(|b| *b == b';')
        .next()
        .ok_or_else(|| BodyError::new("invalid chunk-size line"))?;
    let size_str = std::str::from_utf8(size_token)
        .map_err(|err| BodyError::new(err.to_string()))?
        .trim();
    usize::from_str_radix(size_str, 16)
        .map_err(|_| BodyError::new(format!("invalid chunk-size: {size_str}")))
}
