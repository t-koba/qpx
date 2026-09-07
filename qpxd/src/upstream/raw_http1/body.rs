use super::response::ResponseBodyKind;
use super::{
    Http1ConnectionRecycler, INITIAL_READ_BUF_SIZE, MAX_CHUNKED_BODY_BYTES,
    MAX_EMITTED_BODY_FRAME_SIZE, MAX_HEADER_BYTES, RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
};
use crate::http::codec::h1_common::{find_crlf, parse_header_map};
use bytes::{Buf, BufMut, Bytes, BytesMut};
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
    write_buf: BytesMut,
    state: BodyState,
    recycler: Option<Http1ConnectionRecycler<S>>,
    max_frame_size: usize,
    read_timeout: Duration,
    read_timer: Option<Pin<Box<Sleep>>>,
    read_timer_armed: bool,
}

impl<S> Http1ResponseBody<S> {
    pub(super) fn new(
        stream: S,
        prefix: BytesMut,
        kind: ResponseBodyKind,
        write_buf: BytesMut,
        recycler: Option<Http1ConnectionRecycler<S>>,
    ) -> Self {
        Self::new_with_max_frame_size(
            stream,
            prefix,
            kind,
            write_buf,
            recycler,
            MAX_EMITTED_BODY_FRAME_SIZE,
        )
    }

    pub(super) fn new_with_max_frame_size(
        stream: S,
        prefix: BytesMut,
        kind: ResponseBodyKind,
        write_buf: BytesMut,
        recycler: Option<Http1ConnectionRecycler<S>>,
        max_frame_size: usize,
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
            write_buf,
            state,
            recycler,
            max_frame_size: max_frame_size.max(1),
            read_timeout: RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
            read_timer: None,
            read_timer_armed: false,
        }
    }

    fn finish(&mut self) {
        let Some(stream) = self.stream.take() else {
            return;
        };
        if self.buf.is_empty()
            && let Some(recycler) = self.recycler.take()
        {
            recycler.recycle(
                stream,
                std::mem::take(&mut self.buf),
                std::mem::take(&mut self.write_buf),
            );
        }
    }

    fn discard(&mut self) {
        self.stream.take();
        self.recycler.take();
    }

    fn is_complete(&self) -> bool {
        self.buf.is_empty()
            && matches!(
                self.state,
                BodyState::Done | BodyState::ContentLength { remaining: 0 }
            )
    }

    fn body_error(message: impl Into<String>) -> BodyError {
        BodyError::new(message)
    }
}

impl<S> Drop for Http1ResponseBody<S> {
    fn drop(&mut self) {
        if self.is_complete() {
            self.finish();
        } else {
            self.discard();
        }
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
                        let take = this
                            .buf
                            .len()
                            .min(*remaining as usize)
                            .min(this.max_frame_size);
                        *remaining -= take as u64;
                        return Poll::Ready(Some(Ok(Frame::data(
                            this.buf.split_to(take).freeze(),
                        ))));
                    }
                    // Bounded read-ahead keeps unexpected bytes from entering the reusable pool.
                    let read_size = (*remaining)
                        .clamp(INITIAL_READ_BUF_SIZE as u64, this.max_frame_size as u64)
                        as usize;
                    match poll_read_with_timeout(this, cx, read_size) {
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
                        let take = this.buf.len().min(this.max_frame_size);
                        return Poll::Ready(Some(Ok(Frame::data(
                            this.buf.split_to(take).freeze(),
                        ))));
                    }
                    match poll_read_with_timeout(this, cx, this.max_frame_size) {
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
                        match poll_read_with_timeout(this, cx, INITIAL_READ_BUF_SIZE) {
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
                            let take = this.buf.len().min(*remaining).min(this.max_frame_size);
                            *remaining -= take;
                            return Poll::Ready(Some(Ok(Frame::data(
                                this.buf.split_to(take).freeze(),
                            ))));
                        }
                        let read_size = (*remaining).min(this.max_frame_size);
                        match poll_read_with_timeout(this, cx, read_size) {
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
                        let read_size = 2usize.saturating_sub(this.buf.len()).max(1);
                        match poll_read_with_timeout(this, cx, read_size) {
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
                                if let Some(mut trailers) = trailers {
                                    let removed =
                                        qpx_http::protocol::semantics::sanitize_response_trailers(
                                            &mut trailers,
                                        );
                                    if removed > 0 {
                                        tracing::warn!(
                                            removed,
                                            "dropping forbidden upstream response trailers"
                                        );
                                    }
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
                                match poll_read_with_timeout(this, cx, INITIAL_READ_BUF_SIZE) {
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

    fn is_end_stream(&self) -> bool {
        self.is_complete()
    }
}

fn poll_read_with_timeout<S>(
    body: &mut Http1ResponseBody<S>,
    cx: &mut Context<'_>,
    read_size: usize,
) -> Poll<Result<usize, BodyError>>
where
    S: AsyncRead + Unpin,
{
    let Some(stream) = body.stream.as_mut() else {
        return Poll::Ready(Ok(0));
    };
    let read_size = read_size.max(1);
    if body.buf.capacity().saturating_sub(body.buf.len()) < read_size {
        body.buf.reserve(read_size);
    }
    let mut limited = (&mut body.buf).limit(read_size);
    match tokio_util::io::poll_read_buf(Pin::new(stream), cx, &mut limited) {
        Poll::Ready(Ok(n)) => {
            body.read_timer_armed = false;
            Poll::Ready(Ok(n))
        }
        Poll::Ready(Err(err)) => {
            body.read_timer_armed = false;
            Poll::Ready(Err(BodyError::new(err.to_string())))
        }
        Poll::Pending => {
            if !body.read_timer_armed {
                let deadline = tokio::time::Instant::now() + body.read_timeout;
                if let Some(timer) = body.read_timer.as_mut() {
                    timer.as_mut().reset(deadline);
                } else {
                    body.read_timer = Some(Box::pin(tokio::time::sleep_until(deadline)));
                }
                body.read_timer_armed = true;
            }
            if let Some(timer) = body.read_timer.as_mut()
                && timer.as_mut().poll(cx).is_ready()
            {
                body.read_timer_armed = false;
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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body::Body as _;
    use http_body_util::BodyExt as _;
    use std::future::poll_fn;
    use tokio::io::AsyncWriteExt as _;

    #[tokio::test]
    async fn immediately_ready_body_read_does_not_allocate_timeout_timer() {
        let (mut upstream, proxy) = tokio::io::duplex(64);
        upstream.write_all(b"body").await.expect("write body");
        let mut body = Http1ResponseBody::new(
            proxy,
            BytesMut::new(),
            ResponseBodyKind::ContentLength(4),
            BytesMut::new(),
            None,
        );

        let frame = body
            .frame()
            .await
            .expect("body frame")
            .expect("read body frame");

        assert_eq!(frame.into_data().expect("data frame"), b"body"[..]);
        assert!(body.read_timer.is_none());
        assert!(!body.read_timer_armed);
    }

    #[tokio::test]
    async fn buffered_body_is_emitted_in_fair_bounded_frames() {
        let (_upstream, proxy) = tokio::io::duplex(64);
        let body_bytes = MAX_EMITTED_BODY_FRAME_SIZE * 2 + 7;
        let mut body = Http1ResponseBody::new(
            proxy,
            BytesMut::from(vec![b'x'; body_bytes].as_slice()),
            ResponseBodyKind::ContentLength(body_bytes as u64),
            BytesMut::new(),
            None,
        );

        for expected in [MAX_EMITTED_BODY_FRAME_SIZE, MAX_EMITTED_BODY_FRAME_SIZE, 7] {
            let frame = body
                .frame()
                .await
                .expect("body frame")
                .expect("valid body frame")
                .into_data()
                .expect("data frame");
            assert_eq!(frame.len(), expected);
        }
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn transport_frame_limit_caps_each_upstream_read() {
        const FRAME_LIMIT: usize = 4096;
        let body_bytes = FRAME_LIMIT * 3;
        let (mut upstream, proxy) = tokio::io::duplex(body_bytes * 2);
        upstream
            .write_all(&vec![b'x'; body_bytes])
            .await
            .expect("write body");
        let mut prefix = BytesMut::with_capacity(body_bytes * 2);
        prefix.clear();
        let mut body = Http1ResponseBody::new_with_max_frame_size(
            proxy,
            prefix,
            ResponseBodyKind::ContentLength(body_bytes as u64),
            BytesMut::new(),
            None,
            FRAME_LIMIT,
        );

        for _ in 0..3 {
            let frame = body
                .frame()
                .await
                .expect("body frame")
                .expect("valid body frame")
                .into_data()
                .expect("data frame");
            assert_eq!(frame.len(), FRAME_LIMIT);
        }
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn pending_body_read_arms_timeout_timer() {
        let (_upstream, proxy) = tokio::io::duplex(64);
        let mut body = Http1ResponseBody::new(
            proxy,
            BytesMut::new(),
            ResponseBodyKind::ContentLength(4),
            BytesMut::new(),
            None,
        );

        poll_fn(|cx| {
            assert!(Pin::new(&mut body).poll_frame(cx).is_pending());
            assert!(body.read_timer.is_some());
            assert!(body.read_timer_armed);
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn body_read_reuses_timeout_timer_across_pending_reads() {
        let (mut upstream, proxy) = tokio::io::duplex(64);
        let mut body = Http1ResponseBody::new(
            proxy,
            BytesMut::new(),
            ResponseBodyKind::ContentLength(8),
            BytesMut::new(),
            None,
        );

        poll_fn(|cx| {
            assert!(Pin::new(&mut body).poll_frame(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        upstream.write_all(b"body").await.expect("write body");

        let frame = body
            .frame()
            .await
            .expect("body frame")
            .expect("read body frame");

        assert_eq!(frame.into_data().expect("data frame"), b"body"[..]);
        assert!(body.read_timer.is_some());
        assert!(!body.read_timer_armed);
        poll_fn(|cx| {
            assert!(Pin::new(&mut body).poll_frame(cx).is_pending());
            assert!(body.read_timer.is_some());
            assert!(body.read_timer_armed);
            Poll::Ready(())
        })
        .await;
    }
}
