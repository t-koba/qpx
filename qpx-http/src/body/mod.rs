pub mod metrics;
pub mod tee;

use bytes::Bytes;
use http::HeaderMap;
use http_body::Frame;
use http_body_util::channel::{Channel, SendError as ChannelSendError, Sender as ChannelSender};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty};
use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyError {
    message: std::sync::Arc<str>,
}

impl BodyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: std::sync::Arc::<str>::from(message.into()),
        }
    }

    pub fn aborted() -> Self {
        Self::new("body aborted")
    }
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BodyError {}

impl From<hyper::Error> for BodyError {
    fn from(value: hyper::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<hyper_util::client::legacy::Error> for BodyError {
    fn from(value: hyper_util::client::legacy::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<ChannelSendError> for BodyError {
    fn from(value: ChannelSendError) -> Self {
        Self::new(value.to_string())
    }
}

#[derive(Debug)]
pub struct Body {
    inner: UnsyncBoxBody<Bytes, BodyError>,
    close_signal: Option<Arc<BodyCloseSignal>>,
    pending_trailers: Option<HeaderMap>,
    stream_finished: bool,
}

#[derive(Debug)]
struct BodyCloseSignal {
    token: CancellationToken,
}

impl Body {
    pub fn empty() -> Self {
        Self {
            inner: Empty::<Bytes>::new()
                .map_err(|err| match err {})
                .boxed_unsync(),
            close_signal: None,
            pending_trailers: None,
            stream_finished: true,
        }
    }

    pub fn channel() -> (Sender, Self) {
        Self::channel_with_capacity(16)
    }

    pub fn channel_with_capacity(capacity: usize) -> (Sender, Self) {
        let (sender, body) = Channel::<Bytes, BodyError>::new(capacity);
        let close_signal = Arc::new(BodyCloseSignal {
            token: CancellationToken::new(),
        });
        (
            Sender {
                inner: Some(sender),
                close_signal: close_signal.clone(),
            },
            Self {
                inner: body.boxed_unsync(),
                close_signal: Some(close_signal),
                pending_trailers: None,
                stream_finished: false,
            },
        )
    }

    pub fn replay(bytes: Bytes, trailers: Option<HeaderMap>) -> Self {
        Self {
            inner: ReplayBody::new(bytes, trailers).boxed_unsync(),
            close_signal: None,
            pending_trailers: None,
            stream_finished: false,
        }
    }

    pub fn replay_chunks(chunks: Vec<Bytes>, trailers: Option<HeaderMap>) -> Self {
        Self {
            inner: ChunkReplayBody::new(chunks, trailers).boxed_unsync(),
            close_signal: None,
            pending_trailers: None,
            stream_finished: false,
        }
    }

    pub fn wrap<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes, Error = BodyError> + Send + 'static,
    {
        Self {
            inner: body.boxed_unsync(),
            close_signal: None,
            pending_trailers: None,
            stream_finished: false,
        }
    }

    pub fn limit_bytes(self, max_bytes: usize) -> Self {
        if max_bytes == usize::MAX {
            return self;
        }
        Self::wrap(LimitedBody {
            inner: self,
            max_bytes,
            seen: 0,
            exceeded: false,
        })
    }

    pub async fn data(&mut self) -> Option<Result<Bytes, BodyError>> {
        if self.pending_trailers.is_some() || self.stream_finished {
            return None;
        }
        loop {
            match self.inner.frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => return Some(Ok(data)),
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            self.pending_trailers = Some(trailers);
                            self.stream_finished = true;
                            return None;
                        }
                    }
                },
                Some(Err(err)) => return Some(Err(err)),
                None => {
                    self.stream_finished = true;
                    return None;
                }
            }
        }
    }

    pub async fn trailers(&mut self) -> Result<Option<HeaderMap>, BodyError> {
        if self.pending_trailers.is_some() {
            return Ok(self.pending_trailers.take());
        }
        if self.stream_finished {
            return Ok(None);
        }
        loop {
            match self.inner.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        self.stream_finished = true;
                        return Ok(Some(trailers));
                    }
                }
                Some(Err(err)) => return Err(err),
                None => {
                    self.stream_finished = true;
                    return Ok(None);
                }
            }
        }
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<Bytes> for Body {
    fn from(value: Bytes) -> Self {
        Self::replay(value, None)
    }
}

impl From<Vec<u8>> for Body {
    fn from(value: Vec<u8>) -> Self {
        Self::from(Bytes::from(value))
    }
}

impl From<String> for Body {
    fn from(value: String) -> Self {
        Self::from(Bytes::from(value))
    }
}

impl From<&'static str> for Body {
    fn from(value: &'static str) -> Self {
        Self::from(Bytes::from_static(value.as_bytes()))
    }
}

impl From<&'static [u8]> for Body {
    fn from(value: &'static [u8]) -> Self {
        Self::from(Bytes::from_static(value))
    }
}

impl From<hyper::body::Incoming> for Body {
    fn from(value: hyper::body::Incoming) -> Self {
        Self {
            inner: value.map_err(BodyError::from).boxed_unsync(),
            close_signal: None,
            pending_trailers: None,
            stream_finished: false,
        }
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        if let Some(signal) = &self.close_signal {
            signal.token.cancel();
        }
    }
}

impl http_body::Body for Body {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(trailers) = self.pending_trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        if self.stream_finished {
            return Poll::Ready(None);
        }
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        match &poll {
            Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => {
                self.stream_finished = true;
            }
            Poll::Ready(None) => {
                self.stream_finished = true;
            }
            _ => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.pending_trailers.is_none() && (self.stream_finished || self.inner.is_end_stream())
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Debug)]
pub struct Sender {
    inner: Option<ChannelSender<Bytes, BodyError>>,
    close_signal: Arc<BodyCloseSignal>,
}

#[derive(Debug)]
struct ReplayBody {
    bytes: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

#[derive(Debug)]
struct ChunkReplayBody {
    chunks: VecDeque<Bytes>,
    trailers: Option<HeaderMap>,
    remaining_len: u64,
}

#[derive(Debug)]
struct LimitedBody {
    inner: Body,
    max_bytes: usize,
    seen: usize,
    exceeded: bool,
}

impl ReplayBody {
    fn new(bytes: Bytes, trailers: Option<HeaderMap>) -> Self {
        Self {
            bytes: (!bytes.is_empty()).then_some(bytes),
            trailers,
        }
    }
}

impl http_body::Body for ReplayBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(bytes) = self.bytes.take() {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if let Some(trailers) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.bytes.is_none() && self.trailers.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = http_body::SizeHint::new();
        let size = self
            .bytes
            .as_ref()
            .map(|bytes| bytes.len() as u64)
            .unwrap_or(0);
        hint.set_exact(size);
        hint
    }
}

impl ChunkReplayBody {
    fn new(chunks: Vec<Bytes>, trailers: Option<HeaderMap>) -> Self {
        let remaining_len = chunks.iter().map(|chunk| chunk.len() as u64).sum();
        Self {
            chunks: chunks
                .into_iter()
                .filter(|chunk| !chunk.is_empty())
                .collect(),
            trailers,
            remaining_len,
        }
    }
}

impl http_body::Body for ChunkReplayBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(bytes) = self.chunks.pop_front() {
            self.remaining_len = self.remaining_len.saturating_sub(bytes.len() as u64);
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if let Some(trailers) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty() && self.trailers.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = http_body::SizeHint::new();
        hint.set_exact(self.remaining_len);
        hint
    }
}

impl http_body::Body for LimitedBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.exceeded {
            return Poll::Ready(None);
        }
        let frame = match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => frame,
            other => return other,
        };
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => return Poll::Ready(Some(Ok(frame))),
        };
        let next = match self.seen.checked_add(data.len()) {
            Some(next) => next,
            None => {
                self.exceeded = true;
                return Poll::Ready(Some(Err(BodyError::new("response body limit exceeded"))));
            }
        };
        if next > self.max_bytes {
            self.exceeded = true;
            return Poll::Ready(Some(Err(BodyError::new("response body limit exceeded"))));
        }
        self.seen = next;
        Poll::Ready(Some(Ok(Frame::data(data))))
    }

    fn is_end_stream(&self) -> bool {
        self.exceeded || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = self.inner.size_hint();
        if let Some(upper) = hint.upper()
            && upper > self.max_bytes as u64
        {
            hint = http_body::SizeHint::new();
        }
        hint
    }
}

impl Sender {
    pub async fn send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        match self.inner.as_mut() {
            Some(inner) => inner.send_data(data).await.map_err(BodyError::from),
            None => Err(BodyError::new("body sender closed")),
        }
    }

    pub fn try_send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        match self.inner.as_mut() {
            Some(inner) => inner
                .try_send(Frame::data(data))
                .map_err(|_| BodyError::new("body channel is full")),
            None => Err(BodyError::new("body sender closed")),
        }
    }

    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), BodyError> {
        match self.inner.as_mut() {
            Some(inner) => inner.send_trailers(trailers).await.map_err(BodyError::from),
            None => Err(BodyError::new("body sender closed")),
        }
    }

    pub fn try_send_trailers(&mut self, trailers: HeaderMap) -> Result<(), BodyError> {
        match self.inner.as_mut() {
            Some(inner) => inner
                .try_send(Frame::trailers(trailers))
                .map_err(|_| BodyError::new("body channel is full")),
            None => Err(BodyError::new("body sender closed")),
        }
    }

    pub fn abort(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.abort(BodyError::aborted());
        }
    }

    pub fn is_closed(&self) -> bool {
        self.close_signal.token.is_cancelled()
    }

    pub async fn closed(&self) {
        self.close_signal.token.cancelled().await;
    }
}

pub async fn to_bytes<B>(body: B) -> Result<Bytes, BodyError>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BodyError>,
{
    Ok(body.collect().await.map_err(Into::into)?.to_bytes())
}

#[cfg(test)]
mod tests {
    use crate::body::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn trailers_after_channel_body_end_returns_none_without_panicking() {
        let (mut sender, mut body) = Body::channel();
        sender
            .send_data(Bytes::from_static(b"ok"))
            .await
            .expect("send data");
        drop(sender);

        assert_eq!(
            body.data().await.expect("chunk").expect("chunk bytes"),
            Bytes::from_static(b"ok")
        );
        assert!(body.data().await.is_none());
        assert!(body.trailers().await.expect("trailers").is_none());
        assert!(body.trailers().await.expect("trailers again").is_none());
    }

    #[tokio::test]
    async fn limit_bytes_allows_body_at_limit() {
        let mut body = Body::from(Bytes::from_static(b"abcd")).limit_bytes(4);

        assert_eq!(
            body.data().await.expect("chunk").expect("chunk bytes"),
            Bytes::from_static(b"abcd")
        );
        assert!(body.data().await.is_none());
    }

    #[tokio::test]
    async fn limit_bytes_errors_when_body_exceeds_limit() {
        let mut body = Body::from(Bytes::from_static(b"abcde")).limit_bytes(4);

        let err = body
            .data()
            .await
            .expect("limit error")
            .expect_err("body should exceed limit");
        assert!(err.to_string().contains("response body limit exceeded"));
        assert!(body.data().await.is_none());
    }

    #[tokio::test]
    async fn sender_closed_uses_drop_notification_without_polling_delay() {
        let (sender, body) = Body::channel_with_capacity(4);
        let started = std::time::Instant::now();
        drop(body);

        tokio::time::timeout(std::time::Duration::from_millis(20), sender.closed())
            .await
            .expect("closed notification");
        assert!(started.elapsed() < std::time::Duration::from_millis(50));
    }

    #[tokio::test]
    async fn sender_closed_after_body_already_dropped() {
        let (sender, body) = Body::channel_with_capacity(4);
        drop(body);

        timeout(Duration::from_millis(50), sender.closed())
            .await
            .expect("closed notification after drop");
        assert!(sender.is_closed());
    }

    #[tokio::test]
    async fn sender_closed_while_waiting() {
        let (sender, body) = Body::channel_with_capacity(4);
        let waiter = tokio::spawn(async move {
            timeout(Duration::from_millis(100), sender.closed())
                .await
                .expect("closed waiter woke");
        });

        tokio::task::yield_now().await;
        drop(body);
        waiter.await.expect("waiter task");
    }

    #[tokio::test]
    async fn sender_closed_no_missed_notification_under_concurrency() {
        for _ in 0..256 {
            let (sender, body) = Body::channel_with_capacity(1);
            let waiter = tokio::spawn(async move {
                timeout(Duration::from_millis(100), sender.closed())
                    .await
                    .expect("closed notification was not missed");
            });
            tokio::spawn(async move {
                tokio::task::yield_now().await;
                drop(body);
            });
            waiter.await.expect("waiter task");
        }
    }

    #[tokio::test]
    async fn sender_closed_during_concurrent_send() {
        let (mut sender, body) = Body::channel_with_capacity(1);
        sender
            .send_data(Bytes::from_static(b"first"))
            .await
            .expect("first chunk");

        let send_task =
            tokio::spawn(async move { sender.send_data(Bytes::from_static(b"second")).await });
        tokio::task::yield_now().await;
        drop(body);

        timeout(Duration::from_millis(100), send_task)
            .await
            .expect("send task woke")
            .expect("send task")
            .expect_err("send should fail after receiver drop");
    }

    #[tokio::test]
    async fn client_cancel_stops_body_relay() {
        let (sender, body) = Body::channel_with_capacity(1);
        let relayed = Arc::new(AtomicUsize::new(0));
        let relayed_for_task = relayed.clone();

        let relay = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sender.closed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {
                        relayed_for_task.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });

        drop(body);
        timeout(Duration::from_millis(100), relay)
            .await
            .expect("relay stopped")
            .expect("relay task");
        assert_eq!(relayed.load(Ordering::Relaxed), 0);
    }
}
