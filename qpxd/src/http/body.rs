use bytes::Bytes;
use http::HeaderMap;
use http_body::Frame;
use http_body_util::channel::{Channel, SendError as ChannelSendError, Sender as ChannelSender};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty};
use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use tokio::time::{sleep, Duration};

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
    close_flag: Option<Arc<AtomicBool>>,
    pending_trailers: Option<HeaderMap>,
    stream_finished: bool,
}

impl Body {
    pub fn empty() -> Self {
        Self {
            inner: Empty::<Bytes>::new()
                .map_err(|err| match err {})
                .boxed_unsync(),
            close_flag: None,
            pending_trailers: None,
            stream_finished: true,
        }
    }

    pub fn channel() -> (Sender, Self) {
        let (sender, body) = Channel::<Bytes, BodyError>::new(16);
        let close_flag = Arc::new(AtomicBool::new(false));
        (
            Sender {
                inner: Some(sender),
                close_flag: close_flag.clone(),
            },
            Self {
                inner: body.boxed_unsync(),
                close_flag: Some(close_flag),
                pending_trailers: None,
                stream_finished: false,
            },
        )
    }

    pub fn replay(bytes: Bytes, trailers: Option<HeaderMap>) -> Self {
        Self {
            inner: ReplayBody::new(bytes, trailers).boxed_unsync(),
            close_flag: None,
            pending_trailers: None,
            stream_finished: false,
        }
    }

    pub fn replay_chunks(chunks: Vec<Bytes>, trailers: Option<HeaderMap>) -> Self {
        Self {
            inner: ChunkReplayBody::new(chunks, trailers).boxed_unsync(),
            close_flag: None,
            pending_trailers: None,
            stream_finished: false,
        }
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
            close_flag: None,
            pending_trailers: None,
            stream_finished: false,
        }
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        if let Some(flag) = &self.close_flag {
            flag.store(true, Ordering::Release);
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
    close_flag: Arc<AtomicBool>,
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

impl Sender {
    pub async fn send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        match self.inner.as_mut() {
            Some(inner) => inner.send_data(data).await.map_err(BodyError::from),
            None => Err(BodyError::new("body sender closed")),
        }
    }

    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), BodyError> {
        match self.inner.as_mut() {
            Some(inner) => inner.send_trailers(trailers).await.map_err(BodyError::from),
            None => Err(BodyError::new("body sender closed")),
        }
    }

    pub fn abort(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.abort(BodyError::aborted());
        }
    }

    pub fn is_closed(&self) -> bool {
        self.close_flag.load(Ordering::Acquire)
    }

    pub async fn closed(&self) {
        while !self.is_closed() {
            sleep(Duration::from_millis(100)).await;
        }
    }
}

pub async fn to_bytes<B>(body: B) -> Result<Bytes, BodyError>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<BodyError>,
{
    Ok(body.collect().await.map_err(Into::into)?.to_bytes())
}

pub async fn to_bytes_limited<B>(mut body: B, max_bytes: usize) -> Result<Bytes, BodyError>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BodyError>,
{
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(Into::into)?;
        if let Ok(data) = frame.into_data() {
            let next = out
                .len()
                .checked_add(data.len())
                .ok_or_else(|| BodyError::new("body size overflow"))?;
            if next > max_bytes {
                return Err(BodyError::new(format!(
                    "body exceeds hard cap of {} bytes",
                    max_bytes
                )));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
