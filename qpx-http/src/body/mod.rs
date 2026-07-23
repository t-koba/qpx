pub mod metrics;
pub mod tee;

use bytes::Bytes;
use http::HeaderMap;
use http_body::Frame;
use http_body_util::BodyExt as _;
use http_body_util::channel::{Channel, SendError as ChannelSendError, Sender as ChannelSender};
use http_body_util::combinators::UnsyncBoxBody;
use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
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

pub struct Body {
    inner: BodyInner,
    file_region: Option<FileRegion>,
    close_signal: Option<Arc<BodyCloseSignal>>,
    retained_resource: Option<RetainedResource>,
    pending_trailers: Option<Box<HeaderMap>>,
    stream_finished: bool,
    trailers_sanitized: bool,
    read_timeout_enforced: bool,
}

enum RetainedResource {
    Opaque {
        _resource: Box<dyn Send>,
    },
    Semaphore {
        _permit: tokio::sync::OwnedSemaphorePermit,
    },
}

impl fmt::Debug for Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Body")
            .field("inner", &self.inner)
            .field("file_region", &self.file_region)
            .field("close_signal", &self.close_signal)
            .field("retained_resource", &self.retained_resource.is_some())
            .field("pending_trailers", &self.pending_trailers)
            .field("stream_finished", &self.stream_finished)
            .field("trailers_sanitized", &self.trailers_sanitized)
            .field("read_timeout_enforced", &self.read_timeout_enforced)
            .finish()
    }
}

/// An immutable file extent that can be transferred directly to a compatible
/// transport while the regular body remains available as a portable fallback.
#[derive(Clone, Debug)]
pub struct FileRegion {
    file: Arc<File>,
    offset: u64,
    len: u64,
    portable_fallback: bool,
}

impl FileRegion {
    pub fn file(&self) -> &File {
        self.file.as_ref()
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns whether regular body frames remain available when a transport
    /// cannot consume this file extent directly.
    pub fn has_portable_fallback(&self) -> bool {
        self.portable_fallback
    }
}

#[derive(Debug)]
enum BodyInner {
    Empty,
    Once {
        bytes: Option<Bytes>,
        trailers: Option<Box<HeaderMap>>,
    },
    Chunks {
        chunks: VecDeque<Bytes>,
        trailers: Option<Box<HeaderMap>>,
        remaining_len: u64,
    },
    Boxed(UnsyncBoxBody<Bytes, BodyError>),
}

#[derive(Debug)]
struct BodyCloseSignal {
    token: CancellationToken,
}

impl Body {
    pub fn empty() -> Self {
        Self {
            inner: BodyInner::Empty,
            file_region: None,
            close_signal: None,
            retained_resource: None,
            pending_trailers: None,
            stream_finished: true,
            trailers_sanitized: false,
            read_timeout_enforced: false,
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
                inner: BodyInner::Boxed(body.boxed_unsync()),
                file_region: None,
                close_signal: Some(close_signal),
                retained_resource: None,
                pending_trailers: None,
                stream_finished: false,
                trailers_sanitized: false,
                read_timeout_enforced: false,
            },
        )
    }

    pub fn replay(bytes: Bytes, trailers: Option<HeaderMap>) -> Self {
        if bytes.is_empty() && trailers.is_none() {
            return Self::empty();
        }
        Self {
            inner: BodyInner::Once {
                bytes: (!bytes.is_empty()).then_some(bytes),
                trailers: trailers.map(Box::new),
            },
            file_region: None,
            close_signal: None,
            retained_resource: None,
            pending_trailers: None,
            stream_finished: false,
            trailers_sanitized: false,
            read_timeout_enforced: false,
        }
    }

    pub fn replay_chunks(chunks: Vec<Bytes>, trailers: Option<HeaderMap>) -> Self {
        let remaining_len = chunks.iter().map(|chunk| chunk.len() as u64).sum();
        let chunks = chunks
            .into_iter()
            .filter(|chunk| !chunk.is_empty())
            .collect::<VecDeque<_>>();
        if chunks.is_empty() && trailers.is_none() {
            return Self::empty();
        }
        Self {
            inner: BodyInner::Chunks {
                chunks,
                trailers: trailers.map(Box::new),
                remaining_len,
            },
            file_region: None,
            close_signal: None,
            retained_resource: None,
            pending_trailers: None,
            stream_finished: false,
            trailers_sanitized: false,
            read_timeout_enforced: false,
        }
    }

    pub fn wrap<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes, Error = BodyError> + Send + 'static,
    {
        Self {
            inner: BodyInner::Boxed(body.boxed_unsync()),
            file_region: None,
            close_signal: None,
            retained_resource: None,
            pending_trailers: None,
            stream_finished: false,
            trailers_sanitized: false,
            read_timeout_enforced: false,
        }
    }

    /// Marks that every trailer emitted by this body is already sanitized.
    pub fn mark_trailers_sanitized(mut self) -> Self {
        self.trailers_sanitized = true;
        self
    }

    /// Returns whether trailer sanitization is guaranteed by the body producer.
    pub fn trailers_are_sanitized(&self) -> bool {
        self.trailers_sanitized
    }

    /// Marks that the body producer enforces its own idle read timeout.
    pub fn mark_read_timeout_enforced(mut self) -> Self {
        self.read_timeout_enforced = true;
        self
    }

    /// Returns whether the body producer enforces its own idle read timeout.
    pub fn read_timeout_is_enforced(&self) -> bool {
        self.read_timeout_enforced
    }

    /// Retains a transport resource until this body is dropped.
    pub fn retain_resource<T>(&mut self, resource: T)
    where
        T: Send + 'static,
    {
        debug_assert!(self.retained_resource.is_none());
        self.retained_resource = Some(RetainedResource::Opaque {
            _resource: Box::new(resource),
        });
    }

    /// Retains a semaphore permit without allocating an opaque resource box.
    pub fn retain_semaphore_permit(&mut self, permit: tokio::sync::OwnedSemaphorePermit) {
        debug_assert!(self.retained_resource.is_none());
        self.retained_resource = Some(RetainedResource::Semaphore { _permit: permit });
    }

    /// Returns whether this body is fully materialized instead of streamed.
    pub fn is_materialized(&self) -> bool {
        !matches!(self.inner, BodyInner::Boxed(_))
    }

    /// Returns whether the body has a verified file extent reserved for zero-copy transport.
    pub fn has_file_region(&self) -> bool {
        self.file_region.is_some()
    }

    /// Takes an in-memory body represented by exactly one data frame and no trailers.
    ///
    /// Callers can use this to preserve a single-frame transport fast path without
    /// weakening validation for streamed or trailer-bearing bodies.
    pub fn take_single_frame_without_trailers(&mut self) -> Option<Bytes> {
        if self.close_signal.is_some() || self.pending_trailers.is_some() || self.stream_finished {
            return None;
        }
        let bytes = match &mut self.inner {
            BodyInner::Once { bytes, trailers } if trailers.is_none() => bytes.take(),
            BodyInner::Chunks {
                chunks,
                trailers,
                remaining_len,
            } if trailers.is_none() && chunks.len() == 1 => {
                let bytes = chunks.pop_front();
                *remaining_len = 0;
                bytes
            }
            BodyInner::Empty
            | BodyInner::Once { .. }
            | BodyInner::Chunks { .. }
            | BodyInner::Boxed(_) => None,
        }?;
        self.file_region = None;
        self.stream_finished = true;
        Some(bytes)
    }

    /// Associates a verified immutable file extent with this body. Transports
    /// that cannot use the extent continue to consume the regular body.
    pub fn with_file_region(mut self, file: Arc<File>, offset: u64, len: u64) -> Self {
        self.file_region = Some(FileRegion {
            file,
            offset,
            len,
            portable_fallback: true,
        });
        self
    }

    /// Associates a file extent with a body that is intentionally consumed only by
    /// a compatible zero-copy transport. The caller must route this body exclusively
    /// to a transport that takes the region before polling regular body frames.
    pub fn with_file_region_for_zero_copy(
        mut self,
        file: Arc<File>,
        offset: u64,
        len: u64,
    ) -> Self {
        self.file_region = Some(FileRegion {
            file,
            offset,
            len,
            portable_fallback: false,
        });
        if matches!(self.inner, BodyInner::Empty) {
            self.stream_finished = false;
        }
        self
    }

    /// Takes a file extent only when it exactly represents a single-frame body
    /// without trailers, consuming the fallback frame at the same time.
    pub fn take_file_region_without_trailers(&mut self) -> Option<FileRegion> {
        if self.close_signal.is_some() || self.pending_trailers.is_some() || self.stream_finished {
            return None;
        }
        let region = self.file_region.take()?;
        let bytes = match &mut self.inner {
            BodyInner::Once { bytes, trailers } if trailers.is_none() => bytes,
            BodyInner::Empty if !region.portable_fallback => {
                self.stream_finished = true;
                return Some(region);
            }
            BodyInner::Empty
            | BodyInner::Once { .. }
            | BodyInner::Chunks { .. }
            | BodyInner::Boxed(_) => return None,
        };
        if bytes.as_ref().map(Bytes::len) != usize::try_from(region.len).ok() {
            self.file_region = Some(region);
            return None;
        }
        let _ = bytes.take();
        self.stream_finished = true;
        Some(region)
    }

    pub fn limit_bytes(self, max_bytes: usize) -> Self {
        if max_bytes == usize::MAX || self.materialized_len_within(max_bytes) {
            return self;
        }
        let trailers_sanitized = self.trailers_sanitized;
        let mut body = Self::wrap(LimitedBody {
            inner: self,
            max_bytes,
            seen: 0,
            exceeded: false,
        });
        body.trailers_sanitized = trailers_sanitized;
        body
    }

    fn materialized_len_within(&self, max_bytes: usize) -> bool {
        match &self.inner {
            BodyInner::Empty => true,
            BodyInner::Once { bytes, .. } => bytes.as_ref().map_or(0, Bytes::len) <= max_bytes,
            BodyInner::Chunks { remaining_len, .. } => *remaining_len <= max_bytes as u64,
            BodyInner::Boxed(_) => false,
        }
    }

    pub async fn data(&mut self) -> Option<Result<Bytes, BodyError>> {
        self.file_region = None;
        if self.pending_trailers.is_some() || self.stream_finished {
            return None;
        }
        loop {
            match self.next_frame().await {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => return Some(Ok(data)),
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            self.pending_trailers = Some(Box::new(trailers));
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
        self.file_region = None;
        if self.pending_trailers.is_some() {
            return Ok(self.pending_trailers.take().map(|trailers| *trailers));
        }
        if self.stream_finished {
            return Ok(None);
        }
        loop {
            match self.next_frame().await {
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

    async fn next_frame(&mut self) -> Option<Result<Frame<Bytes>, BodyError>> {
        match &mut self.inner {
            BodyInner::Empty => None,
            BodyInner::Once { bytes, trailers } => {
                if let Some(bytes) = bytes.take() {
                    Some(Ok(Frame::data(bytes)))
                } else {
                    trailers
                        .take()
                        .map(|trailers| Ok(Frame::trailers(*trailers)))
                }
            }
            BodyInner::Chunks {
                chunks,
                trailers,
                remaining_len,
            } => {
                if let Some(bytes) = chunks.pop_front() {
                    *remaining_len = remaining_len.saturating_sub(bytes.len() as u64);
                    Some(Ok(Frame::data(bytes)))
                } else {
                    trailers
                        .take()
                        .map(|trailers| Ok(Frame::trailers(*trailers)))
                }
            }
            BodyInner::Boxed(inner) => inner.frame().await,
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
            inner: BodyInner::Boxed(value.map_err(BodyError::from).boxed_unsync()),
            file_region: None,
            close_signal: None,
            retained_resource: None,
            pending_trailers: None,
            stream_finished: false,
            trailers_sanitized: false,
            read_timeout_enforced: false,
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
        let this = self.as_mut().get_mut();
        this.file_region = None;
        if let Some(trailers) = this.pending_trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(*trailers))));
        }
        if this.stream_finished {
            return Poll::Ready(None);
        }
        let poll = match &mut this.inner {
            BodyInner::Empty => Poll::Ready(None),
            BodyInner::Once { bytes, trailers } => {
                if let Some(bytes) = bytes.take() {
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                } else {
                    Poll::Ready(
                        trailers
                            .take()
                            .map(|trailers| Ok(Frame::trailers(*trailers))),
                    )
                }
            }
            BodyInner::Chunks {
                chunks,
                trailers,
                remaining_len,
            } => {
                if let Some(bytes) = chunks.pop_front() {
                    *remaining_len = remaining_len.saturating_sub(bytes.len() as u64);
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                } else {
                    Poll::Ready(
                        trailers
                            .take()
                            .map(|trailers| Ok(Frame::trailers(*trailers))),
                    )
                }
            }
            BodyInner::Boxed(inner) => Pin::new(inner).poll_frame(cx),
        };
        match &poll {
            Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => {
                this.stream_finished = true;
            }
            Poll::Ready(None) => {
                this.stream_finished = true;
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

impl BodyInner {
    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Once { bytes, trailers } => bytes.is_none() && trailers.is_none(),
            Self::Chunks {
                chunks, trailers, ..
            } => chunks.is_empty() && trailers.is_none(),
            Self::Boxed(inner) => http_body::Body::is_end_stream(inner),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Empty => {
                let mut hint = http_body::SizeHint::new();
                hint.set_exact(0);
                hint
            }
            Self::Once { bytes, .. } => {
                let mut hint = http_body::SizeHint::new();
                let size = bytes.as_ref().map(|bytes| bytes.len() as u64).unwrap_or(0);
                hint.set_exact(size);
                hint
            }
            Self::Chunks { remaining_len, .. } => {
                let mut hint = http_body::SizeHint::new();
                hint.set_exact(*remaining_len);
                hint
            }
            Self::Boxed(inner) => http_body::Body::size_hint(inner),
        }
    }
}

#[derive(Debug)]
pub struct Sender {
    inner: Option<ChannelSender<Bytes, BodyError>>,
    close_signal: Arc<BodyCloseSignal>,
}

#[derive(Debug)]
struct LimitedBody {
    inner: Body,
    max_bytes: usize,
    seen: usize,
    exceeded: bool,
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
    use std::io::Write;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::time::{Duration, timeout};

    struct DropMarker(Arc<AtomicUsize>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn retained_resource_lives_until_streaming_body_is_dropped() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let (_sender, mut body) = Body::channel_with_capacity(1);
        body.retain_resource(DropMarker(dropped.clone()));

        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(body);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn read_timeout_enforcement_marker_is_explicit() {
        let body = Body::from("body");
        assert!(!body.read_timeout_is_enforced());
        assert!(body.mark_read_timeout_enforced().read_timeout_is_enforced());
    }

    #[test]
    fn byte_limit_preserves_trailer_sanitization_guarantee() {
        let body = Body::from("body").mark_trailers_sanitized().limit_bytes(16);
        assert!(body.trailers_are_sanitized());
    }

    #[test]
    fn single_frame_fast_path_only_takes_exact_trailerless_replay() {
        let mut body = Body::from(Bytes::from_static(b"body"));
        assert_eq!(
            body.take_single_frame_without_trailers(),
            Some(Bytes::from_static(b"body"))
        );
        assert!(http_body::Body::is_end_stream(&body));
        assert!(body.take_single_frame_without_trailers().is_none());

        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("valid"));
        let mut with_trailers = Body::replay(Bytes::from_static(b"body"), Some(trailers));
        assert!(with_trailers.take_single_frame_without_trailers().is_none());

        let (_sender, mut streamed) = Body::channel();
        assert!(streamed.take_single_frame_without_trailers().is_none());
    }

    #[tokio::test]
    async fn file_region_is_exact_and_portable_body_consumption_disables_it() {
        let path = std::env::temp_dir().join(format!(
            "qpx-body-region-{}-{}.body",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("create file");
        file.write_all(b"prefixpayload").expect("write file");
        file.flush().expect("flush file");
        let file = Arc::new(file);

        let mut direct = Body::from(Bytes::from_static(b"payload"))
            .with_file_region(file.clone(), 6, 7)
            .limit_bytes(7);
        let region = direct
            .take_file_region_without_trailers()
            .expect("file region");
        assert_eq!(region.offset(), 6);
        assert_eq!(region.len(), 7);
        assert!(region.has_portable_fallback());
        assert!(http_body::Body::is_end_stream(&direct));

        let mut portable = Body::from(Bytes::from_static(b"payload")).with_file_region(file, 6, 7);
        assert_eq!(
            portable.data().await.expect("data").expect("payload"),
            Bytes::from_static(b"payload")
        );
        assert!(portable.take_file_region_without_trailers().is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn zero_copy_only_file_region_can_replace_an_empty_fallback() {
        let file = Arc::new(
            std::fs::File::open(std::env::current_exe().expect("current executable"))
                .expect("open executable"),
        );
        let mut body = Body::empty().with_file_region_for_zero_copy(file, 0, 1);
        let region = body
            .take_file_region_without_trailers()
            .expect("zero-copy file region");
        assert_eq!(region.len(), 1);
        assert!(!region.has_portable_fallback());
        assert!(http_body::Body::is_end_stream(&body));
    }

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
