//! Module-owned streaming boundary. Only this private bridge handles transport frames.
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use qpx_http::body as transport;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A trailer collection with filtered application-metadata observation.
/// Generic metadata methods hide protocol-owned fields; parsed protocol
/// semantics are available through dedicated accessors. Debug hides values.
///
/// ```compile_fail
/// use qpxd::module_api::Trailers;
/// let trailers = Trailers::new();
/// let _ = trailers.get("x-metadata");
/// ```
/// ```compile_fail
/// use qpxd::module_api::Trailers;
/// let trailers = Trailers::new();
/// for entry in trailers { }
/// ```
/// ```compile_fail
/// use http::{HeaderName, HeaderValue};
/// use qpxd::module_api::Trailers;
/// let mut trailers = Trailers::new();
/// let _: Option<HeaderValue> = trailers.insert(
///     HeaderName::from_static("x-example"), HeaderValue::from_static("input"));
/// ```
/// ```compile_fail
/// use qpxd::module_api::Trailers;
/// let _: http::HeaderMap = Trailers::new().into();
/// ```
/// ```compile_fail
/// use qpxd::module_api::Trailers;
/// let _: http::HeaderMap = Trailers::new().metadata().into();
/// ```
/// ```compile_fail
/// use qpxd::module_api::Trailers;
/// for entry in Trailers::new().metadata() { }
/// ```
#[derive(Default, Clone)]
pub struct Trailers {
    inner: HeaderMap,
}

impl Trailers {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    pub(crate) fn from_header_map(inner: HeaderMap) -> Self {
        Self { inner }
    }

    /// Replaces all values for this name without returning the displaced values.
    pub fn insert(&mut self, name: HeaderName, value: HeaderValue) {
        self.inner.insert(name, value);
    }

    pub fn append(&mut self, name: HeaderName, value: HeaderValue) {
        self.inner.append(name, value);
    }

    /// Removes every value for this name without reporting whether one was
    /// present. Use `metadata()` before removal to inspect application fields.
    pub fn remove(&mut self, name: &HeaderName) {
        self.inner.remove(name);
    }

    /// Returns a filtered view of non-reserved application metadata. Exact
    /// value bytes and per-name duplicate order are preserved.
    pub fn metadata(&self) -> TrailerMetadata<'_> {
        TrailerMetadata { inner: &self.inner }
    }

    /// Checks for a non-reserved application metadata field by name.
    pub fn contains_key(&self, name: &HeaderName) -> bool {
        self.metadata().contains_key(name)
    }

    /// Returns the normalized gRPC status when present (`"invalid"` for an
    /// unparsable status value), without exposing the encoded field value.
    pub fn grpc_status(&self) -> Option<String> {
        crate::http::rpc::grpc_status_from_trailers(&self.inner)
    }

    /// Returns the percent-decoded gRPC message when present.
    pub fn grpc_message(&self) -> Option<String> {
        crate::http::rpc::grpc_message_from_trailers(&self.inner)
    }

    /// Decodes the reserved binary gRPC status-detail fields in per-name
    /// order. Each result is the underlying protobuf payload, not a raw
    /// `HeaderValue`; padded and unpadded standard base64 are accepted.
    pub fn grpc_status_details(
        &self,
    ) -> impl Iterator<Item = Result<Bytes, base64::DecodeError>> + '_ {
        crate::http::rpc::grpc_status_details_from_trailers(&self.inner)
    }

    /// Returns the normalized Connect status when present.
    pub fn connect_status(&self) -> Option<String> {
        crate::http::rpc::connect_status_from_trailers(&self.inner)
    }

    /// Returns the percent-decoded Connect message when present.
    pub fn connect_message(&self) -> Option<String> {
        crate::http::rpc::connect_message_from_trailers(&self.inner)
    }
}

/// Borrowed application metadata view. Protocol/framing-owned names are
/// filtered by the HTTP trailer policy and qpxd's RPC semantic owner.
///
/// `HeaderValue` bytes are returned unchanged. `get_all` preserves the
/// per-name value order supplied by `HeaderMap`; `iter` follows the underlying
/// map's iteration order while omitting reserved names.
#[derive(Clone, Copy)]
pub struct TrailerMetadata<'a> {
    inner: &'a HeaderMap,
}

impl TrailerMetadata<'_> {
    pub fn get(&self, name: &HeaderName) -> Option<&HeaderValue> {
        if is_reserved_trailer_name(name) {
            return None;
        }
        self.inner.get(name)
    }

    pub fn get_all(&self, name: &HeaderName) -> impl Iterator<Item = &HeaderValue> + '_ {
        let include = !is_reserved_trailer_name(name);
        self.inner.get_all(name).iter().filter(move |_| include)
    }

    pub fn contains_key(&self, name: &HeaderName) -> bool {
        self.get_all(name).next().is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> + '_ {
        self.inner
            .iter()
            .filter(|(name, _)| !is_reserved_trailer_name(name))
    }
}

impl fmt::Debug for TrailerMetadata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrailerMetadata { .. }")
    }
}

fn is_reserved_trailer_name(name: &HeaderName) -> bool {
    qpx_http::protocol::semantics::is_prohibited_trailer_name(name)
        || crate::http::rpc::is_reserved_rpc_trailer_name(name)
}

impl fmt::Debug for Trailers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Trailers { .. }")
    }
}

/// One ordered module body frame. Trailers remain opaque but forwardable.
#[derive(Debug)]
pub enum BodyFrame {
    Data(Bytes),
    Trailers(Trailers),
}

/// A module stream error, without access to its transport representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyError(transport::BodyError);

impl BodyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(transport::BodyError::new(message))
    }

    pub fn aborted() -> Self {
        Self(transport::BodyError::aborted())
    }
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for BodyError {}

/// An opaque streaming module body, deliberately not an `http_body::Body`.
/// Use [`Self::next_frame`] to forward ordered data and opaque trailers, or
/// [`Self::data`] followed by [`Self::trailers`]. Channels are bounded (default
/// capacity 16), and retain the transport's backpressure and drop semantics.
/// A stream error is terminal: subsequent reads return end-of-stream.
///
/// ```compile_fail
/// use qpxd::module_api::Body;
/// fn transport<B: http_body::Body>(_: B) {}
/// transport(Body::empty());
/// ```
/// ```compile_fail
/// use qpxd::module_api::Body;
/// let _ = Body::empty().mark_trailers_sanitized();
/// ```
/// ```compile_fail
/// use qpxd::module_api::Body;
/// let _: qpx_http::body::Body = Body::empty().into();
/// ```
/// ```compile_fail
/// use qpxd::module_api::Body;
/// let _ = Body::from(qpx_http::body::Body::empty());
/// ```
pub struct Body {
    inner: transport::Body,
    failure: Option<BodyError>,
}

struct TerminalErrorBody(Option<transport::BodyError>);

impl http_body::Body for TerminalErrorBody {
    type Data = Bytes;
    type Error = transport::BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.get_mut().0.take().map(Err))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::new()
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Body { .. }")
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl Body {
    pub fn empty() -> Self {
        Self::from_transport(transport::Body::empty())
    }

    /// Accepts a standard streaming body (including `hyper::body::Incoming`).
    /// Errors retain their display message; frames leave this facade only as
    /// [`BodyFrame`], with opaque trailers. Transport trust assertions are reset.
    pub fn wrap<B>(body: B) -> Self
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: fmt::Display,
    {
        use http_body_util::BodyExt as _;
        Self::from_transport(transport::Body::wrap(
            body.map_err(|error| transport::BodyError::new(error.to_string())),
        ))
    }

    pub fn channel() -> (Sender, Self) {
        Self::channel_with_capacity(16)
    }

    pub fn channel_with_capacity(capacity: usize) -> (Sender, Self) {
        let (inner, body) = transport::Body::channel_with_capacity(capacity);
        (Sender { inner }, Self::from_transport(body))
    }

    pub fn replay(bytes: Bytes, trailers: Option<Trailers>) -> Self {
        Self::from_transport(transport::Body::replay(bytes, trailers.map(|t| t.inner)))
    }

    pub fn replay_chunks(chunks: Vec<Bytes>, trailers: Option<Trailers>) -> Self {
        Self::from_transport(transport::Body::replay_chunks(
            chunks,
            trailers.map(|t| t.inner),
        ))
    }

    pub fn limit_bytes(self, max_bytes: usize) -> Self {
        Self {
            inner: self.inner.limit_bytes(max_bytes),
            failure: self.failure,
        }
    }

    pub async fn data(&mut self) -> Option<Result<Bytes, BodyError>> {
        if self.failure.is_some() {
            return None;
        }
        let result = self.inner.data().await?;
        Some(self.record_result(result))
    }

    /// Drains unread data to reach trailers, just like the transport operation.
    pub async fn trailers(&mut self) -> Result<Option<Trailers>, BodyError> {
        if self.failure.is_some() {
            return Ok(None);
        }
        let result = self.inner.trailers().await;
        self.record_result(result)
            .map(|t| t.map(|inner| Trailers { inner }))
    }

    pub async fn next_frame(&mut self) -> Option<Result<BodyFrame, BodyError>> {
        use http_body_util::BodyExt as _;
        if self.failure.is_some() {
            return None;
        }
        let result = self.inner.frame().await?;
        let frame = match self.record_result(result) {
            Ok(frame) => match frame.into_data() {
                Ok(data) => Ok(BodyFrame::Data(data)),
                Err(frame) => match frame.into_trailers() {
                    Ok(inner) => Ok(BodyFrame::Trailers(Trailers { inner })),
                    Err(_) => {
                        let error = BodyError::new(
                            "transport body emitted a frame without data or trailers",
                        );
                        self.failure = Some(error.clone());
                        Err(error)
                    }
                },
            },
            Err(error) => Err(error),
        };
        Some(frame)
    }

    fn record_result<T>(
        &mut self,
        result: Result<T, transport::BodyError>,
    ) -> Result<T, BodyError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                self.failure = Some(BodyError(error.clone()));
                Err(BodyError(error))
            }
        }
    }

    /// Collects data, discarding trailers. Apply `limit_bytes` first for bounded collection.
    pub async fn to_bytes(self) -> Result<Bytes, BodyError> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        transport::to_bytes(self.inner).await.map_err(BodyError)
    }

    pub(super) fn from_transport(inner: transport::Body) -> Self {
        Self {
            inner,
            failure: None,
        }
    }

    pub(super) fn into_transport(self) -> transport::Body {
        // Reboxing resets the public transport trust assertion. Even a body
        // taken from a trusted internal producer becomes untrusted on re-entry.
        // The nested body retains resources, cancellation, limits and timeouts.
        if let Some(failure) = self.failure {
            return transport::Body::wrap(TerminalErrorBody(Some(failure.0)));
        }
        let timeout_enforced = self.inner.read_timeout_is_enforced();
        let body = transport::Body::wrap(self.inner);
        if timeout_enforced {
            body.mark_read_timeout_enforced()
        } else {
            body
        }
    }
}

macro_rules! body_from {
    ($($ty:ty),* $(,)?) => {$(
        impl From<$ty> for Body {
            fn from(value: $ty) -> Self {
                Self::from_transport(transport::Body::from(value))
            }
        }
    )*};
}
body_from!(Bytes, Vec<u8>, String, &'static str, &'static [u8]);

/// The sending half of a bounded module body channel.
/// Dropping it ends the stream; dropping the body wakes `closed` and senders.
/// `abort` emits a stream error after already queued frames.
pub struct Sender {
    inner: transport::Sender,
}

impl Sender {
    pub async fn send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        self.inner.send_data(data).await.map_err(BodyError)
    }

    pub fn try_send_data(&mut self, data: Bytes) -> Result<(), BodyError> {
        self.inner.try_send_data(data).map_err(BodyError)
    }

    pub async fn send_trailers(&mut self, trailers: Trailers) -> Result<(), BodyError> {
        self.inner
            .send_trailers(trailers.inner)
            .await
            .map_err(BodyError)
    }

    pub fn try_send_trailers(&mut self, trailers: Trailers) -> Result<(), BodyError> {
        self.inner
            .try_send_trailers(trailers.inner)
            .map_err(BodyError)
    }

    pub async fn send_frame(&mut self, frame: BodyFrame) -> Result<(), BodyError> {
        match frame {
            BodyFrame::Data(data) => self.send_data(data).await,
            BodyFrame::Trailers(trailers) => self.send_trailers(trailers).await,
        }
    }

    pub fn abort(&mut self) {
        self.inner.abort();
    }
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
    pub async fn closed(&self) {
        self.inner.closed().await;
    }
}
