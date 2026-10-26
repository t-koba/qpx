//! Owned HTTP messages for in-domain processing.
//!
//! [`Headers`](crate::http_message::Headers) keeps Content-Length behind its typed declaration API. Ordinary
//! fields retain `http`'s bytes, sensitivity and per-name occurrence order; they
//! can only be accessed with a name that cannot denote Content-Length.
//!
//! Import a decoded message once with `from_http`, move the carrier through
//! policy/body stages, and export it with `into_http_for_codec` only at an actual
//! serializer boundary. In particular, an upstream preparation facade is not a
//! serializer boundary. Export validates and canonicalizes the declaration; it
//! does not choose transfer coding or implement method/status body policy.
//!
//! This is the ownership primitive, not a claim that all workspace HTTP paths
//! have migrated. Existing raw-H1 and interim head owners remain independent.

use crate::http_content_length::{
    ContentLengthError, HeaderDiagnostic, HeaderPredicate, HeaderTextSelection, HeaderView,
    VarySelector, canonical_content_length_value,
};
use http::header::{CONTENT_LENGTH, HeaderName, HeaderValue};
use http::{Extensions, HeaderMap, Method, StatusCode, Uri, Version};
use std::fmt;

/// A validated ordinary field name, excluding the owner-managed Content-Length.
///
/// Validation is case-insensitive. There is no unchecked constructor.
///
/// ```
/// use qpx_core::http_message::OrdinaryHeaderName;
/// assert!(OrdinaryHeaderName::try_from("X-Trace").is_ok());
/// assert!(OrdinaryHeaderName::try_from("Content-Length").is_err());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OrdinaryHeaderName(HeaderName);

/// An invalid field name, or an attempt to access Content-Length as an ordinary field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("expected a valid field name other than Content-Length")]
pub struct InvalidOrdinaryHeaderName;

impl TryFrom<HeaderName> for OrdinaryHeaderName {
    type Error = InvalidOrdinaryHeaderName;

    fn try_from(name: HeaderName) -> Result<Self, Self::Error> {
        if name == CONTENT_LENGTH {
            Err(InvalidOrdinaryHeaderName)
        } else {
            Ok(Self(name))
        }
    }
}

impl TryFrom<&str> for OrdinaryHeaderName {
    type Error = InvalidOrdinaryHeaderName;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| InvalidOrdinaryHeaderName)?
            .try_into()
    }
}

impl OrdinaryHeaderName {
    /// The normalized field name, never Content-Length.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// An owner-scoped header view with redacted Content-Length diagnostics.
///
/// This wraps the closed [`HeaderView`] policy API for [`Headers`] only. Predicate
/// matching (`matches`) is unchanged for every field, including Content-Length.
/// Ordinary-field `trace` diagnostics still report the first matching textual
/// value. Content-Length `trace` diagnostics never report text: `actual` is always
/// `None` while `matched` reports the same predicate result the wrapped view
/// computed, matched case-insensitively on the field name. `joined_text` stays
/// unrepresentable for Content-Length and `vary_selector` remains the literal
/// opaque encoding.
///
/// There is no raw-map escape and no conversion back to [`HeaderView`]:
/// ```compile_fail,E0616
/// use qpx_core::http_message::OwnedHeaderView;
/// let view = qpx_core::http_message::Headers::new().view();
/// let _ = view.inner;
/// ```
/// ```compile_fail,E0277
/// use qpx_core::http_message::Headers;
/// fn raw<T: AsRef<http::HeaderMap>>(_: &T) {}
/// raw(&Headers::new().view());
/// ```
/// ```compile_fail,E0277
/// use qpx_core::http_message::Headers;
/// fn raw<T: std::ops::Deref<Target = http::HeaderMap>>(_: &T) {}
/// raw(&Headers::new().view());
/// ```
/// ```compile_fail,E0599
/// use qpx_core::http_message::Headers;
/// let view = Headers::new().view();
/// let _ = view.into_header_view();
/// ```
#[derive(Clone, Copy)]
pub struct OwnedHeaderView<'a> {
    inner: HeaderView<'a>,
}

impl fmt::Debug for OwnedHeaderView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedHeaderView").finish_non_exhaustive()
    }
}

impl<'a> OwnedHeaderView<'a> {
    /// Whether any textual value for `name` matches, without allocating.
    ///
    /// Matching is unchanged for every field, including Content-Length.
    pub fn matches(&self, name: &str, predicate: HeaderPredicate<'_>) -> bool {
        self.inner.matches(name, predicate)
    }

    /// Reports the predicate result without exposing Content-Length text.
    ///
    /// For Content-Length (matched case-insensitively), `actual` is always
    /// `None` and `matched` is the wrapped predicate result. Ordinary fields
    /// delegate unchanged: the first matching textual value, else the first
    /// textual value.
    pub fn trace(&self, name: &str, predicate: HeaderPredicate<'_>) -> HeaderDiagnostic {
        if name.eq_ignore_ascii_case("content-length") {
            HeaderDiagnostic {
                actual: None,
                matched: self.inner.matches(name, predicate),
            }
        } else {
            self.inner.trace(name, predicate)
        }
    }

    /// Selects a validated, case-insensitive name as trimmed, comma-joined text.
    ///
    /// Content-Length stays unrepresentable here; use [`Self::vary_selector`].
    pub fn joined_text(&self, name: &str) -> HeaderTextSelection {
        self.inner.joined_text(name)
    }

    /// Select literal Vary equivalence without exposing Content-Length text.
    pub fn vary_selector(&self, name: &str) -> Option<VarySelector> {
        self.inner.vary_selector(name)
    }
}

/// A header set whose raw map and Content-Length values never escape in-domain.
///
/// Clone is available for intentional message forks and frozen snapshots, not
/// required to move a message between stages. Equality compares every literal
/// field occurrence (including Content-Length), its bytes and sensitivity, in
/// per-name order. Ordering of distinct names is not significant, matching
/// `http::HeaderMap` semantics. No values are returned by comparison; Debug also
/// hides values, including framing declarations.
///
/// These examples compile as external consumers of qpx-core. A consumer cannot
/// reach the raw storage or forge an ordinary name:
/// ```compile_fail,E0616
/// use qpx_core::http_message::Headers;
/// let headers = Headers::new();
/// let _ = headers.inner;
/// ```
/// ```compile_fail,E0423
/// use http::header::CONTENT_LENGTH;
/// use qpx_core::http_message::OrdinaryHeaderName;
/// let name = OrdinaryHeaderName(CONTENT_LENGTH);
/// ```
/// Nor can a raw name select a Content-Length `HeaderValue`:
/// ```compile_fail,E0308
/// use http::header::CONTENT_LENGTH;
/// use qpx_core::http_message::Headers;
/// let headers = Headers::new();
/// let _ = headers.get(&CONTENT_LENGTH);
/// ```
/// There is no raw-map trait escape:
/// ```compile_fail,E0277
/// use qpx_core::http_message::Headers;
/// fn raw<T: AsRef<http::HeaderMap>>(_: &T) {}
/// raw(&Headers::new());
/// ```
/// ```compile_fail,E0277
/// use qpx_core::http_message::Headers;
/// fn raw<T: std::ops::Deref<Target = http::HeaderMap>>(_: &T) {}
/// raw(&Headers::new());
/// ```
/// Standalone map export is private; only a full message's codec handoff can
/// release its framing values:
/// ```compile_fail,E0624
/// use qpx_core::http_message::Headers;
/// let _ = Headers::new().into_codec_headers();
/// ```
/// Policy regex mutation is deliberately not an external value-access API:
/// ```compile_fail,E0624
/// use qpx_core::http_message::Headers;
/// let mut headers = Headers::new();
/// headers.replace_header_regex(&http::header::CONTENT_LENGTH,
///     &regex::Regex::new(".*").unwrap(), "0");
/// ```
#[derive(Clone, Default)]
pub struct Headers {
    inner: HeaderMap,
}

impl fmt::Debug for Headers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Headers").finish_non_exhaustive()
    }
}

impl PartialEq for Headers {
    fn eq(&self, other: &Self) -> bool {
        self.inner.len() == other.inner.len()
            && self.inner.keys().all(|name| {
                let left = self.inner.get_all(name);
                let right = other.inner.get_all(name);
                left.iter().count() == right.iter().count()
                    && left
                        .iter()
                        .zip(right.iter())
                        .all(|(a, b)| a == b && a.is_sensitive() == b.is_sensitive())
            })
    }
}

impl Eq for Headers {}

impl Headers {
    /// Literal presence, even when the declaration is malformed or conflicting.
    /// This does not parse or return the stored declaration.
    pub fn contains_content_length(&self) -> bool {
        self.inner.contains_key(CONTENT_LENGTH)
    }

    /// Literal presence of an ordinary field, including nontextual values.
    pub fn contains_key(&self, name: &OrdinaryHeaderName) -> bool {
        self.inner.contains_key(&name.0)
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    // Only the compiled policy engine may request a textual replacement. No
    // callback, selected text or previous value leaves the owner.
    pub(crate) fn replace_header_regex(
        &mut self,
        name: &HeaderName,
        pattern: &regex::Regex,
        replacement: &str,
    ) -> bool {
        replace_header_regex(&mut self.inner, name, pattern, replacement)
    }

    /// An empty header set, with an absent Content-Length declaration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve the declaration without losing absent, zero or error distinctions.
    pub fn declared_content_length(&self) -> Result<Option<u64>, ContentLengthError> {
        crate::http_content_length::declared_content_length(&self.inner)
    }

    /// Replace all occurrences with one canonical decimal declaration.
    pub fn set_content_length(&mut self, length: u64) {
        self.inner
            .insert(CONTENT_LENGTH, canonical_content_length_value(length));
    }

    /// Remove the declaration (different from declaring zero).
    pub fn remove_content_length(&mut self) {
        self.inner.remove(CONTENT_LENGTH);
    }

    /// Replace all occurrences with the given literal field value.
    ///
    /// This preserves the supplied bytes (padding, zero, empty, or a value the
    /// owner later refuses) without canonicalizing or validating them; the
    /// existing declaration validation still applies at [`Self::declared_content_length`]
    /// and at codec export. There is no return value, so the stored text is not
    /// exposed back to the caller. Prefer [`Self::set_content_length`] when the
    /// length is already resolved numerically.
    pub fn set_content_length_value(&mut self, value: HeaderValue) {
        self.inner.insert(CONTENT_LENGTH, value);
    }

    /// Append one literal field occurrence without changing existing values.
    ///
    /// This preserves padding and duplicates (including equal padded values that
    /// parse to the same length) until codec export canonicalizes them; a
    /// conflicting or invalid sequence still resolves through the existing
    /// [`Self::declared_content_length`] error and fails export. There is no
    /// return value, so stored text is never exposed.
    pub fn append_content_length_value(&mut self, value: HeaderValue) {
        self.inner.append(CONTENT_LENGTH, value);
    }

    /// Closed policy matching, diagnostic and Vary operations owned by qpx-core.
    ///
    /// The returned view preserves predicate matching for every field, including
    /// Content-Length, and preserves ordinary-field diagnostics. Content-Length
    /// trace diagnostics are redacted: `actual` is always `None` while `matched`
    /// still reports the predicate result. `joined_text` stays unrepresentable
    /// for Content-Length and `vary_selector` remains the literal opaque
    /// encoding.
    pub fn view(&self) -> OwnedHeaderView<'_> {
        OwnedHeaderView {
            inner: HeaderView::new(&self.inner),
        }
    }

    /// The first occurrence of an ordinary field.
    pub fn get(&self, name: &OrdinaryHeaderName) -> Option<&HeaderValue> {
        self.inner.get(&name.0)
    }

    /// All ordinary field occurrences, in their original per-name order.
    pub fn get_all<'a>(
        &'a self,
        name: &OrdinaryHeaderName,
    ) -> impl Iterator<Item = &'a HeaderValue> + 'a {
        self.inner.get_all(&name.0).iter()
    }

    /// Replace an ordinary field, returning its previous first value, if any.
    pub fn insert(&mut self, name: OrdinaryHeaderName, value: HeaderValue) -> Option<HeaderValue> {
        self.inner.insert(name.0, value)
    }

    /// Append an ordinary field occurrence without changing existing values.
    pub fn append(&mut self, name: OrdinaryHeaderName, value: HeaderValue) {
        self.inner.append(name.0, value);
    }

    /// Remove every occurrence of an ordinary field.
    pub fn remove(&mut self, name: &OrdinaryHeaderName) -> Option<HeaderValue> {
        self.inner.remove(&name.0)
    }

    /// Iterate ordinary fields only. Content-Length is never included.
    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
        self.inner
            .iter()
            .filter(|(name, _)| *name != CONTENT_LENGTH)
    }

    fn into_codec_headers(mut self) -> Result<HeaderMap, ContentLengthError> {
        if let Some(length) = self.declared_content_length()? {
            self.set_content_length(length);
        }
        Ok(self.inner)
    }
}

// Transitional raw-map callers and Headers share the same replacement operation.
// true means invalid replacement; absent/nontextual first values are skipped.
pub(crate) fn replace_header_regex(
    headers: &mut HeaderMap,
    name: &HeaderName,
    pattern: &regex::Regex,
    replacement: &str,
) -> bool {
    let Some(value) = headers.get(name).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let replaced = pattern.replace_all(value, replacement);
    match HeaderValue::from_str(replaced.as_ref()) {
        Ok(value) => {
            headers.insert(name.clone(), value);
            false
        }
        Err(_) => true,
    }
}

/// An owned request whose headers remain encapsulated across body transformations.
///
/// There is no public raw `http::request::Parts` API:
/// ```compile_fail,E0599
/// use qpx_core::http_message::Request;
/// let request = Request::new(());
/// let _ = request.into_parts();
/// ```
/// ```compile_fail,E0616
/// use qpx_core::http_message::Request;
/// let request = Request::new(());
/// let _ = request.headers.inner;
/// ```
/// Raw mutable header-map replacement is also unavailable:
/// ```compile_fail,E0308
/// use qpx_core::http_message::Request;
/// let mut request = Request::new(());
/// *request.headers_mut() = http::HeaderMap::new();
/// ```
///
/// Positive control: body stages carry the owner, not raw parts.
/// ```
/// use qpx_core::http_message::Request;
/// let mut request = Request::new(vec![1, 2, 3]);
/// request.headers_mut().set_content_length(3);
/// let (head, body) = request.into_head_and_body();
/// let request = head.map_body(|()| body.into_boxed_slice());
/// assert_eq!(request.headers().declared_content_length(), Ok(Some(3)));
/// let wire = request.into_http_for_codec().unwrap();
/// assert_eq!(wire.headers()[http::header::CONTENT_LENGTH], "3");
/// ```
#[derive(Debug)]
pub struct Request<B> {
    method: Method,
    uri: Uri,
    version: Version,
    headers: Headers,
    extensions: Extensions,
    body: B,
}

impl<B> Request<B> {
    /// Construct a GET request for `/`, with HTTP/1.1 and no headers.
    pub fn new(body: B) -> Self {
        Self::from_http(http::Request::new(body))
    }

    /// Import once at decoded codec/library ingress, moving headers and body.
    pub fn from_http(request: http::Request<B>) -> Self {
        let (parts, body) = request.into_parts();
        Self {
            method: parts.method,
            uri: parts.uri,
            version: parts.version,
            headers: Headers {
                inner: parts.headers,
            },
            extensions: parts.extensions,
            body,
        }
    }

    /// Export only to an actual codec/library serializer, validating framing.
    ///
    /// Invalid and conflicting declarations are refused, not silently removed.
    /// Method/body/transfer-coding policy belongs to the caller's protocol stage.
    pub fn into_http_for_codec(self) -> Result<http::Request<B>, ContentLengthError> {
        let headers = self.headers.into_codec_headers()?;
        let mut request = http::Request::new(self.body);
        *request.method_mut() = self.method;
        *request.uri_mut() = self.uri;
        *request.version_mut() = self.version;
        *request.headers_mut() = headers;
        *request.extensions_mut() = self.extensions;
        Ok(request)
    }

    /// The request method.
    pub fn method(&self) -> &Method {
        &self.method
    }
    /// Change the request method.
    pub fn method_mut(&mut self) -> &mut Method {
        &mut self.method
    }
    /// The target URI.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }
    /// Change the target URI.
    pub fn uri_mut(&mut self) -> &mut Uri {
        &mut self.uri
    }
    /// The HTTP version.
    pub fn version(&self) -> Version {
        self.version
    }
    /// Change the HTTP version.
    pub fn version_mut(&mut self) -> &mut Version {
        &mut self.version
    }

    /// Transform the body without cloning or exporting its owned head.
    pub fn map_body<T>(self, f: impl FnOnce(B) -> T) -> Request<T> {
        Request {
            method: self.method,
            uri: self.uri,
            version: self.version,
            headers: self.headers,
            extensions: self.extensions,
            body: f(self.body),
        }
    }

    /// Separate body processing from head processing without exposing raw parts.
    /// Reattach with `head.map_body(|()| body)` after processing (including async work).
    pub fn into_head_and_body(self) -> (Request<()>, B) {
        let Self {
            method,
            uri,
            version,
            headers,
            extensions,
            body,
        } = self;
        (
            Request {
                method,
                uri,
                version,
                headers,
                extensions,
                body: (),
            },
            body,
        )
    }
}

/// An owned response with the same header boundary as [`Request`].
///
/// ```compile_fail,E0599
/// use qpx_core::http_message::Response;
/// let response = Response::new(());
/// let _ = response.into_parts();
/// ```
#[derive(Debug)]
pub struct Response<B> {
    status: StatusCode,
    version: Version,
    headers: Headers,
    extensions: Extensions,
    body: B,
}

impl<B> Response<B> {
    /// Construct a 200 OK response, with HTTP/1.1 and no headers.
    pub fn new(body: B) -> Self {
        Self::from_http(http::Response::new(body))
    }

    /// Import once at decoded codec/library ingress, moving headers and body.
    pub fn from_http(response: http::Response<B>) -> Self {
        let (parts, body) = response.into_parts();
        Self {
            status: parts.status,
            version: parts.version,
            headers: Headers {
                inner: parts.headers,
            },
            extensions: parts.extensions,
            body,
        }
    }

    /// Export only to an actual codec/library serializer, validating framing.
    ///
    /// This does not infer a body size or apply HEAD/no-body status policy.
    pub fn into_http_for_codec(self) -> Result<http::Response<B>, ContentLengthError> {
        let headers = self.headers.into_codec_headers()?;
        let mut response = http::Response::new(self.body);
        *response.status_mut() = self.status;
        *response.version_mut() = self.version;
        *response.headers_mut() = headers;
        *response.extensions_mut() = self.extensions;
        Ok(response)
    }

    /// The response status.
    pub fn status(&self) -> StatusCode {
        self.status
    }
    /// Change the response status.
    pub fn status_mut(&mut self) -> &mut StatusCode {
        &mut self.status
    }
    /// The HTTP version.
    pub fn version(&self) -> Version {
        self.version
    }
    /// Change the HTTP version.
    pub fn version_mut(&mut self) -> &mut Version {
        &mut self.version
    }

    /// Transform the body without cloning or exporting its owned head.
    pub fn map_body<T>(self, f: impl FnOnce(B) -> T) -> Response<T> {
        Response {
            status: self.status,
            version: self.version,
            headers: self.headers,
            extensions: self.extensions,
            body: f(self.body),
        }
    }

    /// Separate body processing from head processing without exposing raw parts.
    pub fn into_head_and_body(self) -> (Response<()>, B) {
        let Self {
            status,
            version,
            headers,
            extensions,
            body,
        } = self;
        (
            Response {
                status,
                version,
                headers,
                extensions,
                body: (),
            },
            body,
        )
    }
}

// The shared message accessors do not expose the standard HTTP carrier or parts.
macro_rules! message_accessors {
    ($message:ident) => {
        impl<B> $message<B> {
            /// The owned header set.
            pub fn headers(&self) -> &Headers {
                &self.headers
            }
            /// Mutate headers through the owner API.
            pub fn headers_mut(&mut self) -> &mut Headers {
                &mut self.headers
            }
            /// Message extensions, moved intact at codec boundaries.
            pub fn extensions(&self) -> &Extensions {
                &self.extensions
            }
            /// Mutate message extensions.
            pub fn extensions_mut(&mut self) -> &mut Extensions {
                &mut self.extensions
            }
            /// The body, untouched by header processing.
            pub fn body(&self) -> &B {
                &self.body
            }
            /// Mutate the body without exporting its head.
            pub fn body_mut(&mut self) -> &mut B {
                &mut self.body
            }
        }
    };
}
message_accessors!(Request);
message_accessors!(Response);
