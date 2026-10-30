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
//! Responses may also cross a genuine library hook with
//! [`Response::into_http_for_library`](crate::http_message::Response::into_http_for_library), a lossless transfer without framing checks.
//!
//! This is the ownership primitive, not a claim that all workspace HTTP paths
//! have migrated. Existing raw-H1 and interim head owners remain independent.
//! [`HeaderTransferPatch`](crate::http_message::HeaderTransferPatch) and
//! [`HeaderExpansionPlan`](crate::http_message::HeaderExpansionPlan) provide closed configured
//! effects for future callers; they do not migrate the live pipeline or serialize
//! request previews.

use crate::http_content_length::{
    ContentLengthError, HeaderDiagnostic, HeaderPredicate, HeaderTextSelection, HeaderView,
    VarySelector, canonical_content_length_value,
};
use http::header::{CONTENT_LENGTH, COOKIE, HeaderName, HeaderValue};
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
    /// Constructs a name from a crate-owned, statically valid ordinary field literal.
    ///
    /// The caller must not pass Content-Length. This is crate-private for fixed protocol
    /// fields whose names are validated at compile time by `HeaderName::from_static`.
    pub(crate) const fn from_static(name: &'static str) -> Self {
        Self(HeaderName::from_static(name))
    }

    /// The normalized field name, never Content-Length.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Ordinary-field effects shared by standard boundary heads and owned heads.
///
/// All names exclude Content-Length. Reads borrow occurrences in order,
/// retaining bytes and sensitivity; no map or message parts escape.
///
/// ```compile_fail
/// use qpx_core::http_message::{Headers, OrdinaryHeaderMut};
/// OrdinaryHeaderMut::ordinary_remove(&mut Headers::new(), &http::header::CONTENT_LENGTH);
/// ```
pub trait OrdinaryHeaderMut {
    /// Borrow every occurrence of an ordinary field in order.
    fn ordinary_values<'a>(
        &'a self,
        name: &OrdinaryHeaderName,
    ) -> impl Iterator<Item = &'a HeaderValue>;
    /// Replace all occurrences with one value.
    fn ordinary_insert(&mut self, name: OrdinaryHeaderName, value: HeaderValue);
    /// Append an occurrence without replacing earlier values.
    fn ordinary_append(&mut self, name: OrdinaryHeaderName, value: HeaderValue);
    /// Remove every occurrence of an ordinary field.
    fn ordinary_remove(&mut self, name: &OrdinaryHeaderName);
    /// Reserve room for additional field lines, as for `HeaderMap::reserve`.
    fn ordinary_reserve(&mut self, additional: usize);
}

impl OrdinaryHeaderMut for HeaderMap {
    fn ordinary_values<'a>(
        &'a self,
        name: &OrdinaryHeaderName,
    ) -> impl Iterator<Item = &'a HeaderValue> {
        self.get_all(&name.0).iter()
    }
    fn ordinary_insert(&mut self, name: OrdinaryHeaderName, value: HeaderValue) {
        self.insert(name.0, value);
    }
    fn ordinary_append(&mut self, name: OrdinaryHeaderName, value: HeaderValue) {
        self.append(name.0, value);
    }
    fn ordinary_remove(&mut self, name: &OrdinaryHeaderName) {
        self.remove(&name.0);
    }
    fn ordinary_reserve(&mut self, additional: usize) {
        self.reserve(additional);
    }
}

impl OrdinaryHeaderMut for Headers {
    fn ordinary_values<'a>(
        &'a self,
        name: &OrdinaryHeaderName,
    ) -> impl Iterator<Item = &'a HeaderValue> {
        self.get_all(name)
    }
    fn ordinary_insert(&mut self, name: OrdinaryHeaderName, value: HeaderValue) {
        self.insert(name, value);
    }
    fn ordinary_append(&mut self, name: OrdinaryHeaderName, value: HeaderValue) {
        self.append(name, value);
    }
    fn ordinary_remove(&mut self, name: &OrdinaryHeaderName) {
        self.remove(name);
    }
    fn ordinary_reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }
}

/// An owner-scoped header view with redacted Content-Length diagnostics.
///
/// This wraps the closed [`HeaderView`] policy API for [`Headers`] only. Predicate
/// matching (`matches`) is unchanged for every field, including Content-Length,
/// except for Cookie in the explicit request policy view.
/// Ordinary-field `trace` diagnostics report the first matching textual
/// value, except for Cookie in the request policy view. Content-Length `trace` diagnostics never report text: `actual` is always
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
    request: Option<(&'a HeaderMap, Version)>,
}

impl fmt::Debug for OwnedHeaderView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedHeaderView").finish_non_exhaustive()
    }
}

impl<'a> OwnedHeaderView<'a> {
    /// Whether a textual value for `name` matches. Request policy views join
    /// multiple H2/H3 Cookie fields as the legacy decoder did.
    pub fn matches(&self, name: &str, predicate: HeaderPredicate<'_>) -> bool {
        self.cookie_diagnostic(name, predicate).map_or_else(
            || self.inner.matches(name, predicate),
            |result| result.matched,
        )
    }

    fn cookie_diagnostic(
        &self,
        name: &str,
        predicate: HeaderPredicate<'_>,
    ) -> Option<HeaderDiagnostic> {
        let (headers, version) = self.request?;
        if !name.eq_ignore_ascii_case("cookie")
            || !matches!(version, Version::HTTP_2 | Version::HTTP_3)
        {
            return None;
        }
        let mut values = headers.get_all(COOKIE).iter();
        let first = values.next()?;
        let second = values.next()?;
        let mut joined = first.as_bytes().to_vec();
        for value in std::iter::once(second).chain(values) {
            if version == Version::HTTP_3 || !joined.is_empty() {
                joined.extend_from_slice(b"; ");
            }
            joined.extend_from_slice(value.as_bytes());
        }
        // H2 omits an empty merged field; H3 retains its separators. Preserve
        // opaque bytes instead of skipping a non-textual occurrence.
        let actual = if version == Version::HTTP_2 && joined.is_empty() {
            None
        } else {
            HeaderValue::from_bytes(&joined)
                .ok()
                .and_then(|v| v.to_str().ok().map(str::to_owned))
        };
        let matched = actual.as_deref().is_some_and(|value| match predicate {
            HeaderPredicate::Present => true,
            HeaderPredicate::Exact(expected) => value == expected,
            HeaderPredicate::Regex(regex) => regex.is_match(value),
        });
        Some(HeaderDiagnostic { actual, matched })
    }

    /// Reports the predicate result without exposing Content-Length text.
    ///
    /// For Content-Length (matched case-insensitively), `actual` is always
    /// `None` and `matched` is the wrapped predicate result. Ordinary fields
    /// delegate unchanged: the first matching textual value, else the first
    /// textual value, except Cookie in a request policy view.
    pub fn trace(&self, name: &str, predicate: HeaderPredicate<'_>) -> HeaderDiagnostic {
        if name.eq_ignore_ascii_case("content-length") {
            HeaderDiagnostic {
                actual: None,
                matched: self.inner.matches(name, predicate),
            }
        } else {
            self.cookie_diagnostic(name, predicate)
                .unwrap_or_else(|| self.inner.trace(name, predicate))
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

/// A closed authorization-selection failure, without field or token contents.
/// Diagnostics and authentication decisions belong to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityAuthorizationError {
    /// More than one occurrence, regardless of the contents.
    Duplicate,
    /// The single occurrence cannot be read as text.
    NonTextual,
    /// Missing token separator, empty token or whitespace inside the token.
    MalformedBearer,
    /// The scheme is neither Bearer nor DPoP.
    MalformedAuthorization,
    /// The field uses DPoP while that extraction mode is disabled.
    DpopDisabled,
}

impl Headers {
    /// Select the first nonempty trimmed textual identity value in occurrence
    /// order. Configured identity fields include Content-Length: this operation
    /// selects literal text, never a parsed or canonicalized length.
    pub fn identity_text(&self, name: &HeaderName) -> Option<String> {
        self.inner
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::trim)
            .find(|value| !value.is_empty())
            .map(str::to_string)
    }

    /// Select comma-separated identity members in occurrence/member order,
    /// skipping nontextual values and empty trimmed members. Deduplication is
    /// stable and case-sensitive, including for literal Content-Length text.
    pub fn identity_members(&self, name: &HeaderName) -> Vec<String> {
        let mut selected = Vec::new();
        for member in crate::http_token::header_value_members(&self.inner, name) {
            if !member.is_empty() && !selected.iter().any(|value| value == member) {
                selected.push(member.to_string());
            }
        }
        selected
    }

    /// Select the first eligible assertion, skipping nontextual/empty values.
    /// Trim the occurrence, remove the configured literal (case-sensitive)
    /// prefix when present, then trim the token and skip empty tokens. No
    /// verification or trust decision is performed here.
    ///
    /// These closed selections do not grant raw access, even for a configured
    /// Content-Length identity source:
    /// ```compile_fail
    /// use qpx_core::http_message::Headers;
    /// let headers = Headers::new();
    /// let _ = headers.get_all(&http::header::CONTENT_LENGTH);
    /// ```
    /// Nor may a caller replace the selection with an arbitrary callback:
    /// ```compile_fail
    /// use qpx_core::http_message::Headers;
    /// let headers = Headers::new();
    /// headers.identity_assertion(&http::header::CONTENT_LENGTH, |value| value);
    /// ```
    pub fn identity_assertion<'a>(
        &'a self,
        name: &HeaderName,
        prefix: Option<&str>,
    ) -> Option<&'a str> {
        for value in self.inner.get_all(name).iter() {
            let Ok(value) = value.to_str() else { continue };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            if let Some(prefix) = prefix {
                if let Some(token) = value.strip_prefix(prefix) {
                    let token = token.trim();
                    if !token.is_empty() {
                        return Some(token);
                    }
                }
                continue;
            }
            return Some(value);
        }
        None
    }

    /// Select a Bearer/DPoP credential from exactly one configured occurrence.
    /// Absence is distinct from duplicate, nontextual and malformed values;
    /// no joining or fallback to a later occurrence is allowed. The boolean
    /// identifies the DPoP scheme. This only extracts credentials, not trust.
    pub fn identity_authorization<'a>(
        &'a self,
        name: &HeaderName,
        dpop_enabled: bool,
    ) -> Result<Option<(&'a str, bool)>, IdentityAuthorizationError> {
        use IdentityAuthorizationError::*;
        let mut values = self.inner.get_all(name).iter();
        let Some(value) = values.next() else {
            return Ok(None);
        };
        if values.next().is_some() {
            return Err(Duplicate);
        }
        let value = value.to_str().map_err(|_| NonTextual)?;
        let Some((scheme, token)) = value.trim().split_once(' ') else {
            return Err(MalformedBearer);
        };
        let dpop_scheme = if scheme.eq_ignore_ascii_case("dpop") {
            if !dpop_enabled {
                return Err(DpopDisabled);
            }
            true
        } else if scheme.eq_ignore_ascii_case("bearer") {
            false
        } else {
            return Err(MalformedAuthorization);
        };
        if token.is_empty() || token.contains(char::is_whitespace) {
            return Err(MalformedBearer);
        }
        Ok(Some((token, dpop_scheme)))
    }

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
            request: None,
        }
    }

    /// Request policy view matching the legacy H2/H3 decoder's Cookie joining.
    ///
    /// Only Cookie predicate matching and diagnostics change. The stored fields,
    /// other names, text selection and Vary selection remain untouched. Use
    /// [`Self::view`] for responses, trailers and protocol-neutral operations.
    pub fn request_policy_view(&self, version: Version) -> OwnedHeaderView<'_> {
        OwnedHeaderView {
            inner: HeaderView::new(&self.inner),
            request: Some((&self.inner, version)),
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

    /// Render selected textual field occurrences for an external metadata message.
    /// Unlike ordinary-field access, this serializer preserves framing spellings
    /// and duplicates; it does not validate or canonicalize the live message.
    pub fn selected_fields_for_serialization(
        &self,
        selected: &[HeaderName],
    ) -> std::collections::HashMap<String, Vec<String>> {
        selected
            .iter()
            .filter_map(|name| {
                let values: Vec<_> = self
                    .inner
                    .get_all(name)
                    .iter()
                    .filter_map(|value| value.to_str().ok())
                    .map(str::to_owned)
                    .collect();
                (!values.is_empty()).then(|| (name.as_str().to_owned(), values))
            })
            .collect()
    }

    /// Closed cache persistence fields without a hot-path JSON round trip.
    ///
    /// Collects the historical textual field pairs directly (names and values
    /// as text, per-name duplicate order, literal Content-Length spellings,
    /// non-text omitted) while filtering the caller-supplied excluded names
    /// (cache `no-cache`/`private` fields). No pairs, maps or message parts
    /// escape; no caller-supplied serializer or field/value callback receives
    /// the framing declarations. The live head is not changed. The returned
    /// carrier offers only fixed JSON persistence operations with the historical
    /// array schema, so persisted metadata bytes are unchanged.
    ///
    /// The former arbitrary pair projection is deliberately unavailable:
    /// ```compile_fail,E0599
    /// use qpx_core::http_message::Headers;
    /// let _: Vec<(String, String)> = Headers::new().textual_fields_for_serialization();
    /// ```
    /// Persistence exports an opaque carrier, never an iterable pair carrier
    /// or raw JSON bytes:
    /// ```compile_fail,E0308
    /// use qpx_core::http_message::Headers;
    /// let _: Vec<(String, String)> = Headers::new().cache_fields(&Default::default());
    /// ```
    /// ```compile_fail,E0308
    /// use qpx_core::http_message::Headers;
    /// let _: Vec<u8> = Headers::new().cache_fields(&Default::default());
    /// ```
    pub fn cache_fields(&self, excluded: &std::collections::HashSet<String>) -> CacheFields {
        let mut inner = Vec::with_capacity(self.inner.len());
        for (name, value) in self.inner.iter() {
            if excluded.contains(name.as_str()) {
                continue;
            }
            let Ok(text) = value.to_str() else {
                continue;
            };
            inner.push((name.as_str().to_owned(), text.to_owned()));
        }
        CacheFields { inner }
    }

    /// Serialize HTTP field lines without exporting a map or framing values.
    /// Used by the TRACE message/http serializer; preserves exact field bytes.
    pub fn write_http_field_lines(
        &self,
        output: &mut Vec<u8>,
        include: impl Fn(&HeaderName) -> bool,
    ) {
        for (name, value) in &self.inner {
            if include(name) {
                output.extend_from_slice(name.as_str().as_bytes());
                output.extend_from_slice(b": ");
                output.extend_from_slice(value.as_bytes());
                output.extend_from_slice(b"\r\n");
            }
        }
    }

    /// Render selected HTTP field lines for textual diagnostics, including framing
    /// spellings and duplicates. Non-text values render as empty text, not raw bytes.
    /// This does not validate or canonicalize the live message.
    pub fn write_textual_http_field_lines(
        &self,
        output: &mut String,
        include: impl Fn(&HeaderName) -> bool,
    ) {
        for (name, value) in &self.inner {
            if include(name) {
                output.push_str(name.as_str());
                output.push_str(": ");
                output.push_str(value.to_str().unwrap_or(""));
                output.push_str("\r\n");
            }
        }
    }

    /// Number of field occurrences, including framing fields and duplicates.
    /// This exposes only the count, never Content-Length values.
    pub fn field_count(&self) -> usize {
        self.inner.len()
    }

    /// Sum field-name and value byte lengths, including every framing occurrence.
    /// When `trim_ows` is set, exclude leading and trailing HTTP whitespace from
    /// each value. Only the aggregate is exposed, not framing field bytes.
    pub fn field_bytes(&self, trim_ows: bool) -> usize {
        self.inner.iter().fold(0usize, |total, (name, value)| {
            let bytes = value.as_bytes();
            let length = if trim_ows {
                let start = bytes
                    .iter()
                    .position(|b| !matches!(b, b' ' | b'\t'))
                    .unwrap_or(bytes.len());
                let end = bytes
                    .iter()
                    .rposition(|b| !matches!(b, b' ' | b'\t'))
                    .map_or(start, |i| i + 1);
                end - start
            } else {
                bytes.len()
            };
            total.saturating_add(name.as_str().len() + length)
        })
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

/// Opaque historical cache field pairs for persistence.
///
/// Holds textual field names and values with per-name duplicate order and
/// literal Content-Length spellings; non-text values are omitted at capture.
/// The inner pairs never escape: hydration and length reads stay inside the
/// owner. Fixed JSON persistence operations retain the historical array of pairs,
/// so persisted metadata bytes and schema are unchanged. No pairs, maps or
/// message parts are returned, and no caller-supplied serializer or
/// field/value callback receives the framing declarations.
///
/// ```compile_fail,E0616
/// use qpx_core::http_message::CacheFields;
/// let fields = CacheFields::default();
/// let _ = fields.inner;
/// ```
/// ```compile_fail,E0599
/// use qpx_core::http_message::CacheFields;
/// let fields = CacheFields::default();
/// let _: Vec<(String, String)> = fields.into_pairs();
/// ```
/// Generic serde access is deliberately unavailable, including arbitrary
/// caller-supplied serializers and deserializers:
/// ```compile_fail,E0277
/// use qpx_core::http_message::CacheFields;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<CacheFields>();
/// ```
/// ```compile_fail,E0277
/// use qpx_core::http_message::CacheFields;
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<CacheFields>();
/// ```
#[derive(Clone, Default)]
pub struct CacheFields {
    inner: Vec<(String, String)>,
}

impl fmt::Debug for CacheFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CacheFields").finish_non_exhaustive()
    }
}

impl CacheFields {
    /// Encode only the historical JSON array of textual pairs at the cache
    /// persistence boundary. No caller-provided serializer observes the fields.
    pub fn to_cache_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(&self.inner)
    }

    /// Import the historical JSON field array at the cache persistence boundary.
    /// Stored spelling, order and even invalid fields survive until hydration.
    pub fn from_cache_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json).map(|inner| Self { inner })
    }

    /// Merge revalidation fields without exporting stored pairs. Predicates see
    /// only lowercase names: one excludes stored fields, the other excludes
    /// updates (e.g. representation labels and Connection-nominated fields).
    /// Content-Length updates are always excluded. Replacements retain stored
    /// spelling and position, and each field's duplicate order is preserved.
    pub fn merge_after_304(
        &self,
        not_modified_headers: &Headers,
        exclude_stored: impl Fn(&str) -> bool,
        exclude_update: impl Fn(&str) -> bool,
    ) -> Self {
        let mut nm = std::collections::HashMap::<String, Vec<String>>::new();
        for (name, value) in not_modified_headers.inner.iter() {
            let lower = name.as_str().to_ascii_lowercase();
            if lower == "content-length" || exclude_update(lower.as_str()) {
                continue;
            }
            let Ok(value) = value.to_str() else {
                continue;
            };
            nm.entry(lower).or_default().push(value.to_string());
        }

        let mut out = Vec::new();
        let mut replaced = std::collections::HashSet::new();
        let mut saw = std::collections::HashSet::new();

        for (name, value) in &self.inner {
            let lower = name.to_ascii_lowercase();
            if exclude_stored(lower.as_str()) {
                continue;
            }
            saw.insert(lower.clone());

            // Excluded 304 fields never reach `nm`, so stored framing labels and
            // other kept fields always survive here unchanged.
            if let Some(values) = nm.get(lower.as_str()) {
                if replaced.insert(lower.clone()) {
                    for v in values {
                        out.push((name.clone(), v.clone()));
                    }
                }
                continue;
            }
            out.push((name.clone(), value.clone()));
        }

        for (name, values) in nm {
            if saw.contains(name.as_str()) {
                continue;
            }
            for v in values {
                out.push((name.clone(), v));
            }
        }

        Self { inner: out }
    }

    /// Rebuild an owner-backed head from historical pairs, preserving
    /// per-name duplicate order and literal Content-Length spellings.
    /// Invalid names or values are skipped, matching historical hydration.
    /// Non-text values never appear here; they were omitted at capture.
    pub fn hydrate(&self) -> Headers {
        let mut out = Headers::new();
        for (name, value) in &self.inner {
            let Ok(name) = http::header::HeaderName::from_bytes(name.as_bytes()) else {
                continue;
            };
            let Ok(value) = http::HeaderValue::from_str(value.as_str()) else {
                continue;
            };
            if name == CONTENT_LENGTH {
                out.append_content_length_value(value);
            } else {
                let Ok(ordinary) = OrdinaryHeaderName::try_from(name) else {
                    continue;
                };
                out.append(ordinary, value);
            }
        }
        out
    }

    /// Declared length without exposing framing text, matching
    /// `declared_content_length_in_named_values` on the historical pairs.
    pub fn declared_content_length(&self) -> Option<u64> {
        crate::http_content_length::declared_content_length_in_named_values(
            self.inner.iter().map(|(name, value)| (name, value)),
        )
        .ok()
        .flatten()
    }
}

/// How a captured field is applied to its destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderTransferMode {
    /// Keep existing occurrences, adding the captured first value last.
    Append,
    /// Replace every existing occurrence with the captured first value.
    Replace,
}

/// An opaque selected-field copy for configured header pass/copy operations.
///
/// Capture uses only the first occurrence, even if it is nontextual or an
/// invalid Content-Length. Apply preserves its exact bytes and sensitivity;
/// an absent source is a no-op, including in replace mode. No numeric length
/// is read and no selected value is returned. Debug hides both names and values.
///
/// An owner-backed source can only be copied under the same field name, so
/// Content-Length cannot be renamed to an ordinary readable field:
/// ```compile_fail,E0061
/// use qpx_core::http_message::{HeaderTransferPatch, Headers};
/// use http::header::{CONTENT_LENGTH, HeaderName};
/// let source = Headers::new();
/// let other = HeaderName::from_static("x-readable");
/// let _ = HeaderTransferPatch::from_headers(&source, CONTENT_LENGTH, other);
/// ```
/// A standard response source supports the configured response-to-request copy
/// operation, including an explicit rename; it does not expose its value:
/// ```
/// use qpx_core::http_message::{HeaderTransferPatch, HeaderTransferMode, Headers};
/// use http::header::{CONTENT_LENGTH, COOKIE, HeaderName, HeaderValue};
/// let mut source = http::Response::new(());
/// source.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from_static(" 007 "));
/// let destination_name = HeaderName::from_static("content-length");
/// let patch = HeaderTransferPatch::from_response(&source, CONTENT_LENGTH, destination_name);
/// let mut destination = Headers::new();
/// patch.apply(&mut destination, HeaderTransferMode::Replace);
/// assert_eq!(destination, qpx_core::http_message::Request::from_http({
///     let mut request = http::Request::new(());
///     request.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from_static(" 007 "));
///     request
/// }).headers().clone());
/// ```
/// This capability does not expose maps or values:
/// ```compile_fail,E0616
/// use qpx_core::http_message::{HeaderTransferPatch, Headers};
/// use http::header::CONTENT_LENGTH;
/// let patch = HeaderTransferPatch::from_headers(&Headers::new(), CONTENT_LENGTH);
/// let _ = patch.value;
/// ```
/// ```compile_fail,E0599
/// use qpx_core::http_message::{HeaderTransferPatch, Headers};
/// use http::header::CONTENT_LENGTH;
/// let patch = HeaderTransferPatch::from_headers(&Headers::new(), CONTENT_LENGTH);
/// let _ = patch.get();
/// ```
/// ```compile_fail,E0599
/// use qpx_core::http_message::{HeaderTransferPatch, Headers};
/// use http::header::CONTENT_LENGTH;
/// let patch = HeaderTransferPatch::from_headers(&Headers::new(), CONTENT_LENGTH);
/// let _ = patch.iter();
/// ```
/// ```compile_fail,E0599
/// use qpx_core::http_message::{HeaderTransferPatch, Headers};
/// use http::header::CONTENT_LENGTH;
/// let patch = HeaderTransferPatch::from_headers(&Headers::new(), CONTENT_LENGTH);
/// let _ = patch.into_header_map();
/// ```
/// ```compile_fail,E0277
/// use qpx_core::http_message::{HeaderTransferPatch, Headers};
/// use http::header::CONTENT_LENGTH;
/// fn raw<T: AsRef<http::HeaderMap>>(_: &T) {}
/// raw(&HeaderTransferPatch::from_headers(&Headers::new(), CONTENT_LENGTH));
/// ```
/// ```compile_fail,E0277
/// use qpx_core::http_message::{HeaderTransferPatch, Headers};
/// use http::header::CONTENT_LENGTH;
/// fn raw<T: std::ops::Deref<Target = http::HeaderMap>>(_: &T) {}
/// raw(&HeaderTransferPatch::from_headers(&Headers::new(), CONTENT_LENGTH));
/// ```
/// ```compile_fail,E0277
/// use qpx_core::http_message::{HeaderTransferPatch, Headers};
/// use http::header::CONTENT_LENGTH;
/// let patch = HeaderTransferPatch::from_headers(&Headers::new(), CONTENT_LENGTH);
/// let _ = serde_json::to_string(&patch);
/// ```
/// Standard response transfer accepts a message, not a raw header map:
/// ```compile_fail,E0308
/// use qpx_core::http_message::HeaderTransferPatch;
/// use http::header::CONTENT_LENGTH;
/// use http::HeaderMap;
/// let _ = HeaderTransferPatch::from_response(&HeaderMap::new(), CONTENT_LENGTH, CONTENT_LENGTH);
/// ```
#[derive(Clone)]
pub struct HeaderTransferPatch {
    destination: HeaderName,
    value: Option<HeaderValue>,
}

impl fmt::Debug for HeaderTransferPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderTransferPatch")
            .finish_non_exhaustive()
    }
}

impl HeaderTransferPatch {
    /// Capture the first occurrence from an owned head without exposing it.
    pub fn from_headers(source: &Headers, name: HeaderName) -> Self {
        Self {
            value: source.inner.get(&name).cloned(),
            destination: name,
        }
    }

    /// Capture the first occurrence of an owned response for a named destination.
    /// Literal bytes and sensitivity stay opaque, including Content-Length.
    pub fn from_owned_response<B>(
        source: &Response<B>,
        name: HeaderName,
        destination: HeaderName,
    ) -> Self {
        Self {
            value: source.headers.inner.get(&name).cloned(),
            destination,
        }
    }

    /// A caller-supplied literal replacement, never a read of stored framing text.
    pub fn literal(destination: HeaderName, value: HeaderValue) -> Self {
        Self {
            destination,
            value: Some(value),
        }
    }

    /// Apply at a standard library response boundary without exposing its fields.
    pub fn apply_to_http_response<B>(
        self,
        response: &mut http::Response<B>,
        mode: HeaderTransferMode,
    ) {
        if let Some(value) = self.value {
            match mode {
                HeaderTransferMode::Replace => {
                    response.headers_mut().insert(self.destination, value);
                }
                HeaderTransferMode::Append => {
                    response.headers_mut().append(self.destination, value);
                }
            }
        }
    }

    /// Capture the first occurrence from a standard response, with the
    /// destination name supplied by the configured capture action.
    pub fn from_response<B>(
        source: &http::Response<B>,
        name: HeaderName,
        destination: HeaderName,
    ) -> Self {
        Self {
            value: source.headers().get(&name).cloned(),
            destination,
        }
    }

    /// Apply the captured value once. Absence never removes a destination field.
    pub fn apply(self, headers: &mut Headers, mode: HeaderTransferMode) {
        let Some(value) = self.value else {
            return;
        };
        match (self.destination == CONTENT_LENGTH, mode) {
            (true, HeaderTransferMode::Append) => headers.append_content_length_value(value),
            (true, HeaderTransferMode::Replace) => headers.set_content_length_value(value),
            (false, HeaderTransferMode::Append) => {
                headers.append(OrdinaryHeaderName(self.destination), value);
            }
            (false, HeaderTransferMode::Replace) => {
                headers.insert(OrdinaryHeaderName(self.destination), value);
            }
        }
    }
}

/// The finite encodings supported by configured selected-field expansion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderExpansionEncoding {
    /// Percent encode every non-alphanumeric byte (not form-urlencoding).
    UrlQuery,
    /// Like UrlQuery, including encoding slashes and punctuation.
    PathSegment,
    /// Reject ASCII controls and validate as a HeaderValue, preserving text.
    Header,
    /// Accept an IP address or the existing ASCII hostname grammar.
    Host,
}

/// Declarative input only: literals or named fields with a finite encoding.
///
/// There is no placeholder parser, request context, callback or raw modifier.
/// The caller retains responsibility for its configured template grammar.
#[derive(Clone)]
pub enum HeaderExpansionSegment {
    /// Caller-provided template text, copied verbatim.
    Literal(String),
    /// Select the first occurrence and apply the chosen encoding inside the owner.
    Field {
        /// Selected field, including a literal Content-Length name.
        name: HeaderName,
        /// Encoding and validation to apply to the selected text.
        encoding: HeaderExpansionEncoding,
    },
}

impl fmt::Debug for HeaderExpansionSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderExpansionSegment")
            .finish_non_exhaustive()
    }
}

/// A configured expansion executed inside the header owner.
///
/// Only the complete output string escapes. Selection uses HeaderMap's first
/// occurrence: absent or nontextual first values substitute empty text, without
/// seeking later duplicates. This also applies to literal Content-Length text,
/// including padded, invalid and conflicting declarations; it never resolves a
/// numeric length. Empty substitutions still undergo the selected validation
/// (so Host rejects them). Literals are copied verbatim, not encoded/validated.
/// Debug and errors never include selected values or contextual literals.
///
/// This is a configured effect, not a general Content-Length text accessor:
/// ```compile_fail,E0308
/// use qpx_core::http_message::Headers;
/// let _ = Headers::new().get(&http::header::CONTENT_LENGTH);
/// ```
/// ```compile_fail,E0599
/// use qpx_core::http_message::Headers;
/// let _ = Headers::new().content_length_text();
/// ```
/// ```compile_fail,E0616
/// use qpx_core::http_message::HeaderExpansionPlan;
/// let plan = HeaderExpansionPlan::new([]);
/// let _ = plan.segments;
/// ```
#[derive(Clone)]
pub struct HeaderExpansionPlan {
    segments: Vec<HeaderExpansionSegment>,
}

impl fmt::Debug for HeaderExpansionPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderExpansionPlan")
            .finish_non_exhaustive()
    }
}

/// Static expansion diagnostics, with no selected field names or values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderExpansionError {
    /// The selected text contained an ASCII control character.
    #[error("template header value contains a control character")]
    HeaderControlCharacter,
    /// HeaderValue validation rejected the selected text.
    #[error("invalid template header value")]
    InvalidHeaderValue,
    /// Host expansion selected empty text, including absent/nontextual fields.
    #[error("template host value must not be empty")]
    EmptyHost,
    /// A non-IP host contained controls or authority/path delimiters.
    #[error("template host value contains invalid characters")]
    InvalidHostCharacters,
    /// A non-IP host failed the ASCII hostname label grammar.
    #[error("template host value is not a valid host name")]
    InvalidHostName,
}

impl HeaderExpansionPlan {
    /// Build a configured effect from literals and selected-field encodings.
    pub fn new(segments: impl IntoIterator<Item = HeaderExpansionSegment>) -> Self {
        Self {
            segments: segments.into_iter().collect(),
        }
    }

    /// Render the whole plan, or return a value-free validation error.
    pub fn render(&self, headers: &Headers) -> Result<String, HeaderExpansionError> {
        use HeaderExpansionEncoding as Encoding;
        use HeaderExpansionError as Error;
        use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

        let mut out = String::new();
        for segment in &self.segments {
            let (name, encoding) = match segment {
                HeaderExpansionSegment::Literal(literal) => {
                    out.push_str(literal);
                    continue;
                }
                HeaderExpansionSegment::Field { name, encoding } => (name, encoding),
            };
            let value = headers
                .inner
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            match encoding {
                Encoding::UrlQuery | Encoding::PathSegment => {
                    out.extend(utf8_percent_encode(value, NON_ALPHANUMERIC));
                }
                Encoding::Header => {
                    if value.bytes().any(|byte| byte.is_ascii_control()) {
                        return Err(Error::HeaderControlCharacter);
                    }
                    HeaderValue::from_str(value).map_err(|_| Error::InvalidHeaderValue)?;
                    out.push_str(value);
                }
                Encoding::Host => {
                    validate_expansion_host(value)?;
                    out.push_str(value);
                }
            }
        }
        Ok(out)
    }
}

fn validate_expansion_host(value: &str) -> Result<(), HeaderExpansionError> {
    use HeaderExpansionError as Error;
    if value.is_empty() {
        return Err(Error::EmptyHost);
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if value.bytes().any(|byte| byte.is_ascii_control())
        || value.contains(['/', '?', '#', '@', ':'])
    {
        return Err(Error::InvalidHostCharacters);
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::InvalidHostName);
        }
    }
    Ok(())
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
#[derive(Clone, Debug)]
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

    /// Transfer to a genuine library consumer that requires `http::Response`.
    ///
    /// Unlike [`Self::into_http_for_codec`], this moves the complete message
    /// without validating, filtering or canonicalizing Content-Length. Field
    /// bytes, duplicate order and sensitivity, status, version, extensions and
    /// the body are unchanged, including malformed or conflicting declarations.
    /// Use this only across an actual library hook, importing its result with
    /// [`Self::from_http`]; it is not an in-domain processing or serializer API.
    pub fn into_http_for_library(self) -> http::Response<B> {
        let mut response = http::Response::new(self.body);
        *response.status_mut() = self.status;
        *response.version_mut() = self.version;
        *response.headers_mut() = self.headers.inner;
        *response.extensions_mut() = self.extensions;
        response
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
