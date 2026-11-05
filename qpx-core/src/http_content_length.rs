//! The declared Content-Length.
//!
//! RFC 9110 section 8.6 gives the field one grammar, `Content-Length =
//! 1*DIGIT`, so the value a sender writes is one decimal. The section
//! also names the one exception a recipient has: a value that is the same
//! decimal repeated as a comma-separated list may be rejected or
//! replaced with a single instance of the decimal, because it likely
//! means an upstream processor combined a duplicate. qpx takes the
//! replacement, so its reader treats an equal-member comma list as one
//! length, and a value that names two different lengths is a conflict
//! rather than a choice.
//!
//! The member grammar, the conflict rule and the entry points have one
//! owner, and it sits in qpx-core, below every crate that reads the
//! declaration, so the HTTP stack and the IPC gateway read the field the
//! same way instead of each keeping its own interpretation.
//!
//! The owner has an entry point for a header map and one for a sequence
//! of named header values, so a site that reads raw header lines reaches
//! the owner as well and does not select the field's values itself.
//!
//! The field has a sending half as well, and the owner holds it too.
//! The section's sender rule forbids forwarding a value that does not
//! match the grammar, and the section's one exception lets a recipient
//! of an equal-member comma list either reject the message or replace
//! that value with a single instance of the decimal value. qpx
//! replaces it: the owner holds the value a writer emits for a resolved
//! length, and the writers that forward a declaration write that value,
//! so the field leaves as one field line whose value is the resolved
//! decimal.
//!
//! A declaration the owner refuses names no length, so the message it
//! came in has ambiguous framing, and the tree answers each side of
//! that. A request that carries one is answered with a bad request, and
//! the HTTP/1 edge closes the connection, because a request whose length
//! cannot be determined cannot be framed. A response from an origin
//! that carries one is refused as well: the proxy answers the client
//! with a bad gateway, and the connection to the origin is closed rather
//! than reused, because the origin's framing is unknown. The reverse
//! path may try another origin first, which is a new request rather
//! than a forwarding of the response that could not be framed.
//!
//! The writers that write it are the ones this tree owns: the HTTP/1
//! request writer, the HTTP/1 raw response relay, the reverse raw
//! HTTP/1 fast path, the HTTP/1 response writers to the client, the
//! HTTP/2 request and response writers, the HTTP/3 request and response
//! writers, and the HTTP/3 library's response head sanitizer. The paths
//! that hand a header map to Hyper's HTTP/1 client writer first replace a
//! resolved declaration with this owner's canonical value, so the library
//! writes one decimal rather than the text that arrived. A declaration
//! this owner refuses is left for the writer's own rules to handle.

use http::HeaderMap;
use http::HeaderValue;
use http::header::CONTENT_LENGTH;
use thiserror::Error;

/// The field's name, as a header spells it.
///
/// The name is compared case-insensitively, as HTTP requires, so a site
/// that reads raw header lines reaches the owner without selecting the
/// field's values itself.
const CONTENT_LENGTH_NAME: &[u8] = b"content-length";

/// Parses one Content-Length comma-list member per RFC 9110 §8.6
/// (`1*DIGIT`): the trimmed member must be a nonempty ASCII digit sequence,
/// then the `u64` value. Plain integer parsing would also accept a leading
/// `+` sign, which is not valid field syntax.
pub fn parse_content_length_member(part: &str) -> Option<u64> {
    let digits = part.trim();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()
}

/// The error a declared Content-Length carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ContentLengthError {
    /// A field value is not readable as text.
    #[error("invalid content-length header")]
    InvalidHeader,
    /// A member is not a `1*DIGIT` sequence.
    #[error("invalid content-length value")]
    InvalidValue,
    /// Two members declare different lengths.
    #[error("conflicting content-length values")]
    Conflicting,
}

/// Resolve the declared Content-Length across every field occurrence and
/// comma-list member. An absent field is `Ok(None)`; an explicit zero is
/// `Ok(Some(0))`. Equal numeric members (including leading zeroes) name one
/// length; different lengths return [`ContentLengthError::Conflicting`].
/// Each member must satisfy the decimal grammar of [`parse_content_length_member`].
///
/// All field values are checked for textual validity before parsing any member,
/// so [`ContentLengthError::InvalidHeader`] takes precedence over invalid numeric
/// syntax or conflicting lengths. No header is changed by this reader.
///
/// In-domain callers use [`crate::http_message::Headers::declared_content_length`]
/// without access to the raw map. Codec/library boundaries with a raw map use
/// this entry point; raw header lines use [`declared_content_length_in_named_values`].
pub fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, ContentLengthError> {
    // Every value is read as text before any member is parsed, so a field
    // that carries a value which is not text is reported the same way
    // whatever else the field carries.
    for value in headers.get_all(CONTENT_LENGTH) {
        value
            .to_str()
            .map_err(|_| ContentLengthError::InvalidHeader)?;
    }
    let mut declared = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let value = value
            .to_str()
            .map_err(|_| ContentLengthError::InvalidHeader)?;
        merge_value(value, &mut declared)?;
    }
    Ok(declared)
}

/// Merges one field value's members into the length the field declares so
/// far.
///
/// Every member of the value declares the same length, so a value that
/// names two different lengths is a conflict rather than a choice.
fn merge_value(value: &str, declared: &mut Option<u64>) -> Result<(), ContentLengthError> {
    for part in value.split(',') {
        let length = parse_content_length_member(part).ok_or(ContentLengthError::InvalidValue)?;
        if let Some(previous) = *declared
            && previous != length
        {
            return Err(ContentLengthError::Conflicting);
        }
        *declared = Some(length);
    }
    Ok(())
}

/// The Content-Length that a sequence of field values declares.
///
/// The values are the field's values in the order they appear. The
/// field's grammar is one decimal (RFC 9110 section 8.6), and the
/// section's one exception lets a recipient treat a value that is the
/// same decimal repeated as a comma-separated list as that decimal, so a
/// value here may hold such a list and still name one length. Two
/// different lengths are a conflict rather than a choice.
///
/// The field's sending half belongs to the owner as well: the grammar a
/// sender writes is one decimal, so the value the owner writes for a
/// resolved length is a single instance of that decimal, and a writer
/// that replaces the declaration it received with it emits one field
/// line whose value is the resolved decimal.
///
/// The Content-Length that a sequence of named header values declares.
///
/// The field's sending half belongs to the owner as well: the grammar a
/// sender writes is one decimal, so the value the owner writes for a
/// resolved length is a single instance of that decimal, and a writer
/// that replaces the declaration it received with it emits one field
/// line whose value is the resolved decimal.
///
/// A site that reads raw header lines has no header map to hand the
/// owner, so it hands the lines themselves: the owner finds the field's
/// own values by their name, matched case-insensitively as HTTP requires,
/// and reads them with the same member grammar and the same conflict rule
/// as every other reader. A site that selected the field's values itself
/// kept a second reading of the field, which is the shape this owner
/// removes.
///
/// The names and the values are borrowed as bytes, so a site whose lines
/// are raw bytes and a site whose lines are text reach the owner without
/// copying them.
///
/// A value that is not text is refused before a conflict is reported, even
/// when the conflict is in an earlier value: the values are read as text
/// first and the members are merged afterwards, so the first value that
/// cannot be read is the error.
pub fn declared_content_length_in_named_values<'a, N, V>(
    headers: impl IntoIterator<Item = (&'a N, &'a V)>,
) -> Result<Option<u64>, ContentLengthError>
where
    N: AsRef<[u8]> + ?Sized + 'a,
    V: AsRef<[u8]> + ?Sized + 'a,
{
    let mut declared = None::<u64>;
    let mut merge_error = None;
    for (name, value) in headers {
        let name: &[u8] = name.as_ref();
        if !name.eq_ignore_ascii_case(CONTENT_LENGTH_NAME) {
            continue;
        }
        let value: &[u8] = value.as_ref();
        let value = std::str::from_utf8(value).map_err(|_| ContentLengthError::InvalidHeader)?;
        if merge_error.is_none()
            && let Err(error) = merge_value(value, &mut declared)
        {
            merge_error = Some(error);
        }
    }
    match merge_error {
        Some(error) => Err(error),
        None => Ok(declared),
    }
}

/// Replaces the field's values with the canonical value for the length
/// they declare.
///
/// The field's grammar is one decimal, so a sender writes one field line
/// whose value is the resolved decimal. A path that hands a header map to
/// another library's writer calls this first, so the library writes the
/// value the section allows rather than the text that arrived.
///
/// A declaration the owner refuses names no length, so the field is left
/// as it is: the writer's own rules decide what a declaration it cannot
/// read means.
pub fn canonicalize_content_length(headers: &mut HeaderMap) {
    let Ok(Some(length)) = declared_content_length(headers) else {
        return;
    };
    headers.insert(CONTENT_LENGTH, canonical_content_length_value(length));
}

/// The canonical field value for a resolved length.
///
/// RFC 9110 section 8.6 gives the field the grammar `1*DIGIT`, so the
/// value a sender writes is one decimal and nothing else. The same
/// section's sender rule forbids forwarding a value that does not match
/// that grammar, and the section's one exception lets a recipient of an
/// equal-member comma list either reject the message or replace that
/// value with a single instance of the decimal value. qpx replaces it,
/// so a writer emits one field line whose value is the resolved decimal.
///
/// The value belongs to the owner, so a writer does not format the
/// decimal itself: a writer that has resolved a length asks the owner
/// for the value of that length and writes what the owner gives it.
pub fn canonical_content_length_value(length: u64) -> HeaderValue {
    HeaderValue::from(length)
}

/// Opaque header view for policy matching and cache Vary selection.
///
/// Matchers using `RuleMatchContext` receive this view instead of the raw map.
/// Its closed predicates expose no raw accessor, `Deref`, conversion, or
/// value callback; Debug also hides the map. This boundary does not enforce
/// header ownership elsewhere in the workspace. Trace diagnostics intentionally
/// expose the selected textual value. Cache Vary selection deliberately exposes
/// a normalized textual projection; this is not whole-workspace ownership.
///
/// Configured names remain case-insensitive and dynamic. Predicates require a
/// textual value: invalid `to_str()` values are skipped, and value order is
/// preserved. Traces report the first matching value, else the first textual
/// value. An absent context map cannot match a nonempty matcher list.
///
/// ```compile_fail
/// use http::HeaderMap;
/// use qpx_core::http_content_length::HeaderView;
///
/// let map = HeaderMap::new();
/// let view = HeaderView::new(&map);
/// let _ = view.inner;
/// ```
#[derive(Clone, Copy)]
pub struct HeaderView<'a> {
    inner: &'a HeaderMap,
}

impl std::fmt::Debug for HeaderView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeaderView").finish_non_exhaustive()
    }
}

/// Closed predicates evaluated by the header owner, never by a value callback.
#[derive(Clone, Copy)]
pub enum HeaderPredicate<'a> {
    /// At least one textual value exists, including an empty value.
    Present,
    /// A textual value equals the configured string.
    Exact(&'a str),
    /// A textual value matches the compiled expression.
    Regex(&'a regex::Regex),
}

/// The diagnostic a header trace reports for one configured name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderDiagnostic {
    /// The first matching textual value, else the first textual value.
    pub actual: Option<String>,
    /// Whether a textual value matched.
    pub matched: bool,
}

/// Closed result of selecting a field's ordered textual values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderTextSelection {
    /// The name is invalid or unavailable here, or a value is not representable as text.
    Unrepresentable,
    /// No field value exists for the validated name.
    Absent,
    /// All values, individually trimmed and comma-joined in encounter order.
    Present(String),
}

/// An opaque, literal `Vary` selector, including for Content-Length.
///
/// Equality uses the existing cache encoding: absence is `\x00`, presence is
/// `\x01` followed by individually trimmed, comma-joined occurrences. This is
/// deliberately not the numeric framing interpretation (`05` differs from `5`).
/// All fields use this type so deserializing a persisted Content-Length selector
/// cannot accidentally restore it as an ordinary, publicly readable string.
///
/// Serde is the explicit persistence boundary and retains the historical string
/// wire format. Ordinary consumers can clone, compare and derive a variant digest,
/// but cannot read the text. Debug is redacted, and there is deliberately no Hash
/// implementation: a caller-supplied hasher could observe the input bytes.
/// This only encapsulates Vary selection, not other HeaderView policy APIs.
///
/// External consumers (including the cache crate) cannot access the field:
/// ```compile_fail,E0616
/// use qpx_core::http_content_length::VarySelector;
/// let selector = VarySelector::from(String::from("\x0105"));
/// let raw = selector.0;
/// ```
/// Nor can they obtain text or bytes through an accessor:
/// ```compile_fail,E0599
/// use qpx_core::http_content_length::VarySelector;
/// let selector = VarySelector::from(String::from("\x0105"));
/// let raw = selector.as_str();
/// ```
/// ```compile_fail,E0599
/// use qpx_core::http_content_length::VarySelector;
/// let selector = VarySelector::from(String::from("\x0105"));
/// let raw = selector.as_bytes();
/// ```
/// ```compile_fail,E0277
/// use qpx_core::http_content_length::VarySelector;
/// fn requires_hash<T: std::hash::Hash>() {}
/// requires_hash::<VarySelector>();
/// ```
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct VarySelector(String);

impl std::fmt::Debug for VarySelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VarySelector([redacted])")
    }
}

/// Accept caller-owned text (for example a synthetic selector or a persistence
/// fixture) without providing the reverse conversion.
impl From<String> for VarySelector {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl VarySelector {
    /// Hash the historical `name=value|` stream with a fixed SHA-256 algorithm.
    /// The digest, not a caller-supplied hasher, crosses the ownership boundary.
    /// Keeping the original stream preserves existing variant storage keys.
    pub fn variant_digest(values: &[(String, Self)]) -> [u8; 32] {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        for (name, value) in values {
            hasher.update(name.as_bytes());
            hasher.update(b"=");
            hasher.update(value.0.as_bytes());
            hasher.update(b"|");
        }
        hasher.finalize().into()
    }
}

impl<'a> HeaderView<'a> {
    /// Borrows a header map for closed selection and policy matching.
    pub fn new(map: &'a HeaderMap) -> Self {
        Self { inner: map }
    }

    /// Selects a validated, case-insensitive name as trimmed, comma-joined text.
    ///
    /// Unlike policy predicates, any non-textual duplicate fails the selection.
    /// Content-Length is unavailable through this generic text API (even when
    /// absent); use the opaque [`Self::vary_selector`] instead.
    pub fn joined_text(&self, name: &str) -> HeaderTextSelection {
        if name.eq_ignore_ascii_case("content-length") {
            return HeaderTextSelection::Unrepresentable;
        }
        self.joined_text_inner(name)
    }

    /// Select literal Vary equivalence without exposing Content-Length text.
    /// Invalid names and any non-textual occurrence fail closed. Absence and
    /// present-empty remain distinct; occurrence boundaries are comma-joined,
    /// so one `a,b` value equals two values `a` and `b`.
    pub fn vary_selector(&self, name: &str) -> Option<VarySelector> {
        match self.joined_text_inner(name) {
            HeaderTextSelection::Unrepresentable => None,
            HeaderTextSelection::Absent => Some(VarySelector("\x00".to_owned())),
            HeaderTextSelection::Present(value) => Some(VarySelector(format!("\x01{value}"))),
        }
    }

    fn joined_text_inner(&self, name: &str) -> HeaderTextSelection {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            return HeaderTextSelection::Unrepresentable;
        };
        let mut joined = None;
        for value in self.inner.get_all(name).iter() {
            let Ok(text) = value.to_str() else {
                return HeaderTextSelection::Unrepresentable;
            };
            match &mut joined {
                None => joined = Some(text.trim().to_owned()),
                Some(out) => {
                    out.push(',');
                    out.push_str(text.trim());
                }
            }
        }
        match joined {
            None => HeaderTextSelection::Absent,
            Some(text) => HeaderTextSelection::Present(text),
        }
    }

    /// Whether any textual value for `name` matches, without allocating.
    pub fn matches(&self, name: &str, predicate: HeaderPredicate<'_>) -> bool {
        self.evaluate(name, predicate).1
    }

    /// Reports the first matching textual value, else the first textual value.
    pub fn trace(&self, name: &str, predicate: HeaderPredicate<'_>) -> HeaderDiagnostic {
        let (actual, matched) = self.evaluate(name, predicate);
        HeaderDiagnostic {
            actual: actual.map(str::to_owned),
            matched,
        }
    }

    fn evaluate(&self, name: &str, predicate: HeaderPredicate<'_>) -> (Option<&str>, bool) {
        let mut first = None;
        for value in self
            .inner
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
        {
            first.get_or_insert(value);
            let matched = match predicate {
                HeaderPredicate::Present => true,
                HeaderPredicate::Exact(expected) => value == expected,
                HeaderPredicate::Regex(regex) => regex.is_match(value),
            };
            if matched {
                return (Some(value), true);
            }
        }
        (first, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn content_length_vary_selection_is_opaque_and_generic_text_is_closed() {
        for values in [vec![], vec![""], vec!["05"], vec![" 42 ", "43"]] {
            let mut headers = HeaderMap::new();
            for value in &values {
                headers.append(CONTENT_LENGTH, HeaderValue::from_str(value).unwrap());
            }
            let view = HeaderView::new(&headers);
            let expected = if values.is_empty() {
                "\x00".to_owned()
            } else {
                format!(
                    "\x01{}",
                    values
                        .iter()
                        .map(|v| v.trim())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            for name in ["content-length", "Content-Length", "CoNtEnT-LeNgTh"] {
                assert_eq!(view.joined_text(name), HeaderTextSelection::Unrepresentable);
                let selector = view.vary_selector(name).unwrap();
                assert_eq!(selector.0, expected);
                assert_eq!(format!("{selector:?}"), "VarySelector([redacted])");
                // Serde is intentionally the persistence escape, not a text accessor.
                assert_eq!(
                    serde_json::to_string(&selector).unwrap(),
                    serde_json::to_string(&expected).unwrap()
                );
                assert_eq!(
                    serde_json::from_str::<VarySelector>(
                        &serde_json::to_string(&expected).unwrap()
                    )
                    .unwrap(),
                    selector
                );
            }
        }
    }

    #[test]
    fn header_view_joined_text_validates_names_and_distinguishes_absent_from_empty() {
        let mut headers = HeaderMap::new();
        headers.insert("x-value", HeaderValue::from_static(""));
        let view = HeaderView::new(&headers);
        for name in ["", "bad name", "x-value:", "é"] {
            assert_eq!(view.joined_text(name), HeaderTextSelection::Unrepresentable);
        }
        assert_eq!(view.joined_text("x-missing"), HeaderTextSelection::Absent);
        assert_eq!(
            view.joined_text("X-Value"),
            HeaderTextSelection::Present(String::new())
        );
    }

    #[test]
    fn header_view_joined_text_preserves_order_and_trims_each_duplicate() {
        let mut headers = HeaderMap::new();
        for value in [" \tsecond ", "", " first\t", " a, b "] {
            headers.append("x-value", HeaderValue::from_static(value));
        }
        assert_eq!(
            HeaderView::new(&headers).joined_text("X-VALUE"),
            HeaderTextSelection::Present("second,,first,a, b".to_owned())
        );
    }

    #[test]
    fn header_view_joined_text_rejects_any_non_textual_duplicate() {
        for invalid_position in 0..3 {
            let mut headers = HeaderMap::new();
            for position in 0..3 {
                headers.append(
                    "x-value",
                    if position == invalid_position {
                        HeaderValue::from_bytes(&[0x80]).unwrap()
                    } else {
                        HeaderValue::from_static("ascii")
                    },
                );
            }
            assert_eq!(
                HeaderView::new(&headers).joined_text("x-value"),
                HeaderTextSelection::Unrepresentable
            );
        }
    }

    #[test]
    fn header_view_debug_redacts_values_including_context_headers_and_trailers() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("9384756102938475"));
        let view = HeaderView::new(&headers);
        let context = crate::rules::RuleMatchContext {
            headers: Some(view),
            rpc_trailers: Some(view),
            ..Default::default()
        };
        assert_eq!(format!("{view:?}"), "HeaderView { .. }");
        for rendered in [
            format!("{view:?}"),
            format!("{view:#?}"),
            format!("{context:?}"),
            format!("{context:#?}"),
        ] {
            assert!(!rendered.contains("9384756102938475"));
            assert!(!rendered.contains("content-length"));
        }
    }

    #[test]
    fn header_view_predicates_require_text_but_accept_empty_text() {
        let mut headers = HeaderMap::new();
        headers.append("x-value", HeaderValue::from_bytes(&[0xff]).unwrap());
        let regex = regex::Regex::new("^$").unwrap();
        for actual in [None, Some("")] {
            if let Some(value) = actual {
                headers.append("x-value", HeaderValue::from_static(value));
            }
            let view = HeaderView::new(&headers);
            for predicate in [
                HeaderPredicate::Present,
                HeaderPredicate::Exact(""),
                HeaderPredicate::Regex(&regex),
            ] {
                for (name, expected) in [("X-Value", actual), ("x-missing", None)] {
                    assert_eq!(view.matches(name, predicate), expected.is_some());
                    assert_eq!(
                        view.trace(name, predicate),
                        HeaderDiagnostic {
                            actual: expected.map(str::to_owned),
                            matched: expected.is_some(),
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn canonical_content_length_value_writes_one_decimal() {
        // The value a sender writes is one decimal, so the owner writes
        // the resolved length as that decimal and nothing else.
        assert_eq!(
            canonical_content_length_value(42).to_str().expect("text"),
            "42"
        );
        assert_eq!(
            canonical_content_length_value(0).to_str().expect("text"),
            "0"
        );
        assert_eq!(
            canonical_content_length_value(u64::MAX)
                .to_str()
                .expect("text"),
            "18446744073709551615"
        );
    }

    #[test]
    fn canonicalize_content_length_replaces_equal_members_with_one_decimal() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42, 42"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));

        canonicalize_content_length(&mut headers);

        let values: Vec<_> = headers.get_all(CONTENT_LENGTH).iter().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "42");
    }

    #[test]
    fn canonicalize_content_length_leaves_a_refused_declaration_unchanged() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("43"));

        canonicalize_content_length(&mut headers);

        let values: Vec<_> = headers.get_all(CONTENT_LENGTH).iter().collect();
        assert_eq!(values, ["42", "43"]);
    }

    #[test]
    fn declared_content_length_reads_every_member_of_every_value() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42, 42"));
        assert_eq!(declared_content_length(&headers), Ok(Some(42)));
    }

    #[test]
    fn declared_content_length_in_named_values_reads_the_field_by_its_name() {
        assert_eq!(
            declared_content_length_in_named_values([
                ("Content-Type", "text/plain"),
                ("Content-Length", "42"),
                ("content-length", "42, 42"),
            ]),
            Ok(Some(42))
        );
    }

    #[test]
    fn declared_content_length_in_named_values_ignores_the_other_fields() {
        assert_eq!(
            declared_content_length_in_named_values([("Content-Type", "text/plain")]),
            Ok(None)
        );
    }

    #[test]
    fn declared_content_length_in_named_values_rejects_a_member_that_is_not_digits() {
        for values in [
            vec![("Content-Length", "+5")],
            vec![("Content-Length", "5, +5")],
            vec![("Content-Length", "")],
            vec![("Content-Length", "4,")],
            vec![("Content-Length", "4,,4")],
        ] {
            assert_eq!(
                declared_content_length_in_named_values(values),
                Err(ContentLengthError::InvalidValue)
            );
        }
    }

    #[test]
    fn declared_content_length_in_named_values_reads_raw_bytes() {
        assert_eq!(
            declared_content_length_in_named_values([
                (&b"Content-Length"[..], &b"42"[..]),
                (&b"content-length"[..], &b"42"[..]),
            ]),
            Ok(Some(42))
        );
    }

    #[test]
    fn declared_content_length_in_named_values_rejects_a_value_that_is_not_text() {
        assert_eq!(
            declared_content_length_in_named_values([(&b"Content-Length"[..], &[0xff][..])]),
            Err(ContentLengthError::InvalidHeader)
        );
    }

    #[test]
    fn declared_content_length_in_named_values_rejects_conflicting_members() {
        assert_eq!(
            declared_content_length_in_named_values([
                ("Content-Length", "5"),
                ("content-length", "6"),
            ]),
            Err(ContentLengthError::Conflicting)
        );
    }

    #[test]
    fn declared_content_length_in_named_values_reports_a_value_that_is_not_text_first() {
        // A value that cannot be read is the error even when an earlier
        // value names two different lengths: the value that is not text is
        // refused before the conflict is reported.
        assert_eq!(
            declared_content_length_in_named_values([
                (&b"Content-Length"[..], &b"5, 6"[..]),
                (&b"content-length"[..], &[0xff][..]),
            ]),
            Err(ContentLengthError::InvalidHeader)
        );
    }

    #[test]
    fn declared_content_length_rejects_a_member_that_is_not_digits() {
        for value in ["+5", "-5", "5x", "", "4,", "4,,4"] {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_LENGTH, HeaderValue::from_static(value));
            assert_eq!(
                declared_content_length(&headers),
                Err(ContentLengthError::InvalidValue),
                "{value}"
            );
        }
    }

    #[test]
    fn declared_content_length_rejects_two_different_lengths() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("5"));
        assert_eq!(
            declared_content_length(&headers),
            Err(ContentLengthError::Conflicting)
        );

        let mut one_value = HeaderMap::new();
        one_value.insert(CONTENT_LENGTH, HeaderValue::from_static("4, 5"));
        assert_eq!(
            declared_content_length(&one_value),
            Err(ContentLengthError::Conflicting)
        );
    }

    #[test]
    fn declared_content_length_rejects_a_value_that_is_not_text() {
        let mut headers = HeaderMap::new();
        headers.append(
            CONTENT_LENGTH,
            HeaderValue::from_bytes(b"\xff").expect("opaque value"),
        );
        assert_eq!(
            declared_content_length(&headers),
            Err(ContentLengthError::InvalidHeader)
        );
    }
}
