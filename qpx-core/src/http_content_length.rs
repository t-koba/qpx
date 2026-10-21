//! The declared Content-Length.
//!
//! RFC 9110 section 8.6 gives the field one grammar: every value is a
//! comma-separated list of `1*DIGIT` members, and every member of every
//! value declares the same length, so a value that names two different
//! lengths is a conflict rather than a choice.
//!
//! The member grammar, the conflict rule and the two entry points have
//! one owner, and it sits in qpx-core, below every crate that reads the
//! declaration, so the HTTP stack and the IPC gateway read the field the
//! same way instead of each keeping its own interpretation.

use http::HeaderMap;
use http::header::CONTENT_LENGTH;
use thiserror::Error;

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

/// The Content-Length that a header set declares.
///
/// RFC 9110 section 8.6: every value is a comma-separated list of `1*DIGIT`
/// members, and every member of every value declares the same length, so a
/// value that names two different lengths is a conflict rather than a choice.
///
/// The owner sits beside the member grammar it uses, so the HTTP/1 and
/// HTTP/2 codecs, the HTTP/3 codec and listener, the cache, the upstream
/// raw HTTP/1 path, the reverse raw HTTP/1 path, the reverse mirror path,
/// the reverse request template and the request validation read the field
/// the same way instead of each keeping its own interpretation.
///
/// The sites that read the declaration through a helper are named here, so
/// the Content-Length gate can check that this list and the tree agree:
///
/// - `qpxd/src/http/body/size/io.rs` reads one value as a size hint rather
///   than a declaration.
///
/// The upstream raw HTTP/1 path reads the declaration through the owner as
/// well: `qpxd/src/upstream/raw_http1/mod.rs` calls it with the header map
/// it holds, and `qpxd/src/upstream/raw_http1/raw_head.rs`, which reads raw
/// header lines rather than a header map, hands the field's values to the
/// owner's value-level entry point. A leading plus sign is refused there
/// too, so an upstream response that frames its body with one is rejected
/// instead of read.
///
/// The reverse raw HTTP/1 path reads the declaration through the owner as
/// well: `qpxd/src/reverse/transport/raw_http1.rs` reads raw header lines
/// rather than a header map, so it hands the field's values to the owner's
/// value-level entry point, and the length it reads says whether the
/// request may carry a body. A leading plus sign is refused there, so a
/// request that declares its length as "+0" is treated as one that may
/// carry a body instead of one without a body, and the fast path is
/// declined for it. A comma list of equal members is still one length and
/// two members that disagree are still a conflict.
///
/// The reverse mirror path reads the declaration through the owner as well:
/// `qpxd/src/reverse/transport/mirrors.rs` calls it for the length that
/// says whether a request can be mirrored. A comma list of equal members is
/// one length there now, so such a request can be mirrored, and a leading
/// plus sign is refused, so a request that declares its length that way is
/// not mirrored.
///
/// The reverse request template reads the declaration through the owner as
/// well: `qpxd/src/reverse/transport/request_template.rs` calls it for the
/// length a retry may buffer and for the length that says whether the
/// request may carry a body. A comma list of equal members is one length
/// there now, so such a request is retried within the threshold, and a
/// leading plus sign is refused, so a request that declares its length that
/// way is not retried.
///
/// The HTTP/3 path reads the declaration through the owner as well:
/// `qpx-h3/src/response.rs` hands the header map to it, so the HTTP/3 server
/// and client frame a body from the same length the HTTP/1 and HTTP/2 paths
/// read. A leading plus sign is refused there too, and the request and the
/// response sides treat that differently: a request that declares its
/// length that way is refused, while a response that declares it that way
/// has the field dropped rather than the response refused.
///
/// The cache reads the declaration through the owner as well:
/// `qpxd-cache/src/entry.rs` hands the stored response's Content-Length
/// values to the owner's value-level entry point, and the test helper in
/// `qpxd-cache/src/util.rs` hands the header map to it. A leading plus sign
/// is refused there too, so a stored response that declares its length that
/// way declares no length: the cache falls back to the stored body's length,
/// and the helper reports no cacheable length.
///
/// The IPC gateway reads the declaration through the owner as well:
/// `qpxf/src/ipc_request.rs` hands the header list's Content-Length values
/// to the owner's value-level entry point, so the length that says how many
/// stdin bytes the script may read is the length the field declares. A
/// leading plus sign is refused there too, so a request that declares its
/// length that way is refused instead of read, and a comma list of equal
/// members is one length there as well.
/// The gate finds those helpers by the names the workspace has used for
/// them, so a site that reads the declaration inline is outside both the
/// list and the gate. Those sites are named here as well, so that the record
/// of the sites that read the declaration is complete:
/// `qpxd-cache/src/backend_http.rs` compares the cached response's declared
/// length with the expected body length, `qpxd/src/http/modules/response_compression.rs`
/// reads the declared length to decide whether the body is compressed,
/// `qpxd/src/http/capture/stream.rs`, `qpxd/src/http/modules/subrequest.rs`
/// and `qpxd/src/reverse/transport/raw_http1.rs` read it as a size hint, and
/// `qpxd/src/policy_context/decision_service/mod.rs` parses it to enforce a
/// hard cap.
///
/// The request guard in `qpxd/src/http/policy/guard.rs` compares the raw
/// field values rather than the length they declare, so it answers a
/// different question and keeps its own reading. A plain integer accepts a
/// leading plus sign that the grammar does not, so folding any of the named
/// sites changes what it accepts: each is a decision of its own.
pub fn declared_content_length(headers: &HeaderMap) -> Result<Option<u64>, ContentLengthError> {
    let mut values = Vec::new();
    for value in headers.get_all(CONTENT_LENGTH) {
        values.push(
            value
                .to_str()
                .map_err(|_| ContentLengthError::InvalidHeader)?,
        );
    }
    declared_content_length_in_values(values)
}

/// The Content-Length that a sequence of field values declares.
///
/// The values are the field's values in the order they appear, and each one
/// is a comma-separated list of `1*DIGIT` members (RFC 9110 section 8.6),
/// so two different lengths are a conflict rather than a choice.
///
/// A site that reads the declaration from raw header lines has no header
/// map to hand the owner, so it hands the values instead: the member
/// grammar and the conflict rule stay in one place.
pub fn declared_content_length_in_values<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<Option<u64>, ContentLengthError> {
    let mut declared = None::<u64>;
    for raw in values {
        for part in raw.split(',') {
            let length =
                parse_content_length_member(part).ok_or(ContentLengthError::InvalidValue)?;
            if let Some(previous) = declared
                && previous != length
            {
                return Err(ContentLengthError::Conflicting);
            }
            declared = Some(length);
        }
    }
    Ok(declared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn declared_content_length_reads_every_member_of_every_value() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("42, 42"));
        assert_eq!(declared_content_length(&headers), Ok(Some(42)));
    }

    #[test]
    fn declared_content_length_in_values_reads_every_member_of_every_value() {
        assert_eq!(
            declared_content_length_in_values(["42", "42, 42"]),
            Ok(Some(42))
        );
        assert_eq!(
            declared_content_length_in_values(Vec::<&str>::new()),
            Ok(None)
        );
    }

    #[test]
    fn declared_content_length_in_values_rejects_a_member_that_is_not_digits() {
        for values in [
            vec!["+5"],
            vec!["5, +5"],
            vec![""],
            vec!["4,"],
            vec!["4,,4"],
        ] {
            assert_eq!(
                declared_content_length_in_values(values),
                Err(ContentLengthError::InvalidValue)
            );
        }
    }

    #[test]
    fn declared_content_length_in_values_rejects_conflicting_members() {
        assert_eq!(
            declared_content_length_in_values(["5", "6"]),
            Err(ContentLengthError::Conflicting)
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
