//! Shared raw `Content-Type` media-type extraction.
//!
//! Both RPC protocol detection and response compression start from the same
//! raw value: the first `Content-Type` field, if readable, with any `;` parameters
//! stripped and surrounding whitespace trimmed. Case handling and matching
//! policy stay with the callers: RPC lowercases an owned copy for its prefix
//! checks, while compression matches case-insensitively against its
//! configured (possibly wildcard) patterns.
use http::HeaderMap;
use http::header::CONTENT_TYPE;

/// Returns the raw media type of the first `Content-Type` field when readable.
///
/// `None` when no field is present or the first field value is not valid header text.
/// No case folding is applied; see the module docs for caller policy.
pub(crate) fn raw_media_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|raw| raw.split(';').next().unwrap_or(raw).trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn strips_parameters_and_trims() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("  application/grpc; charset=utf-8 "),
        );
        assert_eq!(raw_media_type(&headers), Some("application/grpc"));
    }

    #[test]
    fn repeated_fields_keep_first_readable_value() {
        let mut headers = HeaderMap::new();
        headers.append(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.append(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert_eq!(raw_media_type(&headers), Some("text/html"));
    }

    #[test]
    fn unreadable_first_value_is_not_replaced_by_later_value() {
        let mut headers = HeaderMap::new();
        headers.append(
            CONTENT_TYPE,
            HeaderValue::from_bytes(b"\xff").expect("opaque content-type value"),
        );
        headers.append(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(raw_media_type(&headers), None);
    }

    #[test]
    fn missing_or_unreadable_is_none() {
        assert_eq!(raw_media_type(&HeaderMap::new()), None);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_bytes(b"\xff").expect("opaque content-type value"),
        );
        assert_eq!(raw_media_type(&headers), None);
    }
}
