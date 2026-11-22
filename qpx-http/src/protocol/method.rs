use http::Method;
use qpx_core::http_message::{Headers, OrdinaryHeaderName};

/// Registry-backed HTTP method properties used by intermediary decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSemantics {
    pub safe: bool,
    pub idempotent: bool,
    /// Whether a cache key must incorporate the request content and its
    /// representation metadata.
    pub cache_key_includes_content: bool,
}

impl MethodSemantics {
    const fn new(safe: bool, idempotent: bool) -> Self {
        Self {
            safe,
            idempotent,
            cache_key_includes_content: false,
        }
    }

    const QUERY: Self = Self {
        safe: true,
        idempotent: true,
        cache_key_includes_content: true,
    };
}

/// Returns the IANA-registered semantics for a method.
///
/// Unknown extension methods deliberately default to unsafe and
/// non-idempotent. A proxy must not retry, use 0-RTT, or skip cache
/// invalidation without an explicit registry entry.
pub fn method_semantics(method: &Method) -> MethodSemantics {
    if *method == Method::QUERY {
        return MethodSemantics::QUERY;
    }
    match method.as_str() {
        "GET" | "HEAD" | "OPTIONS" | "PRI" | "PROPFIND" | "REPORT" | "SEARCH" | "TRACE" => {
            MethodSemantics::new(true, true)
        }
        "ACL" | "BASELINE-CONTROL" | "BIND" | "CHECKIN" | "CHECKOUT" | "COPY" | "DELETE"
        | "LABEL" | "LINK" | "MERGE" | "MKACTIVITY" | "MKCALENDAR" | "MKCOL" | "MKREDIRECTREF"
        | "MKWORKSPACE" | "MOVE" | "ORDERPATCH" | "PROPPATCH" | "PUT" | "REBIND" | "UNCHECKOUT"
        | "UNBIND" | "UNLINK" | "UNLOCK" | "UPDATE" | "UPDATEREDIRECTREF" | "VERSION-CONTROL" => {
            MethodSemantics::new(false, true)
        }
        "CONNECT" | "LOCK" | "PATCH" | "POST" => MethodSemantics::new(false, false),
        _ => MethodSemantics::new(false, false),
    }
}

/// Returns whether a route-level RFC 6585 precondition policy must reject the request.
pub fn precondition_is_missing(method: &Method, headers: &Headers) -> bool {
    !method_semantics(method).safe
        && !has_valid_if_match(headers)
        && !has_valid_if_unmodified_since(headers)
}

fn has_valid_if_match(headers: &Headers) -> bool {
    let name = OrdinaryHeaderName::try_from(http::header::IF_MATCH).expect("ordinary header");
    headers
        .get_all(&name)
        .any(|value| is_valid_if_match(value.as_bytes()))
}

fn is_valid_if_match(value: &[u8]) -> bool {
    if value == b"*" {
        return true;
    }
    if value.is_empty() {
        return false;
    }
    value.split(|byte| *byte == b',').all(|tag| {
        let tag = trim_ows(tag);
        let Some(inner) = tag
            .strip_prefix(b"\"")
            .and_then(|tag| tag.strip_suffix(b"\""))
        else {
            return false;
        };
        inner
            .iter()
            .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte) || *byte >= 0x80)
    })
}

fn has_valid_if_unmodified_since(headers: &Headers) -> bool {
    let name =
        OrdinaryHeaderName::try_from(http::header::IF_UNMODIFIED_SINCE).expect("ordinary header");
    headers.get_all(&name).any(|value| {
        value
            .to_str()
            .ok()
            .and_then(|date| httpdate::parse_http_date(date).ok())
            .is_some()
    })
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_safe_idempotent_and_content_keyed() {
        let method = Method::QUERY;
        let semantics = method_semantics(&method);
        assert!(semantics.safe);
        assert!(semantics.idempotent);
        assert!(semantics.cache_key_includes_content);
    }

    #[test]
    fn unknown_methods_fail_closed() {
        let method = Method::from_bytes(b"EXPERIMENT").expect("extension method");
        let semantics = method_semantics(&method);
        assert!(!semantics.safe);
        assert!(!semantics.idempotent);
        assert!(!semantics.cache_key_includes_content);
    }

    #[test]
    fn webdav_registry_properties_are_available() {
        let propfind = Method::from_bytes(b"PROPFIND").expect("PROPFIND method");
        let proppatch = Method::from_bytes(b"PROPPATCH").expect("PROPPATCH method");
        assert!(method_semantics(&propfind).safe);
        assert!(method_semantics(&propfind).idempotent);
        assert!(!method_semantics(&proppatch).safe);
        assert!(method_semantics(&proppatch).idempotent);
    }

    #[test]
    fn unsafe_request_precondition_policy_accepts_either_validator() {
        let mut headers = qpx_core::http_message::Headers::new();
        assert!(precondition_is_missing(&Method::PUT, &headers));
        headers.insert(
            qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::IF_MATCH).unwrap(),
            "\"v1\"".parse().unwrap(),
        );
        assert!(!precondition_is_missing(&Method::PUT, &headers));
        headers = qpx_core::http_message::Headers::new();
        headers.insert(
            qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::IF_UNMODIFIED_SINCE)
                .unwrap(),
            "Sat, 11 Jul 2026 00:00:00 GMT".parse().unwrap(),
        );
        assert!(!precondition_is_missing(&Method::DELETE, &headers));
        headers = qpx_core::http_message::Headers::new();
        assert!(!precondition_is_missing(&Method::GET, &headers));
    }
    #[test]
    fn invalid_conditional_headers_do_not_satisfy_precondition_guard() {
        let mut headers = qpx_core::http_message::Headers::new();
        headers.insert(
            qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::IF_UNMODIFIED_SINCE)
                .unwrap(),
            "not-a-date".parse().unwrap(),
        );
        assert!(precondition_is_missing(&Method::PUT, &headers));

        headers = qpx_core::http_message::Headers::new();
        headers.insert(
            qpx_core::http_message::OrdinaryHeaderName::try_from(http::header::IF_MATCH).unwrap(),
            "W/\"v1\"".parse().unwrap(),
        );
        assert!(precondition_is_missing(&Method::PUT, &headers));
    }
}
