use http::Method;

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
    match method.as_str() {
        "GET" | "HEAD" | "OPTIONS" | "PRI" | "PROPFIND" | "REPORT" | "SEARCH" | "TRACE" => {
            MethodSemantics::new(true, true)
        }
        "QUERY" => MethodSemantics::QUERY,
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
pub fn precondition_is_missing(method: &Method, headers: &http::HeaderMap) -> bool {
    !method_semantics(method).safe
        && !headers.contains_key(http::header::IF_MATCH)
        && !headers.contains_key(http::header::IF_UNMODIFIED_SINCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_safe_idempotent_and_content_keyed() {
        let method = Method::from_bytes(b"QUERY").expect("QUERY method");
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
        let mut headers = http::HeaderMap::new();
        assert!(precondition_is_missing(&Method::PUT, &headers));
        headers.insert(http::header::IF_MATCH, "\"v1\"".parse().unwrap());
        assert!(!precondition_is_missing(&Method::PUT, &headers));
        headers.clear();
        headers.insert(
            http::header::IF_UNMODIFIED_SINCE,
            "Sat, 11 Jul 2026 00:00:00 GMT".parse().unwrap(),
        );
        assert!(!precondition_is_missing(&Method::DELETE, &headers));
        headers.clear();
        assert!(!precondition_is_missing(&Method::GET, &headers));
    }
}
