use http::{HeaderMap, StatusCode};
use std::fmt;

/// A decoded informational head, opaque until the protocol sender needs it.
/// Ingress retains the map unchanged; only egress removes hop-by-hop and body
/// framing fields. In particular, no Content-Length parsing happens here.
///
/// These probes include the real owner in a sibling module: importing the
/// crate-private type through qpxd would prove only module visibility, not field
/// privacy. The positive control ensures the same-crate constructor is usable.
///
/// ```
/// mod owner { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/upstream/raw_http1/interim.rs")); }
/// let head = owner::InterimResponseHead::new(http::StatusCode::CONTINUE, http::HeaderMap::new());
/// assert_eq!(head.status, http::StatusCode::CONTINUE);
/// assert!(head.headers_for_egress().is_empty());
/// ```
///
/// ```compile_fail,E0616
/// mod owner { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/upstream/raw_http1/interim.rs")); }
/// fn raw(head: owner::InterimResponseHead) { let _ = head.headers; }
/// ```
///
/// ```compile_fail,E0599
/// mod owner { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/upstream/raw_http1/interim.rs")); }
/// fn raw(head: owner::InterimResponseHead) { let _ = head.headers(); }
/// ```
///
/// ```compile_fail,E0599
/// mod owner { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/upstream/raw_http1/interim.rs")); }
/// fn raw(head: owner::InterimResponseHead) { let _ = head.iter(); }
/// ```
///
/// ```compile_fail,E0277
/// mod owner { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/upstream/raw_http1/interim.rs")); }
/// fn raw(head: owner::InterimResponseHead) { let _: http::HeaderMap = head.into(); }
/// ```
///
/// ```compile_fail,E0277
/// mod owner { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/upstream/raw_http1/interim.rs")); }
/// fn as_map<T: AsRef<http::HeaderMap>>() {}
/// as_map::<owner::InterimResponseHead>();
/// ```
///
/// ```compile_fail,E0277
/// mod owner { include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/upstream/raw_http1/interim.rs")); }
/// fn deref_map<T: std::ops::Deref<Target = http::HeaderMap>>() {}
/// deref_map::<owner::InterimResponseHead>();
/// ```
#[derive(Clone)]
pub(crate) struct InterimResponseHead {
    pub(crate) status: StatusCode,
    headers: HeaderMap,
}

impl InterimResponseHead {
    pub(crate) fn new(status: StatusCode, headers: HeaderMap) -> Self {
        Self { status, headers }
    }

    /// Export only at a protocol serializer/library send boundary.
    pub(crate) fn headers_for_egress(&self) -> HeaderMap {
        let mut headers = self.headers.clone();
        qpx_http::protocol::semantics::sanitize_interim_response_headers(&mut headers);
        headers
    }
}

impl fmt::Debug for InterimResponseHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterimResponseHead")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn interim_ownership_retains_ingress_and_sanitizes_only_egress() {
        let mut headers = HeaderMap::new();
        for link in ["</one>; rel=preload", "</two>; rel=preload"] {
            headers.append("link", HeaderValue::from_static(link));
        }
        for cookie in ["a=1", "b=2"] {
            let mut value = HeaderValue::from_static(cookie);
            value.set_sensitive(true);
            headers.append("set-cookie", value);
        }
        let mut opaque = HeaderValue::from_bytes(b"opaque-\xff").unwrap();
        opaque.set_sensitive(true);
        headers.insert("x-opaque", opaque);
        headers.insert(
            "connection",
            HeaderValue::from_static("x-private, keep-alive"),
        );
        headers.insert("x-private", HeaderValue::from_static("private-value"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=1"));
        // Invalid/conflicting framing is deliberately accepted and retained at
        // ingress, without invoking a length parser on this bodyless head.
        headers.append("content-length", HeaderValue::from_static("invalid"));
        headers.append("content-length", HeaderValue::from_static("99"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("trailer", HeaderValue::from_static("x-trailer"));
        let head = InterimResponseHead::new(StatusCode::EARLY_HINTS, headers.clone());
        assert_eq!(head.headers, headers);
        assert!(!format!("{head:?}").contains("private-value"));
        assert!(!format!("{head:?}").contains("one"));

        let mut out = head.headers_for_egress();
        assert_eq!(out.get_all("link"), headers.get_all("link"));
        assert_eq!(out.get_all("set-cookie"), headers.get_all("set-cookie"));
        assert!(
            out.get_all("set-cookie")
                .iter()
                .all(HeaderValue::is_sensitive)
        );
        assert_eq!(out["x-opaque"].as_bytes(), b"opaque-\xff");
        assert!(out["x-opaque"].is_sensitive());
        for removed in [
            "connection",
            "x-private",
            "keep-alive",
            "content-length",
            "transfer-encoding",
            "trailer",
        ] {
            assert!(!out.contains_key(removed), "{removed}");
        }
        out.clear();
        assert_eq!(head.headers, headers);
        assert_eq!(head.headers_for_egress(), head.clone().headers_for_egress());
    }
}
