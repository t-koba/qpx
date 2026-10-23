use super::ClientConnInfo;
use hyper::Request;
use qpx_core::ipc::meta::IpcRequestMeta;
use qpx_http::body::Body;
use qpx_http::protocol::semantics::connection_nominated_header_names;
use std::collections::{HashMap, HashSet};

fn is_hop_by_hop_header(name: &str) -> bool {
    qpx_http::protocol::semantics::is_hop_by_hop_header_name(name)
        || matches!(name, "proxy" | "trailers")
}

pub(super) fn build_ipc_meta(
    req: &Request<Body>,
    conn: ClientConnInfo,
    verified_identity: Option<qpx_core::ipc::meta::VerifiedIdentityContext>,
    authorization_decision: Option<qpx_core::ipc::meta::AuthorizationDecisionContext>,
) -> IpcRequestMeta {
    let mut headers = Vec::new();
    let connection_tokens: HashSet<_> = connection_nominated_header_names(req.headers()).collect();
    let mut has_host = false;
    for (name, value) in req.headers() {
        let name_str = name.as_str();
        if is_hop_by_hop_header(name_str) {
            continue;
        }
        if connection_tokens.contains(name) {
            continue;
        }
        if let Ok(val_str) = value.to_str() {
            if name_str.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            headers.push((name_str.to_string(), val_str.to_string()));
        }
    }
    // HTTP/2 and HTTP/3 requests carry the authority in the URI/metadata rather than a Host
    // header. CGI expects HTTP_HOST, so synthesize it when missing.
    if !has_host && let Some(authority) = req.uri().authority() {
        headers.push(("host".to_string(), authority.as_str().to_string()));
    }

    let mut params = HashMap::new();
    if let Some(remote) = conn.remote_addr {
        params.insert("REMOTE_ADDR".to_string(), remote.ip().to_string());
        params.insert("REMOTE_PORT".to_string(), remote.port().to_string());
    }

    IpcRequestMeta {
        method: req.method().as_str().to_string(),
        uri: req.uri().to_string(),
        server_protocol: crate::http::protocol::common::http_version_label(req.version())
            .to_string(),
        headers,
        params,
        verified_identity,
        authorization_decision,
        req_body_shm_path: None,
        req_body_shm_size_bytes: None,
        res_body_shm_path: None,
        res_body_shm_size_bytes: None,
        shm_reusable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{build_ipc_meta, is_hop_by_hop_header};
    use crate::ipc_client::ClientConnInfo;
    use hyper::header::{CONNECTION, HeaderValue};
    use qpx_http::body::Body;

    #[test]
    fn ipc_metadata_filters_connection_nominated_headers() {
        let mut req = hyper::Request::builder()
            .uri("https://example.test/path")
            .body(Body::empty())
            .expect("request");
        req.headers_mut()
            .append(CONNECTION, HeaderValue::from_static(" X-Private, UPGRADE "));
        req.headers_mut()
            .append(CONNECTION, HeaderValue::from_static("x-private, x-second"));
        req.headers_mut().append(
            CONNECTION,
            HeaderValue::from_bytes(b"\xff").expect("opaque value"),
        );
        req.headers_mut()
            .insert("x-private", HeaderValue::from_static("secret"));
        req.headers_mut()
            .insert("x-second", HeaderValue::from_static("secret"));
        req.headers_mut()
            .insert("x-kept", HeaderValue::from_static("value"));

        let meta = build_ipc_meta(&req, ClientConnInfo::default(), None, None);
        assert!(!meta.headers.iter().any(|(name, _)| name == "x-private"));
        assert!(!meta.headers.iter().any(|(name, _)| name == "x-second"));
        assert!(!meta.headers.iter().any(|(name, _)| name == "upgrade"));
        assert!(
            meta.headers
                .iter()
                .any(|(name, value)| name == "x-kept" && value == "value")
        );
        assert!(
            meta.headers
                .iter()
                .any(|(name, value)| name == "host" && value == "example.test")
        );
    }

    #[test]
    fn hop_header_filter_uses_shared_names_and_keeps_ipc_extras() {
        for name in [
            "connection",
            "proxy-connection",
            "proxy-authorization",
            "proxy-authenticate",
            "proxy-authentication-info",
            "keep-alive",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "proxy",
            "trailers",
        ] {
            assert!(is_hop_by_hop_header(name), "{name} should be filtered");
        }

        for name in ["host", "content-type", "x-forwarded-for"] {
            assert!(!is_hop_by_hop_header(name), "{name} should be retained");
        }
    }
}
