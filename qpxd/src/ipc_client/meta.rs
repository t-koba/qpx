use super::ClientConnInfo;
use anyhow::Result;
use qpx_core::http_message::Request as OwnerRequest;
use qpx_core::ipc::meta::{IpcRequestHeaders, IpcRequestMeta};
use qpx_http::body::Body;
use qpx_http::protocol::semantics::connection_nominated_header_names;
use std::collections::{HashMap, HashSet};

fn is_hop_by_hop_header(name: &str) -> bool {
    qpx_http::protocol::semantics::is_hop_by_hop_header_name(name)
        || matches!(name, "proxy" | "trailers")
}

pub(super) fn build_ipc_meta(
    req: &OwnerRequest<Body>,
    conn: ClientConnInfo,
    verified_identity: Option<qpx_core::ipc::meta::VerifiedIdentityContext>,
    authorization_decision: Option<qpx_core::ipc::meta::AuthorizationDecisionContext>,
) -> Result<IpcRequestMeta> {
    // The owner validates and canonicalizes the declaration exactly as codec
    // export does. This runs before the caller checks out an IPC connection.
    let fields = req.headers().canonical_fields_for_serialization()?;
    let connection_tokens: HashSet<String> = connection_nominated_header_names(req.headers())
        .map(|name| name.as_str().to_owned())
        .collect();
    let mut headers = IpcRequestHeaders::default();
    let mut has_host = false;
    for (name, value) in fields {
        if is_hop_by_hop_header(&name) || connection_tokens.contains(&name) {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        headers.push((name, value));
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

    Ok(IpcRequestMeta {
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
    })
}

#[cfg(test)]
mod tests {
    use super::{build_ipc_meta, is_hop_by_hop_header};
    use crate::ipc_client::ClientConnInfo;
    use anyhow::Result;
    use hyper::header::{CONNECTION, HeaderValue};
    use qpx_core::http_content_length::ContentLengthError;
    use qpx_core::http_message::Request as OwnerRequest;
    use qpx_core::ipc::meta::{AuthorizationDecisionContext, VerifiedIdentityContext};
    use qpx_http::body::Body;
    use qpx_http::protocol::semantics::connection_nominated_header_names;
    use std::collections::HashSet;

    fn owner(req: hyper::Request<Body>) -> OwnerRequest<Body> {
        OwnerRequest::from_http(req)
    }

    // The wire output before the owner path: serialize after codec-export
    // canonicalization, using the header map iteration that IPC metadata used.
    fn legacy_wire_meta(req: hyper::Request<Body>) -> serde_json::Value {
        let req = OwnerRequest::from_http(req)
            .into_http_for_codec()
            .expect("valid framing");
        let nominated: HashSet<String> = connection_nominated_header_names(req.headers())
            .map(|name| name.as_str().to_owned())
            .collect();
        let mut pairs = Vec::new();
        let mut has_host = false;
        for (name, value) in req.headers() {
            let name = name.as_str();
            if is_hop_by_hop_header(name) || nominated.contains(name) {
                continue;
            }
            let Ok(text) = value.to_str() else {
                continue;
            };
            if name.eq_ignore_ascii_case("host") {
                has_host = true;
            }
            pairs.push((name.to_owned(), text.to_owned()));
        }
        if !has_host && let Some(authority) = req.uri().authority() {
            pairs.push(("host".to_owned(), authority.as_str().to_owned()));
        }
        serde_json::json!({
            "method": req.method().as_str(),
            "uri": req.uri().to_string(),
            "server_protocol": crate::http::protocol::common::http_version_label(req.version()),
            "headers": pairs,
            "params": {},
        })
    }

    fn parity(make_request: impl Fn() -> hyper::Request<Body>) {
        let expected = legacy_wire_meta(make_request());
        let meta = build_ipc_meta(
            &owner(make_request()),
            ClientConnInfo::default(),
            Some(VerifiedIdentityContext {
                subject: Some("subject".to_owned()),
                ..Default::default()
            }),
            Some(AuthorizationDecisionContext {
                policy_id: Some("policy".to_owned()),
                ..Default::default()
            }),
        )
        .expect("owner metadata");
        let mut wire = serde_json::to_value(meta).expect("wire metadata");
        let contexts = wire.as_object_mut().expect("metadata object");
        assert_eq!(
            contexts.remove("verified_identity"),
            Some(serde_json::json!({
                "subject": "subject",
            }))
        );
        assert_eq!(
            contexts.remove("authorization_decision"),
            Some(serde_json::json!({
                "policy_id": "policy",
            }))
        );
        assert_eq!(wire, expected);
    }

    fn duplicate_headers_request() -> hyper::Request<Body> {
        let mut req = hyper::Request::builder()
            .method("POST")
            .uri("https://example.test:8443/path?q=1")
            .body(Body::empty())
            .expect("request");
        for (name, value) in [
            ("content-length", " 0005 "),
            ("x-dup", "first"),
            ("connection", "x-nominated, upgrade"),
            ("x-dup", "second"),
            ("x-nominated", "secret"),
            ("upgrade", "websocket"),
            ("proxy-authorization", "secret"),
            ("x-kept", "value"),
        ] {
            req.headers_mut()
                .append(name, HeaderValue::from_static(value));
        }
        req
    }

    #[test]
    fn owner_metadata_matches_wire_including_duplicates_and_authority_host() {
        parity(duplicate_headers_request);

        let meta = build_ipc_meta(
            &owner(duplicate_headers_request()),
            ClientConnInfo::default(),
            None,
            None,
        )
        .expect("owner metadata");
        let wire = serde_json::to_value(meta).expect("wire metadata");
        let pairs = wire["headers"].as_array().expect("header pairs");
        assert_eq!(pairs[0], serde_json::json!(["content-length", "5"]));
        assert_eq!(pairs[1], serde_json::json!(["x-dup", "first"]));
        assert_eq!(pairs[2], serde_json::json!(["x-dup", "second"]));
        assert_eq!(
            pairs.last(),
            Some(&serde_json::json!(["host", "example.test:8443"]))
        );
        assert!(!pairs.iter().any(|pair| pair[0] == "x-nominated"));
    }

    #[test]
    fn owner_metadata_matches_wire_for_absent_zero_and_explicit_host() {
        for lengths in [Vec::new(), vec!["0"], vec!["000", "0"]] {
            parity(|| {
                let mut req = hyper::Request::builder()
                    .uri("https://example.test/path")
                    .body(Body::empty())
                    .expect("request");
                req.headers_mut()
                    .insert("host", HeaderValue::from_static("upstream.test"));
                for length in &lengths {
                    req.headers_mut()
                        .append("content-length", HeaderValue::from_static(length));
                }
                req
            });
        }

        parity(|| {
            let mut req = hyper::Request::builder()
                .uri("https://example.test/path")
                .body(Body::empty())
                .expect("request");
            req.headers_mut()
                .append("content-length", HeaderValue::from_static("000"));
            req
        });
    }

    #[test]
    fn owner_metadata_omits_connection_nominated_content_length() {
        parity(|| {
            let mut req = hyper::Request::builder()
                .uri("https://example.test/path")
                .body(Body::empty())
                .expect("request");
            req.headers_mut()
                .append(CONNECTION, HeaderValue::from_static("Content-Length"));
            req.headers_mut()
                .append("content-length", HeaderValue::from_static("7"));
            req
        });
    }

    #[test]
    fn owner_metadata_rejects_invalid_content_length_before_serialization() {
        for values in [vec!["invalid"], vec!["3", "4"]] {
            let mut req = OwnerRequest::new(Body::empty());
            for value in values {
                req.headers_mut()
                    .append_content_length_value(HeaderValue::from_static(value));
            }
            let err = build_ipc_meta(&req, ClientConnInfo::default(), None, None)
                .expect_err("invalid declaration must be refused");
            assert!(
                err.downcast_ref::<ContentLengthError>().is_some(),
                "{err:?}"
            );
        }
    }

    #[test]
    fn ipc_metadata_filters_connection_nominated_headers() -> Result<()> {
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

        let meta = build_ipc_meta(&owner(req), ClientConnInfo::default(), None, None)?;
        let wire = serde_json::to_value(meta).expect("wire metadata");
        let pairs = wire["headers"].as_array().expect("header pairs");
        for name in ["x-private", "x-second", "upgrade"] {
            assert!(!pairs.iter().any(|pair| pair[0] == name));
        }
        assert!(pairs.contains(&serde_json::json!(["x-kept", "value"])));
        assert!(pairs.contains(&serde_json::json!(["host", "example.test"])));
        Ok(())
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
