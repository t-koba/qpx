use super::*;
use crate::protocol::semantics::{
    normalize_response_for_request_with_options, sanitize_hop_by_hop_headers,
};
use http::{HeaderValue, Method, Response};

#[test]
fn standard_and_owner_normalization_preserve_framing_distinctions() {
    for status in [100, 101, 103, 200, 204, 205, 304, 407] {
        for method in [Method::GET, Method::HEAD, Method::CONNECT] {
            for upgrade in [false, true] {
                for lengths in [
                    &[][..],
                    &["0"],
                    &["3"],
                    &["3", "3"],
                    &["invalid"],
                    &["3", "4"],
                ] {
                    let make = || {
                        let mut response = Response::builder()
                            .status(status)
                            .header("transfer-encoding", "chunked")
                            .header("trailer", "x-check")
                            .header("x-exact", HeaderValue::from_bytes(b" \x80\t").unwrap())
                            .body("abc".to_owned())
                            .unwrap();
                        for length in lengths {
                            response
                                .headers_mut()
                                .append("content-length", length.parse().unwrap());
                        }
                        response
                    };
                    let mut standard = make();
                    let mut owner = OwnerResponse::from_http(make());
                    let before = owner.headers().declared_content_length();
                    let dropped = normalize_response_for_request_with_options(
                        &method,
                        &mut standard,
                        upgrade,
                    );
                    assert_eq!(
                        dropped,
                        normalize_response_for_request_with_options(&method, &mut owner, upgrade)
                    );
                    let informational = status < 200 && !(status == 101 && upgrade);
                    let no_body = informational
                        || method == Method::HEAD
                        || [204, 205, 304].contains(&status)
                        || (method == Method::CONNECT && (200..300).contains(&status));
                    assert_eq!(dropped, no_body);
                    assert_eq!(standard.status(), owner.status());
                    assert_eq!(
                        owner.status().as_u16(),
                        if informational { 502 } else { status }
                    );
                    assert_eq!(standard.body(), owner.body());
                    assert_eq!(owner.body(), if no_body { "" } else { "abc" });
                    if informational || (no_body && method != Method::HEAD) {
                        assert!(!owner.headers().contains_content_length());
                        assert!(!standard.headers().contains_key("content-length"));
                    } else {
                        assert_eq!(owner.headers().declared_content_length(), before);
                        assert_eq!(
                            owner.headers().contains_content_length(),
                            !lengths.is_empty()
                        );
                        assert_eq!(
                            standard
                                .headers()
                                .get_all("content-length")
                                .iter()
                                .map(|v| v.to_str().unwrap())
                                .collect::<Vec<_>>(),
                            lengths
                        );
                    }
                    let ordinary: Vec<_> = standard
                        .headers()
                        .iter()
                        .filter(|(n, _)| *n != "content-length")
                        .collect();
                    assert_eq!(ordinary, owner.headers().iter().collect::<Vec<_>>());
                }
            }
        }
    }
}

#[test]
fn standard_and_owner_hop_sanitization_consume_all_nominations() {
    for preserve in [false, true] {
        let make = || {
            Response::builder()
                .header("connection", "Content-Length, X-Drop, Upgrade, Via, Date")
                .header("connection", "x-second, invalid name, Keep-Alive")
                .header("content-length", "bad")
                .header("x-drop", "one")
                .header("x-second", "two")
                .header("upgrade", "websocket")
                .header("keep-alive", "timeout=5")
                .header("via", "1.0 upstream")
                .header("date", "Thu, 01 Jan 1970 00:00:00 GMT")
                .header("set-cookie", "a=1")
                .header("set-cookie", "b=2")
                .body(())
                .unwrap()
        };
        let mut standard = make();
        let mut owner = OwnerResponse::from_http(make());
        sanitize_hop_by_hop_headers(standard.headers_mut(), preserve);
        sanitize_hop_by_hop_headers(owner.headers_mut(), preserve);
        assert_eq!(
            standard.headers().iter().collect::<Vec<_>>(),
            owner.headers().iter().collect::<Vec<_>>()
        );
        assert!(!owner.headers().contains_content_length());
        for removed in ["x-drop", "x-second", "via", "date", "keep-alive"] {
            assert!(!standard.headers().contains_key(removed));
        }
        assert_eq!(standard.headers().contains_key("connection"), preserve);
        assert_eq!(standard.headers().contains_key("upgrade"), preserve);
        assert_eq!(standard.headers().get_all("set-cookie").iter().count(), 2);
    }
}

#[test]
fn standard_and_owner_proxy_status_combine_repeated_fields_identically() {
    use crate::proxy_status::append_proxy_status;
    for identifier in ["qpx", "proxy with spaces"] {
        let make = || {
            Response::builder()
                .header("proxy-status", "upstream; received-status=200")
                .header("proxy-status", "middle; details=\"kept\"")
                .body(())
                .unwrap()
        };
        let mut standard = make();
        let mut owner = OwnerResponse::from_http(make());
        append_proxy_status(standard.headers_mut(), identifier).unwrap();
        append_proxy_status(owner.headers_mut(), identifier).unwrap();
        assert_eq!(
            standard.headers().iter().collect::<Vec<_>>(),
            owner.headers().iter().collect::<Vec<_>>()
        );
        assert_eq!(standard.headers().get_all("proxy-status").iter().count(), 1);
        assert!(
            standard.headers()["proxy-status"]
                .to_str()
                .unwrap()
                .starts_with("upstream;received-status=200, middle;details=\"kept\", ")
        );
    }
}
