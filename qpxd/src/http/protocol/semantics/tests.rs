use crate::http::protocol::semantics::*;

#[test]
fn sanitize_removes_connection_tokens_and_hop_headers() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, x-remove"));
    headers.insert("x-remove", HeaderValue::from_static("1"));
    headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
    headers.insert("te", HeaderValue::from_static("trailers"));
    headers.insert("proxy-authorization", HeaderValue::from_static("Basic abc"));
    headers.insert(
        "proxy-authenticate",
        HeaderValue::from_static("Basic realm=\"qpx\""),
    );

    sanitize_hop_by_hop_headers(&mut headers, false);

    assert!(headers.get(CONNECTION).is_none());
    assert!(headers.get("x-remove").is_none());
    assert!(headers.get("keep-alive").is_none());
    assert!(headers.get("te").is_none());
    assert!(headers.get("proxy-authorization").is_none());
    assert!(headers.get("proxy-authenticate").is_none());
}

#[test]
fn sanitize_preserves_upgrade_pair_for_websocket() {
    let mut headers = HeaderMap::new();
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade, keep-alive"));
    headers.insert("upgrade", HeaderValue::from_static("websocket"));
    headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));

    sanitize_hop_by_hop_headers(&mut headers, true);

    assert_eq!(
        headers.get(CONNECTION).and_then(|v| v.to_str().ok()),
        Some("upgrade")
    );
    assert_eq!(
        headers.get("upgrade").and_then(|v| v.to_str().ok()),
        Some("websocket")
    );
    assert!(headers.get("keep-alive").is_none());
}

#[test]
fn append_via_appends_values() {
    let mut headers = HeaderMap::new();
    headers.insert(VIA, HeaderValue::from_static("1.0 old-proxy"));
    append_via_for_version(&mut headers, Version::HTTP_11, "qpx");

    let values: Vec<_> = headers.get_all(VIA).iter().collect();
    assert_eq!(values.len(), 2);
    assert_eq!(values[1].to_str().ok(), Some("1.1 qpx"));
}

#[test]
fn validate_rejects_multiple_host_headers() {
    let mut req = http::Request::builder()
        .uri("http://example.com/")
        .body(())
        .expect("request");
    req.headers_mut()
        .append(HOST, HeaderValue::from_static("example.com"));
    req.headers_mut()
        .append(HOST, HeaderValue::from_static("example.com"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::MultipleHostHeaders);
}

#[test]
fn validate_rejects_invalid_host_value() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("/path")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("exa mple.com"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidHostHeader);
}

#[test]
fn validate_rejects_host_with_userinfo() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("/path")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("user@example.com"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidHostHeader);
}

#[test]
fn validate_accepts_default_port_equivalence() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("http://example.com:80/path")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("example.com"));
    validate_incoming_request(&req).expect("must pass");
}

#[test]
fn normalize_response_keeps_content_length_for_head() {
    let mut resp = http::Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, "42")
        .header(TRANSFER_ENCODING, "chunked")
        .header(TRAILER, "x-trailer")
        .body("payload".to_string())
        .expect("response");
    let changed = normalize_response_for_request(&Method::HEAD, &mut resp);
    assert!(changed);
    assert_eq!(resp.body(), "");
    assert_eq!(resp.headers().get(CONTENT_LENGTH).unwrap(), "42");
    assert!(resp.headers().get(TRANSFER_ENCODING).is_none());
    assert!(resp.headers().get(TRAILER).is_none());
}

#[test]
fn validate_rejects_missing_host_for_http11() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("/only-path")
        .body(())
        .expect("request");
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::MissingHost);
}

#[test]
fn validate_rejects_host_authority_mismatch() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("http://example.com/path")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("other.example"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::HostAuthorityMismatch);
}

#[test]
fn normalize_response_drops_body_headers_for_204() {
    let mut resp = http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(CONTENT_LENGTH, "10")
        .body("payload".to_string())
        .expect("response");
    let changed = normalize_response_for_request(&Method::GET, &mut resp);
    assert!(changed);
    assert_eq!(resp.body(), "");
    assert!(resp.headers().get(CONTENT_LENGTH).is_none());
}

#[test]
fn normalize_response_drops_body_headers_for_205() {
    let mut resp = http::Response::builder()
        .status(StatusCode::RESET_CONTENT)
        .header(CONTENT_LENGTH, "10")
        .body("payload".to_string())
        .expect("response");
    let changed = normalize_response_for_request(&Method::GET, &mut resp);
    assert!(changed);
    assert_eq!(resp.body(), "");
    assert!(resp.headers().get(CONTENT_LENGTH).is_none());
}

#[test]
fn normalize_response_rejects_final_informational_status() {
    let mut resp = http::Response::builder()
        .status(StatusCode::EARLY_HINTS)
        .header(CONTENT_LENGTH, "10")
        .body("payload".to_string())
        .expect("response");
    let changed = normalize_response_for_request(&Method::GET, &mut resp);
    assert!(changed);
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(resp.body(), "");
    assert!(resp.headers().get(CONTENT_LENGTH).is_none());
}

#[test]
fn normalize_response_can_preserve_switching_protocols_for_upgrade_paths() {
    let mut resp = http::Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body("".to_string())
        .expect("response");
    let changed = normalize_response_for_request_with_options(&Method::GET, &mut resp, true);
    assert!(!changed);
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
}

#[test]
fn validate_rejects_mismatched_content_length_values() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("example.com"));
    req.headers_mut()
        .append(CONTENT_LENGTH, HeaderValue::from_static("10"));
    req.headers_mut()
        .append(CONTENT_LENGTH, HeaderValue::from_static("12"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidContentLength);
}

#[test]
fn validate_rejects_transfer_encoding_with_content_length() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("example.com"));
    req.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("5"));
    req.headers_mut()
        .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(
        err,
        RequestValidationError::BothTransferEncodingAndContentLength
    );
}

#[test]
fn validate_rejects_connect_without_port() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::CONNECT)
        .uri("example.com")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("example.com"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidConnectTarget);
}

#[test]
fn validate_accepts_h2_extended_connect_request() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_2)
        .method(Method::CONNECT)
        .uri("https://example.com:443/chat")
        .body(())
        .expect("request");
    req.extensions_mut()
        .insert(h2::ext::Protocol::from("websocket"));
    validate_incoming_request(&req).expect("must pass");
}

#[test]
fn validate_accepts_h2_extended_connect_default_port_authority() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_2)
        .method(Method::CONNECT)
        .uri("https://example.com/chat")
        .body(())
        .expect("request");
    req.extensions_mut()
        .insert(h2::ext::Protocol::from("websocket"));
    validate_incoming_request(&req).expect("must pass");
}

#[test]
fn validate_rejects_connection_header_for_h2() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri("https://example.com/")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("keep-alive"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidH2H3ConnectionHeader);
}

#[test]
fn validate_accepts_te_trailers_for_h2() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri("https://example.com/")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert("te", HeaderValue::from_static("trailers"));
    validate_incoming_request(&req).expect("must pass");
}

#[test]
fn validate_rejects_invalid_te_for_h3() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_3)
        .method(Method::GET)
        .uri("https://example.com/")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert("te", HeaderValue::from_static("gzip"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidH2H3TeHeader);
}

#[test]
fn validate_rejects_transfer_encoding_for_h3() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_3)
        .method(Method::POST)
        .uri("https://example.com/")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidH2H3ConnectionHeader);
}

#[test]
fn validate_accepts_expect_100_continue() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .header(HOST, "example.com")
        .header(EXPECT, "100-continue")
        .body(())
        .expect("request");
    validate_incoming_request(&req).expect("must pass");
}

#[test]
fn validate_rejects_unknown_expectations() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .header(HOST, "example.com")
        .header(EXPECT, "100-continue, other")
        .body(())
        .expect("request");
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidExpectHeader);
}

#[test]
fn validate_rejects_star_form_for_non_options() {
    let uri = http::Uri::builder()
        .path_and_query("*")
        .build()
        .expect("uri");
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri(uri)
        .header(HOST, "example.com")
        .body(())
        .expect("request");
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidRequestTarget);
}

#[test]
fn validate_allows_star_form_for_options() {
    let uri = http::Uri::builder()
        .path_and_query("*")
        .build()
        .expect("uri");
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::OPTIONS)
        .uri(uri)
        .header(HOST, "example.com")
        .body(())
        .expect("request");
    validate_incoming_request(&req).expect("must pass");
}

#[test]
fn validate_rejects_origin_form_without_leading_slash() {
    let uri = http::Uri::builder()
        .path_and_query("relative")
        .build()
        .expect("uri");
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri(uri)
        .header(HOST, "example.com")
        .body(())
        .expect("request");
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidRequestTarget);
}

#[test]
fn validate_rejects_connect_missing_authority() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::CONNECT)
        .uri("/not-authority-form")
        .header(HOST, "example.com:443")
        .body(())
        .expect("request");
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::MissingConnectAuthority);
}

#[test]
fn validate_rejects_connect_absolute_form() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::CONNECT)
        .uri("http://example.com:443/")
        .header(HOST, "example.com:443")
        .body(())
        .expect("request");
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidConnectTarget);
}
