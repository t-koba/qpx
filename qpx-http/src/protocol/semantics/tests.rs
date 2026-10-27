use crate::protocol::semantics::*;

#[test]
fn connection_nominated_header_names_normalizes_valid_tokens() {
    let mut headers = HeaderMap::new();
    headers.append(
        CONNECTION,
        HeaderValue::from_static(" X-Remove, UPGRADE,, "),
    );
    headers.append(CONNECTION, HeaderValue::from_static("x-remove, x-second"));
    headers.append(CONNECTION, HeaderValue::from_static("not a name, x-final"));
    headers.append(
        CONNECTION,
        HeaderValue::from_bytes(b"\xff").expect("opaque value"),
    );

    let names: Vec<_> = connection_nominated_header_names(&headers)
        .map(|name| name.as_str().to_owned())
        .collect();
    assert_eq!(
        names,
        ["x-remove", "upgrade", "x-remove", "x-second", "x-final"]
    );
}

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
fn prohibited_trailer_name_query_matches_the_shared_policy() {
    for name in [
        "content-length",
        "host",
        "authorization",
        "connection",
        "content-type",
    ] {
        let name = HeaderName::from_static(name);
        assert!(is_prohibited_trailer_name(&name), "{name}");
        let mut trailers = HeaderMap::new();
        trailers.insert(name, HeaderValue::from_static("value"));
        assert_eq!(sanitize_response_trailers(&mut trailers), 1);
        assert!(trailers.is_empty());
    }
    assert!(!is_prohibited_trailer_name(&HeaderName::from_static(
        "x-app-metadata"
    )));
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
    validate_incoming_request(&req).expect("must pass");
}

#[test]
fn validation_metadata_reuses_the_parsed_host_authority() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("/path")
        .header(HOST, "example.com:8080")
        .body(())
        .expect("request");

    let req = OwnerRequest::from_http(req);
    let validated = validate_incoming_request_with_metadata(&req).expect("must pass");

    assert_eq!(
        validated.authority().map(http::uri::Authority::as_str),
        Some("example.com:8080")
    );
}

#[test]
fn validation_metadata_prefers_the_absolute_target_authority() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("http://example.com:80/path")
        .header(HOST, "example.com")
        .body(())
        .expect("request");

    let req = OwnerRequest::from_http(req);
    let validated = validate_incoming_request_with_metadata(&req).expect("must pass");

    assert_eq!(
        validated.authority().map(http::uri::Authority::as_str),
        Some("example.com:80")
    );
}

#[test]
fn response_status_body_suppression_preserves_upgrade_exception() {
    assert!(response_status_has_no_body(StatusCode::CONTINUE, false));
    assert!(response_status_has_no_body(
        StatusCode::SWITCHING_PROTOCOLS,
        false
    ));
    assert!(response_status_has_no_body(StatusCode::CONTINUE, true));
    assert!(!response_status_has_no_body(
        StatusCode::SWITCHING_PROTOCOLS,
        true
    ));
    assert!(response_status_has_no_body(StatusCode::NO_CONTENT, true));
    assert!(response_status_has_no_body(StatusCode::RESET_CONTENT, true));
    assert!(response_status_has_no_body(StatusCode::NOT_MODIFIED, true));
    assert!(!response_status_has_no_body(StatusCode::OK, false));
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
    let req = OwnerRequest::from_http(req);
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::MissingHost);
}

#[test]
fn absolute_form_uses_target_authority_over_host() {
    for version in [Version::HTTP_10, Version::HTTP_11] {
        let req = http::Request::builder()
            .version(version)
            .method(Method::GET)
            .uri("http://target.example/path")
            .header(HOST, "stale.example")
            .body(())
            .expect("request");

        let req = OwnerRequest::from_http(req);
        let validated = validate_incoming_request_with_metadata(&req)
            .expect("absolute-form target authority takes precedence");
        assert_eq!(
            validated.authority().map(http::uri::Authority::as_str),
            Some("target.example")
        );
    }
}

#[test]
fn validate_rejects_http2_host_authority_mismatch() {
    let mut req = http::Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri("http://example.com/path")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("other.example"));
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidContentLength);
}

fn request_with_content_length(value: &str) -> OwnerRequest<()> {
    let mut req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .body(())
        .expect("request");
    req.headers_mut()
        .insert(HOST, HeaderValue::from_static("example.com"));
    req.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(value).expect("header"),
    );
    OwnerRequest::from_http(req)
}

#[test]
fn validate_rejects_signed_content_length_members() {
    for value in ["+0", "+123", "  +5  ", "5, +5"] {
        let err =
            validate_incoming_request(&request_with_content_length(value)).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidContentLength, "{value}");
    }
}

#[test]
fn validate_holds_content_length_overflow_boundary() {
    validate_incoming_request(&request_with_content_length("18446744073709551615"))
        .expect("u64::MAX is valid");
    let err = validate_incoming_request(&request_with_content_length("18446744073709551616"))
        .expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidContentLength);
}

#[test]
fn validate_keeps_digit_only_content_length_forms() {
    for value in ["0", "007", "42", "42, 42", " 42 "] {
        validate_incoming_request(&request_with_content_length(value)).expect("valid");
    }
    for value in ["", "4,", ",4", "4,,4", "4, 5"] {
        let err =
            validate_incoming_request(&request_with_content_length(value)).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidContentLength, "{value}");
    }
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
    validate_incoming_request(&req).expect("must pass");
}

#[test]
fn validate_rejects_origin_form_without_leading_slash() {
    // http 1.5.0 fails closed at Uri parse time (PathDoesNotStartWithSlash);
    // treat a builder refusal as the same fail-closed outcome the validator
    // enforced alone on http 1.4.0.
    let uri = match http::Uri::builder().path_and_query("relative").build() {
        Ok(uri) => uri,
        Err(_) => return,
    };
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri(uri)
        .header(HOST, "example.com")
        .body(())
        .expect("request");
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
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
    let req = OwnerRequest::from_http(req);
    let err = validate_incoming_request(&req).expect_err("must fail");
    assert_eq!(err, RequestValidationError::InvalidConnectTarget);
}

#[test]
fn common_h2_retrieval_predicate_accepts_only_the_prevalidated_shape() {
    let request = http::Request::builder()
        .version(Version::HTTP_2)
        .method(Method::GET)
        .uri("https://example.com/resource?q=1")
        .header("accept", "application/octet-stream")
        .body(())
        .expect("request");

    let request = OwnerRequest::from_http(request);
    assert!(is_intrinsically_valid_common_h2_request(&request));
    validate_incoming_request(&request).expect("common shape must pass full validation");
}

#[test]
fn common_h2_retrieval_predicate_defers_validation_sensitive_fields() {
    for (name, value) in [
        ("content-length", "0"),
        ("content-length", ""),
        ("content-length", "0, 1"),
        ("transfer-encoding", "chunked"),
        ("connection", "close"),
        ("proxy-connection", "close"),
        ("keep-alive", "timeout=5"),
        ("upgrade", "websocket"),
        ("expect", "100-continue"),
        ("host", "example.com"),
        ("te", "trailers"),
    ] {
        let request = http::Request::builder()
            .version(Version::HTTP_2)
            .method(Method::GET)
            .uri("https://example.com/resource")
            .header(name, value)
            .body(())
            .expect("request");
        let request = OwnerRequest::from_http(request);
        assert!(!is_intrinsically_valid_common_h2_request(&request));
    }
}

#[test]
fn validate_rejects_explicit_invalid_host_ports() {
    for host in ["example.test:65536", "example.test:", "example.test:abc"] {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::POST)
            .uri("http://example.test/upload")
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_str(host).expect("header"));
        let req = OwnerRequest::from_http(req);
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidHostHeader, "{host}");
    }
}

#[test]
fn validate_rejects_explicit_invalid_uri_authority_ports() {
    for uri in [
        "http://example.test:65536/upload",
        "http://example.test:/upload",
        "http://example.test:abc/upload",
    ] {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::POST)
            .uri(uri)
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_static("example.test"));
        let req = OwnerRequest::from_http(req);
        let err = validate_incoming_request(&req).expect_err("must fail");
        assert_eq!(err, RequestValidationError::InvalidRequestTarget, "{uri}");
    }
}

#[test]
fn validate_keeps_explicit_valid_host_ports() {
    for (uri, host) in [
        ("http://example.test:8080/upload", "example.test:8080"),
        ("https://example.test:443/upload", "example.test:443"),
    ] {
        let mut req = http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::POST)
            .uri(uri)
            .body(())
            .expect("request");
        req.headers_mut()
            .insert(HOST, HeaderValue::from_str(host).expect("header"));
        let req = OwnerRequest::from_http(req);
        validate_incoming_request(&req).expect("valid explicit port");
    }
}

#[test]
fn common_h2_retrieval_predicate_rejects_explicit_invalid_ports() {
    for uri in [
        "https://example.com:65536/resource",
        "https://example.com:/resource",
        "https://example.com:abc/resource",
    ] {
        let request = http::Request::builder()
            .version(Version::HTTP_2)
            .method(Method::GET)
            .uri(uri)
            .body(())
            .expect("request");
        let request = OwnerRequest::from_http(request);
        assert!(!is_intrinsically_valid_common_h2_request(&request), "{uri}");
        assert!(validate_incoming_request(&request).is_err(), "{uri}");
    }
}

#[test]
fn common_h2_retrieval_predicate_rejects_other_protocol_shapes() {
    for request in [
        http::Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("https://example.com/resource")
            .body(())
            .expect("HTTP/1 request"),
        http::Request::builder()
            .version(Version::HTTP_2)
            .method(Method::POST)
            .uri("https://example.com/resource")
            .body(())
            .expect("POST request"),
        http::Request::builder()
            .version(Version::HTTP_2)
            .method(Method::GET)
            .uri("/resource")
            .body(())
            .expect("origin-form request"),
    ] {
        let request = OwnerRequest::from_http(request);
        assert!(!is_intrinsically_valid_common_h2_request(&request));
    }
}

#[test]
fn validate_accepts_h1_chunked_transfer_encoding() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .header(HOST, "example.com")
        .header(TRANSFER_ENCODING, "chunked")
        .body(())
        .expect("request");
    let req = OwnerRequest::from_http(req);
    validate_incoming_request(&req).expect("chunked-final TE must pass");
}

#[test]
fn validate_accepts_h1_transfer_encoding_ending_in_chunked() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .header(HOST, "example.com")
        .header(TRANSFER_ENCODING, "gzip, chunked")
        .body(())
        .expect("request");
    let req = OwnerRequest::from_http(req);
    validate_incoming_request(&req).expect("gzip, chunked must pass");
}

#[test]
fn validate_rejects_h1_chunked_not_final_transfer_encoding() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .header(HOST, "example.com")
        .header(TRANSFER_ENCODING, "chunked, identity")
        .body(())
        .expect("request");
    let req = OwnerRequest::from_http(req);
    let err = validate_incoming_request(&req).expect_err("chunked, identity must fail");
    assert_eq!(err, RequestValidationError::InvalidTransferEncoding);
}

#[test]
fn validate_rejects_h1_transfer_encoding_without_chunked() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::POST)
        .uri("http://example.com/upload")
        .header(HOST, "example.com")
        .header(TRANSFER_ENCODING, "gzip")
        .body(())
        .expect("request");
    let req = OwnerRequest::from_http(req);
    let err = validate_incoming_request(&req).expect_err("gzip without chunked must fail");
    assert_eq!(err, RequestValidationError::InvalidTransferEncoding);
    assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);
}

#[test]
fn validate_rejects_h1_upgrade_with_content_length() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("http://example.com/chat")
        .header(HOST, "example.com")
        .header("upgrade", "websocket")
        .header(CONTENT_LENGTH, "5")
        .body(())
        .expect("request");
    let req = OwnerRequest::from_http(req);
    let err = validate_incoming_request(&req).expect_err("Upgrade+CL must fail");
    assert_eq!(err, RequestValidationError::UpgradeWithContentLength);
    assert_eq!(err.http_status(), StatusCode::BAD_REQUEST);
}

#[test]
fn validate_accepts_h1_websocket_upgrade_without_body() {
    let req = http::Request::builder()
        .version(Version::HTTP_11)
        .method(Method::GET)
        .uri("http://example.com/chat")
        .header(HOST, "example.com")
        .header("upgrade", "websocket")
        .header(CONNECTION, "Upgrade")
        .body(())
        .expect("request");
    let req = OwnerRequest::from_http(req);
    validate_incoming_request(&req).expect("bodiless WS upgrade must pass");
}

#[test]
fn capsule_protocol_accepts_boolean_true() {
    for value in ["?1", " ?1 "] {
        let mut headers = HeaderMap::new();
        headers.insert("capsule-protocol", HeaderValue::from_static(value));
        assert!(capsule_protocol_enabled(&headers), "{value:?}");
    }
}

#[test]
fn capsule_protocol_ignores_valid_unknown_parameters() {
    for value in [
        "?1;foo=bar",
        "?1;flag",
        "?1;flag=?0;title=\"unknown, value\";count=1",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("capsule-protocol", HeaderValue::from_static(value));
        assert!(capsule_protocol_enabled(&headers), "{value:?}");
    }
}

#[test]
fn capsule_protocol_absent_or_boolean_false_is_not_enabled() {
    assert!(!capsule_protocol_enabled(&HeaderMap::new()));
    for value in ["?0", "?0;foo=?1"] {
        let mut headers = HeaderMap::new();
        headers.insert("capsule-protocol", HeaderValue::from_static(value));
        assert!(!capsule_protocol_enabled(&headers), "{value:?}");
    }
}

#[test]
fn capsule_protocol_rejects_non_boolean_items() {
    for value in ["true", "\"?1\"", "1", "1.0", ":AQ==:"] {
        let mut headers = HeaderMap::new();
        headers.insert("capsule-protocol", HeaderValue::from_static(value));
        assert!(!capsule_protocol_enabled(&headers), "{value:?}");
    }
}

#[test]
fn capsule_protocol_rejects_malformed_items_and_parameters() {
    for value in [
        "",
        "?2",
        "?1junk",
        "?1;",
        "?1;foo=",
        "?1;Foo=bar",
        "?1;foo=\"unterminated",
        "?1;foo=bar garbage",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("capsule-protocol", HeaderValue::from_static(value));
        assert!(!capsule_protocol_enabled(&headers), "{value:?}");
    }
}

#[test]
fn capsule_protocol_rejects_comma_lists() {
    for value in ["?1, ?1", "?1, ?0", "?1;foo=bar, ?1"] {
        let mut headers = HeaderMap::new();
        headers.insert("capsule-protocol", HeaderValue::from_static(value));
        assert!(!capsule_protocol_enabled(&headers), "{value:?}");
    }
}

#[test]
fn capsule_protocol_rejects_repeated_field_lines() {
    for values in [["?1", "?1"], ["?1", "?0"], ["?0", "?1"], ["", "?1"]] {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("capsule-protocol", HeaderValue::from_static(value));
        }
        assert!(!capsule_protocol_enabled(&headers), "{values:?}");
    }
}

#[test]
fn authority_resolution_preserves_host_errors_even_for_http1_absolute_form() {
    for (values, expected) in [
        (
            vec![b"".as_slice()],
            RequestValidationError::EmptyHostHeader,
        ),
        (
            vec![b" ".as_slice()],
            RequestValidationError::EmptyHostHeader,
        ),
        (
            vec![b"\xff".as_slice()],
            RequestValidationError::InvalidHostHeader,
        ),
        (
            vec![b"exa mple.com".as_slice()],
            RequestValidationError::InvalidHostHeader,
        ),
        (
            vec![b"", b"example.com".as_slice()],
            RequestValidationError::MultipleHostHeaders,
        ),
    ] {
        for version in [
            Version::HTTP_10,
            Version::HTTP_11,
            Version::HTTP_2,
            Version::HTTP_3,
        ] {
            let mut req = http::Request::builder()
                .version(version)
                .uri("https://example.com/")
                .body(())
                .expect("request");
            for value in &values {
                req.headers_mut()
                    .append(HOST, HeaderValue::from_bytes(value).expect("header"));
            }
            let req = OwnerRequest::from_http(req);
            assert_eq!(validate_incoming_request(&req), Err(expected.clone()));
            assert_eq!(
                resolve_request_authority(
                    req.headers(),
                    req.uri().authority(),
                    req.uri().scheme_str()
                ),
                Err(expected.clone())
            );
        }
    }
}

#[test]
fn authority_resolution_preserves_fallback_and_scheme_default_ports() {
    for (host, target, scheme, expected) in [
        (
            None,
            "/",
            Some("http"),
            Err(RequestValidationError::MissingHost),
        ),
        (
            None,
            "/",
            Some("https"),
            Err(RequestValidationError::MissingHost),
        ),
        (None, "/", None, Ok(None)),
        (
            Some("Example.COM:443"),
            "https://example.com/",
            Some("https"),
            Ok(Some("example.com")),
        ),
        (
            Some("example.com:80"),
            "/",
            Some("http"),
            Ok(Some("example.com:80")),
        ),
        (
            Some("other.example"),
            "https://example.com/",
            Some("https"),
            Err(RequestValidationError::HostAuthorityMismatch),
        ),
        (
            Some("example.com"),
            "https://example.com:abc/",
            Some("https"),
            Err(RequestValidationError::InvalidRequestTarget),
        ),
    ] {
        let mut builder = http::Request::builder().uri(target);
        if let Some(host) = host {
            builder = builder.header(HOST, host);
        }
        let req = OwnerRequest::from_http(builder.body(()).expect("request"));
        let result = resolve_request_authority(req.headers(), req.uri().authority(), scheme);
        assert_eq!(
            result
                .as_ref()
                .map(|a| a.as_ref().map(http::uri::Authority::as_str)),
            expected.as_ref().map(|a| *a)
        );
    }
}

#[test]
fn content_length_presence_and_errors_precede_connection_header_validation() {
    for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
        for (length, expected) in [
            (None, Ok(())),
            (
                Some("0"),
                Err(RequestValidationError::BothTransferEncodingAndContentLength),
            ),
            (
                Some("0, 0"),
                Err(RequestValidationError::BothTransferEncodingAndContentLength),
            ),
            (Some(""), Err(RequestValidationError::InvalidContentLength)),
            (
                Some("0, 1"),
                Err(RequestValidationError::InvalidContentLength),
            ),
        ] {
            let mut builder = http::Request::builder()
                .version(version)
                .uri("https://example.com/")
                .header(HOST, "example.com")
                .header(TRANSFER_ENCODING, "chunked");
            if let Some(length) = length {
                builder = builder.header(CONTENT_LENGTH, length);
            }
            let req = OwnerRequest::from_http(builder.body(()).expect("request"));
            let expected = if length.is_none() && version != Version::HTTP_11 {
                Err(RequestValidationError::InvalidH2H3ConnectionHeader)
            } else {
                expected
            };
            assert_eq!(validate_incoming_request(&req), expected);
        }
    }
}

#[test]
fn common_h2_head_shape_is_sufficient_with_opaque_ordinary_fields() {
    let req = OwnerRequest::from_http(
        http::Request::builder()
            .version(Version::HTTP_2)
            .method(Method::HEAD)
            .uri("https://example.com/")
            .header(
                "x-opaque",
                HeaderValue::from_bytes(b"\xff").expect("header"),
            )
            .body(())
            .expect("request"),
    );
    assert!(is_intrinsically_valid_common_h2_request(&req));
    validate_incoming_request(&req).expect("fast shape must pass full validation");
}

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
#[test]
fn h3_connect_header_validation_keeps_content_length_error_precedence() {
    let req = OwnerRequest::from_http(
        http::Request::builder()
            .header(CONTENT_LENGTH, "0, 1")
            .header(CONNECTION, "close")
            .body(())
            .expect("request"),
    );
    assert_eq!(
        validate_h2_h3_connect_headers(req.headers()),
        Err(RequestValidationError::InvalidContentLength)
    );
}
