use super::*;
use qpx_core::config::HttpGuardLimitsConfig;

#[test]
fn header_normalization_trims_only_http_ows() {
    assert_eq!(trimmed_http_ows_len(b" \tvalue\t "), 5);
    assert_eq!(trimmed_http_ows_len(b" \t "), 0);
    assert_eq!(trimmed_http_ows_len(b"\x80value\x80"), 7);
}

#[test]
fn guard_detects_conflicting_content_length() {
    let profile = CompiledHttpGuardProfile {
        profile: HttpGuardProfileConfig {
            name: "strict".to_string(),
            normalize: Default::default(),
            protocol_safety: Default::default(),
            limits: Default::default(),
            json: Default::default(),
            multipart: Default::default(),
        },
    };
    let mut req = Request::builder()
        .uri("http://example.com/")
        .body(Body::empty())
        .expect("request");
    req.headers_mut().append(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("10"),
    );
    req.headers_mut().append(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("11"),
    );
    let reject = profile.evaluate_request(&req).expect("guard");
    assert!(reject.is_some());
}

#[test]
fn request_body_observation_limit_only_lowers_the_base_limit() {
    // No guard: the base limit stands unchanged.
    assert_eq!(request_body_observation_limit(None, 4096), 4096);

    // A guard cap below the base limit lowers it.
    let capped = profile_with_body_bytes(1024);
    assert_eq!(request_body_observation_limit(Some(&capped), 4096), 1024);

    // A guard cap above the base limit never raises it.
    let generous = profile_with_body_bytes(8192);
    assert_eq!(request_body_observation_limit(Some(&generous), 4096), 4096);
}

fn profile_with_body_bytes(body_bytes: usize) -> CompiledHttpGuardProfile {
    CompiledHttpGuardProfile {
        profile: HttpGuardProfileConfig {
            name: "capped".to_string(),
            normalize: Default::default(),
            protocol_safety: Default::default(),
            limits: HttpGuardLimitsConfig {
                body_bytes: Some(body_bytes),
                ..Default::default()
            },
            json: Default::default(),
            multipart: Default::default(),
        },
    }
}

fn strict_profile() -> CompiledHttpGuardProfile {
    CompiledHttpGuardProfile {
        profile: HttpGuardProfileConfig {
            name: "strict".to_string(),
            normalize: Default::default(),
            protocol_safety: Default::default(),
            limits: Default::default(),
            json: Default::default(),
            multipart: Default::default(),
        },
    }
}

fn head_request(version: http::Version) -> Request<Body> {
    let mut req = Request::builder()
        .uri("http://example.com/")
        .version(version)
        .body(Body::empty())
        .expect("request");
    // `Request::builder` defaults to HTTP/1.1; enforce the requested version
    // explicitly so H1.0/H2 cases exercise their own policy branch.
    *req.version_mut() = version;
    req
}

#[test]
fn guard_rejects_content_length_with_transfer_encoding() {
    let profile = strict_profile();
    let mut req = head_request(http::Version::HTTP_11);
    req.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("10"),
    );
    req.headers_mut().insert(
        http::header::TRANSFER_ENCODING,
        http::HeaderValue::from_static("chunked"),
    );
    let reject = profile.evaluate_request(&req).expect("guard");
    assert!(reject.is_some());
}

#[test]
fn guard_accepts_content_length_values_that_declare_the_same_length() {
    let profile = strict_profile();
    // RFC 9112 section 6.3 lets a recipient replace duplicated
    // Content-Length values that declare the same length with one value, so
    // the guard reads the length the field declares and not the text of its
    // values.
    for values in [["10", "10"], ["10", "10, 10"], ["10, 10", "10, 10"]] {
        let mut req = head_request(http::Version::HTTP_11);
        for value in values {
            req.headers_mut().append(
                http::header::CONTENT_LENGTH,
                http::HeaderValue::from_static(value),
            );
        }
        let reject = profile.evaluate_request(&req).expect("guard");
        assert!(reject.is_none(), "content-length {values:?} must pass");
    }
}

#[test]
fn guard_rejects_a_content_length_that_names_two_lengths() {
    let profile = strict_profile();
    // One value that names two lengths is a conflict as well, so the guard
    // refuses it rather than reading a length out of it.
    let mut req = head_request(http::Version::HTTP_11);
    req.headers_mut().insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("10, 11"),
    );
    let reject = profile.evaluate_request(&req).expect("guard");
    assert!(reject.is_some());
}

#[test]
fn guard_rejects_a_content_length_that_declares_no_length() {
    let profile = strict_profile();
    // A declaration the owner refuses is not a length, and a request whose
    // length cannot be determined has ambiguous framing.
    for value in ["+10", "abc", "", "10,"] {
        let mut req = head_request(http::Version::HTTP_11);
        req.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_str(value).expect("content-length value"),
        );
        let reject = profile.evaluate_request(&req).expect("guard");
        assert!(reject.is_some(), "content-length {value:?} must be refused");
    }
}

#[test]
fn guard_rejects_ambiguous_transfer_encoding_values() {
    let profile = strict_profile();
    for te in [
        "chunked, chunked",
        "gzip, chunked",
        "chunked; ext=1",
        "x-chunked",
        "chunked ",
    ] {
        let mut req = head_request(http::Version::HTTP_11);
        // `chunked ` (trailing OWS) is valid framing and must pass; the rest
        // must reject fail-closed.
        req.headers_mut().insert(
            http::header::TRANSFER_ENCODING,
            http::HeaderValue::from_str(te).expect("te value"),
        );
        let reject = profile.evaluate_request(&req).expect("guard");
        if te.trim().eq_ignore_ascii_case("chunked") {
            assert!(reject.is_none(), "valid TE {te:?} must pass");
        } else {
            assert_eq!(
                reject.expect("ambiguous TE rejected").body,
                "unsupported Transfer-Encoding: only a single chunked coding is supported",
                "ambiguous TE {te:?}"
            );
        }
    }
}

#[test]
fn guard_preserves_invalid_transfer_encoding_error_message() {
    let profile = strict_profile();

    let mut invalid = head_request(http::Version::HTTP_11);
    invalid.headers_mut().insert(
        http::header::TRANSFER_ENCODING,
        http::HeaderValue::from_bytes(b"\xff").expect("obs-text header value"),
    );
    let reject = profile
        .evaluate_request(&invalid)
        .expect("guard")
        .expect("invalid TE rejected");
    assert_eq!(reject.body, "invalid Transfer-Encoding header");
}

#[test]
fn guard_rejects_split_transfer_encoding_headers() {
    let profile = strict_profile();
    let mut req = head_request(http::Version::HTTP_11);
    req.headers_mut().append(
        http::header::TRANSFER_ENCODING,
        http::HeaderValue::from_static("chunked"),
    );
    req.headers_mut().append(
        http::header::TRANSFER_ENCODING,
        http::HeaderValue::from_static("chunked"),
    );
    let reject = profile.evaluate_request(&req).expect("guard");
    assert!(reject.is_some());
}

#[test]
fn guard_rejects_transfer_encoding_on_http10() {
    let profile = strict_profile();
    let mut req = head_request(http::Version::HTTP_10);
    req.headers_mut().insert(
        http::header::TRANSFER_ENCODING,
        http::HeaderValue::from_static("chunked"),
    );
    let reject = profile.evaluate_request(&req).expect("guard");
    assert!(reject.is_some());
}

#[test]
fn guard_allows_single_chunked_on_http11_and_trailers_on_h2() {
    let profile = strict_profile();
    let mut req = head_request(http::Version::HTTP_11);
    req.headers_mut().insert(
        http::header::TRANSFER_ENCODING,
        http::HeaderValue::from_static("chunked"),
    );
    assert!(profile.evaluate_request(&req).expect("guard").is_none());
    let mut h2 = head_request(http::Version::HTTP_2);
    h2.headers_mut()
        .insert(http::header::TE, http::HeaderValue::from_static("trailers"));
    assert!(profile.evaluate_request(&h2).expect("guard").is_none());
}

#[tokio::test]
async fn guard_streams_observed_json_without_full_bytes_materialization() {
    let profile = CompiledHttpGuardProfile {
        profile: HttpGuardProfileConfig {
            name: "json".to_string(),
            normalize: Default::default(),
            protocol_safety: Default::default(),
            limits: Default::default(),
            json: qpx_core::config::HttpGuardJsonConfig {
                max_depth: Some(2),
                max_fields: None,
            },
            multipart: Default::default(),
        },
    };
    let req = Request::builder()
        .uri("http://example.com/")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"outer":{"inner":1}}"#))
        .expect("request");
    let req = crate::http::body::size::buffer_request_body_with_reason(
        req,
        1024,
        std::time::Duration::from_secs(1),
        "test",
    )
    .await
    .expect("buffer");

    let reject = profile
        .evaluate_request_async(&req)
        .await
        .expect("guard")
        .expect("reject");
    assert_eq!(reject.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn guard_streams_observed_multipart_without_full_bytes_materialization() {
    let profile = CompiledHttpGuardProfile {
        profile: HttpGuardProfileConfig {
            name: "multipart".to_string(),
            normalize: Default::default(),
            protocol_safety: Default::default(),
            limits: Default::default(),
            json: Default::default(),
            multipart: qpx_core::config::HttpGuardMultipartConfig {
                max_parts: Some(1),
                max_name_bytes: None,
                max_filename_bytes: None,
            },
        },
    };
    let req = Request::builder()
        .uri("http://example.com/")
        .header(
            http::header::CONTENT_TYPE,
            "multipart/form-data; boundary=x",
        )
        .body(Body::from(
            "--x\r\ncontent-disposition: form-data; name=\"a\"\r\n\r\n1\r\n--x\r\ncontent-disposition: form-data; name=\"b\"\r\n\r\n2\r\n--x--\r\n",
        ))
        .expect("request");
    let req = crate::http::body::size::buffer_request_body_with_reason(
        req,
        1024,
        std::time::Duration::from_secs(1),
        "test",
    )
    .await
    .expect("buffer");

    let reject = profile
        .evaluate_request_async(&req)
        .await
        .expect("guard")
        .expect("reject");
    assert_eq!(reject.status, StatusCode::PAYLOAD_TOO_LARGE);
}
