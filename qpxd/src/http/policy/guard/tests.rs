use super::*;
use qpx_core::config::HttpGuardLimitsConfig;

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
    let mut req = http::Request::builder()
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
    let req = Request::from_http(req);
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
    let mut req = http::Request::builder()
        .uri("http://example.com/")
        .version(version)
        .body(Body::empty())
        .expect("request");
    // `Request::builder` defaults to HTTP/1.1; enforce the requested version
    // explicitly so H1.0/H2 cases exercise their own policy branch.
    *req.version_mut() = version;
    Request::from_http(req)
}

#[test]
fn guard_rejects_content_length_with_transfer_encoding() {
    let profile = strict_profile();
    let mut req = head_request(http::Version::HTTP_11);
    req.headers_mut()
        .set_content_length_value(http::HeaderValue::from_static("10"));
    req.headers_mut().insert(
        OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING).unwrap(),
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
            req.headers_mut()
                .append_content_length_value(http::HeaderValue::from_static(value));
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
    req.headers_mut()
        .set_content_length_value(http::HeaderValue::from_static("10, 11"));
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
        req.headers_mut().set_content_length_value(
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
            OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING).unwrap(),
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
        OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING).unwrap(),
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
        OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING).unwrap(),
        http::HeaderValue::from_static("chunked"),
    );
    req.headers_mut().append(
        OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING).unwrap(),
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
        OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING).unwrap(),
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
        OrdinaryHeaderName::try_from(http::header::TRANSFER_ENCODING).unwrap(),
        http::HeaderValue::from_static("chunked"),
    );
    assert!(profile.evaluate_request(&req).expect("guard").is_none());
    let mut h2 = head_request(http::Version::HTTP_2);
    h2.headers_mut().insert(
        OrdinaryHeaderName::try_from(http::header::TE).unwrap(),
        http::HeaderValue::from_static(" \ttrailers\t "),
    );
    assert!(profile.evaluate_request(&h2).expect("guard").is_none());

    let mut invalid_h2 = head_request(http::Version::HTTP_2);
    invalid_h2.headers_mut().insert(
        OrdinaryHeaderName::try_from(http::header::TE).unwrap(),
        http::HeaderValue::from_static("trailers, gzip"),
    );
    assert!(
        profile
            .evaluate_request(&invalid_h2)
            .expect("guard")
            .is_some()
    );
}

#[test]
fn guard_rejects_split_te_headers_on_h2_and_h3() {
    let profile = strict_profile();
    for version in [http::Version::HTTP_2, http::Version::HTTP_3] {
        let mut req = head_request(version);
        req.headers_mut().append(
            OrdinaryHeaderName::try_from(http::header::TE).unwrap(),
            http::HeaderValue::from_static("trailers"),
        );
        req.headers_mut().append(
            OrdinaryHeaderName::try_from(http::header::TE).unwrap(),
            http::HeaderValue::from_static("gzip"),
        );
        let reject = profile.evaluate_request(&req).expect("guard");
        assert_eq!(
            reject.expect("split TE headers rejected on H2/H3").body,
            "HTTP/2 and HTTP/3 TE must be trailers",
            "version {version:?}"
        );
    }
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
    let req = http::Request::builder()
        .uri("http://example.com/")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"outer":{"inner":1}}"#))
        .expect("request");
    let req = crate::http::body::size::buffer_request_body_with_reason(
        Request::from_http(req),
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
async fn guard_rejects_malformed_json_as_bad_request() {
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
    let req = http::Request::builder()
        .uri("http://example.com/")
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"x":1,}"#))
        .expect("request");
    let req = crate::http::body::size::buffer_request_body_with_reason(
        Request::from_http(req),
        1024,
        std::time::Duration::from_secs(1),
        "test",
    )
    .await
    .expect("buffer");

    let reject = profile
        .evaluate_request_async(&req)
        .await
        .expect("syntax error must not be an internal error")
        .expect("malformed JSON must be rejected");
    assert_eq!(reject.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn guard_streams_observed_multipart_without_full_bytes_materialization() {
    let mut fixture =
        b"--x\r\nCoNtEnT-DiSpOsItIoN: form-data; NAME=\"upload\"; FILENAME=\"a.bin\"\r\n\r\n"
            .to_vec();
    fixture.push(0xff);
    fixture.extend_from_slice(
        b"\r\n--x\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n2\r\n--x--\r\n",
    );
    let body = bytes::Bytes::from(fixture);
    let multipart = |max_parts, max_name_bytes, max_filename_bytes| {
        qpx_core::config::HttpGuardMultipartConfig {
            max_parts,
            max_name_bytes,
            max_filename_bytes,
        }
    };

    for (limits, expected) in [
        (
            multipart(Some(1), None, None),
            Some("multipart part count exceeds http_guard limit"),
        ),
        (multipart(Some(2), None, None), None),
        (
            multipart(Some(2), Some(5), None),
            Some("multipart field name exceeds http_guard limit"),
        ),
        (
            multipart(Some(2), None, Some(4)),
            Some("multipart filename exceeds http_guard limit"),
        ),
    ] {
        let profile = CompiledHttpGuardProfile {
            profile: HttpGuardProfileConfig {
                name: "multipart".to_string(),
                normalize: Default::default(),
                protocol_safety: Default::default(),
                limits: Default::default(),
                json: Default::default(),
                multipart: limits,
            },
        };
        let req = http::Request::builder()
            .uri("http://example.com/")
            .header(
                http::header::CONTENT_TYPE,
                "multipart/form-data; BOUNDARY=x",
            )
            .body(Body::from(body.clone()))
            .expect("request");
        let req = crate::http::body::size::buffer_request_body_with_reason(
            Request::from_http(req),
            1024,
            std::time::Duration::from_secs(1),
            "test",
        )
        .await
        .expect("buffer");

        let reject = profile.evaluate_request_async(&req).await.expect("guard");
        match expected {
            Some(message) => {
                let reject = reject.expect("reject");
                assert_eq!(reject.status, StatusCode::PAYLOAD_TOO_LARGE);
                assert_eq!(reject.body, message);
            }
            None => assert!(reject.is_none()),
        }
    }
}

#[tokio::test]
async fn guard_ignores_mime_looking_multipart_payload_lines() {
    let body = bytes::Bytes::from(
        b"--x\r\nContent-Disposition: form-data; name=\"a\"; filename=\"a.bin\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         MIME snapshot:\r\n\
         Content-Disposition: form-data; name=\"this-name-is-far-too-long\"\r\n\
         --x--\r\n"
            .to_vec(),
    );
    let profile = CompiledHttpGuardProfile {
        profile: HttpGuardProfileConfig {
            name: "multipart".to_string(),
            normalize: Default::default(),
            protocol_safety: Default::default(),
            limits: Default::default(),
            json: Default::default(),
            multipart: qpx_core::config::HttpGuardMultipartConfig {
                max_parts: Some(2),
                max_name_bytes: Some(5),
                max_filename_bytes: Some(5),
            },
        },
    };
    let req = http::Request::builder()
        .uri("http://example.com/")
        .header(
            http::header::CONTENT_TYPE,
            "multipart/form-data; boundary=x",
        )
        .body(Body::from(body))
        .expect("request");
    let req = crate::http::body::size::buffer_request_body_with_reason(
        Request::from_http(req),
        1024,
        std::time::Duration::from_secs(1),
        "test",
    )
    .await
    .expect("buffer");

    assert!(
        profile
            .evaluate_request_async(&req)
            .await
            .expect("guard")
            .is_none()
    );
}

#[test]
fn guard_counts_separate_h3_cookie_fields() {
    let mut profile = strict_profile();
    profile.profile.limits.header_count = Some(1);
    let req = Request::from_http(
        http::Request::builder()
            .version(http::Version::HTTP_3)
            .uri("https://example.com/")
            .header("cookie", "a=1")
            .header("cookie", "b=2")
            .body(Body::empty())
            .unwrap(),
    );
    assert_eq!(
        profile.evaluate_request(&req).unwrap().unwrap().body,
        "header count exceeds http_guard limit"
    );
    profile.profile.limits.header_count = Some(2);
    assert!(profile.evaluate_request(&req).unwrap().is_none());
    let cookie = OrdinaryHeaderName::try_from("cookie").unwrap();
    assert_eq!(
        req.headers()
            .get_all(&cookie)
            .map(|v| v.as_bytes())
            .collect::<Vec<_>>(),
        [b"a=1".as_slice(), b"b=2".as_slice()]
    );
}

#[test]
fn guard_header_limits_include_duplicate_content_length_and_ows() {
    let mut profile = strict_profile();
    profile.profile.limits.header_bytes = Some(30);
    let mut req = head_request(http::Version::HTTP_11);
    req.headers_mut()
        .append_content_length_value(http::HeaderValue::from_static(" 1 "));
    req.headers_mut()
        .append_content_length_value(http::HeaderValue::from_static("1"));
    assert_eq!(
        profile.evaluate_request(&req).unwrap().unwrap().body,
        "header bytes exceed http_guard limit"
    );
    profile.profile.normalize.headers = true;
    assert!(profile.evaluate_request(&req).unwrap().is_none());
    profile.profile.limits.header_count = Some(1);
    assert_eq!(
        profile.evaluate_request(&req).unwrap().unwrap().body,
        "header count exceeds http_guard limit"
    );
}

#[test]
fn guard_framing_rejection_precedes_header_limits() {
    let mut profile = strict_profile();
    profile.profile.limits.header_count = Some(0);
    let mut req = head_request(http::Version::HTTP_11);
    req.headers_mut()
        .set_content_length_value(http::HeaderValue::from_static("bad"));
    assert_eq!(
        profile.evaluate_request(&req).unwrap().unwrap().body,
        "invalid Content-Length header"
    );
}
