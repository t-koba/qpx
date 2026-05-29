use super::*;

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
