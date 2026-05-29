use super::*;
use bytes::Bytes;

#[tokio::test]
async fn finalize_response_sanitizes_h2_trailers_for_h1_downstream() {
    let (mut sender, body) = Body::channel_with_capacity(16);
    tokio::spawn(async move {
        let _ = sender.send_data(Bytes::from_static(b"ok")).await;
        let mut trailers = http::HeaderMap::new();
        trailers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("99"),
        );
        trailers.insert("x-allowed", http::HeaderValue::from_static("kept"));
        let _ = sender.send_trailers(trailers).await;
    });

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .unwrap();
    finalize_response_in_place(
        &Method::GET,
        http::Version::HTTP_11,
        "qpx",
        &mut response,
        false,
    );

    let body = response.body_mut();
    let chunk = body.data().await.unwrap().unwrap();
    assert_eq!(chunk, Bytes::from_static(b"ok"));

    let trailers = body.trailers().await.unwrap().expect("trailers");
    assert!(!trailers.contains_key(http::header::CONTENT_LENGTH));
    assert_eq!(
        trailers
            .get("x-allowed")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );
}

#[tokio::test]
async fn trace_loopback_filters_sensitive_headers_by_default() {
    let mut request = Request::builder()
        .method(Method::TRACE)
        .uri("http://example.com/trace")
        .header(http::header::HOST, "example.com")
        .header(http::header::AUTHORIZATION, "Bearer secret")
        .header(http::header::COOKIE, "sid=abc")
        .header(http::header::CONNECTION, "keep-alive")
        .header("x-forwarded-for", "203.0.113.9")
        .header("traceparent", "00-abc-123-01")
        .header("x-visible", "kept")
        .body(Body::from("body"))
        .expect("request");

    let body = serialize_trace_loopback_message(&mut request, false, 1024, Duration::from_secs(1))
        .await
        .expect("trace body");
    let body = String::from_utf8(body).expect("utf8");

    assert!(body.contains("TRACE http://example.com/trace HTTP/1.1\r\n"));
    assert!(body.contains("host: example.com\r\n"));
    assert!(body.contains("x-visible: kept\r\n"));
    assert!(!body.contains("authorization:"));
    assert!(!body.contains("cookie:"));
    assert!(!body.contains("connection:"));
    assert!(!body.contains("x-forwarded-for:"));
    assert!(!body.contains("traceparent:"));
    assert!(body.ends_with("\r\n\r\nbody"));
}

#[tokio::test]
async fn trace_loopback_can_reflect_all_headers_when_enabled() {
    let mut request = Request::builder()
        .method(Method::TRACE)
        .uri("http://example.com/trace")
        .header(http::header::HOST, "example.com")
        .header(http::header::AUTHORIZATION, "Bearer secret")
        .header("x-forwarded-for", "203.0.113.9")
        .body(Body::empty())
        .expect("request");

    let body = serialize_trace_loopback_message(&mut request, true, 1024, Duration::from_secs(1))
        .await
        .expect("trace body");
    let body = String::from_utf8(body).expect("utf8");

    assert!(body.contains("authorization: Bearer secret\r\n"));
    assert!(body.contains("x-forwarded-for: 203.0.113.9\r\n"));
}

#[tokio::test]
async fn trace_loopback_rejects_body_above_hard_cap() {
    let mut request = Request::builder()
        .method(Method::TRACE)
        .uri("http://example.com/trace")
        .body(Body::from("body"))
        .expect("request");

    let err = serialize_trace_loopback_message(&mut request, false, 3, Duration::from_secs(1))
        .await
        .expect_err("trace body above cap");
    assert!(err.to_string().contains("TRACE request body exceeds"));
}
