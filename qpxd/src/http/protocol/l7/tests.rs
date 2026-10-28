use super::*;
use bytes::Bytes;

#[test]
fn finalize_response_preserves_pre_sanitized_body() {
    let mut response = Response::new(Body::from("ok").mark_trailers_sanitized());

    finalize_response_in_place(
        &Method::GET,
        http::Version::HTTP_11,
        "qpx",
        &mut response,
        false,
    );

    assert!(response.body().trailers_are_sanitized());
}

#[test]
fn prepare_request_synchronizes_host_only_for_absolute_targets() {
    let mut absolute = Request::from_http(
        http::Request::builder()
            .uri("https://example.com/resource")
            .header(http::header::HOST, "stale.example")
            .body(Body::empty())
            .expect("absolute request"),
    );
    prepare_request_with_headers_in_place(&mut absolute, "qpx", None, false);
    assert_eq!(
        absolute
            .headers()
            .get(&OrdinaryHeaderName::try_from(http::header::HOST.clone()).expect("ordinary field"))
            .unwrap(),
        "example.com"
    );

    let mut origin = Request::from_http(
        http::Request::builder()
            .uri("/resource")
            .header(http::header::HOST, "origin.example")
            .body(Body::empty())
            .expect("origin-form request"),
    );
    prepare_request_with_headers_in_place(&mut origin, "qpx", None, false);
    assert_eq!(
        origin
            .headers()
            .get(&OrdinaryHeaderName::try_from(http::header::HOST.clone()).expect("ordinary field"))
            .unwrap(),
        "origin.example"
    );
}

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
async fn prepare_request_rejects_forbidden_h2_trailers() {
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("2"),
    );
    let mut request = Request::from_http(
        http::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/upload")
            .version(http::Version::HTTP_2)
            .body(Body::replay(Bytes::from_static(b"ok"), Some(trailers)))
            .expect("request"),
    );

    prepare_request_with_headers_in_place(&mut request, "qpx", None, false);

    assert_eq!(
        request
            .body_mut()
            .data()
            .await
            .expect("body frame")
            .expect("body chunk"),
        Bytes::from_static(b"ok")
    );
    let err = request
        .body_mut()
        .trailers()
        .await
        .expect_err("forbidden request trailers must fail");
    assert_eq!(err.to_string(), "body aborted");
}

#[tokio::test]
async fn finalize_response_preserves_body_stream_errors() {
    let (mut sender, body) = Body::channel();
    sender.abort();
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(body)
        .expect("response");

    finalize_response_in_place(
        &Method::GET,
        http::Version::HTTP_11,
        "qpx",
        &mut response,
        false,
    );

    let err = response
        .body_mut()
        .data()
        .await
        .expect("body error frame")
        .expect_err("upstream body error must be preserved");
    assert_eq!(err.to_string(), "body aborted");
}

#[tokio::test]
async fn trace_loopback_filters_sensitive_headers_by_default() {
    let mut request = Request::from_http(
        http::Request::builder()
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
            .expect("request"),
    );

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
    let mut request = Request::from_http(
        http::Request::builder()
            .method(Method::TRACE)
            .uri("http://example.com/trace")
            .header(http::header::HOST, "example.com")
            .header(http::header::AUTHORIZATION, "Bearer secret")
            .header("x-forwarded-for", "203.0.113.9")
            .body(Body::empty())
            .expect("request"),
    );

    let body = serialize_trace_loopback_message(&mut request, true, 1024, Duration::from_secs(1))
        .await
        .expect("trace body");
    let body = String::from_utf8(body).expect("utf8");

    assert!(body.contains("authorization: Bearer secret\r\n"));
    assert!(body.contains("x-forwarded-for: 203.0.113.9\r\n"));
}

#[tokio::test]
async fn trace_loopback_rejects_body_above_hard_cap() {
    let mut request = Request::from_http(
        http::Request::builder()
            .method(Method::TRACE)
            .uri("http://example.com/trace")
            .body(Body::from("body"))
            .expect("request"),
    );

    let err = serialize_trace_loopback_message(&mut request, false, 3, Duration::from_secs(1))
        .await
        .expect_err("trace body above cap");
    assert!(err.to_string().contains("TRACE request body exceeds"));
}

async fn run_max_forwards(
    method: Method,
    values: &[&str],
) -> (Option<Response<Body>>, Request<Body>) {
    let mut request = Request::from_http(
        http::Request::builder()
            .method(method)
            .uri("/")
            .body(Body::empty())
            .expect("request"),
    );
    for value in values {
        request.headers_mut().append(
            OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS.clone())
                .expect("ordinary field"),
            http::HeaderValue::from_str(value).expect("header value"),
        );
    }

    let response =
        handle_max_forwards_in_place(&mut request, "qpx", false, 1024, Duration::from_secs(1))
            .await;
    (response, request)
}

#[tokio::test]
async fn max_forwards_accepts_only_ows_wrapped_decimal_and_decrements() {
    for (value, expected) in [("1", "0"), ("001", "0"), (" \t2\t ", "1")] {
        let (response, request) = run_max_forwards(Method::OPTIONS, &[value]).await;
        assert!(response.is_none(), "{value:?} should be forwarded");
        assert_eq!(
            request
                .headers()
                .get(
                    &OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS.clone())
                        .expect("ordinary field")
                )
                .unwrap(),
            expected
        );
    }

    for (method, expected) in [
        (Method::OPTIONS, StatusCode::NO_CONTENT),
        (Method::TRACE, StatusCode::OK),
    ] {
        let (response, _) = run_max_forwards(method, &["0"]).await;
        assert_eq!(
            response
                .expect("zero Max-Forwards is handled locally")
                .status(),
            expected
        );
    }
}

#[tokio::test]
async fn max_forwards_rejects_signed_and_non_decimal_values() {
    for value in ["+0", "+1", "-1", "", "1, 2"] {
        let (response, _) = run_max_forwards(Method::OPTIONS, &[value]).await;
        assert_eq!(
            response.expect("invalid Max-Forwards is rejected").status(),
            StatusCode::BAD_REQUEST,
            "accepted invalid value {value:?}"
        );
    }

    let (response, _) = run_max_forwards(Method::OPTIONS, &["1", "2"]).await;
    assert_eq!(
        response
            .expect("duplicate Max-Forwards is rejected")
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn max_forwards_caps_large_decimal_values_before_forwarding() {
    let (response, request) = run_max_forwards(Method::OPTIONS, &["4294967295"]).await;
    assert!(response.is_none());
    assert_eq!(
        request
            .headers()
            .get(
                &OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS.clone())
                    .expect("ordinary field")
            )
            .unwrap(),
        "4294967294"
    );

    let (response, request) = run_max_forwards(Method::OPTIONS, &["4294967296"]).await;
    assert!(response.is_none());
    assert_eq!(
        request
            .headers()
            .get(
                &OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS.clone())
                    .expect("ordinary field")
            )
            .unwrap(),
        "4294967295"
    );

    // The RFC permits the recipient to cap at its maximum supported value.
    let (response, request) = run_max_forwards(Method::OPTIONS, &["4294967297"]).await;
    assert!(response.is_none());
    assert_eq!(
        request
            .headers()
            .get(
                &OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS.clone())
                    .expect("ordinary field")
            )
            .unwrap(),
        "4294967295"
    );

    let very_large = "9".repeat(40);
    let (response, request) = run_max_forwards(Method::OPTIONS, &[very_large.as_str()]).await;
    assert!(response.is_none());
    assert_eq!(
        request
            .headers()
            .get(
                &OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS.clone())
                    .expect("ordinary field")
            )
            .unwrap(),
        "4294967295"
    );
}

#[tokio::test]
async fn max_forwards_is_ignored_for_other_methods() {
    let (response, request) = run_max_forwards(Method::POST, &["+1"]).await;
    assert!(response.is_none());
    assert_eq!(
        request
            .headers()
            .get(
                &OrdinaryHeaderName::try_from(http::header::MAX_FORWARDS.clone())
                    .expect("ordinary field")
            )
            .unwrap(),
        "+1"
    );
}

fn request_set_headers(yaml: &str) -> CompiledHeaderControl {
    CompiledHeaderControl::compile(&serde_yaml::from_str(yaml).expect("header config"))
        .expect("compiled headers")
}

#[test]
fn prepare_request_consumes_nominations_before_request_set() {
    let control = request_set_headers(
        r#"
request_set:
  x-qpx-trusted: proxy-value
  connection: X-Configured-Hop
  x-configured-hop: must-not-leak
  keep-alive: timeout=5
"#,
    );
    let mut request = Request::from_http(
        http::Request::builder()
            .uri("https://example.com/")
            .header("connection", "X-QpX-TrUsTeD, x-ClIeNt-OnLy")
            .header("connection", "Keep-Alive")
            .header("x-qpx-trusted", "client-value")
            .header("x-client-only", "must-not-leak")
            .body(Body::empty())
            .expect("request"),
    );
    prepare_request_with_headers_in_place(&mut request, "qpx", Some(&control), false);
    assert_eq!(
        request
            .headers()
            .get(&OrdinaryHeaderName::try_from("x-qpx-trusted").expect("ordinary field"))
            .unwrap(),
        "proxy-value"
    );
    for name in [
        "x-client-only",
        "connection",
        "x-configured-hop",
        "keep-alive",
    ] {
        assert!(
            !request
                .headers()
                .contains_key(&OrdinaryHeaderName::try_from(name).expect("ordinary field")),
            "{name}"
        );
    }
}

#[test]
fn consume_hop_headers_preserves_websocket_detection_and_strips_nominations() {
    use crate::http::protocol::websocket::is_websocket_upgrade;
    let control = request_set_headers("request_set: { x-qpx-trusted: proxy-value }");
    let mut request = Request::from_http(
        http::Request::builder()
            .uri("http://example.com/socket")
            .header("connection", "UpGrAdE, X-QpX-TrUsTeD")
            .header("connection", "x-ClIeNt-OnLy, Keep-Alive")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("x-qpx-trusted", "client-value")
            .header("x-client-only", "must-not-leak")
            .body(Body::empty())
            .expect("request"),
    );
    assert!(is_websocket_upgrade(request.method(), request.headers()).expect("original upgrade"));
    consume_request_hop_headers(&mut request);
    // Reverse applies route controls before it detects upgrades.
    apply_request_header_control_in_place(&mut request, Some(&control));
    let websocket = is_websocket_upgrade(request.method(), request.headers()).expect("upgrade");
    assert!(websocket);
    prepare_request_with_headers_in_place(&mut request, "qpx", None, websocket);
    assert_eq!(
        request
            .headers()
            .get(&OrdinaryHeaderName::try_from("connection").expect("ordinary field"))
            .unwrap(),
        "upgrade"
    );
    assert_eq!(
        request
            .headers()
            .get(&OrdinaryHeaderName::try_from("upgrade").expect("ordinary field"))
            .unwrap(),
        "websocket"
    );
    assert_eq!(
        request
            .headers()
            .get(&OrdinaryHeaderName::try_from("x-qpx-trusted").expect("ordinary field"))
            .unwrap(),
        "proxy-value"
    );
    assert!(
        !request
            .headers()
            .contains_key(&OrdinaryHeaderName::try_from("x-client-only").expect("ordinary field"))
    );
}

#[test]
fn consume_hop_headers_defers_incomplete_upgrade_to_existing_route_controls() {
    use crate::http::protocol::websocket::is_websocket_upgrade;
    let mut request = Request::from_http(
        http::Request::builder()
            .header("connection", "X-Client-Only")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("x-client-only", "must-not-leak")
            .body(Body::empty())
            .expect("request"),
    );
    consume_request_hop_headers(&mut request);
    assert!(is_websocket_upgrade(request.method(), request.headers()).is_err());
    // Existing route-driven completion of an upgrade is not moved before controls.
    let control = request_set_headers("request_set: { connection: upgrade }");
    apply_request_header_control_in_place(&mut request, Some(&control));
    assert!(is_websocket_upgrade(request.method(), request.headers()).expect("route upgrade"));
    assert!(
        !request
            .headers()
            .contains_key(&OrdinaryHeaderName::try_from("x-client-only").expect("ordinary field"))
    );
}

#[tokio::test]
async fn consume_hop_headers_keeps_h1_trailer_validation() {
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("2"),
    );
    let mut request = Request::from_http(
        http::Request::builder()
            .version(http::Version::HTTP_11)
            .header("trailer", "content-length")
            .header("connection", "X-Client-Only")
            .body(Body::replay(Bytes::from_static(b"ok"), Some(trailers)))
            .expect("request"),
    );
    consume_request_hop_headers(&mut request);
    prepare_request_with_headers_in_place(&mut request, "qpx", None, false);
    assert!(
        !request
            .headers()
            .contains_key(&OrdinaryHeaderName::try_from("trailer").expect("ordinary field"))
    );
    assert_eq!(request.body_mut().data().await.unwrap().unwrap(), "ok");
    assert!(request.body_mut().trailers().await.is_err());
}

mod response_finalization;
