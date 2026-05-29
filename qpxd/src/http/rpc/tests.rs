use super::*;
use qpx_core::config::RpcLocalResponseConfig;
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn parses_grpc_web_trailer_frame() {
    let body = Bytes::from(frame_grpc_web_trailers(
        b"grpc-status: 7\r\ngrpc-message: denied\r\n",
    ));
    let mut observer = GrpcFrameObserver::grpc_web(false, None, None);
    observer.feed(&body).expect("feed");
    let summary = observer.finish().expect("summary");
    let trailers = summary.trailers.expect("trailers");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("7")
    );
    assert_eq!(summary.message_count, 0);
}

#[test]
fn parses_grpc_frame_across_chunk_boundaries() {
    let body = frame_grpc_message(Bytes::from_static(b"hello"));
    let mut observer = GrpcFrameObserver::new(None);
    for chunk in body.chunks(2) {
        observer.feed(chunk).expect("feed");
    }
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 5);
}

#[tokio::test]
async fn buffered_grpc_request_precomputes_rpc_summary() {
    let mut body = frame_grpc_message(Bytes::from_static(b"hello"));
    body.extend_from_slice(&frame_grpc_message(Bytes::from_static(b"world")));
    let req = Request::builder()
        .method("POST")
        .uri("/demo.Echo/Say")
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(Body::from(body))
        .expect("request");

    let req = crate::http::body::size::buffer_request_body_with_reason(
        req,
        1024,
        Duration::from_secs(1),
        "rpc.body",
    )
    .await
    .expect("buffered");

    assert!(
        req.extensions()
            .get::<PrecomputedRpcBodySummary>()
            .is_some()
    );
    let rpc = inspect_request(&req).await;
    assert_eq!(rpc.request_message_count, Some(2));
    assert_eq!(rpc.request_message_bytes, Some(10));
    assert_eq!(rpc.streaming.as_deref(), Some("client"));
}

#[test]
fn grpc_observer_rejects_messages_over_limit() {
    let body = frame_grpc_message(Bytes::from_static(b"hello"));
    let mut observer = GrpcFrameObserver::new(Some(4));
    let err = observer.feed(&body[..5]).expect_err("too large");
    assert!(matches!(
        err,
        GrpcFrameError::MessageTooLarge { len: 5, max: 4 }
    ));
}

#[test]
fn grpc_web_observer_uses_separate_trailer_limit() {
    let body = Bytes::from(frame_grpc_web_trailers(b"grpc-status: 0\r\n"));
    let mut observer = GrpcFrameObserver::grpc_web(false, Some(4), Some(64));
    observer.feed(&body[..5]).expect("trailer header allowed");
    observer.feed(&body[5..]).expect("trailer body allowed");
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 0);

    let mut observer = GrpcFrameObserver::grpc_web(false, Some(1024), Some(4));
    let err = observer.feed(&body[..5]).expect_err("trailer too large");
    assert!(matches!(
        err,
        GrpcFrameError::TrailerTooLarge { len: 16, max: 4 }
    ));
}

#[test]
fn grpc_web_observer_rejects_huge_trailer_length_without_explicit_limit() {
    let mut observer = GrpcFrameObserver::grpc_web(false, None, None);
    let err = observer
        .feed(&[0x80, 0xff, 0xff, 0xff, 0xff])
        .expect_err("huge trailer length must be rejected before allocation");
    assert!(matches!(
        err,
        GrpcFrameError::TrailerTooLarge {
            len: 4_294_967_295,
            max: DEFAULT_MAX_GRPC_WEB_TRAILER_BYTES
        }
    ));
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_streaming_observer_parses_envelopes() {
    let mut body = Vec::new();
    body.extend_from_slice(&frame_grpc_message(Bytes::from_static(b"hello")));
    body.push(0x02);
    body.extend_from_slice(&(r#"{"code":"ok","message":"done"}"#.len() as u32).to_be_bytes());
    body.extend_from_slice(br#"{"code":"ok","message":"done"}"#);

    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/connect+json"),
    );
    let mut observer =
        streaming_rpc_observer(&headers, None, Some(1024), Some(1024)).expect("observer");
    for chunk in body.chunks(3) {
        observer.feed(chunk).expect("feed");
    }
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 5);
    assert_eq!(
        summary
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("connect-code"))
            .and_then(|value| value.to_str().ok()),
        Some("ok")
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_streaming_observer_accepts_compressed_message_envelopes() {
    let mut body = Vec::new();
    body.push(0x01);
    body.extend_from_slice(&5u32.to_be_bytes());
    body.extend_from_slice(b"hello");

    let mut observer = ConnectFrameObserver::new(Some(8), Some(8));
    observer.feed(body.as_slice()).expect("compressed messages");
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 5);
    assert!(summary.trailers.is_none());
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_streaming_observer_treats_compressed_end_stream_as_metadata() {
    let mut body = Vec::new();
    body.push(0x03);
    body.extend_from_slice(&(r#"{"code":"ok","message":"done"}"#.len() as u32).to_be_bytes());
    body.extend_from_slice(br#"{"code":"ok","message":"done"}"#);

    let mut observer = ConnectFrameObserver::new(Some(8), Some(64));
    observer.feed(body.as_slice()).expect("compressed metadata");
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 0);
    assert_eq!(
        summary
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("connect-code"))
            .and_then(|value| value.to_str().ok()),
        Some("ok")
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_streaming_observer_rejects_unknown_envelope_bits() {
    let mut observer = ConnectFrameObserver::new(None, None);
    let err = observer
        .feed(&[0x04, 0, 0, 0, 0])
        .expect_err("unknown flag bit must fail");
    assert!(format!("{err}").contains("unsupported Connect envelope flags"));
}

#[test]
fn grpc_web_text_observer_decodes_incrementally() {
    let encoded = BASE64.encode(frame_grpc_message(Bytes::from_static(b"hello")));
    let mut observer = GrpcFrameObserver::grpc_web(true, None, None);
    for chunk in encoded.as_bytes().chunks(3) {
        observer.feed(chunk).expect("feed");
    }
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 5);
}

#[test]
fn grpc_web_text_observer_rejects_oversized_message_before_finish() {
    let encoded = BASE64.encode(frame_grpc_message(Bytes::from_static(b"hello")));
    let mut observer = GrpcFrameObserver::grpc_web(true, Some(4), None);
    observer
        .feed(&encoded.as_bytes()[..4])
        .expect("partial header");
    let err = observer
        .feed(&encoded.as_bytes()[4..8])
        .expect_err("frame header should reveal oversized message");
    assert!(matches!(
        err,
        GrpcFrameError::MessageTooLarge { len: 5, max: 4 }
    ));
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn streaming_observer_uses_response_fallback_protocol() {
    let headers = HeaderMap::new();
    let observer = streaming_rpc_observer(&headers, Some("grpc"), Some(1024), None)
        .expect("fallback observer");
    assert_eq!(observer.protocol(), "grpc");
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn grpc_timeout_parser_and_formatter_round_trip_common_units() {
    assert_eq!(parse_grpc_timeout("500m"), Some(Duration::from_millis(500)));
    assert_eq!(parse_grpc_timeout("2S"), Some(Duration::from_secs(2)));
    assert_eq!(parse_grpc_timeout("1H"), Some(Duration::from_secs(3600)));
    assert_eq!(parse_grpc_timeout("123456789m"), None);
    assert_eq!(format_grpc_timeout(Duration::from_millis(500)), "500m");
    assert_eq!(format_grpc_timeout(Duration::ZERO), "1n");
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn grpc_deadline_prefers_client_timeout_when_shorter() {
    let started = Instant::now();
    let mut headers = HeaderMap::new();
    headers.insert("grpc-timeout", http::HeaderValue::from_static("250m"));
    assert_eq!(
        resolve_rpc_deadline(&headers, "grpc", Duration::from_secs(1), started).instant(),
        started + Duration::from_millis(250)
    );
    headers.insert("grpc-timeout", http::HeaderValue::from_static("10S"));
    assert_eq!(
        resolve_rpc_deadline(&headers, "grpc", Duration::from_secs(1), started).instant(),
        started + Duration::from_secs(1)
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn grpc_deadline_clamps_oversized_client_timeout_before_instant_add() {
    let started = Instant::now();
    let mut headers = HeaderMap::new();
    headers.insert("grpc-timeout", http::HeaderValue::from_static("99999999H"));
    assert_eq!(
        resolve_rpc_deadline(&headers, "grpc", Duration::from_secs(1), started).instant(),
        started + Duration::from_secs(1)
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_deadline_uses_connect_timeout_ms_header() {
    let started = Instant::now();
    let mut headers = HeaderMap::new();
    headers.insert("connect-timeout-ms", http::HeaderValue::from_static("250"));
    headers.insert("grpc-timeout", http::HeaderValue::from_static("1n"));
    let deadline = resolve_rpc_deadline(&headers, "connect", Duration::from_secs(1), started);
    assert_eq!(deadline.instant(), started + Duration::from_millis(250));
    assert_eq!(deadline.protocol(), RpcDeadlineProtocol::Connect);

    let mut forwarded = HeaderMap::new();
    forwarded.insert("grpc-timeout", http::HeaderValue::from_static("1n"));
    apply_grpc_deadline_header(&mut forwarded, deadline);
    assert!(!forwarded.contains_key("grpc-timeout"));
    assert!(forwarded.contains_key("connect-timeout-ms"));
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_fallback_does_not_treat_json_error_as_streaming_envelope() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    assert!(streaming_rpc_observer(&headers, Some("connect"), Some(1024), Some(1024)).is_none());

    headers.insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/connect+json"),
    );
    assert!(streaming_rpc_observer(&headers, Some("connect"), Some(1024), Some(1024)).is_some());
}

#[test]
fn grpc_path_extracts_service_and_method() {
    assert_eq!(
        extract_service_and_method("/demo.Echo/Say"),
        Some(("demo.Echo", "Say"))
    );
    assert!(extract_service_and_method("/invalid").is_none());
}

#[test]
fn rpc_status_labels_are_normalized_to_fixed_sets() {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("9999"));
    assert_eq!(
        extract_grpc_status_and_message(&HeaderMap::new(), Some(&trailers)).0,
        Some("invalid".to_string())
    );
    trailers.insert("grpc-status", http::HeaderValue::from_static("16"));
    assert_eq!(
        extract_grpc_status_and_message(&HeaderMap::new(), Some(&trailers)).0,
        Some("16".to_string())
    );

    let body = Bytes::from_static(br#"{"code":"attacker-controlled","message":"x"}"#);
    assert_eq!(
        extract_connect_status_and_message(Some(&body)).0,
        Some("invalid".to_string())
    );
    let body = Bytes::from_static(br#"{"code":"deadline_exceeded","message":"x"}"#);
    assert_eq!(
        extract_connect_status_and_message(Some(&body)).0,
        Some("deadline_exceeded".to_string())
    );
}

#[tokio::test]
async fn grpc_local_response_emits_trailers() {
    let response = build_rpc_local_response(
        &RpcLocalResponseConfig {
            protocol: "grpc".to_string(),
            status: Some("14".to_string()),
            message: Some("unavailable".to_string()),
            http_status: Some(200),
            headers: HashMap::new(),
            trailers: HashMap::new(),
        },
        b"",
    )
    .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    assert!(body.data().await.is_none());
    let trailers = body.trailers().await.expect("trailers").expect("present");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("14")
    );
}

#[tokio::test]
async fn grpc_web_local_response_emits_trailer_frame() {
    let response = build_rpc_local_response(
        &RpcLocalResponseConfig {
            protocol: "grpc_web".to_string(),
            status: Some("7".to_string()),
            message: Some("denied".to_string()),
            http_status: Some(200),
            headers: HashMap::new(),
            trailers: HashMap::new(),
        },
        b"",
    )
    .expect("response");
    let bytes = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    let mut observer = GrpcFrameObserver::grpc_web(false, None, None);
    observer.feed(&bytes).expect("feed");
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 0);
    let trailers = summary.trailers.expect("trailers");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("7")
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[tokio::test]
async fn grpc_web_deadline_response_uses_body_trailer_frame() {
    let response = build_grpc_deadline_exceeded_response("grpc_web").expect("deadline response");
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc-web+proto")
    );
    let bytes = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    let mut observer = GrpcFrameObserver::grpc_web(false, None, None);
    observer.feed(&bytes).expect("feed");
    let summary = observer.finish().expect("summary");
    assert_eq!(
        summary
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-status"))
            .and_then(|value| value.to_str().ok()),
        Some("4")
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[tokio::test]
async fn connect_deadline_response_uses_json_error_body() {
    let response = build_grpc_deadline_exceeded_response("connect").expect("deadline response");
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let bytes = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    let text = std::str::from_utf8(&bytes).expect("utf8");
    assert!(text.contains("\"code\":\"deadline_exceeded\""));
}
