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

#[test]
fn grpc_observer_parses_five_byte_header_split_one_byte_at_a_time() {
    let mut body = frame_grpc_message(Bytes::from_static(b"hello"));
    body.extend_from_slice(&frame_grpc_message(Bytes::from_static(b"world")));
    let mut observer = GrpcFrameObserver::new(None);
    for byte in body {
        observer.feed(&[byte]).expect("feed byte");
    }
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 2);
    assert_eq!(summary.message_bytes, 10);
}

#[tokio::test]
async fn buffered_grpc_request_precomputes_rpc_summary() {
    let mut body = frame_grpc_message(Bytes::from_static(b"hello"));
    body.extend_from_slice(&frame_grpc_message(Bytes::from_static(b"world")));
    let req = qpx_core::http_message::Request::from_http(
        Request::builder()
            .method("POST")
            .uri("/demo.Echo/Say")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(Body::from(body))
            .expect("request"),
    );

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
    assert_eq!(rpc.message_size, Some(10));
    assert_eq!(rpc.streaming.as_deref(), Some("client"));
}

#[tokio::test]
async fn empty_grpc_request_reports_zero_payload_size_and_matches() {
    let body = frame_grpc_message(Bytes::from_static(b""));
    assert_eq!(body.len(), 5);
    let req = qpx_core::http_message::Request::from_http(
        Request::builder()
            .method("POST")
            .uri("/demo.Echo/Say")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(Body::from(body))
            .expect("request"),
    );

    let req = crate::http::body::size::buffer_request_body_with_reason(
        req,
        1024,
        Duration::from_secs(1),
        "rpc.body",
    )
    .await
    .expect("buffered");
    let rpc = inspect_request(&req).await;
    assert_eq!(rpc.protocol.as_deref(), Some("grpc"));
    assert_eq!(rpc.request_message_count, Some(1));
    assert_eq!(rpc.request_message_bytes, Some(0));
    assert_eq!(rpc.message_size, Some(0));

    let cfg = qpx_core::config::MatchConfig {
        rpc: Some(qpx_core::config::RpcMatchConfig {
            message_size: vec!["0".to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut interner = qpx_core::prefilter::StringInterner::default();
    let (compiled, _) =
        qpx_core::matchers::CompiledMatch::compile(&cfg, &mut interner).expect("compile");
    let ctx = qpx_core::rules::RuleMatchContext {
        rpc_message_size: rpc.message_size,
        ..Default::default()
    };
    assert!(compiled.matches(&ctx));
}

#[tokio::test]
async fn empty_grpc_response_reports_zero_payload_size() {
    let req = qpx_core::http_message::Request::from_http(
        Request::builder()
            .method("POST")
            .uri("/demo.Echo/Say")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(Body::empty())
            .expect("request"),
    );
    let ctx = inspect_request(&req).await;

    let body = frame_grpc_message(Bytes::from_static(b""));
    let response = http::Response::builder()
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(Body::from(body))
        .expect("response");
    let response = crate::http::body::size::buffer_response_body_with_reason(
        response,
        1024,
        Duration::from_secs(1),
        "rpc.body",
    )
    .await
    .expect("buffered");
    let inspected = inspect_response(&ctx, &response).await;
    assert_eq!(inspected.protocol.as_deref(), Some("grpc"));
    assert_eq!(inspected.response_message_count, Some(1));
    assert_eq!(inspected.response_message_bytes, Some(0));
    assert_eq!(inspected.message_size, Some(0));
}

#[tokio::test]
async fn trailer_only_grpc_web_response_keeps_zero_size_with_trailers() {
    let req = qpx_core::http_message::Request::from_http(
        Request::builder()
            .method("POST")
            .uri("/demo.Echo/Say")
            .header(http::header::CONTENT_TYPE, "application/grpc-web+proto")
            .body(Body::empty())
            .expect("request"),
    );
    let ctx = inspect_request(&req).await;

    let body = frame_grpc_web_trailers(b"grpc-status: 0\r\n");
    let response = http::Response::builder()
        .header(http::header::CONTENT_TYPE, "application/grpc-web+proto")
        .body(Body::from(body))
        .expect("response");
    let response = crate::http::body::size::buffer_response_body_with_reason(
        response,
        1024,
        Duration::from_secs(1),
        "rpc.body",
    )
    .await
    .expect("buffered");
    let inspected = inspect_response(&ctx, &response).await;
    assert_eq!(inspected.protocol.as_deref(), Some("grpc_web"));
    assert_eq!(inspected.response_message_count, Some(0));
    assert_eq!(inspected.response_message_bytes, Some(0));
    assert_eq!(inspected.message_size, Some(0));
    assert_eq!(inspected.status.as_deref(), Some("0"));
    let trailers = inspected.trailers.as_ref().expect("trailers");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
}

#[tokio::test]
async fn malformed_grpc_request_falls_back_to_observed_size() {
    let body = vec![0, 0, 0, 0, 5, b'h', b'i'];
    let req = qpx_core::http_message::Request::from_http(
        Request::builder()
            .method("POST")
            .uri("/demo.Echo/Say")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(Body::from(body.clone()))
            .expect("request"),
    );

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
            .is_none()
    );
    let rpc = inspect_request(&req).await;
    assert_eq!(rpc.request_message_count, None);
    assert_eq!(rpc.request_message_bytes, None);
    assert_eq!(rpc.message_size, Some(body.len() as u64));
}

#[tokio::test]
async fn malformed_grpc_response_falls_back_to_observed_size() {
    let req = qpx_core::http_message::Request::from_http(
        Request::builder()
            .method("POST")
            .uri("/demo.Echo/Say")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(Body::empty())
            .expect("request"),
    );
    let ctx = inspect_request(&req).await;

    let body = vec![0, 0, 0, 0, 5, b'h', b'i'];
    let response = http::Response::builder()
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(Body::from(body.clone()))
        .expect("response");
    let response = crate::http::body::size::buffer_response_body_with_reason(
        response,
        1024,
        Duration::from_secs(1),
        "rpc.body",
    )
    .await
    .expect("buffered");
    assert!(
        response
            .extensions()
            .get::<PrecomputedRpcBodySummary>()
            .is_none()
    );
    let inspected = inspect_response(&ctx, &response).await;
    assert_eq!(inspected.response_message_count, None);
    assert_eq!(inspected.response_message_bytes, None);
    assert_eq!(inspected.message_size, Some(body.len() as u64));
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
    body.extend_from_slice(&(r#"{"metadata":{}}"#.len() as u32).to_be_bytes());
    body.extend_from_slice(br#"{"metadata":{}}"#);

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
    let envelope = r#"{"error":{"code":"unavailable","message":"busy"},"metadata":{"example-trailer":["a","b"]}}"#;
    body.push(0x03);
    body.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    body.extend_from_slice(envelope.as_bytes());

    let mut observer = ConnectFrameObserver::new(Some(8), Some(256));
    observer.feed(body.as_slice()).expect("compressed metadata");
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 0);
    let trailers = summary.trailers.as_ref().expect("trailers");
    assert_eq!(
        trailers
            .get("connect-code")
            .and_then(|value| value.to_str().ok()),
        Some("unavailable")
    );
    assert_eq!(
        trailers
            .get("connect-message")
            .and_then(|value| value.to_str().ok()),
        Some("busy")
    );
    let values: Vec<_> = trailers
        .get_all("example-trailer")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    assert_eq!(values, vec!["a", "b"]);
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_streaming_observer_reassembles_eos_metadata_split_one_byte_at_a_time() {
    let mut body = Vec::new();
    body.push(0x02);
    body.extend_from_slice(&(r#"{}"#.len() as u32).to_be_bytes());
    body.extend_from_slice(br#"{}"#);

    let mut observer = ConnectFrameObserver::new(Some(8), Some(64));
    for byte in body {
        observer.feed(&[byte]).expect("feed byte");
    }
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
fn grpc_web_text_observer_parses_base64_quantum_split_one_byte_at_a_time() {
    let mut body = frame_grpc_message(Bytes::from_static(b"hello"));
    body.extend_from_slice(&frame_grpc_web_trailers(b"grpc-status: 0\r\n"));
    let encoded = BASE64.encode(body);
    let mut observer = GrpcFrameObserver::grpc_web(true, None, None);
    for byte in encoded.bytes() {
        observer.feed(&[byte]).expect("feed base64 byte");
    }
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 5);
    assert_eq!(
        summary
            .trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-status"))
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
}

#[test]
fn grpc_web_text_observer_accepts_independently_padded_frames() {
    // Encoders may emit each frame as an independently padded base64 chunk:
    // padding ends the chunk, not the response.
    let first = BASE64.encode(frame_grpc_message(Bytes::from_static(b"ab")));
    let second = BASE64.encode(frame_grpc_message(Bytes::from_static(b"c")));
    assert!(
        first.ends_with('='),
        "frame encoding must carry padding, got {first}"
    );
    let mut encoded = first;
    encoded.push_str(&second);
    let mut observer = GrpcFrameObserver::grpc_web(true, None, None);
    for chunk in encoded.as_bytes().chunks(3) {
        observer.feed(chunk).expect("feed");
    }
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 2);
    assert_eq!(summary.message_bytes, 3);
}

#[test]
fn grpc_web_text_observer_accepts_padded_prefix_split() {
    // A one-byte prefix encoded alone carries padding mid-stream.
    let body = [
        frame_grpc_message(Bytes::from_static(b"ab")),
        frame_grpc_message(Bytes::from_static(b"c")),
    ]
    .concat();
    let mut encoded = BASE64.encode(&body[..1]);
    encoded.push_str(&BASE64.encode(&body[1..]));
    let mut observer = GrpcFrameObserver::grpc_web(true, None, None);
    observer.feed(encoded.as_bytes()).expect("feed");
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 2);
    assert_eq!(summary.message_bytes, 3);
}

#[test]
fn grpc_web_text_observer_accepts_empty_final_message() {
    let encoded = BASE64.encode([0, 0, 0, 0, 0]);
    let mut observer = GrpcFrameObserver::grpc_web(true, None, None);
    observer.feed(encoded.as_bytes()).expect("feed");
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 0);
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_streaming_observer_accepts_empty_final_message() {
    let mut observer = ConnectFrameObserver::new(None, None);
    observer.feed(&[0, 0, 0, 0, 0]).expect("empty message");
    let summary = observer.finish().expect("summary");
    assert_eq!(summary.message_count, 1);
    assert_eq!(summary.message_bytes, 0);
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_streaming_observer_rejects_empty_end_envelope() {
    // A zero-length end envelope carries no EndStreamResponse JSON; it must
    // fail at feed time rather than stick the machine mid-frame.
    let mut observer = ConnectFrameObserver::new(None, None);
    observer
        .feed(&[0x02, 0, 0, 0, 0])
        .expect_err("empty end envelope must fail");
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
    use qpx_core::http_message::{Headers, OrdinaryHeaderName};
    let started = Instant::now();
    let name = OrdinaryHeaderName::try_from("grpc-timeout").expect("grpc-timeout is ordinary");
    let mut headers = Headers::new();
    headers.insert(name.clone(), http::HeaderValue::from_static("250m"));
    assert_eq!(
        resolve_rpc_deadline(&headers, "grpc", Duration::from_secs(1), started).instant(),
        started + Duration::from_millis(250)
    );
    headers.insert(name, http::HeaderValue::from_static("10S"));
    assert_eq!(
        resolve_rpc_deadline(&headers, "grpc", Duration::from_secs(1), started).instant(),
        started + Duration::from_secs(1)
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn grpc_deadline_clamps_oversized_client_timeout_before_instant_add() {
    use qpx_core::http_message::{Headers, OrdinaryHeaderName};
    let started = Instant::now();
    let mut headers = Headers::new();
    headers.insert(
        OrdinaryHeaderName::try_from("grpc-timeout").expect("grpc-timeout is ordinary"),
        http::HeaderValue::from_static("99999999H"),
    );
    assert_eq!(
        resolve_rpc_deadline(&headers, "grpc", Duration::from_secs(1), started).instant(),
        started + Duration::from_secs(1)
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_deadline_uses_connect_timeout_ms_header() {
    use qpx_core::http_message::{Headers, OrdinaryHeaderName};
    let started = Instant::now();
    let mut headers = Headers::new();
    headers.insert(
        OrdinaryHeaderName::try_from("connect-timeout-ms").expect("ordinary"),
        http::HeaderValue::from_static("250"),
    );
    headers.insert(
        OrdinaryHeaderName::try_from("grpc-timeout").expect("ordinary"),
        http::HeaderValue::from_static("1n"),
    );
    let deadline = resolve_rpc_deadline(&headers, "connect", Duration::from_secs(1), started);
    assert_eq!(deadline.instant(), started + Duration::from_millis(250));
    assert_eq!(deadline.protocol(), RpcDeadlineProtocol::Connect);

    let mut forwarded = Headers::new();
    forwarded.insert(
        OrdinaryHeaderName::try_from("grpc-timeout").expect("ordinary"),
        http::HeaderValue::from_static("1n"),
    );
    apply_grpc_deadline_header(&mut forwarded, deadline);
    assert!(
        !forwarded.contains_key(&OrdinaryHeaderName::try_from("grpc-timeout").expect("ordinary"))
    );
    assert!(
        forwarded
            .contains_key(&OrdinaryHeaderName::try_from("connect-timeout-ms").expect("ordinary"))
    );
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
    let bytes = qpx_http::body::to_bytes(response.into_body())
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
    let response =
        build_grpc_deadline_exceeded_response("grpc_web", None).expect("deadline response");
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc-web+proto")
    );
    let bytes = qpx_http::body::to_bytes(response.into_body())
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
    let response =
        build_grpc_deadline_exceeded_response("connect", None).expect("deadline response");
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        response
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let bytes = qpx_http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    let text = std::str::from_utf8(&bytes).expect("utf8");
    assert!(text.contains("\"code\":\"deadline_exceeded\""));
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[tokio::test]
async fn connect_streaming_deadline_response_uses_end_stream_envelope() {
    for codec in ["application/connect+proto", "application/connect+json"] {
        let response = build_grpc_deadline_exceeded_response("connect", Some(codec))
            .expect("deadline response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(codec)
        );
        let bytes = qpx_http::body::to_bytes(response.into_body())
            .await
            .expect("body");
        assert!(
            bytes.len() > 5,
            "framed Connect deadline body must hold one envelope for {codec}"
        );
        assert_eq!(
            bytes[0], 0x02,
            "deadline envelope must be terminal for {codec}"
        );
        let envelope_len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        assert_eq!(
            bytes.len(),
            5 + envelope_len,
            "deadline reply must carry exactly one envelope and no data messages for {codec}"
        );
        let text = std::str::from_utf8(&bytes[5..]).expect("utf8");
        assert!(text.contains("\"error\":{"));
        assert!(text.contains("\"code\":\"deadline_exceeded\""));
        assert!(text.contains("deadline exceeded at proxy"));
        let trailers = parse_connect_end_stream_metadata(&bytes[5..]).expect("end stream");
        assert_eq!(
            trailers.get("connect-code").and_then(|v| v.to_str().ok()),
            Some("deadline_exceeded")
        );
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[tokio::test]
async fn connect_unary_codecs_keep_json_deadline_body() {
    for content_type in [
        None,
        Some("application/json"),
        Some("application/proto"),
        Some("application/connect+unknown"),
    ] {
        let response = build_grpc_deadline_exceeded_response("connect", content_type)
            .expect("deadline response");
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
    }
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_end_stream_reports_omitted_error_as_ok() {
    let trailers = parse_connect_end_stream_metadata(br#"{"metadata":{}}"#).expect("envelope");
    assert_eq!(
        trailers.get("connect-code").and_then(|v| v.to_str().ok()),
        Some("ok")
    );
    assert!(trailers.get("connect-message").is_none());
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_end_stream_metadata_never_overrides_protocol_status() {
    let raw = br#"{"error":{"code":"unavailable","message":"busy"},"metadata":{"connect-code":["ok"],"connect-message":["fake"]}}"#;
    let trailers = parse_connect_end_stream_metadata(raw).expect("envelope");
    assert_eq!(
        trailers.get("connect-code").and_then(|v| v.to_str().ok()),
        Some("unavailable")
    );
    assert_eq!(
        trailers
            .get("connect-message")
            .and_then(|v| v.to_str().ok()),
        Some("busy")
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_end_stream_status_feeds_stream_metric_extraction() {
    let raw = br#"{"error":{"code":"unavailable","message":"busy"},"metadata":{"example-trailer":["a"]}}"#;
    let trailers = parse_connect_end_stream_metadata(raw).expect("envelope");
    assert_eq!(
        extract_connect_stream_status_and_message(Some(&trailers)),
        (Some("unavailable".to_string()), Some("busy".to_string()))
    );
    let ok = parse_connect_end_stream_metadata(br#"{}"#).expect("empty envelope");
    assert_eq!(
        extract_connect_stream_status_and_message(Some(&ok)),
        (Some("ok".to_string()), None)
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_end_stream_multiline_message_observes_status() {
    let envelope =
        r#"{"error":{"code":"unavailable","message":"busy\nretry\tlater ✓"},"metadata":{}}"#;
    let mut body = Vec::new();
    body.push(0x02);
    body.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    body.extend_from_slice(envelope.as_bytes());

    let mut observer = ConnectFrameObserver::new(Some(8), Some(256));
    observer
        .feed(body.as_slice())
        .expect("multiline message observes");
    let summary = observer.finish().expect("summary");
    let trailers = summary.trailers.as_ref().expect("trailers");
    assert_eq!(
        extract_connect_stream_status_and_message(Some(trailers)),
        (
            Some("unavailable".to_string()),
            Some("busy\nretry\tlater ✓".to_string())
        )
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
#[test]
fn connect_end_stream_skips_unrepresentable_metadata() {
    let envelope = r#"{"error":{"code":"unavailable","message":"busy"},"metadata":{"bad-trailer":"a\nb","good-trailer":"x"}}"#;
    let trailers = parse_connect_end_stream_metadata(envelope.as_bytes()).expect("envelope");
    assert_eq!(
        extract_connect_stream_status_and_message(Some(&trailers)).0,
        Some("unavailable".to_string())
    );
    assert!(trailers.get("bad-trailer").is_none());
    assert_eq!(
        trailers.get("good-trailer").and_then(|v| v.to_str().ok()),
        Some("x")
    );
}

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
mod connect_inspection_tests {
    use super::*;
    use crate::http::body::size::{
        buffer_request_body_with_reason, buffer_response_body, buffer_response_body_with_reason,
    };

    fn frame_connect_payload(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(0x00);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn frame_connect_end_stream(envelope: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + envelope.len());
        out.push(0x02);
        out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
        out.extend_from_slice(envelope.as_bytes());
        out
    }

    async fn connect_request_ctx() -> RpcMatchContext {
        let req = qpx_core::http_message::Request::from_http(
            Request::builder()
                .method("POST")
                .uri("/demo.Echo/Say")
                .header(http::header::CONTENT_TYPE, "application/connect+json")
                .body(Body::empty())
                .expect("request"),
        );
        inspect_request(&req).await
    }

    fn framed_error_body() -> Vec<u8> {
        let mut body = frame_connect_payload(b"hi");
        body.extend_from_slice(&frame_connect_payload(b"bye"));
        body.extend_from_slice(&frame_connect_end_stream(
            r#"{"error":{"code":"unavailable","message":"busy"},"metadata":{}}"#,
        ));
        body
    }

    async fn check_framed_error_inspection(response: http::Response<Body>) {
        let ctx = connect_request_ctx().await;
        let inspected = inspect_response(&ctx, &response).await;
        assert_eq!(inspected.protocol.as_deref(), Some("connect"));
        assert_eq!(inspected.status.as_deref(), Some("unavailable"));
        assert_eq!(inspected.message.as_deref(), Some("busy"));
        assert_eq!(inspected.response_message_count, Some(2));
        assert_eq!(inspected.response_message_bytes, Some(5));
    }

    #[tokio::test]
    async fn precomputed_connect_error_reports_status_and_message_counts() {
        let response = http::Response::builder()
            .header(http::header::CONTENT_TYPE, "application/connect+json")
            .body(Body::from(framed_error_body()))
            .expect("response");

        let response =
            buffer_response_body_with_reason(response, 1024, Duration::from_secs(1), "rpc.body")
                .await
                .expect("buffered");
        let precomputed = response
            .extensions()
            .get::<PrecomputedRpcBodySummary>()
            .expect("precomputed connect summary");
        let (count, bytes, trailers) = precomputed.clone().0.into_parts();
        assert_eq!(count, 2);
        assert_eq!(bytes, 5);
        assert!(trailers.is_some());

        check_framed_error_inspection(response).await;
    }

    #[tokio::test]
    async fn buffered_connect_error_reports_status_and_message_counts() {
        let response = http::Response::builder()
            .header(http::header::CONTENT_TYPE, "application/connect+json")
            .body(Body::from(framed_error_body()))
            .expect("response");

        let response = buffer_response_body(response, 1024, Duration::from_secs(1))
            .await
            .expect("buffered");
        assert!(
            response
                .extensions()
                .get::<PrecomputedRpcBodySummary>()
                .is_none()
        );

        check_framed_error_inspection(response).await;
    }

    #[tokio::test]
    async fn unary_connect_error_keeps_body_status() {
        let response = http::Response::builder()
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("connect-protocol-version", "1")
            .body(Body::from(r#"{"code":"unavailable","message":"busy"}"#))
            .expect("response");

        let response = buffer_response_body(response, 1024, Duration::from_secs(1))
            .await
            .expect("buffered");
        let ctx = connect_request_ctx().await;
        let inspected = inspect_response(&ctx, &response).await;
        assert_eq!(inspected.protocol.as_deref(), Some("connect"));
        assert_eq!(inspected.status.as_deref(), Some("unavailable"));
        assert_eq!(inspected.message.as_deref(), Some("busy"));
    }

    async fn inspect_buffered_connect_request(
        body: Vec<u8>,
        content_type: &'static str,
        reason: &'static str,
    ) -> RpcMatchContext {
        let req = qpx_core::http_message::Request::from_http(
            Request::builder()
                .method("POST")
                .uri("/demo.Echo/Say")
                .header(http::header::CONTENT_TYPE, content_type)
                .body(Body::from(body))
                .expect("request"),
        );
        let req = buffer_request_body_with_reason(req, 1024, Duration::from_secs(1), reason)
            .await
            .expect("buffered");
        inspect_request(&req).await
    }

    async fn inspect_buffered_unary_connect_request(
        body: Vec<u8>,
        reason: &'static str,
    ) -> RpcMatchContext {
        let req = qpx_core::http_message::Request::from_http(
            Request::builder()
                .method("POST")
                .uri("/demo.Echo/Say")
                .header(http::header::CONTENT_TYPE, "application/json")
                .header("connect-protocol-version", "1")
                .body(Body::from(body))
                .expect("request"),
        );
        let req = buffer_request_body_with_reason(req, 1024, Duration::from_secs(1), reason)
            .await
            .expect("buffered");
        inspect_request(&req).await
    }

    fn assert_connect_post_summary(inspected: &RpcMatchContext, count: usize, bytes: u64) {
        assert_eq!(inspected.protocol.as_deref(), Some("connect"));
        assert_eq!(inspected.request_message_count, Some(count));
        assert_eq!(inspected.request_message_bytes, Some(bytes));
        assert_eq!(inspected.message_size, Some(bytes));
        // Connect POST currently infers no streaming label.
        assert_eq!(inspected.streaming, None);
        assert_eq!(
            infer_request_streaming(Some("connect"), "POST", inspected.request_message_count),
            None
        );
    }

    #[tokio::test]
    async fn buffered_connect_request_envelopes_match_across_buffer_reasons() {
        let mut body = frame_connect_payload(b"a");
        body.extend_from_slice(&frame_connect_payload(b"b"));
        for content_type in ["application/connect+proto", "application/connect+json"] {
            let rpc =
                inspect_buffered_connect_request(body.clone(), content_type, "rpc.body").await;
            let guarded =
                inspect_buffered_connect_request(body.clone(), content_type, "http_guard.body")
                    .await;
            assert_connect_post_summary(&rpc, 2, 2);
            assert_connect_post_summary(&guarded, 2, 2);
        }
    }

    #[tokio::test]
    async fn buffered_connect_request_empty_envelope_matches_across_buffer_reasons() {
        let body = frame_connect_payload(b"");
        assert_eq!(body.len(), 5);
        for content_type in ["application/connect+proto", "application/connect+json"] {
            let rpc =
                inspect_buffered_connect_request(body.clone(), content_type, "rpc.body").await;
            let guarded =
                inspect_buffered_connect_request(body.clone(), content_type, "http_guard.body")
                    .await;
            assert_connect_post_summary(&rpc, 1, 0);
            assert_connect_post_summary(&guarded, 1, 0);
        }
    }

    #[tokio::test]
    async fn unary_connect_request_keeps_whole_body_across_buffer_reasons() {
        let body = br#"{"message":"hi"}"#.to_vec();
        let expected = body.len() as u64;
        for reason in ["rpc.body", "http_guard.body"] {
            let inspected = inspect_buffered_unary_connect_request(body.clone(), reason).await;
            assert_eq!(inspected.protocol.as_deref(), Some("connect"));
            assert_eq!(inspected.request_message_count, Some(1));
            assert_eq!(inspected.request_message_bytes, Some(expected));
            assert_eq!(inspected.message_size, Some(expected));
            assert_eq!(inspected.streaming, None);
            assert_eq!(
                infer_request_streaming(Some("connect"), "POST", inspected.request_message_count),
                None
            );
        }
    }

    #[test]
    fn connect_trailers_win_over_unary_body() {
        let trailers = parse_connect_end_stream_metadata(
            br#"{"error":{"code":"unavailable","message":"busy"}}"#,
        )
        .expect("envelope");
        let body = Bytes::from_static(br#"{"code":"ok","message":"nope"}"#);
        let headers = HeaderMap::new();
        assert_eq!(
            extract_rpc_status_and_message(Some("connect"), &headers, Some(&trailers), Some(&body)),
            (Some("unavailable".to_string()), Some("busy".to_string()))
        );

        let body = Bytes::from_static(br#"{"code":"unavailable","message":"busy"}"#);
        assert_eq!(
            extract_rpc_status_and_message(Some("connect"), &headers, None, Some(&body)),
            (Some("unavailable".to_string()), Some("busy".to_string()))
        );
    }
}

#[cfg(not(any(feature = "http3-backend-h3", feature = "http3-backend-qpx")))]
#[tokio::test]
async fn connect_enveloped_request_keeps_whole_body_without_backend_features() {
    // Without the Connect backend features the observed-body fallback stays
    // generic whole-body for both precompute-eligible and guard reasons.
    let mut body = Vec::new();
    for payload in [b"a".as_slice(), b"b".as_slice()] {
        body.push(0x00);
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(payload);
    }
    let expected = body.len() as u64;
    assert_eq!(expected, 12);
    for reason in ["rpc.body", "http_guard.body"] {
        let req = qpx_core::http_message::Request::from_http(
            Request::builder()
                .method("POST")
                .uri("/demo.Echo/Say")
                .header(http::header::CONTENT_TYPE, "application/connect+proto")
                .body(Body::from(body.clone()))
                .expect("request"),
        );
        let req = crate::http::body::size::buffer_request_body_with_reason(
            req,
            1024,
            Duration::from_secs(1),
            reason,
        )
        .await
        .expect("buffered");
        let inspected = inspect_request(&req).await;
        assert_eq!(inspected.protocol.as_deref(), Some("connect"));
        assert_eq!(inspected.request_message_count, Some(1));
        assert_eq!(inspected.request_message_bytes, Some(expected));
        assert_eq!(inspected.message_size, Some(expected));
        assert_eq!(inspected.streaming, None);
    }
}

#[test]
fn connect_get_is_labeled_unary() {
    assert_eq!(
        infer_request_streaming(Some("connect"), "GET", None),
        Some("unary")
    );
    assert_eq!(infer_request_streaming(Some("connect"), "POST", None), None);
    assert_eq!(
        infer_request_streaming(Some("connect"), "get", Some(3)),
        Some("unary")
    );
}

#[tokio::test]
async fn recognized_connect_get_keeps_unary_label_on_response() {
    let req = qpx_core::http_message::Request::from_http(
        Request::builder()
            .method("GET")
            .uri("/demo.Echo/Say?connect=v1&message=%7B%7D")
            .header(http::header::CONTENT_TYPE, "application/connect+json")
            .body(Body::empty())
            .expect("request"),
    );
    let ctx = inspect_request(&req).await;
    assert_eq!(ctx.protocol.as_deref(), Some("connect"));
    assert_eq!(ctx.streaming.as_deref(), Some("unary"));

    let response = http::Response::builder()
        .body(Body::empty())
        .expect("response");
    let inspected = inspect_response(&ctx, &response).await;
    assert_eq!(inspected.streaming.as_deref(), Some("unary"));
}

#[test]
fn rpc_protocol_from_content_type_matches_ordered_prefixes() {
    use super::protocol::rpc_protocol_from_content_type;
    assert_eq!(
        rpc_protocol_from_content_type("application/grpc-web"),
        Some("grpc_web")
    );
    assert_eq!(
        rpc_protocol_from_content_type("application/grpc-web-text"),
        Some("grpc_web")
    );
    assert_eq!(
        rpc_protocol_from_content_type("application/grpc-web+proto"),
        Some("grpc_web")
    );
    assert_eq!(
        rpc_protocol_from_content_type("application/grpc"),
        Some("grpc")
    );
    assert_eq!(
        rpc_protocol_from_content_type("application/grpc+proto"),
        Some("grpc")
    );
    assert_eq!(
        rpc_protocol_from_content_type("application/connect+json"),
        Some("connect")
    );
    assert_eq!(
        rpc_protocol_from_content_type("application/connect+proto"),
        Some("connect")
    );
}

#[test]
fn rpc_protocol_from_content_type_rejects_unknown_inputs_without_normalizing() {
    use super::protocol::rpc_protocol_from_content_type;
    assert_eq!(rpc_protocol_from_content_type("application/json"), None);
    assert_eq!(rpc_protocol_from_content_type(""), None);
    assert_eq!(rpc_protocol_from_content_type("grpc"), None);
    assert_eq!(rpc_protocol_from_content_type("grpc_web"), None);
    assert_eq!(rpc_protocol_from_content_type("connect"), None);
    // No trimming or case folding: inputs are already lowercased upstream.
    assert_eq!(rpc_protocol_from_content_type(" application/grpc"), None);
    assert_eq!(rpc_protocol_from_content_type("Application/grpc"), None);
    assert_eq!(rpc_protocol_from_content_type("APPLICATION/GRPC-WEB"), None);
}
