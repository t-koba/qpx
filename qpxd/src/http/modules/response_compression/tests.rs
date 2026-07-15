use super::*;

#[test]
fn request_snapshot_is_absent_without_accept_encoding() {
    let request = hyper::Request::builder()
        .method(Method::GET)
        .header(
            "available-dictionary",
            ":AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
        )
        .body(Body::empty())
        .expect("request");
    assert!(CompressionRequest::from_request(&request).is_none());
}

#[test]
fn request_snapshot_only_copies_compression_negotiation_fields() {
    let request = hyper::Request::builder()
        .method(Method::POST)
        .header(ACCEPT_ENCODING, "gzip")
        .header("dictionary-id", "example")
        .header("x-unrelated", "must-not-be-copied")
        .body(Body::empty())
        .expect("request");
    let snapshot = CompressionRequest::from_request(&request).expect("snapshot");
    assert_eq!(snapshot.method, Method::POST);
    assert_eq!(
        snapshot.headers.get(ACCEPT_ENCODING),
        Some(&HeaderValue::from_static("gzip"))
    );
    assert_eq!(
        snapshot.headers.get("dictionary-id"),
        Some(&HeaderValue::from_static("example"))
    );
    assert!(!snapshot.headers.contains_key("x-unrelated"));
}

#[test]
fn detects_event_stream_content_type_with_parameters() {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    assert!(is_event_stream_headers(&headers));
}

#[test]
fn event_stream_is_not_a_regular_compressible_text_type() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    assert!(content_type_allowed(&headers, &[]));
    assert!(is_event_stream_headers(&headers));
}

#[test]
fn event_stream_compression_requires_explicit_force() {
    let request = hyper::Request::builder()
        .method(Method::GET)
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("request");
    let request = HttpModuleRequestView::from_request(&request);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/event-stream")
        .header(CONTENT_LENGTH, "12")
        .body(Body::empty())
        .expect("response");
    let mut config = ResponseCompressionModuleConfig {
        min_body_bytes: 1,
        max_body_bytes: 1024,
        content_types: Vec::new(),
        force_compress_event_stream: false,
        gzip: true,
        brotli: false,
        zstd: false,
        gzip_level: 1,
        brotli_level: 1,
        zstd_level: 1,
        worker_count: 1,
        low_latency_flush: false,
        dictionary: None,
    };

    let selected = select_response_encoding(&request, &config, &response).expect("select encoding");
    assert_eq!(selected, None);

    config.force_compress_event_stream = true;
    let selected = select_response_encoding(&request, &config, &response).expect("select encoding");
    assert_eq!(selected, Some(ContentEncoding::Gzip));
}

#[test]
fn no_body_success_responses_are_not_compressed() {
    let config = ResponseCompressionModuleConfig {
        min_body_bytes: 1,
        max_body_bytes: 1024,
        content_types: Vec::new(),
        force_compress_event_stream: false,
        gzip: true,
        brotli: false,
        zstd: false,
        gzip_level: 1,
        brotli_level: 1,
        zstd_level: 1,
        worker_count: 1,
        low_latency_flush: false,
        dictionary: None,
    };

    let connect_request = hyper::Request::builder()
        .method(Method::CONNECT)
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("request");
    let connect_request = HttpModuleRequestView::from_request(&connect_request);
    let connect_response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "12")
        .body(Body::empty())
        .expect("response");
    assert_eq!(
        select_response_encoding(&connect_request, &config, &connect_response)
            .expect("select encoding"),
        None
    );

    let get_request = hyper::Request::builder()
        .method(Method::GET)
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("request");
    let get_request = HttpModuleRequestView::from_request(&get_request);
    let reset_content_response = Response::builder()
        .status(StatusCode::RESET_CONTENT)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "12")
        .body(Body::empty())
        .expect("response");
    assert_eq!(
        select_response_encoding(&get_request, &config, &reset_content_response)
            .expect("select encoding"),
        None
    );
}
