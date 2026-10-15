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

#[test]
fn response_no_transform_disables_compression() {
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
    let get_request = hyper::Request::builder()
        .method(Method::GET)
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("request");
    let get_request = HttpModuleRequestView::from_request(&get_request);
    let compressible = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "12")
        .header(http::header::CACHE_CONTROL, "public, max-age=60")
        .body(Body::empty())
        .expect("response");
    assert_eq!(
        select_response_encoding(&get_request, &config, &compressible).expect("select encoding"),
        Some(ContentEncoding::Gzip)
    );
    let frozen = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "12")
        .header(
            http::header::CACHE_CONTROL,
            "public, no-transform, max-age=60",
        )
        .body(Body::empty())
        .expect("response");
    assert_eq!(
        select_response_encoding(&get_request, &config, &frozen).expect("select encoding"),
        None
    );
    // The dictionary path gates on the same shared predicate.
    assert!(!response_is_compressible(&Method::GET, &config, &frozen).expect("predicate runs"));
}

fn identity_test_config() -> ResponseCompressionModuleConfig {
    ResponseCompressionModuleConfig {
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
    }
}

fn vary_values(response: &Response<Body>) -> String {
    response
        .headers()
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ")
        .to_ascii_lowercase()
}

#[test]
fn identity_response_carries_vary_when_compression_negotiable() {
    // Explicit identity rejection: this client gets identity, but a later
    // gzip client must not be served it from a downstream cache.
    let config = identity_test_config();
    let request = hyper::Request::builder()
        .method(Method::GET)
        .header(http::header::ACCEPT_ENCODING, "gzip;q=0")
        .body(Body::empty())
        .expect("request");
    let request = HttpModuleRequestView::from_request(&request);
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "12")
        .header(http::header::CACHE_CONTROL, "public, max-age=60")
        .body(Body::empty())
        .expect("response");
    assert_eq!(
        select_response_encoding(&request, &config, &response).expect("select encoding"),
        None
    );
    // Selection alone leaves identity unmarked: the old observable gap.
    assert!(!response.headers().contains_key(VARY));
    mark_identity_variant(&config, &mut response).expect("mark identity");
    assert!(
        vary_values(&response).contains("accept-encoding"),
        "identity needs Vary, got {:?}",
        response.headers().get_all(VARY)
    );
}

#[test]
fn identity_response_keeps_fast_path_when_nothing_negotiable() {
    let config = identity_test_config();
    // Non-compressible body: negotiation cannot change the output.
    let mut image = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/png")
        .header(CONTENT_LENGTH, "12")
        .body(Body::empty())
        .expect("response");
    mark_identity_variant(&config, &mut image).expect("mark identity");
    assert!(!image.headers().contains_key(VARY));
    // Nothing enabled: even a compressible body stays untouched.
    let disabled = ResponseCompressionModuleConfig {
        gzip: false,
        ..identity_test_config()
    };
    let mut text = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "12")
        .body(Body::empty())
        .expect("response");
    mark_identity_variant(&disabled, &mut text).expect("mark identity");
    assert!(!text.headers().contains_key(VARY));
}

#[test]
fn identity_response_carries_dictionary_vary_when_dictionary_configured() {
    let config = ResponseCompressionModuleConfig {
        gzip: false,
        brotli: false,
        zstd: false,
        dictionary: Some(qpx_core::config::ResponseCompressionDictionaryConfig {
            path: "/nonexistent".to_string(),
            id: Some("example".to_string()),
            encoding: "dcz".to_string(),
        }),
        ..identity_test_config()
    };
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "12")
        .body(Body::empty())
        .expect("response");
    mark_identity_variant(&config, &mut response).expect("mark identity");
    let vary = vary_values(&response);
    for token in ["accept-encoding", "available-dictionary", "dictionary-id"] {
        assert!(vary.contains(token), "missing {token}, got {vary:?}");
    }
}

#[test]
fn identity_preferred_ranks_explicit_quality_only() {
    // Absent identity keeps encoding selection; ties do too.
    assert!(!identity_preferred(1000, 0));
    assert!(!identity_preferred(1000, 1000));
    assert!(!identity_preferred(0, 0));
    // Explicit identity above the encoding wins; below loses.
    assert!(identity_preferred(100, 1000));
    assert!(!identity_preferred(1000, 500));
}

#[test]
fn explicit_identity_quality_beats_lower_encoding() {
    let config = identity_test_config();
    let request = hyper::Request::builder()
        .method(Method::GET)
        .header(http::header::ACCEPT_ENCODING, "gzip;q=0.1, identity;q=1")
        .body(Body::empty())
        .expect("request");
    let request = HttpModuleRequestView::from_request(&request);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, "12")
        .body(Body::empty())
        .expect("response");
    assert_eq!(
        select_response_encoding(&request, &config, &response).expect("select encoding"),
        None
    );
}

#[test]
fn higher_encoding_quality_beats_identity() {
    let config = identity_test_config();
    for accept in ["gzip, identity;q=0.5", "gzip;q=1, identity;q=1"] {
        let request = hyper::Request::builder()
            .method(Method::GET)
            .header(http::header::ACCEPT_ENCODING, accept)
            .body(Body::empty())
            .expect("request");
        let request = HttpModuleRequestView::from_request(&request);
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .body(Body::empty())
            .expect("response");
        assert_eq!(
            select_response_encoding(&request, &config, &response).expect("select encoding"),
            Some(ContentEncoding::Gzip),
            "encoding keeps ties and higher quality for {accept:?}"
        );
    }
}

fn response_with_digests(
    body: &'static str,
    cache_control: Option<&'static str>,
) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(
            CONTENT_DIGEST.clone(),
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
        )
        .header(
            REPR_DIGEST.clone(),
            "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
        );
    if let Some(cache_control) = cache_control {
        builder = builder.header(http::header::CACHE_CONTROL, cache_control);
    }
    builder.body(Body::from(body)).expect("response")
}

fn assert_digest_fields_present(headers: &HeaderMap) {
    assert!(headers.contains_key(CONTENT_DIGEST.clone()));
    assert!(headers.contains_key(REPR_DIGEST.clone()));
}

fn assert_digest_fields_absent(headers: &HeaderMap) {
    assert!(!headers.contains_key(CONTENT_DIGEST.clone()));
    assert!(!headers.contains_key(REPR_DIGEST.clone()));
}

fn compression_context(accept_encoding: &str) -> HttpModuleContext {
    let mut ctx = super::super::tests::module_test_context();
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT_ENCODING,
        HeaderValue::from_str(accept_encoding).expect("encoding"),
    );
    ctx.extensions_mut().insert(CompressionRequest {
        method: Method::GET,
        headers,
    });
    ctx
}

#[tokio::test]
async fn ordinary_compression_drops_both_digest_fields_from_transformed_headers() {
    let module = ResponseCompressionModule::new(identity_test_config()).expect("module");
    let ctx = compression_context("gzip");
    let response = response_with_digests("hello world!", None);

    let compressed = module.compress(&ctx, response).await.expect("compression");
    assert_eq!(
        compressed.headers().get(CONTENT_ENCODING),
        Some(&HeaderValue::from_static("gzip"))
    );
    assert_digest_fields_absent(compressed.headers());
    let compressed_body = to_bytes(compressed.into_body())
        .await
        .expect("compressed body");
    assert!(!compressed_body.is_empty());
}

#[tokio::test]
async fn dictionary_compression_drops_both_digest_fields_and_no_transform_preserves_them() {
    use base64::Engine as _;

    let dictionary = b"frequent words from an example response";
    let temp_dir = tempfile::tempdir().expect("temporary directory");
    let dictionary_path = temp_dir.path().join("dictionary");
    std::fs::write(&dictionary_path, dictionary).expect("write dictionary");
    let config = ResponseCompressionModuleConfig {
        dictionary: Some(qpx_core::config::ResponseCompressionDictionaryConfig {
            path: dictionary_path.to_string_lossy().into_owned(),
            id: Some("example".to_string()),
            encoding: "dcb".to_string(),
        }),
        ..identity_test_config()
    };
    let module = ResponseCompressionModule::new(config).expect("module");
    let ctx = super::super::tests::module_test_context();
    let dictionary_hash: [u8; 32] = Sha256::digest(dictionary).into();
    let mut request_headers = HeaderMap::new();
    request_headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("dcb"));
    request_headers.insert(
        "available-dictionary",
        HeaderValue::from_str(&format!(
            ":{}:",
            base64::engine::general_purpose::STANDARD.encode(dictionary_hash)
        ))
        .expect("available dictionary"),
    );
    request_headers.insert("dictionary-id", HeaderValue::from_static("\"example\""));

    let compressed = module
        .compress_with_dictionary(
            &ctx,
            &Method::GET,
            &request_headers,
            response_with_digests("frequent words from a response", None),
        )
        .await
        .expect("dictionary compression");
    let DictionaryCompressionOutcome::Compressed(compressed) = compressed else {
        panic!("dictionary should be selected");
    };
    assert_eq!(
        compressed.headers().get(CONTENT_ENCODING),
        Some(&HeaderValue::from_static("dcb"))
    );
    assert_digest_fields_absent(compressed.headers());

    let unchanged = module
        .compress_with_dictionary(
            &ctx,
            &Method::GET,
            &request_headers,
            response_with_digests(
                "frequent words from a response",
                Some("public, no-transform"),
            ),
        )
        .await
        .expect("no-transform response");
    let DictionaryCompressionOutcome::Unchanged(unchanged) = unchanged else {
        panic!("no-transform response must not be compressed");
    };
    assert_digest_fields_present(unchanged.headers());
}

#[tokio::test]
async fn identity_and_no_transform_responses_preserve_both_digest_fields() {
    let module = ResponseCompressionModule::new(identity_test_config()).expect("module");
    for (accept_encoding, cache_control) in
        [("gzip", Some("public, no-transform")), ("gzip;q=0", None)]
    {
        let ctx = compression_context(accept_encoding);
        let response = response_with_digests("hello world!", cache_control);
        let unchanged = module
            .compress(&ctx, response)
            .await
            .expect("unchanged response");
        assert!(!unchanged.headers().contains_key(CONTENT_ENCODING));
        assert_digest_fields_present(unchanged.headers());
        let body = to_bytes(unchanged.into_body())
            .await
            .expect("identity body");
        assert_eq!(body, "hello world!");
    }
}
