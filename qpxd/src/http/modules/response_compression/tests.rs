use super::*;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::Response as HttpResponse;

#[test]
fn accept_encoding_parses_shared_members_across_repeated_fields() {
    let mut headers = HeaderMap::new();
    headers.append(
        ACCEPT_ENCODING,
        HeaderValue::from_static(" GZip ;q=0.5, br "),
    );
    headers.append(
        ACCEPT_ENCODING,
        HeaderValue::from_static(", identity;q=1, "),
    );
    headers.append(
        ACCEPT_ENCODING,
        HeaderValue::from_bytes(b"\xff").expect("opaque encoding value"),
    );

    assert_eq!(
        parse_accept_encoding(&headers),
        vec![
            ("gzip".to_string(), 500),
            ("br".to_string(), 1000),
            ("identity".to_string(), 1000),
        ]
    );
}

#[test]
fn append_vary_accept_encoding_preserves_repeated_mixed_case_fields() {
    let mut headers = HeaderMap::new();
    headers.append(VARY, HeaderValue::from_static("Origin"));
    headers.append(VARY, HeaderValue::from_static("aCcEpT-EnCoDiNg"));

    append_vary_accept_encoding(&mut headers);

    let values: Vec<_> = headers
        .get_all(VARY)
        .iter()
        .map(|value| value.to_str().expect("text Vary value"))
        .collect();
    assert_eq!(values, ["Origin", "aCcEpT-EnCoDiNg"]);
}

#[test]
fn append_vary_accept_encoding_appends_when_no_readable_member_matches() {
    let mut headers = HeaderMap::new();
    headers.append(
        VARY,
        HeaderValue::from_bytes(b"\xff").expect("opaque Vary value"),
    );
    headers.append(VARY, HeaderValue::from_static("Origin"));

    append_vary_accept_encoding(&mut headers);

    let values: Vec<_> = headers.get_all(VARY).iter().collect();
    assert_eq!(values.len(), 3);
    assert_eq!(values[0].as_bytes(), b"\xff");
    assert_eq!(values[1].to_str().expect("text Vary value"), "Origin");
    assert_eq!(
        values[2].to_str().expect("text Vary value"),
        "Accept-Encoding"
    );
}

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
    assert!(
        CompressionRequest::from_request(&qpx_core::http_message::Request::from_http(request))
            .is_none()
    );
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
    let snapshot =
        CompressionRequest::from_request(&qpx_core::http_message::Request::from_http(request))
            .expect("snapshot");
    assert_eq!(snapshot.method, Method::POST);
    assert_eq!(
        snapshot.headers.get(&ord(ACCEPT_ENCODING)),
        Some(&HeaderValue::from_static("gzip"))
    );
    assert_eq!(
        snapshot
            .headers
            .get(&ord(http::HeaderName::from_static("dictionary-id"))),
        Some(&HeaderValue::from_static("example"))
    );
    assert!(
        !snapshot
            .headers
            .contains_key(&ord(http::HeaderName::from_static("x-unrelated")))
    );
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
fn missing_or_unreadable_content_type_is_neither_event_stream_nor_allowed() {
    let headers = HeaderMap::new();
    assert!(!is_event_stream_headers(&headers));
    assert!(!content_type_allowed(&headers, &[]));
    assert!(!content_type_allowed(&headers, &["text/plain".to_string()]));

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_bytes(b"\xff").expect("opaque content-type value"),
    );
    assert!(!is_event_stream_headers(&headers));
    assert!(!content_type_allowed(&headers, &[]));
}

#[test]
fn repeated_content_type_fields_keep_first_value() {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    headers.append(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    assert!(is_event_stream_headers(&headers));
    assert!(!content_type_allowed(&headers, &["text/plain".to_string()]));
}

#[test]
fn event_stream_compression_requires_explicit_force() {
    let request = hyper::Request::builder()
        .method(Method::GET)
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("request");
    let response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/event-stream")
            .header(CONTENT_LENGTH, "12")
            .body(Body::empty())
            .expect("response"),
    );
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

    let selected =
        select_response_encoding(request.method(), request.headers(), &config, &response)
            .expect("select encoding");
    assert_eq!(selected, None);

    config.force_compress_event_stream = true;
    let selected =
        select_response_encoding(request.method(), request.headers(), &config, &response)
            .expect("select encoding");
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
    let connect_response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .body(Body::empty())
            .expect("response"),
    );
    assert_eq!(
        select_response_encoding(
            connect_request.method(),
            connect_request.headers(),
            &config,
            &connect_response
        )
        .expect("select encoding"),
        None
    );

    let get_request = hyper::Request::builder()
        .method(Method::GET)
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .body(Body::empty())
        .expect("request");
    let reset_content_response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::RESET_CONTENT)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .body(Body::empty())
            .expect("response"),
    );
    assert_eq!(
        select_response_encoding(
            get_request.method(),
            get_request.headers(),
            &config,
            &reset_content_response
        )
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
    let compressible = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .header(http::header::CACHE_CONTROL, "public, max-age=60")
            .body(Body::empty())
            .expect("response"),
    );
    assert_eq!(
        select_response_encoding(
            get_request.method(),
            get_request.headers(),
            &config,
            &compressible
        )
        .expect("select encoding"),
        Some(ContentEncoding::Gzip)
    );
    let frozen = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .header(
                http::header::CACHE_CONTROL,
                "public, no-transform, max-age=60",
            )
            .body(Body::empty())
            .expect("response"),
    );
    assert_eq!(
        select_response_encoding(
            get_request.method(),
            get_request.headers(),
            &config,
            &frozen
        )
        .expect("select encoding"),
        None
    );
    // The dictionary path gates on the same shared predicate.
    assert!(!response_is_compressible(&Method::GET, &config, &frozen).expect("predicate runs"));
}

#[test]
fn the_compressible_window_reads_the_declared_length_through_the_owner() {
    let config = identity_test_config();

    // A comma list of equal members is one length, so the response declares
    // a size inside the window and is compressible.
    let response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12, 12")
            .body(Body::empty())
            .expect("response"),
    );
    assert!(
        response_body_is_compressible(&config, &response).expect("predicate runs"),
        "a comma list of equal members is one length"
    );

    // A declaration the owner refuses names no length, so the response
    // declares no size and is not compressed.
    let response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "+12")
            .body(Body::empty())
            .expect("response"),
    );
    assert!(!response_body_is_compressible(&config, &response).expect("predicate runs"));

    // Two members that disagree declare no length either.
    let response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12, 13")
            .body(Body::empty())
            .expect("response"),
    );
    assert!(!response_body_is_compressible(&config, &response).expect("predicate runs"));
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
        .get_all(&ord(VARY))
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
    let mut response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .header(http::header::CACHE_CONTROL, "public, max-age=60")
            .body(Body::empty())
            .expect("response"),
    );
    assert_eq!(
        select_response_encoding(request.method(), request.headers(), &config, &response)
            .expect("select encoding"),
        None
    );
    // Selection alone leaves identity unmarked: the old observable gap.
    assert!(!response.headers().contains_key(&ord(VARY)));
    mark_identity_variant(&config, &mut response).expect("mark identity");
    assert!(
        vary_values(&response).contains("accept-encoding"),
        "identity needs Vary, got {:?}",
        response.headers().get_all(&ord(VARY)).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn absent_accept_encoding_identity_response_marks_downstream_cache_variant() {
    let module = ResponseCompressionModule::new(identity_test_config()).expect("module");
    let ctx = super::super::tests::module_test_context();
    let response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .header(http::header::CACHE_CONTROL, "public, max-age=60")
            .body(Body::from("hello world!"))
            .expect("response"),
    );

    let identity = module
        .compress(&ctx, response)
        .await
        .expect("identity response");
    assert!(!identity.headers().contains_key(&ord(CONTENT_ENCODING)));
    assert!(
        vary_values(&identity).contains("accept-encoding"),
        "identity response must prevent a downstream cache from masking a later compressed variant"
    );
    assert_eq!(
        to_bytes(identity.into_head_and_body().1)
            .await
            .expect("identity body"),
        "hello world!"
    );
}

#[tokio::test]
async fn absent_accept_encoding_does_not_mark_ineligible_or_no_transform_identity() {
    let module = ResponseCompressionModule::new(identity_test_config()).expect("module");
    let ctx = super::super::tests::module_test_context();
    let controls = [
        Response::from_http(
            HttpResponse::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "image/png")
                .header(CONTENT_LENGTH, "12")
                .body(Body::from("hello world!"))
                .expect("ineligible response"),
        ),
        Response::from_http(
            HttpResponse::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .header(CONTENT_LENGTH, "12")
                .header(
                    http::header::CACHE_CONTROL,
                    "public, no-transform, max-age=60",
                )
                .body(Body::from("hello world!"))
                .expect("no-transform response"),
        ),
    ];

    for response in controls {
        let identity = module
            .compress(&ctx, response)
            .await
            .expect("identity response");
        assert!(
            !identity.headers().contains_key(&ord(VARY)),
            "ineligible identity response should preserve its original Vary behavior"
        );
    }
}

#[test]
fn identity_response_keeps_fast_path_when_nothing_negotiable() {
    let config = identity_test_config();
    // Non-compressible body: negotiation cannot change the output.
    let mut image = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "image/png")
            .header(CONTENT_LENGTH, "12")
            .body(Body::empty())
            .expect("response"),
    );
    mark_identity_variant(&config, &mut image).expect("mark identity");
    assert!(!image.headers().contains_key(&ord(VARY)));
    // Nothing enabled: even a compressible body stays untouched.
    let disabled = ResponseCompressionModuleConfig {
        gzip: false,
        ..identity_test_config()
    };
    let mut text = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .body(Body::empty())
            .expect("response"),
    );
    mark_identity_variant(&disabled, &mut text).expect("mark identity");
    assert!(!text.headers().contains_key(&ord(VARY)));
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
    let mut response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .body(Body::empty())
            .expect("response"),
    );
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
    let response = Response::from_http(
        HttpResponse::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, "12")
            .body(Body::empty())
            .expect("response"),
    );
    assert_eq!(
        select_response_encoding(request.method(), request.headers(), &config, &response)
            .expect("select encoding"),
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
        let response = Response::from_http(
            HttpResponse::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .header(CONTENT_LENGTH, "12")
                .body(Body::empty())
                .expect("response"),
        );
        assert_eq!(
            select_response_encoding(request.method(), request.headers(), &config, &response)
                .expect("select encoding"),
            Some(ContentEncoding::Gzip),
            "encoding keeps ties and higher quality for {accept:?}"
        );
    }
}

fn response_with_digests(
    body: &'static str,
    cache_control: Option<&'static str>,
) -> Response<Body> {
    let mut builder = HttpResponse::builder()
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
    Response::from_http(builder.body(Body::from(body)).expect("response"))
}

fn assert_digest_fields_present(headers: &Headers) {
    assert!(headers.contains_key(&ord(CONTENT_DIGEST.clone())));
    assert!(headers.contains_key(&ord(REPR_DIGEST.clone())));
}

fn assert_digest_fields_absent(headers: &Headers) {
    assert!(!headers.contains_key(&ord(CONTENT_DIGEST.clone())));
    assert!(!headers.contains_key(&ord(REPR_DIGEST.clone())));
}

fn compression_context(accept_encoding: &str) -> HttpModuleContext {
    let mut ctx = super::super::tests::module_test_context();
    let mut headers = Headers::new();
    headers.insert(
        ord(ACCEPT_ENCODING),
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
        compressed.headers().get(&ord(CONTENT_ENCODING)),
        Some(&HeaderValue::from_static("gzip"))
    );
    assert_digest_fields_absent(compressed.headers());
    let compressed_body = to_bytes(compressed.into_head_and_body().1)
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

    let marker = Arc::new(23_usize);
    let mut response = response_with_digests("frequent words from a response", None);
    *response.version_mut() = http::Version::HTTP_2;
    *response.status_mut() = StatusCode::ACCEPTED;
    response.extensions_mut().insert(marker.clone());
    let compressed = module
        .compress_with_dictionary(&ctx, &Method::GET, &request_headers, response)
        .await
        .expect("dictionary compression");
    let DictionaryCompressionOutcome::Compressed(compressed) = compressed else {
        panic!("dictionary should be selected");
    };
    assert_eq!(
        compressed.headers().get(&ord(CONTENT_ENCODING)),
        Some(&HeaderValue::from_static("dcb"))
    );
    assert_eq!(compressed.status(), StatusCode::ACCEPTED);
    assert_eq!(compressed.version(), http::Version::HTTP_2);
    assert!(Arc::ptr_eq(
        compressed.extensions().get::<Arc<usize>>().unwrap(),
        &marker
    ));
    assert_digest_fields_absent(compressed.headers());
    let compressed_length = compressed
        .headers()
        .declared_content_length()
        .expect("dictionary compression sets a readable length")
        .expect("dictionary compression declares a length");
    let compressed_body = to_bytes(compressed.into_head_and_body().1)
        .await
        .expect("dictionary body");
    assert_eq!(
        u64::try_from(compressed_body.len()).expect("body length"),
        compressed_length,
        "dictionary length must match encoded body"
    );
    assert_ne!(
        compressed_body.as_ref(),
        b"frequent words from a response",
        "dictionary path must transform the body when eligible"
    );

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
    assert!(
        !unchanged.headers().contains_key(&ord(CONTENT_ENCODING)),
        "no-transform dictionary response must stay identity"
    );
    assert_eq!(
        unchanged
            .headers()
            .declared_content_length()
            .expect("no-transform preserves a readable length")
            .expect("no-transform preserves a length"),
        u64::try_from("frequent words from a response".len()).expect("origin length"),
        "no-transform must preserve the origin length"
    );
    let unchanged_body = to_bytes(unchanged.into_head_and_body().1)
        .await
        .expect("no-transform body");
    assert_eq!(
        unchanged_body.as_ref(),
        b"frequent words from a response",
        "no-transform must preserve the origin body"
    );
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
        assert!(!unchanged.headers().contains_key(&ord(CONTENT_ENCODING)));
        assert_digest_fields_present(unchanged.headers());
        let body = to_bytes(unchanged.into_head_and_body().1)
            .await
            .expect("identity body");
        assert_eq!(body, "hello world!");
    }
}

#[tokio::test]
async fn ordinary_compression_strips_length_and_etag_unless_no_transform() {
    use std::io::Read as _;

    // Synthetic origin representation shared by both cases. The compressible
    // variant proves the eligible path strips Length/ETag and transforms the
    // body (the post-cache-writeback downstream transform); the no-transform
    // variant proves the shared predicate refuses that transform.
    const BODY: &str = "hello world! hello world! hello world! hello world! ";
    const ETAG_VALUE: &str = "\"synthetic-etag\"";
    fn origin_response(cache_control: &'static str) -> Response<Body> {
        Response::from_http(
            HttpResponse::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .header(CONTENT_LENGTH, BODY.len().to_string())
                .header(ETAG, ETAG_VALUE)
                .header(http::header::CACHE_CONTROL, cache_control)
                .body(Body::from(BODY))
                .expect("response"),
        )
    }

    let module = ResponseCompressionModule::new(identity_test_config()).expect("module");

    // Without no-transform: eligible, so full compression applies.
    let ctx = compression_context("gzip");
    let compressed = module
        .compress(&ctx, origin_response("public, max-age=60"))
        .await
        .expect("compression");
    assert_eq!(
        compressed.headers().get(&ord(CONTENT_ENCODING)),
        Some(&HeaderValue::from_static("gzip")),
        "eligible response must gain content encoding"
    );
    assert!(
        !compressed.headers().contains_content_length(),
        "ordinary compression must strip content length"
    );
    assert!(
        !compressed.headers().contains_key(&ord(ETAG)),
        "ordinary compression must strip etag"
    );
    assert!(
        vary_values(&compressed).contains("accept-encoding"),
        "compressed variant must carry Vary"
    );
    let compressed_body = to_bytes(compressed.into_head_and_body().1)
        .await
        .expect("compressed body");
    assert!(
        !compressed_body.is_empty(),
        "compressed body must not be empty"
    );
    assert_ne!(
        compressed_body.as_ref(),
        BODY.as_bytes(),
        "eligible body must be transformed"
    );
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(compressed_body.as_ref())
        .read_to_end(&mut decoded)
        .expect("gzip decodes");
    assert_eq!(
        decoded.as_slice(),
        BODY.as_bytes(),
        "gzip transform must round-trip the origin body"
    );

    // With no-transform: the shared predicate refuses, so identity is preserved.
    let ctx = compression_context("gzip");
    let unchanged = module
        .compress(&ctx, origin_response("public, no-transform, max-age=60"))
        .await
        .expect("unchanged response");
    assert!(
        !unchanged.headers().contains_key(&ord(CONTENT_ENCODING)),
        "no-transform response must not gain content encoding"
    );
    assert_eq!(
        unchanged
            .headers()
            .declared_content_length()
            .expect("no-transform preserves a readable length")
            .expect("no-transform preserves a length"),
        u64::try_from(BODY.len()).expect("origin length"),
        "no-transform must preserve the origin length"
    );
    assert_eq!(
        unchanged.headers().get(&ord(ETAG)),
        Some(&HeaderValue::from_static(ETAG_VALUE)),
        "no-transform must preserve the origin etag"
    );
    assert!(
        !unchanged.headers().contains_key(&ord(VARY)),
        "no-transform identity must not gain Vary"
    );
    let unchanged_body = to_bytes(unchanged.into_head_and_body().1)
        .await
        .expect("identity body");
    assert_eq!(
        unchanged_body.as_ref(),
        BODY.as_bytes(),
        "no-transform must preserve the origin body"
    );
}

#[tokio::test]
async fn owned_compression_preserves_metadata_trailers_and_body_errors() {
    use bytes::Bytes;
    use http_body_util::BodyExt as _;
    use std::io::Read as _;

    let module = ResponseCompressionModule::new(identity_test_config()).unwrap();
    for abort in [false, true] {
        let body = if abort {
            let (mut sender, body) = Body::channel();
            sender.abort();
            body
        } else {
            let mut trailers = HeaderMap::new();
            trailers.append("x-trailer", HeaderValue::from_static("first"));
            trailers.append("x-trailer", HeaderValue::from_static("second"));
            trailers.insert(CONTENT_DIGEST.clone(), HeaderValue::from_static("stale"));
            trailers.insert(REPR_DIGEST.clone(), HeaderValue::from_static("stale"));
            Body::replay_chunks(
                vec![Bytes::from_static(b"hello "), Bytes::from_static(b"world!")],
                Some(trailers),
            )
        };
        let marker = Arc::new(42_usize);
        let mut response = response_with_digests("hello world!", None).map_body(|_| body);
        *response.status_mut() = StatusCode::ACCEPTED;
        *response.version_mut() = http::Version::HTTP_2;
        response.extensions_mut().insert(marker.clone());
        let name = ord(http::HeaderName::from_static("x-opaque"));
        let mut opaque = HeaderValue::from_bytes(b"\x80opaque").unwrap();
        opaque.set_sensitive(true);
        response.headers_mut().append(name.clone(), opaque);
        response
            .headers_mut()
            .append(name.clone(), HeaderValue::from_static("second"));
        let compressed = module
            .compress(&compression_context("gzip"), response)
            .await
            .unwrap();
        assert_eq!(compressed.status(), StatusCode::ACCEPTED);
        assert_eq!(compressed.version(), http::Version::HTTP_2);
        assert!(Arc::ptr_eq(
            compressed.extensions().get::<Arc<usize>>().unwrap(),
            &marker
        ));
        let values = compressed.headers().get_all(&name).collect::<Vec<_>>();
        assert_eq!(values[0].as_bytes(), b"\x80opaque");
        assert!(values[0].is_sensitive());
        assert_eq!(values[1], "second");
        assert!(!compressed.headers().contains_content_length());
        let collected = compressed.into_head_and_body().1.collect().await;
        if abort {
            assert!(
                collected.is_err(),
                "an aborted origin must not become successful compressed EOF"
            );
        } else {
            let collected = collected.unwrap();
            let trailers = collected.trailers().unwrap();
            assert_eq!(
                trailers.get_all("x-trailer").iter().collect::<Vec<_>>(),
                ["first", "second"]
            );
            assert!(!trailers.contains_key(CONTENT_DIGEST.clone()));
            assert!(!trailers.contains_key(REPR_DIGEST.clone()));
            let bytes = collected.to_bytes();
            let mut decoded = String::new();
            flate2::read::GzDecoder::new(bytes.as_ref())
                .read_to_string(&mut decoded)
                .unwrap();
            assert_eq!(decoded, "hello world!");
        }
    }
}
