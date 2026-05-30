use super::*;

#[tokio::test]
async fn lookup_only_if_cached_miss() {
    let mut req = make_get_request("/a");
    req.headers_mut().insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached"),
    );
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let out = lookup(req.method(), req.headers(), &key, &policy(), &backends)
        .await
        .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}

#[tokio::test]
async fn lookup_fetches_body_only_for_matching_vary_variant() {
    let mut req = make_get_request("/vary-body-fetch");
    req.headers_mut()
        .insert("accept-language", http::HeaderValue::from_static("ja"));
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let policy = policy();
    let namespace = super::util::cache_namespace(&policy, "default");
    let primary = key.primary_hash();
    let en_variant = variant_storage_key(
        primary.as_str(),
        &[("accept-language".to_string(), "en".to_string())],
    );
    let ja_variant = variant_storage_key(
        primary.as_str(),
        &[("accept-language".to_string(), "ja".to_string())],
    );
    let backend = Arc::new(MockBackend::new());
    let index = VariantIndex {
        variants: vec![en_variant.clone(), ja_variant.clone()],
    };
    backend
        .put(
            namespace.as_str(),
            index_storage_key(primary.as_str()).as_str(),
            serde_json::to_vec(&index).expect("index").as_slice(),
            60,
        )
        .await
        .expect("put index");
    for (variant, lang, body) in [
        (en_variant.as_str(), "en", b"english".as_slice()),
        (ja_variant.as_str(), "ja", b"japanese".as_slice()),
    ] {
        let envelope = CachedResponseEnvelope {
            status: 200,
            headers: vec![
                (
                    "cache-control".to_string(),
                    "public, max-age=60".to_string(),
                ),
                ("content-length".to_string(), body.len().to_string()),
            ],
            body: CachedBody::from_bytes(bytes::Bytes::from(body.to_vec())),
            body_len: body.len() as u64,
            stored_at_ms: super::util::now_millis(),
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: vec!["accept-language".to_string()],
            vary_values: vec![("accept-language".to_string(), lang.to_string())],
        };
        backend
            .put(
                namespace.as_str(),
                variant,
                encode_cached_response_metadata(&envelope)
                    .expect("metadata")
                    .as_slice(),
                60,
            )
            .await
            .expect("put metadata");
        backend
            .put(
                namespace.as_str(),
                cache_body_storage_key(variant).as_str(),
                body,
                60,
            )
            .await
            .expect("put body");
    }

    let mut backends = HashMap::new();
    backends.insert("b".to_string(), backend.clone() as Arc<dyn CacheBackend>);
    let out = lookup(req.method(), req.headers(), &key, &policy, &backends)
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"japanese");

    let gets = backend.get_log();
    assert!(gets.contains(&MockBackend::key(namespace.as_str(), en_variant.as_str())));
    assert!(gets.contains(&MockBackend::key(namespace.as_str(), ja_variant.as_str())));
    assert!(
        !gets.contains(&MockBackend::key(
            namespace.as_str(),
            cache_body_storage_key(en_variant.as_str()).as_str(),
        )),
        "non-matching variant body must not be fetched: {gets:?}"
    );
    assert!(gets.contains(&MockBackend::key(
        namespace.as_str(),
        cache_body_storage_key(ja_variant.as_str()).as_str(),
    )));
}

#[tokio::test]
async fn head_lookup_reuses_get_cache_entry_without_body() {
    let req = make_get_request("/head-shared");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let _ = store_and_drain(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        make_response(StatusCode::OK, "public, max-age=60", "hello"),
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
            request_collapse_guard: None,
        },
        &backends,
    )
    .await
    .expect("store");

    let head_req = Request::builder()
        .method(Method::HEAD)
        .uri("http://example.com/head-shared")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("head request");
    let head_key = CacheRequestKey::for_lookup(&head_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert!(body.is_empty());
}

#[tokio::test]
async fn cached_head_hit_preserves_stored_representation_length() {
    let head_req = Request::builder()
        .method(Method::HEAD)
        .uri("http://example.com/head-length")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("head request");
    let head_key = CacheRequestKey::for_lookup(&head_req, "http")
        .expect("key")
        .expect("some key");
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "public, max-age=60")
        .header(CONTENT_LENGTH, "123")
        .body(Body::empty())
        .expect("response");
    let backends = backend_map();
    let _ = store_and_drain(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
            request_collapse_guard: None,
        },
        &backends,
    )
    .await
    .expect("store");

    let out = lookup(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(
        response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some("123")
    );
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert!(body.is_empty());
}

#[tokio::test]
async fn head_response_does_not_poison_get_cache_entry() {
    let head_req = Request::builder()
        .method(Method::HEAD)
        .uri("http://example.com/head-only")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("head request");
    let head_key = CacheRequestKey::for_lookup(&head_req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let _ = store_and_drain(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        make_response(StatusCode::OK, "public, max-age=60", ""),
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
            request_collapse_guard: None,
        },
        &backends,
    )
    .await
    .expect("store");

    let head_out = lookup(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        &backends,
    )
    .await
    .expect("head lookup");
    assert!(matches!(head_out, LookupOutcome::Hit(_)));

    let get_req = make_get_request("/head-only");
    let get_key = CacheRequestKey::for_lookup(&get_req, "http")
        .expect("key")
        .expect("some key");
    let get_out = lookup(
        get_req.method(),
        get_req.headers(),
        &get_key,
        &policy(),
        &backends,
    )
    .await
    .expect("get lookup");
    assert!(matches!(get_out, LookupOutcome::Miss));
}

#[tokio::test]
async fn post_response_is_write_through_but_can_seed_get_when_content_location_matches() {
    let post_req = Request::builder()
        .method(Method::POST)
        .uri("http://example.com/post-cache")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");
    let post_key = CacheRequestKey::for_lookup(&post_req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "posted");
    response.headers_mut().insert(
        CONTENT_LOCATION,
        http::HeaderValue::from_static("/post-cache"),
    );
    let _ = store_and_drain(
        post_req.method(),
        post_req.headers(),
        &post_key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
            request_collapse_guard: None,
        },
        &backends,
    )
    .await
    .expect("store");

    let post_out = lookup(
        post_req.method(),
        post_req.headers(),
        &post_key,
        &policy(),
        &backends,
    )
    .await
    .expect("post lookup");
    assert!(matches!(post_out, LookupOutcome::Miss));

    let get_req = make_get_request("/post-cache");
    let get_key = CacheRequestKey::for_lookup(&get_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        get_req.method(),
        get_req.headers(),
        &get_key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"posted");
}

#[tokio::test]
async fn post_response_without_matching_content_location_is_not_stored() {
    let post_req = Request::builder()
        .method(Method::POST)
        .uri("http://example.com/post-no-location")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");
    let post_key = CacheRequestKey::for_lookup(&post_req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let _ = store_and_drain(
        post_req.method(),
        post_req.headers(),
        &post_key,
        &policy(),
        make_response(StatusCode::OK, "public, max-age=60", "posted"),
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
            request_collapse_guard: None,
        },
        &backends,
    )
    .await
    .expect("store");

    let get_req = make_get_request("/post-no-location");
    let get_key = CacheRequestKey::for_lookup(&get_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        get_req.method(),
        get_req.headers(),
        &get_key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::Miss));
}
