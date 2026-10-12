use super::*;

#[tokio::test]
async fn stale_revalidation_lookup_defers_body_fetch_until_stale_fallback() {
    let req = make_get_request("/revalidate-body-lazy");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backend = Arc::new(MockBackend::new());
    let mut backends = HashMap::new();
    backends.insert("b".to_string(), backend.clone() as Arc<dyn CacheBackend>);
    let response = make_response(
        StatusCode::OK,
        "no-cache, stale-if-error=60, max-age=60",
        "body-a",
    );
    store_and_drain(
        req.method(),
        req.headers(),
        &key,
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
    backend.clear_get_log();

    let outcome = lookup(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    assert!(matches!(outcome, LookupOutcome::Revalidate(_)));
    let variant_key = variant_storage_key(key.primary_hash().as_str(), &[]);
    let body_key = cache_body_storage_key(variant_key.as_str());
    let gets = backend.get_log();
    assert!(
        !gets.contains(&MockBackend::key("ns", body_key.as_str())),
        "revalidation lookup must not materialize stale body before origin result: {gets:?}"
    );
}

#[tokio::test]
async fn unsafe_method_invalidates_cached_target() {
    let req = make_get_request("/invalidate");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let response = make_response(StatusCode::OK, "max-age=60", "body-a");
    let _ = store_and_drain(
        req.method(),
        req.headers(),
        &key,
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

    let target_key = CacheRequestKey::for_target(&req, "http")
        .expect("key")
        .expect("some key");
    maybe_invalidate(
        &Method::POST,
        StatusCode::OK,
        &http::HeaderMap::new(),
        Some(&target_key),
        &policy(),
        &backends,
    )
    .await
    .expect("invalidate");

    let mut only_cached = make_get_request("/invalidate");
    only_cached.headers_mut().insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached"),
    );
    let key = CacheRequestKey::for_lookup(&only_cached, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        only_cached.method(),
        only_cached.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}

#[tokio::test]
async fn maybe_store_does_not_block_downstream_on_idle_cacheable_body() {
    let req = make_get_request("/idle-cache-body");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let (sender, body) = Body::channel();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "public, max-age=60")
        .body(body)
        .expect("response");
    let backends = backend_map();
    let writeback_admission = test_writeback_admission();

    let stored = tokio::time::timeout(
        Duration::from_millis(25),
        super::maybe_store(
            req.method(),
            req.headers(),
            &key,
            &policy(),
            response,
            CacheStoreContext {
                timing: CacheStoreTiming {
                    response_delay_secs: 0,
                    body_read_timeout: Duration::from_millis(10),
                    request_collapse_guard: None,
                },
                writeback_admission: &writeback_admission,
                backends: &backends,
            },
        ),
    )
    .await
    .expect("store must not wait for idle response body")
    .expect("store response");
    assert_eq!(
        stored
            .headers()
            .get(CACHE_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("qpx; fwd=miss")
    );
    drop(sender);

    let out = lookup(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::Miss));
}

#[tokio::test]
async fn vary_less_store_publishes_no_variant_index() {
    let req = make_get_request("/vary-less");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backend = Arc::new(MockBackend::new());
    let mut backends = HashMap::new();
    backends.insert("b".to_string(), backend.clone() as Arc<dyn CacheBackend>);
    let response = make_response(StatusCode::OK, "max-age=60", "body-a");
    let _ = store_and_drain(
        req.method(),
        req.headers(),
        &key,
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

    let primary = key.primary_hash();
    assert!(
        backend
            .get("ns", index_storage_key(primary.as_str()).as_str())
            .await
            .expect("get index")
            .is_none(),
        "Vary-less stores must not publish a variant index"
    );

    let outcome = lookup(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    assert!(
        matches!(outcome, LookupOutcome::Hit(_)),
        "lookup must hit the canonical default variant without an index"
    );
}

#[tokio::test]
async fn unsafe_method_invalidates_cached_query_variants() {
    // RFC 9111 §4.4: a successful unsafe request invalidates all stored
    // responses for the target URI, including QUERY primaries holding
    // content-digest variants.
    fn query_key(path: &str, digest: &str) -> CacheRequestKey {
        let req = hyper::Request::builder()
            .method(Method::QUERY)
            .uri(path)
            .header(http::header::HOST, "example.com")
            .body(Body::empty())
            .expect("request");
        CacheRequestKey::for_lookup(&req, "http")
            .expect("key")
            .expect("some key")
            .with_content_digest(digest)
    }

    async fn lookup_hit(
        method: &Method,
        headers: &http::HeaderMap,
        key: &CacheRequestKey,
        backends: &HashMap<String, Arc<dyn CacheBackend>>,
    ) -> bool {
        matches!(
            lookup(
                method,
                headers,
                key,
                &policy(),
                backends,
                &test_revalidations(),
            )
            .await
            .expect("lookup"),
            LookupOutcome::Hit(_)
        )
    }

    let backends = backend_map();
    let timing = || CacheStoreTiming {
        response_delay_secs: 0,
        body_read_timeout: Duration::from_secs(1),
        request_collapse_guard: None,
    };
    let headers = http::HeaderMap::new();

    let key_a = query_key("/invalidate-query", "sha-256:a");
    let key_b = query_key("/invalidate-query", "sha-256:b");
    for (key, body) in [(&key_a, "query-a"), (&key_b, "query-b")] {
        let response = make_response(StatusCode::OK, "public, max-age=60", body);
        let _ = store_and_drain(
            &Method::QUERY,
            &headers,
            key,
            &policy(),
            response,
            timing(),
            &backends,
        )
        .await
        .expect("store query variant");
    }
    let get_req = make_get_request("/invalidate-query");
    let get_key = CacheRequestKey::for_lookup(&get_req, "http")
        .expect("key")
        .expect("some key");
    let _ = store_and_drain(
        get_req.method(),
        get_req.headers(),
        &get_key,
        &policy(),
        make_response(StatusCode::OK, "public, max-age=60", "get-body"),
        timing(),
        &backends,
    )
    .await
    .expect("store get");

    assert!(lookup_hit(&Method::QUERY, &headers, &key_a, &backends).await);
    assert!(lookup_hit(&Method::QUERY, &headers, &key_b, &backends).await);
    assert!(lookup_hit(get_req.method(), get_req.headers(), &get_key, &backends).await);

    let post_req = hyper::Request::builder()
        .method(Method::POST)
        .uri("/invalidate-query")
        .header(http::header::HOST, "example.com")
        .body(Body::empty())
        .expect("request");
    let target_key = CacheRequestKey::for_target(&post_req, "http")
        .expect("key")
        .expect("some key");
    maybe_invalidate(
        &Method::POST,
        StatusCode::OK,
        &http::HeaderMap::new(),
        Some(&target_key),
        &policy(),
        &backends,
    )
    .await
    .expect("invalidate");

    // Error responses must not invalidate: re-store, then fail the mutation.
    for (key, body) in [(&key_a, "query-a"), (&key_b, "query-b")] {
        let response = make_response(StatusCode::OK, "public, max-age=60", body);
        let _ = store_and_drain(
            &Method::QUERY,
            &headers,
            key,
            &policy(),
            response,
            timing(),
            &backends,
        )
        .await
        .expect("re-store query variant");
    }
    let _ = store_and_drain(
        get_req.method(),
        get_req.headers(),
        &get_key,
        &policy(),
        make_response(StatusCode::OK, "public, max-age=60", "get-body"),
        timing(),
        &backends,
    )
    .await
    .expect("re-store get");
    maybe_invalidate(
        &Method::POST,
        StatusCode::INTERNAL_SERVER_ERROR,
        &http::HeaderMap::new(),
        Some(&target_key),
        &policy(),
        &backends,
    )
    .await
    .expect("invalidate attempt");
    assert!(lookup_hit(&Method::QUERY, &headers, &key_a, &backends).await);
    assert!(lookup_hit(&Method::QUERY, &headers, &key_b, &backends).await);
    assert!(lookup_hit(get_req.method(), get_req.headers(), &get_key, &backends).await);

    // Successful mutation purges both QUERY digest variants and the GET entry.
    maybe_invalidate(
        &Method::POST,
        StatusCode::OK,
        &http::HeaderMap::new(),
        Some(&target_key),
        &policy(),
        &backends,
    )
    .await
    .expect("invalidate");
    assert!(!lookup_hit(&Method::QUERY, &headers, &key_a, &backends).await);
    assert!(!lookup_hit(&Method::QUERY, &headers, &key_b, &backends).await);
    assert!(!lookup_hit(get_req.method(), get_req.headers(), &get_key, &backends).await);
}

#[tokio::test]
async fn revalidate_not_modified_merges_policy_headers_not_framing() {
    // RFC 9111 §3.2: a 304 refreshes stored metadata (CSP, extension fields)
    // while the unchanged body keeps its framing labels.
    let now = super::util::now_millis();
    let backend = Arc::new(MockBackend::new());
    let mut backends = HashMap::new();
    backends.insert("b".to_string(), backend.clone() as Arc<dyn CacheBackend>);
    let state = RevalidationState {
        backend,
        namespace: "ns".to_string(),
        variant_key: "obj:reval:y".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: None,
        envelope: CachedResponseEnvelope {
            status: 200,
            headers: vec![
                (
                    "cache-control".to_string(),
                    "public, max-age=10".to_string(),
                ),
                ("etag".to_string(), "\"v1\"".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
                (
                    "content-security-policy".to_string(),
                    "default-src *".to_string(),
                ),
                ("x-origin-policy".to_string(), "old".to_string()),
                ("content-length".to_string(), "5".to_string()),
            ],
            body: CachedBody::from_bytes(bytes::Bytes::from_static(b"hello")),
            body_len: 5,
            stored_at_ms: now.saturating_sub(40_000),
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 10,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            header_map: Default::default(),
            response_directives: Default::default(),
            response_header_values: Default::default(),
        },
        revalidations: test_revalidations(),
    };
    let not_modified = hyper::Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(http::header::ETAG, "\"v1\"")
        .header(http::header::CACHE_CONTROL, "public, max-age=300")
        .header("content-security-policy", "default-src 'none'")
        .header("x-origin-policy", "new")
        .header("x-new-policy", "added")
        .header("x-repeated", "one")
        .header("x-repeated", "two")
        .header(http::header::CONTENT_LENGTH, "99")
        .header(http::header::CONTENT_ENCODING, "br")
        .header(http::header::CONNECTION, "x-hop")
        .header("x-hop", "drop-me")
        .body(Body::empty())
        .expect("304 response");
    let response = revalidate_not_modified(
        &Method::GET,
        &http::HeaderMap::new(),
        &policy(),
        not_modified,
        state,
        0,
        &backends,
    )
    .await
    .expect("revalidate");
    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    // Policy metadata is replaced or added.
    assert_eq!(
        get("content-security-policy").as_deref(),
        Some("default-src 'none'")
    );
    assert_eq!(get("x-origin-policy").as_deref(), Some("new"));
    assert_eq!(get("x-new-policy").as_deref(), Some("added"));
    let repeated: Vec<_> = headers
        .get_all("x-repeated")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    assert_eq!(repeated, vec!["one".to_string(), "two".to_string()]);
    assert_eq!(get("cache-control").as_deref(), Some("public, max-age=300"));
    // Framing of the unchanged body is preserved, not taken from the 304.
    assert_eq!(get("content-length").as_deref(), Some("5"));
    assert!(headers.get(http::header::CONTENT_ENCODING).is_none());
    assert!(headers.get("x-hop").is_none());
    // Unchanged body bytes are served.
    let body = qpx_http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"hello");
}
