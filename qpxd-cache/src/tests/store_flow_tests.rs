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

    let stored = tokio::time::timeout(
        Duration::from_millis(25),
        super::maybe_store(
            req.method(),
            req.headers(),
            &key,
            &policy(),
            response,
            CacheStoreTiming {
                response_delay_secs: 0,
                body_read_timeout: Duration::from_millis(10),
                request_collapse_guard: None,
            },
            &backends,
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
        Some("MISS")
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
