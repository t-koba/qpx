use super::*;

#[tokio::test]
async fn only_if_cached_does_not_trigger_revalidation() {
    let req = make_get_request("/revalidate-only-if-cached");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "no-cache, max-age=60", "body-a");
    response
        .headers_mut()
        .insert(ETAG, http::HeaderValue::from_static("\"v1\""));
    let backends = backend_map();
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

    let mut only_cached = make_get_request("/revalidate-only-if-cached");
    only_cached.headers_mut().insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached"),
    );
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
async fn only_if_cached_conditional_request_returns_miss_without_network() {
    let mut req = make_get_request("/conditional-only-if-cached");
    req.headers_mut().insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached"),
    );
    req.headers_mut()
        .insert(IF_NONE_MATCH, http::HeaderValue::from_static("\"etag\""));
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
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
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}

#[tokio::test]
async fn vary_controls_cache_hits() {
    let mut req = make_get_request("/vary");
    req.headers_mut()
        .insert("accept-language", http::HeaderValue::from_static("ja"));
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "max-age=60", "hello");
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("accept-language"));
    let backends = backend_map();

    let stored = store_and_drain(
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
    assert_eq!(
        stored
            .headers()
            .get(CACHE_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("MISS")
    );

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
    assert!(matches!(out, LookupOutcome::Hit(_)));

    let mut miss_req = make_get_request("/vary");
    miss_req
        .headers_mut()
        .insert("accept-language", http::HeaderValue::from_static("en"));
    let miss_key = CacheRequestKey::for_lookup(&miss_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        miss_req.method(),
        miss_req.headers(),
        &miss_key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::Miss));
}

#[tokio::test]
async fn set_cookie_is_not_stored_by_default() {
    let req = make_get_request("/cookie-default-blocked");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "hello");
    response.headers_mut().insert(
        SET_COOKIE,
        http::HeaderValue::from_static("sid=abc; Path=/; HttpOnly"),
    );
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("cookie"));
    let backends = backend_map();
    let mut p = policy();
    p.allow_set_cookie_store = false;

    let _ = store_and_drain(
        req.method(),
        req.headers(),
        &key,
        &p,
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
        req.method(),
        req.headers(),
        &key,
        &p,
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::Miss));
}

#[tokio::test]
async fn set_cookie_requires_explicit_opt_in_with_public_and_vary_cookie() {
    let req = make_get_request("/cookie-opt-in");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "hello");
    response.headers_mut().insert(
        SET_COOKIE,
        http::HeaderValue::from_static("sid=abc; Path=/; HttpOnly"),
    );
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("cookie"));
    let backends = backend_map();
    let mut p = policy();
    p.allow_set_cookie_store = true;

    let _ = store_and_drain(
        req.method(),
        req.headers(),
        &key,
        &p,
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
        req.method(),
        req.headers(),
        &key,
        &p,
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::Hit(_)));
}

#[tokio::test]
async fn stale_no_cache_entry_revalidates_and_updates() {
    let mut req = make_get_request("/reval");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "no-cache, max-age=60", "body-a");
    response
        .headers_mut()
        .insert(ETAG, http::HeaderValue::from_static("\"v1\""));

    let backends = backend_map();
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
    let state = match outcome {
        LookupOutcome::Revalidate(state) => state,
        _ => panic!("expected revalidation"),
    };
    attach_revalidation_headers(req.headers_mut(), &state);
    assert!(req.headers().contains_key(IF_NONE_MATCH));

    let not_modified = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(DATE, "Tue, 02 Jan 2024 00:00:00 GMT")
        .body(Body::empty())
        .expect("304");
    let refreshed = revalidate_not_modified(
        req.method(),
        req.headers(),
        &policy(),
        not_modified,
        state,
        0,
        &backends,
    )
    .await
    .expect("revalidate");
    assert_eq!(
        refreshed
            .headers()
            .get(CACHE_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("REVALIDATED")
    );
}
