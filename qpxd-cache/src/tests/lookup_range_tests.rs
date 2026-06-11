use super::*;

#[tokio::test]
async fn lookup_serves_single_range_from_cache() {
    let req = make_get_request("/range-hit");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "hello world");
    response
        .headers_mut()
        .insert(ETAG, http::HeaderValue::from_static("\"v1\""));
    response.headers_mut().insert(
        LAST_MODIFIED,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
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

    let mut ranged = make_get_request("/range-hit");
    ranged
        .headers_mut()
        .insert(RANGE, http::HeaderValue::from_static("bytes=6-10"));
    ranged
        .headers_mut()
        .insert(IF_RANGE, http::HeaderValue::from_static("\"v1\""));
    let out = lookup(
        ranged.method(),
        ranged.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some("bytes 6-10/11")
    );
    let body = qpx_http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"world");
}

#[tokio::test]
async fn lookup_ignores_range_for_head_requests() {
    let req = make_get_request("/head-range");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let response = make_response(StatusCode::OK, "public, max-age=60", "hello world");
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

    let mut ranged = make_head_request("/head-range");
    ranged
        .headers_mut()
        .insert(RANGE, http::HeaderValue::from_static("bytes=6-10"));
    let out = lookup(
        ranged.method(),
        ranged.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(CONTENT_RANGE).is_none());
    let body = qpx_http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert!(body.is_empty());
}

#[tokio::test]
async fn lookup_returns_412_for_if_match_miss() {
    let req = make_get_request("/if-match");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "hello");
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

    let mut conditional = make_get_request("/if-match");
    conditional
        .headers_mut()
        .insert(IF_MATCH, http::HeaderValue::from_static("\"v2\""));
    let out = lookup(
        conditional.method(),
        conditional.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn lookup_returns_416_for_unsatisfiable_range() {
    let req = make_get_request("/range-miss");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let response = make_response(StatusCode::OK, "public, max-age=60", "hello");
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

    let mut ranged = make_get_request("/range-miss");
    ranged
        .headers_mut()
        .insert(RANGE, http::HeaderValue::from_static("bytes=99-120"));
    let out = lookup(
        ranged.method(),
        ranged.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some("bytes */5")
    );
}

#[tokio::test]
async fn if_range_mismatch_falls_back_to_full_response() {
    let req = make_get_request("/if-range-date");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "hello");
    response.headers_mut().insert(
        LAST_MODIFIED,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
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

    let mut ranged = make_get_request("/if-range-date");
    ranged
        .headers_mut()
        .insert(RANGE, http::HeaderValue::from_static("bytes=0-1"));
    ranged.headers_mut().insert(
        IF_RANGE,
        http::HeaderValue::from_static("Mon, 01 Jan 2024 00:00:00 GMT"),
    );
    ranged.headers_mut().insert(
        IF_UNMODIFIED_SINCE,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    let out = lookup(
        ranged.method(),
        ranged.headers(),
        &key,
        &policy(),
        &backends,
        &test_revalidations(),
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let body = qpx_http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"hello");
}
