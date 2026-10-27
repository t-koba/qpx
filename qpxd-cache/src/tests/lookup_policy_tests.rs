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
        &req,
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
        ord("cache-control"),
        http::HeaderValue::from_static("only-if-cached"),
    );
    let out = lookup(
        &only_cached,
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
        ord("cache-control"),
        http::HeaderValue::from_static("only-if-cached"),
    );
    req.headers_mut().insert(
        ord("if-none-match"),
        http::HeaderValue::from_static("\"etag\""),
    );
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let out = lookup(&req, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}

#[tokio::test]
async fn vary_controls_cache_hits() {
    let mut req = make_get_request("/vary");
    req.headers_mut()
        .insert(ord("accept-language"), http::HeaderValue::from_static("ja"));
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "max-age=60", "hello");
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("accept-language"));
    let backends = backend_map();

    let stored = store_and_drain(
        &req,
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
        Some("qpx; fwd=miss")
    );

    let out = lookup(&req, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    if !matches!(out, LookupOutcome::Hit(_)) {
        eprintln!("OUTCOME_DEBUG {:?}", out);
    }
    assert!(matches!(out, LookupOutcome::Hit(_)));

    let mut miss_req = make_get_request("/vary");
    miss_req
        .headers_mut()
        .insert(ord("accept-language"), http::HeaderValue::from_static("en"));
    let miss_key = CacheRequestKey::for_lookup(&miss_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        &miss_req,
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
        &req,
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
    let out = lookup(&req, &key, &p, &backends, &test_revalidations())
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
        &req,
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
    let out = lookup(&req, &key, &p, &backends, &test_revalidations())
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
        &req,
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

    let outcome = lookup(&req, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let state = match outcome {
        LookupOutcome::Revalidate(state) => state,
        _ => panic!("expected revalidation"),
    };
    attach_revalidation_headers(req.headers_mut(), &state);
    assert!(req.headers().contains_key(&ord("if-none-match")));

    let not_modified = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(DATE, "Tue, 02 Jan 2024 00:00:00 GMT")
        .body(Body::empty())
        .expect("304");
    let refreshed = revalidate_not_modified(&req, &policy(), not_modified, state, 0, &backends)
        .await
        .expect("revalidate");
    assert_eq!(
        refreshed
            .headers()
            .get(CACHE_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("qpx; fwd=stale; fwd-status=304")
    );
}

#[tokio::test]
async fn zero_max_age_entry_revalidates_on_immediate_lookup() {
    // RFC 9111 §4.2: a stored max-age=0 entry is stale at age zero, so even
    // an immediate lookup must revalidate rather than hit.
    let req = make_get_request("/zero");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let response = make_response(StatusCode::OK, "max-age=0", "body-a");

    let backends = backend_map();
    let _ = store_and_drain(
        &req,
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

    let outcome = lookup(&req, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(matches!(outcome, LookupOutcome::Revalidate(_)));
}

#[tokio::test]
async fn authorization_public_without_vary_is_not_shared_across_credentials() {
    let mut req_a = make_get_request("/auth-no-vary");
    req_a.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer A"),
    );
    let key = CacheRequestKey::for_lookup(&req_a, "http")
        .expect("key")
        .expect("some key");
    let response = make_response(StatusCode::OK, "public, max-age=60", "private-a");
    let backends = backend_map();
    let _ = store_and_drain(
        &req_a,
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
    let mut req_b = make_get_request("/auth-no-vary");
    req_b.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer B"),
    );
    let out = lookup(&req_b, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(
        !matches!(out, LookupOutcome::Hit(_)),
        "public Authorization response without Vary: Authorization must not be served across credentials"
    );
}

#[tokio::test]
async fn authorization_public_with_vary_authorization_is_partitioned() {
    let mut req_a = make_get_request("/auth-vary");
    req_a.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer A"),
    );
    let key = CacheRequestKey::for_lookup(&req_a, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "private-a");
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("Authorization"));
    let backends = backend_map();
    let _ = store_and_drain(
        &req_a,
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
    let out_same = lookup(&req_a, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(matches!(out_same, LookupOutcome::Hit(_)));
    let mut req_b = make_get_request("/auth-vary");
    req_b.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer B"),
    );
    let out_other = lookup(&req_b, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(matches!(out_other, LookupOutcome::Miss));
}

#[tokio::test]
async fn authorization_without_vary_opt_out_restores_shared_storage() {
    let mut req_a = make_get_request("/auth-opt-out");
    req_a.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer A"),
    );
    let key = CacheRequestKey::for_lookup(&req_a, "http")
        .expect("key")
        .expect("some key");
    let response = make_response(StatusCode::OK, "public, max-age=60", "shared");
    let backends = backend_map();
    let mut p = policy();
    p.allow_authorization_without_vary_store = true;
    let _ = store_and_drain(
        &req_a,
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
    let mut req_b = make_get_request("/auth-opt-out");
    req_b.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer B"),
    );
    let out = lookup(&req_b, &key, &p, &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(matches!(out, LookupOutcome::Hit(_)));
}

#[tokio::test]
async fn authorization_proxy_revalidate_alone_is_not_storable() {
    // RFC 9111 §3.5: proxy-revalidate alone does not grant shared storage
    // permission for Authorization-bearing requests. Even the identical
    // credential must miss.
    let mut req_a = make_get_request("/auth-proxy-revalidate");
    req_a.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer A"),
    );
    let key = CacheRequestKey::for_lookup(&req_a, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "max-age=60, proxy-revalidate", "private-a");
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("Authorization"));
    let backends = backend_map();
    let _ = store_and_drain(
        &req_a,
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
    let out_same = lookup(&req_a, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(
        !matches!(out_same, LookupOutcome::Hit(_)),
        "proxy-revalidate alone must not unlock Authorization shared storage"
    );
}

#[tokio::test]
async fn authorization_proxy_revalidate_alone_opt_out_still_misses() {
    // The no-Vary opt-out cannot bypass the RFC 9111 §3.5 storage gate.
    let mut req_a = make_get_request("/auth-proxy-revalidate-opt-out");
    req_a.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer A"),
    );
    let key = CacheRequestKey::for_lookup(&req_a, "http")
        .expect("key")
        .expect("some key");
    let response = make_response(StatusCode::OK, "max-age=60, proxy-revalidate", "private-a");
    let backends = backend_map();
    let mut p = policy();
    p.allow_authorization_without_vary_store = true;
    let _ = store_and_drain(
        &req_a,
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
    let out = lookup(&req_a, &key, &p, &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(
        !matches!(out, LookupOutcome::Hit(_)),
        "opt-out must not bypass the RFC 9111 §3.5 Authorization storage gate"
    );
}

#[tokio::test]
async fn authorization_must_revalidate_with_vary_is_partitioned_hit() {
    // Positive control: must-revalidate grants §3.5 permission; Vary partitions.
    let mut req_a = make_get_request("/auth-must-revalidate");
    req_a.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer A"),
    );
    let key = CacheRequestKey::for_lookup(&req_a, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "max-age=60, must-revalidate", "private-a");
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("Authorization"));
    let backends = backend_map();
    let _ = store_and_drain(
        &req_a,
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
    let out_same = lookup(&req_a, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(matches!(out_same, LookupOutcome::Hit(_)));
}

#[tokio::test]
async fn authorization_s_maxage_with_vary_is_partitioned_hit() {
    // Positive control: s-maxage grants §3.5 permission; Vary partitions.
    let mut req_a = make_get_request("/auth-s-maxage");
    req_a.headers_mut().insert(
        ord("authorization"),
        http::HeaderValue::from_static("Bearer A"),
    );
    let key = CacheRequestKey::for_lookup(&req_a, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "max-age=60, s-maxage=60", "private-a");
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("Authorization"));
    let backends = backend_map();
    let _ = store_and_drain(
        &req_a,
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
    let out_same = lookup(&req_a, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    assert!(matches!(out_same, LookupOutcome::Hit(_)));
}
