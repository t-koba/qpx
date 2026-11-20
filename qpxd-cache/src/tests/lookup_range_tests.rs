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

    let mut ranged = make_get_request("/range-hit");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=6-10"));
    ranged
        .headers_mut()
        .insert(ord("if-range"), http::HeaderValue::from_static("\"v1\""));
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        crate::tests::wire_headers(response.headers())
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some("bytes 6-10/11")
    );
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"world");
}

/// RFC 9110 §14.2: Range applies only when the response without Range would
/// be 200 OK. A cached 404 must stay a 404 with its full body, not become a
/// 206 carrying a slice of the error page.
#[tokio::test]
async fn lookup_ignores_range_for_cached_not_found() {
    let req = make_get_request("/cached-404-range");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let response = make_response(StatusCode::NOT_FOUND, "public, max-age=60", "missing");
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

    let mut ranged = make_get_request("/cached-404-range");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=0-1"));
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        crate::tests::wire_headers(response.headers())
            .get(CONTENT_RANGE)
            .is_none()
    );
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"missing");
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

    let mut ranged = make_head_request("/head-range");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=6-10"));
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        crate::tests::wire_headers(response.headers())
            .get(CONTENT_RANGE)
            .is_none()
    );
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
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

    let mut conditional = make_get_request("/if-match");
    conditional
        .headers_mut()
        .insert(ord("if-match"), http::HeaderValue::from_static("\"v2\""));
    let out = lookup(
        &conditional,
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
async fn lookup_if_match_takes_precedence_over_if_unmodified_since() {
    let req = make_get_request("/if-match-precedence");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "hello");
    response
        .headers_mut()
        .insert(ETAG, http::HeaderValue::from_static("\"v1\""));
    response.headers_mut().insert(
        LAST_MODIFIED,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
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

    for (if_match, expected_status) in [
        (Some("\"v1\""), StatusCode::OK),
        (Some("*"), StatusCode::OK),
        (Some("\"v2\""), StatusCode::PRECONDITION_FAILED),
        (None, StatusCode::PRECONDITION_FAILED),
    ] {
        let mut conditional = make_get_request("/if-match-precedence");
        if let Some(if_match) = if_match {
            conditional
                .headers_mut()
                .insert(ord("if-match"), http::HeaderValue::from_static(if_match));
        }
        conditional.headers_mut().insert(
            ord("if-unmodified-since"),
            http::HeaderValue::from_static("Mon, 01 Jan 2024 00:00:00 GMT"),
        );
        let out = lookup(
            &conditional,
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
        assert_eq!(response.status(), expected_status, "If-Match: {if_match:?}");
    }
}

#[tokio::test]
async fn lookup_parses_comma_containing_entity_tag_lists() {
    let req = make_get_request("/etag-comma");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "hello");
    response
        .headers_mut()
        .insert(ETAG, http::HeaderValue::from_static("\"a,b\""));
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

    for (name, value, expected_status) in [
        ("if-match", "\"a,b\"", StatusCode::OK),
        ("if-match", "\"missing,tag\", \"a,b\"", StatusCode::OK),
        ("if-match", "W/\"a,b\"", StatusCode::PRECONDITION_FAILED),
        ("if-match", "*", StatusCode::OK),
        ("if-none-match", "\"a,b\"", StatusCode::NOT_MODIFIED),
        ("if-none-match", "W/\"a,b\"", StatusCode::NOT_MODIFIED),
        (
            "if-none-match",
            "\"missing,tag\", W/\"a,b\"",
            StatusCode::NOT_MODIFIED,
        ),
        ("if-none-match", "*", StatusCode::NOT_MODIFIED),
    ] {
        let mut conditional = make_get_request("/etag-comma");
        conditional
            .headers_mut()
            .insert(ord(name), http::HeaderValue::from_static(value));
        let out = lookup(
            &conditional,
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
        assert_eq!(response.status(), expected_status, "{name}: {value}");
    }

    let mut repeated = make_get_request("/etag-comma");
    repeated.headers_mut().append(
        ord("if-none-match"),
        http::HeaderValue::from_static("W/\"missing,tag\""),
    );
    repeated.headers_mut().append(
        ord("if-none-match"),
        http::HeaderValue::from_static("W/\"a,b\""),
    );
    let out = lookup(&repeated, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
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

    let mut ranged = make_get_request("/range-miss");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=99-120"));
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        crate::tests::wire_headers(response.headers())
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

    let mut ranged = make_get_request("/if-range-date");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=0-1"));
    ranged.headers_mut().insert(
        ord("if-range"),
        http::HeaderValue::from_static("Mon, 01 Jan 2024 00:00:00 GMT"),
    );
    ranged.headers_mut().insert(
        ord("if-unmodified-since"),
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"hello");
}

#[tokio::test]
async fn if_range_later_date_falls_back_to_full_response() {
    // RFC 9110 §13.1.5: only an exact date match keeps the range. A later
    // If-Range date must not yield a 206 stitched from another version.
    let req = make_get_request("/if-range-later-date");
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

    let mut ranged = make_get_request("/if-range-later-date");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=0-1"));
    ranged.headers_mut().insert(
        ord("if-range"),
        http::HeaderValue::from_static("Wed, 03 Jan 2024 00:00:00 GMT"),
    );
    ranged.headers_mut().insert(
        ord("if-unmodified-since"),
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"hello");
}

#[tokio::test]
async fn if_range_equal_date_serves_partial_response() {
    // Positive control: an exact date match preserves the requested range,
    // but only with strong-validator evidence: Date strictly after
    // Last-Modified (RFC 9110 §§13.1.5, 8.8.2.2). The lifetime covers the
    // fixed 2024 validator dates so apparent age keeps the entry fresh.
    let req = make_get_request("/if-range-equal-date");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=1000000000", "hello");
    response.headers_mut().insert(
        LAST_MODIFIED,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    response.headers_mut().insert(
        DATE,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:01 GMT"),
    );
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

    let mut ranged = make_get_request("/if-range-equal-date");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=0-1"));
    ranged.headers_mut().insert(
        ord("if-range"),
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"he");
}

#[tokio::test]
async fn if_range_equal_date_without_date_falls_back_to_full_response() {
    // No Date header means no strong-validator evidence: an equal
    // Last-Modified alone must not yield a 206.
    let req = make_get_request("/if-range-no-date");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=1000000000", "hello");
    response.headers_mut().insert(
        LAST_MODIFIED,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
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

    let mut ranged = make_get_request("/if-range-no-date");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=0-1"));
    ranged.headers_mut().insert(
        ord("if-range"),
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"hello");
}

#[tokio::test]
async fn if_range_equal_date_with_same_date_falls_back_to_full_response() {
    // Date equal to Last-Modified carries no separation evidence: the
    // stored date stays weak and the range must be ignored.
    let req = make_get_request("/if-range-same-date");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=1000000000", "hello");
    response.headers_mut().insert(
        LAST_MODIFIED,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    response.headers_mut().insert(
        DATE,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
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

    let mut ranged = make_get_request("/if-range-same-date");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=0-1"));
    ranged.headers_mut().insert(
        ord("if-range"),
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"hello");
}

#[tokio::test]
async fn if_range_equal_date_with_earlier_date_falls_back_to_full_response() {
    // Date earlier than Last-Modified contradicts strength (and a sane
    // origin clock): the range must be ignored.
    let req = make_get_request("/if-range-earlier-date");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "public, max-age=1000000000", "hello");
    response.headers_mut().insert(
        LAST_MODIFIED,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    response.headers_mut().insert(
        DATE,
        http::HeaderValue::from_static("Mon, 01 Jan 2024 00:00:00 GMT"),
    );
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

    let mut ranged = make_get_request("/if-range-earlier-date");
    ranged
        .headers_mut()
        .insert(ord("range"), http::HeaderValue::from_static("bytes=0-1"));
    ranged.headers_mut().insert(
        ord("if-range"),
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    let out = lookup(&ranged, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"hello");
}

/// RFC 9110 §13.2.1: preconditions are ignored when the response without
/// them would be neither 2xx nor 412. A cached 404 must keep its status and
/// body even when the client sends `If-None-Match: *`.
#[tokio::test]
async fn lookup_ignores_if_none_match_for_cached_not_found() {
    let mut req = make_get_request("/cached-404-condition");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let _ = store_and_drain(
        &req,
        &key,
        &policy(),
        make_response(StatusCode::NOT_FOUND, "public, max-age=60", "missing"),
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
            request_collapse_guard: None,
        },
        &backends,
    )
    .await
    .expect("store");

    req.headers_mut()
        .insert(ord("if-none-match"), http::HeaderValue::from_static("*"));
    let out = lookup(&req, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let LookupOutcome::Hit(response) = out else {
        panic!("expected cache hit");
    };
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = qpx_http::body::to_bytes(response.into_head_and_body().1)
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"missing");

    // The same status guard applies to state-changing preconditions: a
    // cached 404 must not be replaced by a synthetic 412 either.
    req.headers_mut().remove(&ord("if-none-match"));
    req.headers_mut()
        .insert(ord("if-match"), http::HeaderValue::from_static("\"nope\""));
    let out = lookup(&req, &key, &policy(), &backends, &test_revalidations())
        .await
        .expect("lookup");
    let LookupOutcome::Hit(response) = out else {
        panic!("expected cache hit");
    };
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
