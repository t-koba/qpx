use super::*;

#[test]
fn stale_can_be_served_with_max_stale() {
    let req = RequestDirectives {
        max_stale: Some(Some(60)),
        ..RequestDirectives::default()
    };
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: vec![("cache-control".to_string(), "max-age=10".to_string())],
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 10,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        header_map: Default::default(),
        response_directives: Default::default(),
        response_header_values: Default::default(),
    };
    let disposition = classify_for_request(&req, &envelope, 40_000);
    assert!(matches!(disposition, CacheEntryDisposition::ServeStale));
}

#[test]
fn immutable_fresh_response_ignores_request_no_cache() {
    let req = RequestDirectives {
        no_cache: true,
        ..RequestDirectives::default()
    };
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: vec![(
            "cache-control".to_string(),
            "max-age=60, immutable".to_string(),
        )],
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 60,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        header_map: Default::default(),
        response_directives: Default::default(),
        response_header_values: Default::default(),
    };

    let disposition = classify_for_request(&req, &envelope, 30_000);
    assert!(matches!(disposition, CacheEntryDisposition::ServeFresh));
}

#[test]
fn stale_while_revalidate_allows_serving_stale_without_max_stale() {
    let req = RequestDirectives::default();
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: vec![(
            "cache-control".to_string(),
            "max-age=10, stale-while-revalidate=60".to_string(),
        )],
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 10,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        header_map: Default::default(),
        response_directives: Default::default(),
        response_header_values: Default::default(),
    };
    let disposition = classify_for_request(&req, &envelope, 40_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::ServeStaleWhileRevalidate
    ));
}

#[test]
fn must_revalidate_blocks_stale_while_revalidate() {
    let req = RequestDirectives::default();
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: vec![(
            "cache-control".to_string(),
            "max-age=10, must-revalidate, stale-while-revalidate=60".to_string(),
        )],
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 10,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        header_map: Default::default(),
        response_directives: Default::default(),
        response_header_values: Default::default(),
    };
    let disposition = classify_for_request(&req, &envelope, 40_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn only_if_cached_swr_does_not_trigger_background_revalidation() {
    let req = RequestDirectives {
        only_if_cached: true,
        ..RequestDirectives::default()
    };
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: vec![(
            "cache-control".to_string(),
            "max-age=10, stale-while-revalidate=60".to_string(),
        )],
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 10,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        header_map: Default::default(),
        response_directives: Default::default(),
        response_header_values: Default::default(),
    };
    let disposition = classify_for_request(&req, &envelope, 40_000);
    assert!(matches!(disposition, CacheEntryDisposition::ServeStale));
}

#[tokio::test]
async fn stale_if_error_fallback_omits_obsolete_warning_headers() {
    let now = super::util::now_millis();
    let backend = Arc::new(MockBackend::new());
    backend
        .put(
            "ns",
            cache_body_storage_key("obj:x:y").as_str(),
            b"hello",
            60,
        )
        .await
        .expect("put body");
    let state = RevalidationState {
        backend,
        namespace: "ns".to_string(),
        variant_key: "obj:x:y".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: CachedResponseEnvelope {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: CachedBody::default(),
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
    let response = maybe_build_stale_if_error_response(&state)
        .await
        .expect("stale response");
    assert!(response.headers().get("warning").is_none());
}

#[tokio::test]
async fn must_revalidate_blocks_stale_if_error_fallback() {
    let now = super::util::now_millis();
    let state = RevalidationState {
        backend: Arc::new(MockBackend::new()),
        namespace: "ns".to_string(),
        variant_key: "obj:x:y".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: CachedResponseEnvelope {
            status: 200,
            headers: vec![(
                "cache-control".to_string(),
                "must-revalidate, stale-if-error=60".to_string(),
            )],
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
    assert!(maybe_build_stale_if_error_response(&state).await.is_none());
}

fn s_maxage_envelope(cache_control: &str, freshness_lifetime_secs: u64) -> CachedResponseEnvelope {
    CachedResponseEnvelope {
        status: 200,
        headers: vec![("cache-control".to_string(), cache_control.to_string())],
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        header_map: Default::default(),
        response_directives: Default::default(),
        response_header_values: Default::default(),
    }
}

#[test]
fn s_maxage_blocks_stale_with_max_stale() {
    // RFC 9111 §5.2.2.10: s-maxage incorporates proxy-revalidate, so an
    // expired s-maxage entry must revalidate even when the request allows
    // stale (age 40s, freshness 10s, max-stale 60s).
    let req = RequestDirectives {
        max_stale: Some(Some(60)),
        ..RequestDirectives::default()
    };
    let envelope = s_maxage_envelope("public, max-age=60, s-maxage=10", 10);
    let disposition = classify_for_request(&req, &envelope, 40_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn s_maxage_blocks_stale_while_revalidate() {
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("public, s-maxage=10, stale-while-revalidate=60", 10);
    let disposition = classify_for_request(&req, &envelope, 40_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn fresh_s_maxage_response_is_served() {
    // Positive control: the prohibition applies only to stale entries.
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("public, max-age=60, s-maxage=10", 10);
    let disposition = classify_for_request(&req, &envelope, 5_000);
    assert!(matches!(disposition, CacheEntryDisposition::ServeFresh));
}

#[tokio::test]
async fn s_maxage_blocks_stale_if_error_fallback() {
    let now = super::util::now_millis();
    let backend = Arc::new(MockBackend::new());
    backend
        .put(
            "ns",
            cache_body_storage_key("obj:smaxage:y").as_str(),
            b"hello",
            60,
        )
        .await
        .expect("put body");
    let state = RevalidationState {
        backend,
        namespace: "ns".to_string(),
        variant_key: "obj:smaxage:y".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: CachedResponseEnvelope {
            status: 200,
            headers: vec![(
                "cache-control".to_string(),
                "public, s-maxage=10, stale-if-error=60".to_string(),
            )],
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
    assert!(maybe_build_stale_if_error_response(&state).await.is_none());
}

#[test]
fn no_cache_blocks_stale_while_revalidate() {
    // RFC 9111 §5.2.2.4: unqualified response no-cache MUST NOT satisfy a
    // request without successful validation, even for stale reuse. Age 11s,
    // freshness 10s, SWR window 60s: must revalidate, not serve stale.
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("no-cache, max-age=10, stale-while-revalidate=60", 10);
    let disposition = classify_for_request(&req, &envelope, 11_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn no_cache_blocks_only_if_cached_swr_stale() {
    // Without the prohibition the SWR branch would return ServeStale for
    // only-if-cached; with it the age-11 stale entry must 504 instead.
    let req = RequestDirectives {
        only_if_cached: true,
        ..RequestDirectives::default()
    };
    let envelope = s_maxage_envelope("no-cache, max-age=10, stale-while-revalidate=60", 10);
    let disposition = classify_for_request(&req, &envelope, 11_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn qualified_no_cache_fields_still_allow_swr() {
    // Control: qualified no-cache names fields to strip, not a reuse ban,
    // so the same age-11 entry stays reusable via SWR.
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope(
        "no-cache=\"authorization\", max-age=10, stale-while-revalidate=60",
        10,
    );
    let disposition = classify_for_request(&req, &envelope, 11_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::ServeStaleWhileRevalidate
    ));
}

#[test]
fn ordinary_swr_serves_at_age_11() {
    // Ordinary control: without no-cache the same age-11 entry is reusable
    // via SWR, proving the ban above comes from unqualified no-cache.
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("max-age=10, stale-while-revalidate=60", 10);
    let disposition = classify_for_request(&req, &envelope, 11_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::ServeStaleWhileRevalidate
    ));
}

#[tokio::test]
async fn ordinary_stale_if_error_serves_at_age_11() {
    // Ordinary control: without no-cache the same age-11 entry is rescuable
    // via stale-if-error, proving the ban above comes from unqualified
    // no-cache.
    let now = super::util::now_millis();
    let backend = Arc::new(MockBackend::new());
    backend
        .put(
            "ns",
            cache_body_storage_key("obj:ordinary:stale-if-error").as_str(),
            b"hello",
            60,
        )
        .await
        .expect("put body");
    let state = RevalidationState {
        backend,
        namespace: "ns".to_string(),
        variant_key: "obj:ordinary:stale-if-error".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: s_maxage_envelope("max-age=10, stale-if-error=60", 10),
        revalidations: test_revalidations(),
    };
    let mut state = state;
    state.envelope.stored_at_ms = now.saturating_sub(11_000);
    state.envelope.body_len = 5;
    assert!(maybe_build_stale_if_error_response(&state).await.is_some());
}

#[tokio::test]
async fn no_cache_blocks_stale_if_error_fallback() {
    let now = super::util::now_millis();
    let backend = Arc::new(MockBackend::new());
    backend
        .put(
            "ns",
            cache_body_storage_key("obj:nocache:y").as_str(),
            b"hello",
            60,
        )
        .await
        .expect("put body");
    let state = RevalidationState {
        backend,
        namespace: "ns".to_string(),
        variant_key: "obj:nocache:y".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: s_maxage_envelope("no-cache, max-age=10, stale-if-error=60", 10),
        revalidations: test_revalidations(),
    };
    let mut state = state;
    // Age 11s, freshness 10s, stale-if-error window 60s: must revalidate, not serve stale.
    state.envelope.stored_at_ms = now.saturating_sub(11_000);
    state.envelope.body_len = 5;
    assert!(maybe_build_stale_if_error_response(&state).await.is_none());
}

#[tokio::test]
async fn no_cache_blocks_head_stale_if_error_fallback() {
    let now = super::util::now_millis();
    let state = RevalidationState {
        backend: Arc::new(MockBackend::new()),
        namespace: "ns".to_string(),
        variant_key: "obj:nocache:h".to_string(),
        request_method: Method::HEAD,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: s_maxage_envelope("no-cache, max-age=10, stale-if-error=60", 10),
        revalidations: test_revalidations(),
    };
    let mut state = state;
    // HEAD at age 11s must likewise revalidate instead of serving stale.
    state.envelope.stored_at_ms = now.saturating_sub(11_000);
    assert!(maybe_build_stale_if_error_response(&state).await.is_none());
}

#[test]
fn zero_lifetime_is_never_fresh() {
    // RFC 9111 §4.2: response_is_fresh = (freshness_lifetime > current_age).
    // A max-age=0 entry is stale even at age zero and must revalidate.
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("max-age=0", 0);
    let disposition = classify_for_request(&req, &envelope, 0);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn exact_expiry_requires_revalidation() {
    // At age == freshness the entry is stale, not fresh; the seconds on
    // either side keep their outcomes.
    let req = RequestDirectives::default();
    let before = classify_for_request(&req, &s_maxage_envelope("max-age=60", 60), 59_000);
    assert!(matches!(before, CacheEntryDisposition::ServeFresh));
    let at = classify_for_request(&req, &s_maxage_envelope("max-age=60", 60), 60_000);
    assert!(matches!(at, CacheEntryDisposition::RequiresRevalidation));
    let after = classify_for_request(&req, &s_maxage_envelope("max-age=60", 60), 61_000);
    assert!(matches!(after, CacheEntryDisposition::RequiresRevalidation));
}

#[test]
fn exact_expiry_must_revalidate_requires_revalidation() {
    // Title case: an expired must-revalidate entry at its exact boundary
    // must not be served fresh.
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("must-revalidate, max-age=60", 60);
    let disposition = classify_for_request(&req, &envelope, 60_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn exact_expiry_proxy_revalidate_requires_revalidation() {
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("proxy-revalidate, max-age=60", 60);
    let disposition = classify_for_request(&req, &envelope, 60_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn s_maxage_zero_requires_revalidation() {
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("public, s-maxage=0", 0);
    let disposition = classify_for_request(&req, &envelope, 0);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[test]
fn exact_expiry_allows_explicit_max_stale() {
    // An explicit client stale allowance still applies at the boundary:
    // staleness 0 is within the max-stale window.
    let req = RequestDirectives {
        max_stale: Some(Some(60)),
        ..RequestDirectives::default()
    };
    let envelope = s_maxage_envelope("max-age=60", 60);
    let disposition = classify_for_request(&req, &envelope, 60_000);
    assert!(matches!(disposition, CacheEntryDisposition::ServeStale));
}

#[test]
fn request_max_age_zero_still_permits_fresh_response() {
    // Control: request max-age keeps its own "age no greater than" semantics;
    // a fresh age-0 response stays permitted. Only the response-lifetime
    // boundary changes.
    let req = RequestDirectives {
        max_age: Some(0),
        ..RequestDirectives::default()
    };
    let envelope = s_maxage_envelope("max-age=60", 60);
    let disposition = classify_for_request(&req, &envelope, 0);
    assert!(matches!(disposition, CacheEntryDisposition::ServeFresh));
}

#[test]
fn exact_expiry_swr_serves_stale_while_revalidate() {
    // The exact expiry second is stale with staleness 0, which is inside the
    // stale-while-revalidate window (RFC 5861 §3).
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("max-age=60, stale-while-revalidate=60", 60);
    let disposition = classify_for_request(&req, &envelope, 60_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::ServeStaleWhileRevalidate
    ));
}

#[test]
fn exact_expiry_only_if_cached_swr_serves_stale() {
    let req = RequestDirectives {
        only_if_cached: true,
        ..RequestDirectives::default()
    };
    let envelope = s_maxage_envelope("max-age=60, stale-while-revalidate=60", 60);
    let disposition = classify_for_request(&req, &envelope, 60_000);
    assert!(matches!(disposition, CacheEntryDisposition::ServeStale));
}

#[test]
fn exact_expiry_must_revalidate_overrides_swr() {
    // Control: the stale prohibition still wins over the SWR window.
    let req = RequestDirectives::default();
    let envelope = s_maxage_envelope("must-revalidate, max-age=60, stale-while-revalidate=60", 60);
    let disposition = classify_for_request(&req, &envelope, 60_000);
    assert!(matches!(
        disposition,
        CacheEntryDisposition::RequiresRevalidation
    ));
}

#[tokio::test]
async fn stale_if_error_serves_at_exact_expiry() {
    let now = super::util::now_millis();
    let backend = Arc::new(MockBackend::new());
    backend
        .put(
            "ns",
            cache_body_storage_key("obj:stale_err:edge").as_str(),
            b"hello",
            60,
        )
        .await
        .expect("put body");
    let state = RevalidationState {
        backend,
        namespace: "ns".to_string(),
        variant_key: "obj:stale_err:edge".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: s_maxage_envelope("max-age=60, stale-if-error=60", 60),
        revalidations: test_revalidations(),
    };
    let mut state = state;
    state.envelope.stored_at_ms = now.saturating_sub(60_000);
    state.envelope.body_len = 5;
    assert!(maybe_build_stale_if_error_response(&state).await.is_some());
}

#[tokio::test]
async fn stale_if_error_serves_zero_lifetime_entry() {
    // Worst case from review: a max-age=0 entry is always stale, so
    // stale-if-error must still rescue it during its first second.
    let now = super::util::now_millis();
    let backend = Arc::new(MockBackend::new());
    backend
        .put(
            "ns",
            cache_body_storage_key("obj:stale_err:zero").as_str(),
            b"hello",
            60,
        )
        .await
        .expect("put body");
    let state = RevalidationState {
        backend,
        namespace: "ns".to_string(),
        variant_key: "obj:stale_err:zero".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: s_maxage_envelope("max-age=0, stale-if-error=60", 0),
        revalidations: test_revalidations(),
    };
    let mut state = state;
    state.envelope.stored_at_ms = now;
    state.envelope.body_len = 5;
    assert!(maybe_build_stale_if_error_response(&state).await.is_some());
}

#[tokio::test]
async fn must_revalidate_blocks_stale_if_error_at_exact_expiry() {
    // Control: the stale prohibition still wins over the stale-if-error window.
    let now = super::util::now_millis();
    let state = RevalidationState {
        backend: Arc::new(MockBackend::new()),
        namespace: "ns".to_string(),
        variant_key: "obj:stale_err:mr".to_string(),
        request_method: Method::GET,
        request_directives: RequestDirectives::default(),
        stale_if_error_secs: Some(60),
        envelope: s_maxage_envelope("must-revalidate, max-age=60, stale-if-error=60", 60),
        revalidations: test_revalidations(),
    };
    let mut state = state;
    state.envelope.stored_at_ms = now.saturating_sub(60_000);
    assert!(maybe_build_stale_if_error_response(&state).await.is_none());
}

#[test]
fn fixed_envelope_accessors_preserve_first_value_and_invalid_text_behavior() {
    let mut headers = http::HeaderMap::new();
    headers.append(
        http::header::ETAG,
        http::HeaderValue::from_static("\"first\""),
    );
    headers.append(
        http::header::ETAG,
        http::HeaderValue::from_static("\"second\""),
    );
    headers.append(
        http::header::LAST_MODIFIED,
        http::HeaderValue::from_static("Mon, 01 Jan 2024 00:00:00 GMT"),
    );
    headers.append(
        http::header::LAST_MODIFIED,
        http::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
    );
    headers.append(
        http::header::DATE,
        http::HeaderValue::from_static("Wed, 03 Jan 2024 00:00:00 GMT"),
    );
    headers.append(
        http::header::DATE,
        http::HeaderValue::from_static("Thu, 04 Jan 2024 00:00:00 GMT"),
    );
    let envelope = envelope_with_hydrated_headers(headers);

    assert_eq!(envelope.etag(), Some("\"first\""));
    assert_eq!(
        envelope.last_modified(),
        Some("Mon, 01 Jan 2024 00:00:00 GMT")
    );
    assert_eq!(envelope.date(), Some("Wed, 03 Jan 2024 00:00:00 GMT"));

    let mut invalid_first = http::HeaderMap::new();
    invalid_first.append(
        http::header::ETAG,
        http::HeaderValue::from_bytes(&[0xff]).expect("obs-text header value"),
    );
    invalid_first.append(
        http::header::ETAG,
        http::HeaderValue::from_static("\"valid\""),
    );
    assert_eq!(envelope_with_hydrated_headers(invalid_first).etag(), None);
}

fn envelope_with_hydrated_headers(headers: http::HeaderMap) -> CachedResponseEnvelope {
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: Vec::new(),
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 0,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        header_map: Default::default(),
        response_directives: Default::default(),
        response_header_values: Default::default(),
    };
    envelope
        .header_map
        .set(Box::new(headers))
        .expect("fresh lock");
    envelope
}
