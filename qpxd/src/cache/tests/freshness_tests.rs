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
    };
    let disposition = classify_for_request(&req, &envelope, 40_000);
    assert!(matches!(disposition, CacheEntryDisposition::ServeStale));
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
        },
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
        },
    };
    assert!(maybe_build_stale_if_error_response(&state).await.is_none());
}
