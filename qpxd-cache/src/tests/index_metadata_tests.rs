use super::*;

#[tokio::test]
async fn purge_cache_key_removes_variant_objects_and_index() {
    let req = make_get_request("/purge");
    let key = CacheRequestKey::for_target(&req, "http")
        .expect("cache key")
        .expect("target key");
    let policy = policy();
    let namespace = super::util::cache_namespace(&policy, "default");
    let backend = Arc::new(MockBackend::new());
    let primary = key.primary_hash();
    let variant = variant_storage_key(primary.as_str(), &[]);
    let index = VariantIndex {
        variants: vec![variant.clone()],
    };
    backend
        .put(namespace.as_str(), variant.as_str(), b"cached", 30)
        .await
        .expect("put variant");
    backend
        .put(
            namespace.as_str(),
            cache_body_storage_key(variant.as_str()).as_str(),
            b"cached body",
            30,
        )
        .await
        .expect("put variant body");
    backend
        .put(
            namespace.as_str(),
            index_storage_key(primary.as_str()).as_str(),
            serde_json::to_vec(&index)
                .expect("serialize index")
                .as_slice(),
            30,
        )
        .await
        .expect("put index");
    let mut backends = HashMap::new();
    backends.insert("b".to_string(), backend.clone() as Arc<dyn CacheBackend>);

    let purged = purge_cache_key(&key, &policy, &backends)
        .await
        .expect("purge");

    assert!(purged);
    assert!(
        backend
            .get(namespace.as_str(), variant.as_str())
            .await
            .expect("get variant")
            .is_none()
    );
    assert!(
        backend
            .get(
                namespace.as_str(),
                cache_body_storage_key(variant.as_str()).as_str(),
            )
            .await
            .expect("get variant body")
            .is_none()
    );
    assert!(
        backend
            .get(
                namespace.as_str(),
                index_storage_key(primary.as_str()).as_str(),
            )
            .await
            .expect("get index")
            .is_none()
    );
}

#[tokio::test]
async fn request_collapse_notifies_followers() {
    let req = make_get_request("/collapse");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("lookup key");
    let collapse = test_request_collapse();
    let leader = match collapse.begin(&key) {
        RequestCollapseJoin::Leader(guard) => guard,
        RequestCollapseJoin::Follower(_) => panic!("expected leader"),
    };
    let waiter = match collapse.begin(&key) {
        RequestCollapseJoin::Leader(_) => panic!("expected follower"),
        RequestCollapseJoin::Follower(waiter) => waiter,
    };
    let wait_task = tokio::spawn(async move { waiter.wait(Duration::from_millis(100)).await });
    tokio::task::yield_now().await;
    drop(leader);
    assert!(wait_task.await.expect("wait task"));
}

#[tokio::test]
async fn request_collapse_guard_waits_for_cache_writeback() {
    let req = make_get_request("/collapse-writeback");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("lookup key");
    let collapse = test_request_collapse();
    let leader = match collapse.begin(&key) {
        RequestCollapseJoin::Leader(guard) => guard,
        RequestCollapseJoin::Follower(_) => panic!("expected leader"),
    };
    let waiter = match collapse.begin(&key) {
        RequestCollapseJoin::Leader(_) => panic!("expected follower"),
        RequestCollapseJoin::Follower(waiter) => waiter,
    };
    let (mut sender, body) = Body::channel();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "public, max-age=60")
        .body(body)
        .expect("response");
    let backends = backend_map();
    let stored = super::maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
            request_collapse_guard: Some(leader),
        },
        &backends,
    )
    .await
    .expect("store response");

    let wait_task = tokio::spawn(async move { waiter.wait(Duration::from_millis(250)).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(!wait_task.is_finished());
    sender
        .send_data(Bytes::from_static(b"cached"))
        .await
        .expect("send body");
    drop(sender);
    let _ = qpx_http::body::to_bytes(stored.into_body())
        .await
        .expect("drain primary body");
    assert!(wait_task.await.expect("wait task"));
}

#[test]
fn upsert_variant_with_cap_keeps_most_recent_entries() {
    let mut index = VariantIndex::default();
    let mut evicted = Vec::new();
    for i in 0..(MAX_VARIANTS_PER_PRIMARY + 4) {
        evicted.extend(upsert_variant_with_cap(
            &mut index,
            format!("v-{i}").as_str(),
        ));
    }
    assert_eq!(index.variants.len(), MAX_VARIANTS_PER_PRIMARY);
    assert_eq!(evicted.len(), 4);
    assert_eq!(index.variants.first(), Some(&"v-4".to_string()));
    assert_eq!(
        index.variants.last(),
        Some(&format!("v-{}", MAX_VARIANTS_PER_PRIMARY + 3))
    );
}

#[tokio::test]
async fn load_variant_index_rejects_corrupted_payload() {
    let backend = MockBackend::new();
    backend
        .put(
            "ns",
            super::vary::index_storage_key("primary").as_str(),
            b"{",
            60,
        )
        .await
        .expect("put");

    let err = load_variant_index(&backend, "ns", "primary")
        .await
        .expect_err("corrupted index must fail");
    assert!(
        err.to_string().contains("EOF") || err.to_string().contains("expected"),
        "unexpected error: {err}"
    );

    let raw = backend
        .get("ns", super::vary::index_storage_key("primary").as_str())
        .await
        .expect("get");
    assert!(raw.is_some(), "corrupted index must not self-delete");
}

#[test]
fn decode_cached_response_metadata_rejects_non_http_status_class() {
    let envelope = CachedResponseEnvelope {
        status: 700,
        headers: Vec::new(),
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 30,
        vary_headers: Vec::new(),
        vary_values: Vec::new(),
        header_map: Default::default(),
    };
    let encoded = encode_cached_response_metadata(&envelope).expect("encode");
    let err = decode_cached_response_metadata(Bytes::from(encoded))
        .expect_err("6xx cache status must be rejected");
    assert!(err.to_string().contains("out of range"), "{err}");
}

#[test]
fn vary_matching_works() {
    let mut req_headers = http::HeaderMap::new();
    req_headers.insert("accept-language", http::HeaderValue::from_static("ja"));
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: Vec::new(),
        body: CachedBody::default(),
        body_len: 0,
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 30,
        vary_headers: vec!["accept-language".to_string()],
        vary_values: vec![("accept-language".to_string(), "ja".to_string())],
        header_map: Default::default(),
    };
    assert!(matches_vary(&req_headers, &envelope));
}
