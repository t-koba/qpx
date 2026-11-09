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
async fn disk_cache_vary_transitions_publish_the_latest_response() {
    let directory = std::env::temp_dir()
        .canonicalize()
        .expect("canonical temporary directory")
        .join(format!(
            "qpx-cache-vary-transition-{}-{}",
            std::process::id(),
            super::super::util::now_millis()
        ));
    let config = qpx_core::config::CacheBackendConfig {
        name: "b".into(),
        kind: "disk".into(),
        path: Some(directory.display().to_string()),
        max_bytes: Some(16 * 1024 * 1024),
        max_object_bytes: 1024 * 1024,
        sweep_interval_secs: 3600,
        timeout_ms: 500,
        endpoint: String::new(),
        auth_header_env: None,
    };
    let backend = Arc::new(
        crate::backend_disk::DiskCacheBackend::new(config.clone())
            .expect("create real disk backend"),
    );
    let backends = HashMap::from([("b".into(), backend.clone() as Arc<dyn CacheBackend>)]);
    let mut req = make_get_request("/vary-transition");
    req.headers_mut()
        .insert("accept-language", "en".parse().expect("language"));
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("cache key");
    for (varies, body) in [
        (false, "initial"),
        (true, "english"),
        (false, "replacement"),
    ] {
        let mut response = make_response(StatusCode::OK, "max-age=60", body);
        if varies {
            response
                .headers_mut()
                .insert(VARY, "accept-language".parse().expect("vary"));
        }
        let collapse = test_request_collapse();
        let leader = match collapse.begin(&key) {
            RequestCollapseJoin::Leader(guard) => guard,
            RequestCollapseJoin::Follower(_) => panic!("expected publication leader"),
        };
        let waiter = match collapse.begin(&key) {
            RequestCollapseJoin::Follower(waiter) => waiter,
            RequestCollapseJoin::Leader(_) => panic!("expected publication follower"),
        };
        store_and_drain(
            req.method(),
            req.headers(),
            &key,
            &policy(),
            response,
            CacheStoreTiming {
                response_delay_secs: 0,
                body_read_timeout: Duration::from_secs(2),
                request_collapse_guard: Some(leader),
            },
            &backends,
        )
        .await
        .expect("store response");
        assert!(
            waiter.wait(Duration::from_secs(2)).await,
            "disk writeback did not complete"
        );
        let restarted = Arc::new(
            crate::backend_disk::DiskCacheBackend::new(config.clone())
                .expect("restart disk backend"),
        );
        let cold_backends = HashMap::from([("b".into(), restarted as Arc<dyn CacheBackend>)]);
        for view in [&backends, &cold_backends] {
            let outcome = lookup(
                req.method(),
                req.headers(),
                &key,
                &policy(),
                view,
                &test_revalidations(),
            )
            .await
            .expect("lookup latest response");
            let LookupOutcome::Hit(response) = outcome else {
                panic!("published response was not a cache hit")
            };
            assert_eq!(
                qpx_http::body::to_bytes(response.into_body())
                    .await
                    .expect("read cached response"),
                body
            );
        }
    }
    drop(backends);
    drop(backend);
    std::fs::remove_dir_all(directory).expect("remove real cache directory");
}
