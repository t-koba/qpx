use crate::store::*;
use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, HOST};

fn test_policy() -> CachePolicyConfig {
    CachePolicyConfig {
        enabled: true,
        backend: "memory".to_string(),
        namespace: Some("tests".to_string()),
        default_ttl_secs: Some(30),
        max_object_bytes: 1024 * 1024,
        allow_set_cookie_store: false,
        allow_authorization_without_vary_store: false,
    }
}

#[test]
fn must_understand_allows_storage_when_status_requirements_are_understood() {
    let request = qpx_core::http_message::Request::from_http(
        hyper::Request::builder()
            .method(Method::GET)
            .uri("http://example.com/cache")
            .header(HOST, "example.com")
            .body(())
            .expect("request"),
    );
    let response = qpx_core::http_message::Response::from_http(
        http::Response::builder()
            .status(StatusCode::OK)
            .header(
                CACHE_CONTROL,
                "public, no-store, max-age=60, must-understand",
            )
            .header(CONTENT_LENGTH, "2")
            .body(Body::from("ok"))
            .expect("response"),
    );
    let directives = parse_response_directives(response.headers());
    assert!(directives.must_understand);
    assert!(is_response_storable(
        request.headers(),
        request.method(),
        None,
        &response,
        &test_policy(),
        Some(60),
        &directives,
    ));
}

#[test]
fn must_understand_rejects_statuses_with_unimplemented_storage_requirements() {
    let request = qpx_core::http_message::Request::from_http(
        hyper::Request::builder()
            .method(Method::GET)
            .uri("http://example.com/cache")
            .header(HOST, "example.com")
            .body(())
            .expect("request"),
    );
    let response = qpx_core::http_message::Response::from_http(
        http::Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(
                CACHE_CONTROL,
                "public, no-store, max-age=60, must-understand",
            )
            .header(CONTENT_LENGTH, "2")
            .body(Body::from("ok"))
            .expect("response"),
    );
    let directives = parse_response_directives(response.headers());
    assert!(directives.must_understand);
    assert!(!is_response_storable(
        request.headers(),
        request.method(),
        None,
        &response,
        &test_policy(),
        Some(60),
        &directives,
    ));
}

#[test]
fn must_understand_rejects_unknown_final_status_codes() {
    let request = qpx_core::http_message::Request::from_http(
        hyper::Request::builder()
            .method(Method::GET)
            .uri("http://example.com/cache")
            .header(HOST, "example.com")
            .body(())
            .expect("request"),
    );
    let response = qpx_core::http_message::Response::from_http(
        http::Response::builder()
            .status(StatusCode::from_u16(299).expect("status"))
            .header(
                CACHE_CONTROL,
                "public, no-store, max-age=60, must-understand",
            )
            .header(CONTENT_LENGTH, "2")
            .body(Body::from("ok"))
            .expect("response"),
    );
    let directives = parse_response_directives(response.headers());
    assert!(directives.must_understand);
    assert!(!is_response_storable(
        request.headers(),
        request.method(),
        None,
        &response,
        &test_policy(),
        Some(60),
        &directives,
    ));
}

#[test]
fn body_length_expectation_matches_no_body_response_semantics() {
    let mut headers = http::HeaderMap::new();
    headers.insert(CONTENT_LENGTH, http::HeaderValue::from_static("123"));
    for (method, status) in [
        (Method::HEAD, StatusCode::OK),
        (Method::GET, StatusCode::CONTINUE),
        (Method::GET, StatusCode::SWITCHING_PROTOCOLS),
        (Method::GET, StatusCode::NO_CONTENT),
        (Method::GET, StatusCode::RESET_CONTENT),
        (Method::GET, StatusCode::NOT_MODIFIED),
        (Method::CONNECT, StatusCode::OK),
        (Method::CONNECT, StatusCode::CREATED),
    ] {
        assert_eq!(
            expected_body_length(&method, status, &crate::tests::owned_headers(&headers)).unwrap(),
            None
        );
    }
    assert_eq!(
        expected_body_length(
            &Method::GET,
            StatusCode::OK,
            &crate::tests::owned_headers(&headers)
        )
        .unwrap(),
        Some(123)
    );
    assert_eq!(
        expected_body_length(
            &Method::CONNECT,
            StatusCode::FORBIDDEN,
            &crate::tests::owned_headers(&headers)
        )
        .unwrap(),
        Some(123)
    );
}

#[test]
fn body_length_expectation_rejects_a_declaration_the_owner_refuses() {
    let mut conflicting = http::HeaderMap::new();
    conflicting.append(CONTENT_LENGTH, http::HeaderValue::from_static("4"));
    conflicting.append(CONTENT_LENGTH, http::HeaderValue::from_static("5"));
    assert!(
        expected_body_length(
            &Method::GET,
            StatusCode::OK,
            &crate::tests::owned_headers(&conflicting)
        )
        .is_err()
    );

    let mut member = http::HeaderMap::new();
    member.insert(CONTENT_LENGTH, http::HeaderValue::from_static("+4"));
    assert!(
        expected_body_length(
            &Method::GET,
            StatusCode::OK,
            &crate::tests::owned_headers(&member)
        )
        .is_err()
    );

    let mut list = http::HeaderMap::new();
    list.insert(CONTENT_LENGTH, http::HeaderValue::from_static("4, 4"));
    assert_eq!(
        expected_body_length(
            &Method::GET,
            StatusCode::OK,
            &crate::tests::owned_headers(&list)
        )
        .unwrap(),
        Some(4)
    );
}

#[tokio::test]
async fn length_checked_body_validates_terminal_frames_and_preserves_source_errors() {
    use hyper::body::Body as _;
    for source in [
        Body::empty(),
        Body::replay(Bytes::new(), Some(http::HeaderMap::new())),
    ] {
        let mut checked = validate_body_length(source, Some(1));
        assert!(
            !checked.is_end_stream(),
            "must poll EOF even for an empty source"
        );
        assert_eq!(checked.size_hint().exact(), None);
        assert!(checked.data().await.unwrap().is_err());
    }
    let checked = validate_body_length(
        Body::replay(Bytes::from_static(b"ok"), Some(http::HeaderMap::new())),
        Some(2),
    );
    assert_eq!(qpx_http::body::to_bytes(checked).await.unwrap(), "ok");

    let (mut sender, source) = Body::channel();
    sender.abort();
    let mut checked = validate_body_length(source, Some(0));
    assert!(
        checked.data().await.unwrap().is_err(),
        "source errors must not become EOF"
    );
}

#[test]
fn refreshed_selectors_preserve_query_digest_and_fail_closed_on_obs_text() {
    use qpx_core::http_message::Headers as OwnedHeaders;
    let fields = vec!["content-length".to_owned()];
    let mut headers = OwnedHeaders::new();
    headers.set_content_length_value(http::HeaderValue::from_static("05"));
    let previous = cache_vary_values(headers.view(), &fields, Some("digest-a")).unwrap();
    headers.set_content_length_value(http::HeaderValue::from_static("5"));
    let refreshed = refreshed_vary_values(headers.view(), &fields, &previous).unwrap();
    assert_eq!(
        refreshed,
        cache_vary_values(headers.view(), &fields, Some("digest-a")).unwrap()
    );
    assert_ne!(refreshed, previous);
    headers.append_content_length_value(http::HeaderValue::from_bytes(&[0x80]).unwrap());
    assert!(refreshed_vary_values(headers.view(), &fields, &previous).is_none());
    headers = OwnedHeaders::new();
    assert_eq!(
        refreshed_vary_values(headers.view(), &[], &previous),
        Some(vec![previous[1].clone()])
    );
}

// Normal stores use immutable generation keys, including Vary-less stores.
// Exercise the canonical-key writeback guard directly without weakening that
// ownership: replacing the canonical object must never retire the new object.
#[tokio::test]
async fn canonical_writeback_remains_available_after_index_eviction() {
    for disk in [false, true] {
        let root = std::env::temp_dir().join(format!("qpx-canonical-{}", uuid::Uuid::new_v4()));
        let backend: Arc<dyn CacheBackend> = if disk {
            Arc::new(
                crate::backend_disk::DiskCacheBackend::new(qpx_core::config::CacheBackendConfig {
                    writer_mode: Default::default(),
                    commit_lock_stripes: 64,
                    name: "memory".into(),
                    kind: "disk".into(),
                    endpoint: String::new(),
                    path: Some(root.display().to_string()),
                    max_bytes: Some(1024 * 1024),
                    sweep_interval_secs: 60,
                    timeout_ms: 1000,
                    max_object_bytes: 1024,
                    auth_header_env: None,
                })
                .unwrap(),
            )
        } else {
            Arc::new(crate::tests::MockBackend::new())
        };
        let request = OwnerRequest::from_http(
            http::Request::builder()
                .uri("http://example.com/canonical")
                .header(HOST, "example.com")
                .body(())
                .unwrap(),
        );
        let key = CacheRequestKey::for_lookup(&request, "http")
            .unwrap()
            .unwrap();
        let policy = test_policy();
        let namespace = cache_namespace(&policy, "default");
        let canonical = variant_storage_key(&key.primary_hash(), &[]);
        for body in ["old", "new"] {
            let admission = CacheWritebackAdmission::with_default_capacity();
            CacheWriteback {
                backend: backend.clone(),
                namespace: namespace.into(),
                storage_primary: key.primary_hash_arc(),
                variant_key: canonical.clone(),
                status: 200,
                headers: CachedHeaders::from_pairs(vec![(
                    "cache-control".into(),
                    "public, max-age=60".into(),
                )]),
                stored_at_ms: now_millis(),
                initial_age_secs: 0,
                response_delay_secs: 0,
                freshness_lifetime_secs: 60,
                vary_headers: Vec::new(),
                vary_values: Vec::new(),
                ttl: 60,
                max_cacheable_body_bytes: 1024,
                body_read_timeout: Duration::from_secs(1),
                _request_collapse_guard: None,
                _writeback_permit: admission.try_acquire().unwrap(),
            }
            .store(Body::from(body))
            .await
            .unwrap();
        }
        backend
            .delete(namespace, &index_storage_key(&key.primary_hash()))
            .await
            .unwrap();
        let backends = HashMap::from([("memory".into(), backend)]);
        let revalidations = Arc::new(crate::types::InFlightRevalidations::with_default_shards());
        let crate::LookupOutcome::Hit(response) =
            crate::lookup(&request, &key, &policy, &backends, &revalidations)
                .await
                .unwrap()
        else {
            panic!("canonical replacement must hit")
        };
        assert_eq!(
            qpx_http::body::to_bytes(response.into_head_and_body().1)
                .await
                .unwrap(),
            "new"
        );
        if disk {
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
