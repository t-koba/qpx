use crate::store::*;
use http::header::{CACHE_CONTROL, CONTENT_LENGTH, HOST};

fn test_policy() -> CachePolicyConfig {
    CachePolicyConfig {
        enabled: true,
        backend: "memory".to_string(),
        namespace: Some("tests".to_string()),
        default_ttl_secs: Some(30),
        max_object_bytes: 1024 * 1024,
        allow_set_cookie_store: false,
    }
}

#[test]
fn must_understand_allows_storage_when_status_requirements_are_understood() {
    let request = hyper::Request::builder()
        .method(Method::GET)
        .uri("http://example.com/cache")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(
            CACHE_CONTROL,
            "public, no-store, max-age=60, must-understand",
        )
        .header(CONTENT_LENGTH, "2")
        .body(Body::from("ok"))
        .expect("response");
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
    let request = hyper::Request::builder()
        .method(Method::GET)
        .uri("http://example.com/cache")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");
    let response = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(
            CACHE_CONTROL,
            "public, no-store, max-age=60, must-understand",
        )
        .header(CONTENT_LENGTH, "2")
        .body(Body::from("ok"))
        .expect("response");
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
    let request = hyper::Request::builder()
        .method(Method::GET)
        .uri("http://example.com/cache")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");
    let response = Response::builder()
        .status(StatusCode::from_u16(299).expect("status"))
        .header(
            CACHE_CONTROL,
            "public, no-store, max-age=60, must-understand",
        )
        .header(CONTENT_LENGTH, "2")
        .body(Body::from("ok"))
        .expect("response");
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

#[cfg(unix)]
#[tokio::test]
async fn obsolete_variant_cleanup_preserves_filesystem_errors() {
    let root = std::env::temp_dir()
        .canonicalize()
        .expect("canonical temporary directory")
        .join(format!(
            "qpx-obsolete-delete-{}-{}",
            std::process::id(),
            now_millis()
        ));
    let saved = root.with_extension("saved");
    let outside = root.with_extension("outside");
    let backend = Arc::new(
        crate::backend_disk::DiskCacheBackend::new(qpx_core::config::CacheBackendConfig {
            name: "disk".into(),
            kind: "disk".into(),
            endpoint: String::new(),
            path: Some(root.display().to_string()),
            max_bytes: Some(16 * 1024 * 1024),
            max_object_bytes: 1024 * 1024,
            sweep_interval_secs: 3600,
            timeout_ms: 500,
            auth_header_env: None,
        })
        .expect("create real disk backend"),
    );
    backend
        .put("tests", "old", b"metadata", 60)
        .await
        .expect("write metadata");
    let body_key = cache_body_storage_key("old");
    backend
        .put("tests", &body_key, b"body", 60)
        .await
        .expect("write body");
    std::fs::create_dir(&outside).expect("create outside directory");
    std::fs::write(outside.join("sentinel"), b"protected").expect("write outside sentinel");
    std::fs::rename(&root, &saved).expect("move real cache directory");
    std::os::unix::fs::symlink(&outside, &root).expect("replace root with symlink");
    let result =
        delete_obsolete_variants(backend.clone(), "tests".into(), vec!["old".into()]).await;
    std::fs::remove_file(&root).expect("remove replacement symlink");
    std::fs::rename(&saved, &root).expect("restore real cache directory");
    let error = result.expect_err("cleanup must return the real filesystem error");
    assert!(format!("{error:#}").contains("failed to remove disk cache object"));
    assert_eq!(
        std::fs::read(outside.join("sentinel")).expect("read outside sentinel"),
        b"protected"
    );
    assert_eq!(
        std::fs::read_dir(&outside)
            .expect("list outside directory")
            .count(),
        1
    );
    assert_eq!(
        backend
            .get("tests", "old")
            .await
            .expect("read metadata")
            .expect("retained metadata"),
        "metadata"
    );
    assert_eq!(
        backend
            .get("tests", &body_key)
            .await
            .expect("read body")
            .expect("retained body"),
        "body"
    );
    delete_obsolete_variants(backend.clone(), "tests".into(), vec!["old".into()])
        .await
        .expect("remove obsolete variant metadata and body");
    assert!(
        backend
            .get("tests", "old")
            .await
            .expect("read removed metadata")
            .is_none()
    );
    assert!(
        backend
            .get("tests", &body_key)
            .await
            .expect("read removed body")
            .is_none()
    );
    std::fs::remove_dir_all(root).expect("remove cache fixture");
    std::fs::remove_dir_all(outside).expect("remove outside fixture");
}
