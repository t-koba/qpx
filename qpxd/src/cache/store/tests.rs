use crate::cache::store::*;
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
