use super::directives::{parse_request_directives, parse_response_directives};
use super::lookup_ops::classify_for_request;
use super::types::{
    CacheEntryDisposition, CachedResponseEnvelope, RequestDirectives, VariantIndex, VarySpec,
    CACHE_HEADER, MAX_VARIANTS_PER_PRIMARY,
};
use super::util::{cacheable_content_length, load_variant_index, upsert_variant_with_cap};
use super::vary::{index_storage_key, matches_vary, parse_vary, variant_storage_key};
use super::*;
use crate::cache::purge_cache_key;
use crate::http::body::Body;
use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use http::header::{CACHE_CONTROL, CONTENT_LOCATION, DATE, VARY};
use http::header::{
    CONTENT_LENGTH, ETAG, HOST, IF_MATCH, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE,
    LAST_MODIFIED, SET_COOKIE, TRANSFER_ENCODING,
};
use http::header::{CONTENT_RANGE, RANGE};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

struct MockBackend {
    map: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockBackend {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    fn key(namespace: &str, key: &str) -> String {
        format!("{}::{}", namespace, key)
    }
}

#[async_trait]
impl CacheBackend for MockBackend {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .map
            .lock()
            .expect("lock")
            .get(Self::key(namespace, key).as_str())
            .cloned())
    }

    async fn put(&self, namespace: &str, key: &str, value: &[u8], _ttl_secs: u64) -> Result<()> {
        self.map
            .lock()
            .expect("lock")
            .insert(Self::key(namespace, key), value.to_vec());
        Ok(())
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        self.map
            .lock()
            .expect("lock")
            .remove(Self::key(namespace, key).as_str());
        Ok(())
    }
}

fn policy() -> CachePolicyConfig {
    CachePolicyConfig {
        enabled: true,
        backend: "b".to_string(),
        namespace: Some("ns".to_string()),
        default_ttl_secs: Some(30),
        max_object_bytes: 1024 * 1024,
        allow_set_cookie_store: false,
    }
}

fn backend_map() -> HashMap<String, Arc<dyn CacheBackend>> {
    let mut map = HashMap::new();
    map.insert(
        "b".to_string(),
        Arc::new(MockBackend::new()) as Arc<dyn CacheBackend>,
    );
    map
}

fn make_get_request(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("http://example.com{}", path))
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request")
}

fn make_response(status: StatusCode, cache_control: &str, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CACHE_CONTROL, cache_control)
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body.to_string()))
        .expect("response")
}

#[test]
fn parse_request_directives_max_stale_and_only_if_cached() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached, max-stale=30, min-fresh=5"),
    );
    let parsed = parse_request_directives(&headers);
    assert!(parsed.only_if_cached);
    assert_eq!(parsed.max_stale, Some(Some(30)));
    assert_eq!(parsed.min_fresh, Some(5));
}

#[test]
fn parse_request_directives_invalid_max_stale_is_ignored() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("max-stale=invalid"),
    );
    let parsed = parse_request_directives(&headers);
    assert_eq!(parsed.max_stale, None);
}

#[test]
fn parse_request_directives_supports_single_byte_range() {
    let mut headers = http::HeaderMap::new();
    headers.insert(RANGE, http::HeaderValue::from_static("bytes=3-7"));
    headers.insert(IF_RANGE, http::HeaderValue::from_static("\"v1\""));
    let parsed = parse_request_directives(&headers);
    assert!(parsed.range.is_some());
    assert!(parsed.if_range.is_some());
    assert!(!parsed.has_unsupported_conditionals);
}

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
    assert!(backend
        .get(namespace.as_str(), variant.as_str())
        .await
        .expect("get variant")
        .is_none());
    assert!(backend
        .get(
            namespace.as_str(),
            index_storage_key(primary.as_str()).as_str(),
        )
        .await
        .expect("get index")
        .is_none());
}

#[tokio::test]
async fn request_collapse_notifies_followers() {
    let req = make_get_request("/collapse");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("lookup key");
    let leader = match begin_request_collapse(&key) {
        RequestCollapseJoin::Leader(guard) => guard,
        RequestCollapseJoin::Follower(_) => panic!("expected leader"),
    };
    let waiter = match begin_request_collapse(&key) {
        RequestCollapseJoin::Leader(_) => panic!("expected follower"),
        RequestCollapseJoin::Follower(waiter) => waiter,
    };
    let wait_task = tokio::spawn(async move { waiter.wait(Duration::from_millis(100)).await });
    tokio::task::yield_now().await;
    drop(leader);
    assert!(wait_task.await.expect("wait task"));
}

#[test]
fn parse_request_directives_no_cache_with_field_names() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("no-cache=\"set-cookie,authorization\""),
    );
    let parsed = parse_request_directives(&headers);
    assert!(parsed.no_cache);
}

#[test]
fn parse_response_directives_private_with_field_names() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("private=\"authorization\", max-age=60"),
    );
    let parsed = parse_response_directives(&headers);
    assert!(!parsed.private);
    assert_eq!(parsed.private_fields, vec!["authorization".to_string()]);
    assert_eq!(parsed.max_age, Some(60));
}

#[test]
fn parse_response_directives_no_cache_with_field_names() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("no-cache=\"set-cookie\""),
    );
    let parsed = parse_response_directives(&headers);
    assert!(!parsed.no_cache);
    assert_eq!(parsed.no_cache_fields, vec!["set-cookie".to_string()]);
}

#[test]
fn parse_response_directives_must_understand() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("public, max-age=60, must-understand"),
    );
    let parsed = parse_response_directives(&headers);
    assert!(parsed.must_understand);
    assert_eq!(parsed.max_age, Some(60));
}

#[test]
fn parse_response_directives_rfc5861_extensions() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("max-age=60, stale-while-revalidate=30, stale-if-error=120"),
    );
    let parsed = parse_response_directives(&headers);
    assert_eq!(parsed.max_age, Some(60));
    assert_eq!(parsed.stale_while_revalidate, Some(30));
    assert_eq!(parsed.stale_if_error, Some(120));
}

#[test]
fn parse_vary_star_is_uncacheable() {
    let mut headers = http::HeaderMap::new();
    headers.insert(VARY, http::HeaderValue::from_static("*"));
    assert!(matches!(parse_vary(&headers), VarySpec::Any));
}

#[test]
fn cacheable_content_length_rejects_chunked_transfer() {
    let mut headers = http::HeaderMap::new();
    headers.insert(CONTENT_LENGTH, http::HeaderValue::from_static("10"));
    headers.insert(TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
    assert_eq!(cacheable_content_length(&headers), None);
}

#[test]
fn cacheable_content_length_rejects_inconsistent_values() {
    let mut headers = http::HeaderMap::new();
    headers.insert(CONTENT_LENGTH, http::HeaderValue::from_static("10, 11"));
    assert_eq!(cacheable_content_length(&headers), None);
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
fn vary_matching_works() {
    let mut req_headers = http::HeaderMap::new();
    req_headers.insert("accept-language", http::HeaderValue::from_static("ja"));
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: Vec::new(),
        body_b64: String::new(),
        stored_at_ms: 0,
        initial_age_secs: 0,
        response_delay_secs: 0,
        freshness_lifetime_secs: 30,
        vary_headers: vec!["accept-language".to_string()],
        vary_values: vec![("accept-language".to_string(), "ja".to_string())],
    };
    assert!(matches_vary(&req_headers, &envelope));
}

#[test]
fn stale_can_be_served_with_max_stale() {
    let req = RequestDirectives {
        max_stale: Some(Some(60)),
        ..RequestDirectives::default()
    };
    let envelope = CachedResponseEnvelope {
        status: 200,
        headers: vec![("cache-control".to_string(), "max-age=10".to_string())],
        body_b64: String::new(),
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
        body_b64: String::new(),
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
        body_b64: String::new(),
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
fn stale_if_error_fallback_omits_obsolete_warning_headers() {
    let now = super::util::now_millis();
    let body = base64::engine::general_purpose::STANDARD.encode("hello");
    let state = RevalidationState {
        namespace: "ns".to_string(),
        variant_key: "obj:x:y".to_string(),
        stale_if_error_secs: Some(60),
        envelope: CachedResponseEnvelope {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body_b64: body,
            stored_at_ms: now.saturating_sub(40_000),
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 10,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
        },
    };
    let response = maybe_build_stale_if_error_response(&state).expect("stale response");
    assert!(response.headers().get("warning").is_none());
}

#[tokio::test]
async fn lookup_only_if_cached_miss() {
    let mut req = make_get_request("/a");
    req.headers_mut().insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached"),
    );
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let out = lookup(req.method(), req.headers(), &key, &policy(), &backends)
        .await
        .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}

#[tokio::test]
async fn head_lookup_reuses_get_cache_entry_without_body() {
    let req = make_get_request("/head-shared");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        make_response(StatusCode::OK, "public, max-age=60", "hello"),
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");

    let head_req = Request::builder()
        .method(Method::HEAD)
        .uri("http://example.com/head-shared")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("head request");
    let head_key = CacheRequestKey::for_lookup(&head_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some("5")
    );
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert!(body.is_empty());
}

#[tokio::test]
async fn cached_head_hit_preserves_stored_representation_length() {
    let head_req = Request::builder()
        .method(Method::HEAD)
        .uri("http://example.com/head-length")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("head request");
    let head_key = CacheRequestKey::for_lookup(&head_req, "http")
        .expect("key")
        .expect("some key");
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "public, max-age=60")
        .header(CONTENT_LENGTH, "123")
        .body(Body::empty())
        .expect("response");
    let backends = backend_map();
    let _ = maybe_store(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");

    let out = lookup(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(
        response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()),
        Some("123")
    );
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert!(body.is_empty());
}

#[tokio::test]
async fn head_response_does_not_poison_get_cache_entry() {
    let head_req = Request::builder()
        .method(Method::HEAD)
        .uri("http://example.com/head-only")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("head request");
    let head_key = CacheRequestKey::for_lookup(&head_req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let _ = maybe_store(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        make_response(StatusCode::OK, "public, max-age=60", ""),
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");

    let head_out = lookup(
        head_req.method(),
        head_req.headers(),
        &head_key,
        &policy(),
        &backends,
    )
    .await
    .expect("head lookup");
    assert!(matches!(head_out, LookupOutcome::Hit(_)));

    let get_req = make_get_request("/head-only");
    let get_key = CacheRequestKey::for_lookup(&get_req, "http")
        .expect("key")
        .expect("some key");
    let get_out = lookup(
        get_req.method(),
        get_req.headers(),
        &get_key,
        &policy(),
        &backends,
    )
    .await
    .expect("get lookup");
    assert!(matches!(get_out, LookupOutcome::Miss));
}

#[tokio::test]
async fn post_response_is_write_through_but_can_seed_get_when_content_location_matches() {
    let post_req = Request::builder()
        .method(Method::POST)
        .uri("http://example.com/post-cache")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");
    let post_key = CacheRequestKey::for_lookup(&post_req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let mut response = make_response(StatusCode::OK, "public, max-age=60", "posted");
    response.headers_mut().insert(
        CONTENT_LOCATION,
        http::HeaderValue::from_static("/post-cache"),
    );
    let _ = maybe_store(
        post_req.method(),
        post_req.headers(),
        &post_key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");

    let post_out = lookup(
        post_req.method(),
        post_req.headers(),
        &post_key,
        &policy(),
        &backends,
    )
    .await
    .expect("post lookup");
    assert!(matches!(post_out, LookupOutcome::Miss));

    let get_req = make_get_request("/post-cache");
    let get_key = CacheRequestKey::for_lookup(&get_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        get_req.method(),
        get_req.headers(),
        &get_key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"posted");
}

#[tokio::test]
async fn post_response_without_matching_content_location_is_not_stored() {
    let post_req = Request::builder()
        .method(Method::POST)
        .uri("http://example.com/post-no-location")
        .header(HOST, "example.com")
        .body(Body::empty())
        .expect("request");
    let post_key = CacheRequestKey::for_lookup(&post_req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let _ = maybe_store(
        post_req.method(),
        post_req.headers(),
        &post_key,
        &policy(),
        make_response(StatusCode::OK, "public, max-age=60", "posted"),
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");

    let get_req = make_get_request("/post-no-location");
    let get_key = CacheRequestKey::for_lookup(&get_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        get_req.method(),
        get_req.headers(),
        &get_key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::Miss));
}

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
    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
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
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"world");
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
    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
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
    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
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
    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
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
    )
    .await
    .expect("lookup");
    let response = match out {
        LookupOutcome::Hit(response) => response,
        _ => panic!("expected cache hit"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    let body = crate::http::body::to_bytes(response.into_body())
        .await
        .expect("body");
    assert_eq!(body.as_ref(), b"hello");
}

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
    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");

    let mut only_cached = make_get_request("/revalidate-only-if-cached");
    only_cached.headers_mut().insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached"),
    );
    let out = lookup(
        only_cached.method(),
        only_cached.headers(),
        &key,
        &policy(),
        &backends,
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}

#[tokio::test]
async fn only_if_cached_conditional_request_returns_miss_without_network() {
    let mut req = make_get_request("/conditional-only-if-cached");
    req.headers_mut().insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached"),
    );
    req.headers_mut()
        .insert(IF_NONE_MATCH, http::HeaderValue::from_static("\"etag\""));
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let backends = backend_map();
    let out = lookup(req.method(), req.headers(), &key, &policy(), &backends)
        .await
        .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}

#[tokio::test]
async fn vary_controls_cache_hits() {
    let mut req = make_get_request("/vary");
    req.headers_mut()
        .insert("accept-language", http::HeaderValue::from_static("ja"));
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let mut response = make_response(StatusCode::OK, "max-age=60", "hello");
    response
        .headers_mut()
        .insert(VARY, http::HeaderValue::from_static("accept-language"));
    let backends = backend_map();

    let stored = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
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
        Some("MISS")
    );

    let out = lookup(req.method(), req.headers(), &key, &policy(), &backends)
        .await
        .expect("lookup");
    assert!(matches!(out, LookupOutcome::Hit(_)));

    let mut miss_req = make_get_request("/vary");
    miss_req
        .headers_mut()
        .insert("accept-language", http::HeaderValue::from_static("en"));
    let miss_key = CacheRequestKey::for_lookup(&miss_req, "http")
        .expect("key")
        .expect("some key");
    let out = lookup(
        miss_req.method(),
        miss_req.headers(),
        &miss_key,
        &policy(),
        &backends,
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

    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &p,
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");
    let out = lookup(req.method(), req.headers(), &key, &p, &backends)
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

    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &p,
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");
    let out = lookup(req.method(), req.headers(), &key, &p, &backends)
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
    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
        },
        &backends,
    )
    .await
    .expect("store");

    let outcome = lookup(req.method(), req.headers(), &key, &policy(), &backends)
        .await
        .expect("lookup");
    let state = match outcome {
        LookupOutcome::Revalidate(state) => state,
        _ => panic!("expected revalidation"),
    };
    attach_revalidation_headers(req.headers_mut(), &state);
    assert!(req.headers().contains_key(IF_NONE_MATCH));

    let not_modified = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(DATE, "Tue, 02 Jan 2024 00:00:00 GMT")
        .body(Body::empty())
        .expect("304");
    let refreshed = revalidate_not_modified(
        req.method(),
        req.headers(),
        &policy(),
        not_modified,
        state,
        0,
        &backends,
    )
    .await
    .expect("revalidate");
    assert_eq!(
        refreshed
            .headers()
            .get(CACHE_HEADER)
            .and_then(|v| v.to_str().ok()),
        Some("REVALIDATED")
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
    let _ = maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_secs(1),
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
    )
    .await
    .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}

#[tokio::test]
async fn maybe_store_times_out_idle_cacheable_body() {
    let req = make_get_request("/idle-cache-body");
    let key = CacheRequestKey::for_lookup(&req, "http")
        .expect("key")
        .expect("some key");
    let (_sender, body) = Body::channel();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CACHE_CONTROL, "public, max-age=60")
        .body(body)
        .expect("response");
    let backends = backend_map();

    let err = match maybe_store(
        req.method(),
        req.headers(),
        &key,
        &policy(),
        response,
        CacheStoreTiming {
            response_delay_secs: 0,
            body_read_timeout: Duration::from_millis(10),
        },
        &backends,
    )
    .await
    {
        Ok(_) => panic!("idle cacheable body must time out"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("timed out"));
}
