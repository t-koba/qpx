use super::directives::{parse_request_directives, parse_response_directives};
use super::lookup_ops::classify_for_request;
use super::types::{
    CacheEntryDisposition, CachedResponseEnvelope, RequestDirectives, VariantIndex, VarySpec,
    CACHE_HEADER, MAX_VARIANTS_PER_PRIMARY,
};
use super::util::{cacheable_content_length, upsert_variant_with_cap};
use super::vary::{matches_vary, parse_vary};
use super::*;
use anyhow::Result;
use async_trait::async_trait;
use base64::Engine;
use http::header::{CACHE_CONTROL, DATE, VARY};
use http::header::{CONTENT_LENGTH, ETAG, HOST, IF_NONE_MATCH, SET_COOKIE, TRANSFER_ENCODING};
use http::header::WARNING;
use hyper::{Body, Method, Request, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

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
fn stale_if_error_fallback_builds_warning_response() {
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
    let warnings = response
        .headers()
        .get_all(WARNING)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>();
    assert!(warnings.iter().any(|v| v.contains("110")));
    assert!(warnings.iter().any(|v| v.contains("111")));
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
    let out = lookup(req.headers(), &key, &policy(), &backends)
        .await
        .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
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
        0,
        &backends,
    )
    .await
    .expect("store");

    let mut only_cached = make_get_request("/revalidate-only-if-cached");
    only_cached.headers_mut().insert(
        CACHE_CONTROL,
        http::HeaderValue::from_static("only-if-cached"),
    );
    let out = lookup(only_cached.headers(), &key, &policy(), &backends)
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
    let out = lookup(req.headers(), &key, &policy(), &backends)
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
        0,
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

    let out = lookup(req.headers(), &key, &policy(), &backends)
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
    let out = lookup(miss_req.headers(), &miss_key, &policy(), &backends)
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
        0,
        &backends,
    )
    .await
    .expect("store");
    let out = lookup(req.headers(), &key, &p, &backends)
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
        0,
        &backends,
    )
    .await
    .expect("store");
    let out = lookup(req.headers(), &key, &p, &backends)
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
        0,
        &backends,
    )
    .await
    .expect("store");

    let outcome = lookup(req.headers(), &key, &policy(), &backends)
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
    let refreshed =
        revalidate_not_modified(req.headers(), &policy(), not_modified, state, 0, &backends)
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
        0,
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
    let out = lookup(only_cached.headers(), &key, &policy(), &backends)
        .await
        .expect("lookup");
    assert!(matches!(out, LookupOutcome::OnlyIfCachedMiss));
}
