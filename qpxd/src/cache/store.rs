use super::directives::{
    parse_request_directives, parse_response_directives, parse_response_directives_from_vec,
};
use super::entry::{header_map_from_vec, merge_headers_after_304, primary_from_variant_key};
use super::freshness::{
    freshness_lifetime_secs, freshness_lifetime_secs_from_vec, initial_age_secs,
    initial_age_secs_from_vec,
};
use super::invalidate::invalidate_primary;
use super::types::{
    CacheBackend, CacheRequestKey, CachedResponseEnvelope, ResponseDirectives, RevalidationState,
    VarySpec, CACHE_HEADER, INDEX_TTL_SECS, MAX_CACHE_OBJECT_BYTES,
};
use super::util::{
    cache_namespace, load_variant_index, now_millis, sanitize_cached_headers_for_storage,
    upsert_variant_with_cap,
};
use super::vary::{
    index_storage_key, parse_vary, variant_storage_key, vary_values_from_request_headers,
};
use crate::http::body::Body;
use anyhow::Result;
use base64::Engine;
use http::header::{AUTHORIZATION, CONTENT_LOCATION, EXPIRES, SET_COOKIE};
use hyper::{Method, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

pub struct CacheStoreTiming {
    pub response_delay_secs: u64,
    pub body_read_timeout: Duration,
}

async fn collect_body_limited(
    mut body: Body,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<bytes::Bytes> {
    use bytes::BytesMut;
    let mut out = BytesMut::new();
    while let Some(chunk) = timeout(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow::anyhow!("cache object body read timed out"))?
    {
        let chunk = chunk?;
        let next = out
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("cache object length overflow"))?;
        if next > max_body_bytes {
            return Err(anyhow::anyhow!(
                "cache object exceeds configured limit: {} bytes",
                max_body_bytes
            ));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out.freeze())
}

pub async fn maybe_store(
    request_method: &Method,
    request_headers: &http::HeaderMap,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    response: Response<Body>,
    timing: CacheStoreTiming,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<Response<Body>> {
    if !policy.enabled {
        return Ok(response);
    }

    let req = parse_request_directives(request_headers);
    if req.no_store {
        let mut response = response;
        response
            .headers_mut()
            .insert(CACHE_HEADER, http::HeaderValue::from_static("BYPASS"));
        return Ok(response);
    }

    let Some(backend) = backends.get(policy.backend.as_str()) else {
        return Ok(response);
    };

    let now = now_millis();
    let resp_directives = parse_response_directives(response.headers());
    let freshness = freshness_lifetime_secs(response.headers(), policy, now, &resp_directives);
    let is_storable = is_response_storable(
        request_headers,
        request_method,
        Some(key),
        &response,
        policy,
        freshness,
        &resp_directives,
    );

    let max_cacheable_body_bytes = policy.max_object_bytes.min(MAX_CACHE_OBJECT_BYTES);
    if !is_storable {
        let mut response = response;
        response
            .headers_mut()
            .insert(CACHE_HEADER, http::HeaderValue::from_static("MISS"));
        return Ok(response);
    }
    let (parts, body) = response.into_parts();
    let body_bytes =
        collect_body_limited(body, max_cacheable_body_bytes, timing.body_read_timeout).await?;
    let mut response = Response::from_parts(parts, Body::from(body_bytes.clone()));

    let vary = parse_vary(response.headers());
    let vary = match vary {
        VarySpec::Any => {
            response
                .headers_mut()
                .insert(CACHE_HEADER, http::HeaderValue::from_static("MISS"));
            return Ok(response);
        }
        VarySpec::Fields(v) => v,
    };

    let Some(freshness_lifetime_secs) = freshness else {
        response
            .headers_mut()
            .insert(CACHE_HEADER, http::HeaderValue::from_static("MISS"));
        return Ok(response);
    };

    let storage_key = response_storage_key(request_method, response.headers(), key)
        .unwrap_or_else(|| key.clone());
    let storage_primary = storage_key.primary_hash();
    let initial_age_secs = initial_age_secs(response.headers(), now, timing.response_delay_secs);
    let vary_values = vary_values_from_request_headers(request_headers, &vary);
    let variant_key = variant_storage_key(storage_primary.as_str(), &vary_values);
    let envelope = CachedResponseEnvelope {
        status: response.status().as_u16(),
        headers: sanitize_cached_headers_for_storage(response.headers(), &resp_directives),
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body_bytes),
        stored_at_ms: now,
        initial_age_secs,
        response_delay_secs: timing.response_delay_secs,
        freshness_lifetime_secs,
        vary_headers: vary,
        vary_values,
    };

    let payload = serde_json::to_vec(&envelope)?;
    let namespace = cache_namespace(policy, "default");
    let ttl = object_retention_ttl_secs(freshness_lifetime_secs, &resp_directives);
    let _ = backend
        .put(namespace.as_str(), variant_key.as_str(), &payload, ttl)
        .await;

    let mut index = load_variant_index(
        backend.as_ref(),
        namespace.as_str(),
        storage_primary.as_str(),
    )
    .await?;
    let evicted = upsert_variant_with_cap(&mut index, &variant_key);
    for old in evicted {
        let _ = backend.delete(namespace.as_str(), old.as_str()).await;
    }
    let index_payload = serde_json::to_vec(&index)?;
    let _ = backend
        .put(
            namespace.as_str(),
            index_storage_key(storage_primary.as_str()).as_str(),
            &index_payload,
            ttl.max(INDEX_TTL_SECS),
        )
        .await;

    response
        .headers_mut()
        .insert(CACHE_HEADER, http::HeaderValue::from_static("MISS"));
    Ok(response)
}

pub async fn revalidate_not_modified(
    request_method: &Method,
    request_headers: &http::HeaderMap,
    policy: &CachePolicyConfig,
    not_modified: Response<Body>,
    state: RevalidationState,
    response_delay_secs: u64,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<Response<Body>> {
    if !policy.enabled {
        return Ok(not_modified);
    }
    let Some(backend) = backends.get(policy.backend.as_str()) else {
        return Ok(not_modified);
    };

    let now = now_millis();
    let merged_headers = merge_headers_after_304(&state.envelope.headers, not_modified.headers());
    let directives = parse_response_directives_from_vec(&merged_headers);
    let freshness = freshness_lifetime_secs_from_vec(&merged_headers, policy, now, &directives)
        .unwrap_or_else(|| policy.default_ttl_secs.unwrap_or(1));
    let vary_headers = state.envelope.vary_headers.clone();
    let initial_age_secs = initial_age_secs_from_vec(&merged_headers, now, response_delay_secs);

    let merged_header_map = header_map_from_vec(&merged_headers);
    let mut storable_response = Response::new(Body::empty());
    *storable_response.status_mut() =
        StatusCode::from_u16(state.envelope.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    *storable_response.headers_mut() = merged_header_map.clone();

    if !is_response_storable(
        request_headers,
        request_method,
        None,
        &storable_response,
        policy,
        Some(freshness),
        &directives,
    ) {
        // The representation is no longer storable (e.g. new no-store/private). Purge it.
        if let Some(primary) = primary_from_variant_key(state.variant_key.as_str()) {
            let _ = invalidate_primary(backend.as_ref(), state.namespace.as_str(), primary).await;
        } else {
            let _ = backend
                .delete(state.namespace.as_str(), state.variant_key.as_str())
                .await;
        }
        let volatile = CachedResponseEnvelope {
            status: state.envelope.status,
            headers: merged_headers,
            body_b64: state.envelope.body_b64,
            stored_at_ms: now,
            initial_age_secs,
            response_delay_secs,
            freshness_lifetime_secs: freshness,
            vary_headers: vary_headers.clone(),
            vary_values: vary_values_from_request_headers(request_headers, &vary_headers),
        };
        return super::entry::response_from_envelope_for_request(
            request_method,
            &parse_request_directives(request_headers),
            &volatile,
            now,
            "REVALIDATED",
        );
    }

    let sanitized = sanitize_cached_headers_for_storage(&merged_header_map, &directives);
    let updated = CachedResponseEnvelope {
        status: state.envelope.status,
        headers: sanitized,
        body_b64: state.envelope.body_b64,
        stored_at_ms: now,
        initial_age_secs,
        response_delay_secs,
        freshness_lifetime_secs: freshness,
        vary_headers: vary_headers.clone(),
        vary_values: vary_values_from_request_headers(request_headers, &vary_headers),
    };

    let ttl = object_retention_ttl_secs(updated.freshness_lifetime_secs, &directives);
    let payload = serde_json::to_vec(&updated)?;
    let _ = backend
        .put(
            state.namespace.as_str(),
            state.variant_key.as_str(),
            &payload,
            ttl,
        )
        .await;

    super::entry::response_from_envelope_for_request(
        request_method,
        &parse_request_directives(request_headers),
        &updated,
        now,
        "REVALIDATED",
    )
}

fn object_retention_ttl_secs(freshness_lifetime_secs: u64, directives: &ResponseDirectives) -> u64 {
    let extra = directives
        .stale_while_revalidate
        .unwrap_or(0)
        .max(directives.stale_if_error.unwrap_or(0));
    freshness_lifetime_secs.saturating_add(extra).max(1)
}

fn is_response_storable(
    request_headers: &http::HeaderMap,
    request_method: &Method,
    key: Option<&CacheRequestKey>,
    response: &Response<Body>,
    policy: &CachePolicyConfig,
    freshness_lifetime: Option<u64>,
    directives: &ResponseDirectives,
) -> bool {
    if freshness_lifetime.is_none() {
        return false;
    };
    let understands_status_requirements =
        cache_understands_status_storage_requirements(response.status());
    if directives.must_understand && !understands_status_requirements {
        return false;
    }
    if (directives.no_store && !(directives.must_understand && understands_status_requirements))
        || (directives.private && directives.private_fields.is_empty())
    {
        return false;
    }
    if response.headers().contains_key(SET_COOKIE) {
        if !policy.allow_set_cookie_store {
            return false;
        }
        if !directives.public {
            return false;
        }
        match parse_vary(response.headers()) {
            VarySpec::Fields(fields) if fields.iter().any(|name| name == "cookie") => {}
            _ => return false,
        }
    }
    if request_headers.contains_key(AUTHORIZATION)
        && !(directives.public
            || directives.s_maxage.is_some()
            || directives.must_revalidate
            || directives.proxy_revalidate)
    {
        return false;
    }
    if response.status().is_informational() {
        return false;
    }
    if response.status() == StatusCode::PARTIAL_CONTENT {
        return false;
    }
    match *request_method {
        Method::GET | Method::HEAD => true,
        Method::POST | Method::PATCH => {
            has_explicit_freshness(response.headers(), directives)
                && key
                    .map(|key| content_location_matches_target(response.headers(), key))
                    .unwrap_or(false)
        }
        _ => false,
    }
}

fn response_storage_key(
    request_method: &Method,
    response_headers: &http::HeaderMap,
    key: &CacheRequestKey,
) -> Option<CacheRequestKey> {
    match *request_method {
        Method::GET | Method::HEAD => Some(key.clone()),
        Method::POST | Method::PATCH if content_location_matches_target(response_headers, key) => {
            Some(key.with_method_group("GET"))
        }
        _ => None,
    }
}

fn has_explicit_freshness(
    response_headers: &http::HeaderMap,
    directives: &ResponseDirectives,
) -> bool {
    directives.s_maxage.is_some()
        || directives.max_age.is_some()
        || response_headers.contains_key(EXPIRES)
}

fn content_location_matches_target(
    response_headers: &http::HeaderMap,
    key: &CacheRequestKey,
) -> bool {
    let Some(raw) = response_headers
        .get(CONTENT_LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    let Some(base) = key.absolute_url() else {
        return false;
    };
    let Ok(resolved) = base.join(raw) else {
        return false;
    };
    if resolved.fragment().is_some() {
        return false;
    }
    let Some(authority) = super::key::normalize_url_authority(&resolved) else {
        return false;
    };
    resolved.scheme().eq_ignore_ascii_case(key.scheme.as_str())
        && authority == key.authority
        && resolved.path() == base.path()
        && resolved.query() == base.query()
}

fn cache_understands_status_storage_requirements(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::OK
            | StatusCode::CREATED
            | StatusCode::ACCEPTED
            | StatusCode::NON_AUTHORITATIVE_INFORMATION
            | StatusCode::NO_CONTENT
            | StatusCode::RESET_CONTENT
            | StatusCode::MULTI_STATUS
            | StatusCode::ALREADY_REPORTED
            | StatusCode::MULTIPLE_CHOICES
            | StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
            | StatusCode::BAD_REQUEST
            | StatusCode::UNAUTHORIZED
            | StatusCode::PAYMENT_REQUIRED
            | StatusCode::FORBIDDEN
            | StatusCode::NOT_FOUND
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::NOT_ACCEPTABLE
            | StatusCode::PROXY_AUTHENTICATION_REQUIRED
            | StatusCode::REQUEST_TIMEOUT
            | StatusCode::CONFLICT
            | StatusCode::GONE
            | StatusCode::LENGTH_REQUIRED
            | StatusCode::PRECONDITION_FAILED
            | StatusCode::PAYLOAD_TOO_LARGE
            | StatusCode::URI_TOO_LONG
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::RANGE_NOT_SATISFIABLE
            | StatusCode::EXPECTATION_FAILED
            | StatusCode::MISDIRECTED_REQUEST
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::LOCKED
            | StatusCode::FAILED_DEPENDENCY
            | StatusCode::UPGRADE_REQUIRED
            | StatusCode::PRECONDITION_REQUIRED
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            | StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::NOT_IMPLEMENTED
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
            | StatusCode::HTTP_VERSION_NOT_SUPPORTED
            | StatusCode::VARIANT_ALSO_NEGOTIATES
            | StatusCode::INSUFFICIENT_STORAGE
            | StatusCode::LOOP_DETECTED
            | StatusCode::NOT_EXTENDED
            | StatusCode::NETWORK_AUTHENTICATION_REQUIRED
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
