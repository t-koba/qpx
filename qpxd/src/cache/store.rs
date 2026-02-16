use super::directives::{
    parse_request_directives, parse_response_directives, parse_response_directives_from_vec,
};
use super::entry::{
    header_map_from_vec, merge_headers_after_304, primary_from_variant_key, response_from_envelope,
};
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
    cache_namespace, cacheable_content_length, load_variant_index, now_millis,
    sanitize_cached_headers_for_storage, upsert_variant_with_cap,
};
use super::vary::{
    index_storage_key, parse_vary, variant_storage_key, vary_values_from_request_headers,
};
use anyhow::Result;
use base64::Engine;
use http::header::{AUTHORIZATION, SET_COOKIE};
use hyper::{Body, Method, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashMap;
use std::sync::Arc;

pub async fn maybe_store(
    request_method: &Method,
    request_headers: &http::HeaderMap,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    response: Response<Body>,
    response_delay_secs: u64,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<Response<Body>> {
    if !policy.enabled {
        return Ok(response);
    }
    if request_method != Method::GET {
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
    let Some(content_length) = cacheable_content_length(response.headers()) else {
        // Avoid unbounded buffering for unknown-length/chunked payloads.
        let mut response = response;
        response
            .headers_mut()
            .insert(CACHE_HEADER, http::HeaderValue::from_static("MISS"));
        return Ok(response);
    };
    if content_length > max_cacheable_body_bytes as u64 {
        let mut response = response;
        response
            .headers_mut()
            .insert(CACHE_HEADER, http::HeaderValue::from_static("MISS"));
        return Ok(response);
    }

    let (parts, body) = response.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await?;
    let mut response = Response::from_parts(parts, Body::from(body_bytes.clone()));

    if body_bytes.len() > max_cacheable_body_bytes {
        response
            .headers_mut()
            .insert(CACHE_HEADER, http::HeaderValue::from_static("MISS"));
        return Ok(response);
    }

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

    let initial_age_secs = initial_age_secs(response.headers(), now, response_delay_secs);
    let vary_values = vary_values_from_request_headers(request_headers, &vary);
    let variant_key = variant_storage_key(key.primary_hash().as_str(), &vary_values);
    let envelope = CachedResponseEnvelope {
        status: response.status().as_u16(),
        headers: sanitize_cached_headers_for_storage(response.headers(), &resp_directives),
        body_b64: base64::engine::general_purpose::STANDARD.encode(&body_bytes),
        stored_at_ms: now,
        initial_age_secs,
        response_delay_secs,
        freshness_lifetime_secs,
        vary_headers: vary,
        vary_values,
    };

    let payload = serde_json::to_vec(&envelope)?;
    let namespace = cache_namespace(policy, "default");
    let ttl = freshness_lifetime_secs.max(1);
    let _ = backend
        .put(namespace.as_str(), variant_key.as_str(), &payload, ttl)
        .await;

    let mut index = load_variant_index(
        backend.as_ref(),
        namespace.as_str(),
        key.primary_hash().as_str(),
    )
    .await
    .unwrap_or_default();
    let evicted = upsert_variant_with_cap(&mut index, &variant_key);
    for old in evicted {
        let _ = backend.delete(namespace.as_str(), old.as_str()).await;
    }
    let index_payload = serde_json::to_vec(&index)?;
    let _ = backend
        .put(
            namespace.as_str(),
            index_storage_key(key.primary_hash().as_str()).as_str(),
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
        &Method::GET,
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
            freshness_lifetime_secs: freshness.max(1),
            vary_headers: vary_headers.clone(),
            vary_values: vary_values_from_request_headers(request_headers, &vary_headers),
        };
        return response_from_envelope(&volatile, now, "REVALIDATED", false);
    }

    let sanitized = sanitize_cached_headers_for_storage(&merged_header_map, &directives);
    let updated = CachedResponseEnvelope {
        status: state.envelope.status,
        headers: sanitized,
        body_b64: state.envelope.body_b64,
        stored_at_ms: now,
        initial_age_secs,
        response_delay_secs,
        freshness_lifetime_secs: freshness.max(1),
        vary_headers: vary_headers.clone(),
        vary_values: vary_values_from_request_headers(request_headers, &vary_headers),
    };

    let ttl = updated.freshness_lifetime_secs.max(1);
    let payload = serde_json::to_vec(&updated)?;
    let _ = backend
        .put(
            state.namespace.as_str(),
            state.variant_key.as_str(),
            &payload,
            ttl,
        )
        .await;

    response_from_envelope(&updated, now, "REVALIDATED", false)
}

fn is_response_storable(
    request_headers: &http::HeaderMap,
    request_method: &Method,
    response: &Response<Body>,
    policy: &CachePolicyConfig,
    freshness_lifetime: Option<u64>,
    directives: &ResponseDirectives,
) -> bool {
    if request_method != Method::GET {
        return false;
    }
    let Some(ttl) = freshness_lifetime else {
        return false;
    };
    if ttl == 0 {
        return false;
    }
    if directives.no_store || (directives.private && directives.private_fields.is_empty()) {
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
    matches!(
        response.status(),
        StatusCode::OK
            | StatusCode::NON_AUTHORITATIVE_INFORMATION
            | StatusCode::NO_CONTENT
            | StatusCode::MULTIPLE_CHOICES
            | StatusCode::MOVED_PERMANENTLY
            | StatusCode::PERMANENT_REDIRECT
            | StatusCode::NOT_FOUND
            | StatusCode::METHOD_NOT_ALLOWED
            | StatusCode::GONE
            | StatusCode::URI_TOO_LONG
            | StatusCode::NOT_IMPLEMENTED
    )
}
