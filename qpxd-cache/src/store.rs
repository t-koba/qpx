use super::directives::{parse_request_directives, parse_response_directives};
use super::entry::{header_map_from_vec, merge_headers_after_304, primary_from_variant_key};
use super::freshness::{freshness_lifetime_secs, initial_age_secs};
use super::invalidate::invalidate_primary;
use super::types::{
    CACHE_HEADER, CacheBackend, CacheRequestKey, CachedBody, CachedResponseEnvelope,
    INDEX_TTL_SECS, MAX_CACHE_OBJECT_BYTES, RequestCollapseGuard, ResponseDirectives,
    RevalidationState, VarySpec, cache_body_storage_key, encode_cached_response_metadata,
};
use super::util::{
    cache_namespace, load_variant_index, now_millis, sanitize_cached_headers_for_storage,
    upsert_variant_with_cap,
};
use super::vary::{
    index_storage_key, parse_vary, variant_storage_key, vary_values_from_request_headers,
};
use anyhow::Result;
use http::header::{AUTHORIZATION, CONTENT_LOCATION, EXPIRES, SET_COOKIE};
use hyper::{Method, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use qpx_http::body::Body;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tracing::warn;

const CACHE_WRITEBACK_MIRROR_CHANNEL_CAPACITY: usize = 128;
pub struct CacheStoreTiming {
    pub response_delay_secs: u64,
    pub body_read_timeout: Duration,
    pub request_collapse_guard: Option<RequestCollapseGuard>,
}

pub async fn maybe_store(
    request_method: &Method,
    request_headers: &http::HeaderMap,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    mut response: Response<Body>,
    timing: CacheStoreTiming,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<Response<Body>> {
    if !policy.enabled {
        return Ok(response);
    }

    let req = parse_request_directives(request_headers);
    if req.no_store {
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

    let storage_key = response_storage_key(request_method, response.headers(), key)
        .unwrap_or_else(|| key.clone());
    let storage_primary = storage_key.primary_hash();
    let initial_age_secs = initial_age_secs(response.headers(), now, timing.response_delay_secs);
    let vary_values = vary_values_from_request_headers(request_headers, &vary);
    let variant_key = variant_storage_key(storage_primary.as_str(), &vary_values);
    let namespace = cache_namespace(policy, "default");
    let ttl = object_retention_ttl_secs(freshness_lifetime_secs, &resp_directives);
    let writeback = CacheWriteback {
        backend: backend.clone(),
        namespace,
        storage_primary,
        variant_key,
        status: response.status().as_u16(),
        headers: sanitize_cached_headers_for_storage(response.headers(), &resp_directives),
        stored_at_ms: now,
        initial_age_secs,
        response_delay_secs: timing.response_delay_secs,
        freshness_lifetime_secs,
        vary_headers: vary,
        vary_values,
        ttl,
        max_cacheable_body_bytes,
        body_read_timeout: timing.body_read_timeout,
        _request_collapse_guard: timing.request_collapse_guard,
    };

    let (parts, body) = response.into_parts();
    let (primary_body, mut mirrors) = qpx_http::body::tee::tee_body_lossy_with_metrics(
        body,
        vec![Some(max_cacheable_body_bytes)],
        CACHE_WRITEBACK_MIRROR_CHANNEL_CAPACITY,
        Some("cache_writeback"),
    );
    if let Some(mirror_body) = mirrors.pop() {
        tokio::spawn(async move {
            if let Err(err) = writeback.store(mirror_body).await {
                warn!(error = ?err, "cache writeback failed");
            }
        });
    } else {
        warn!("cache writeback mirror was not created");
    }
    let mut response = Response::from_parts(parts, primary_body);

    response
        .headers_mut()
        .insert(CACHE_HEADER, http::HeaderValue::from_static("MISS"));
    Ok(response)
}

struct CacheWriteback {
    backend: Arc<dyn CacheBackend>,
    namespace: String,
    storage_primary: String,
    variant_key: String,
    status: u16,
    headers: Vec<(String, String)>,
    stored_at_ms: u64,
    initial_age_secs: u64,
    response_delay_secs: u64,
    freshness_lifetime_secs: u64,
    vary_headers: Vec<String>,
    vary_values: Vec<(String, String)>,
    ttl: u64,
    max_cacheable_body_bytes: usize,
    body_read_timeout: Duration,
    _request_collapse_guard: Option<RequestCollapseGuard>,
}

impl CacheWriteback {
    async fn store(self, body: Body) -> Result<()> {
        let body_key = cache_body_storage_key(&self.variant_key);
        let body_put = self.backend.put_object_stream(
            self.namespace.as_str(),
            body_key.as_str(),
            body,
            self.max_cacheable_body_bytes,
            self.body_read_timeout,
            self.ttl,
        );
        let index_load = load_variant_index(
            self.backend.as_ref(),
            self.namespace.as_str(),
            self.storage_primary.as_str(),
        );
        let (body_len, mut index) = tokio::try_join!(body_put, index_load)?;
        record_cache_writeback_body_stream(body_len);
        let envelope = CachedResponseEnvelope {
            status: self.status,
            headers: self.headers,
            body: CachedBody::default(),
            body_len,
            stored_at_ms: self.stored_at_ms,
            initial_age_secs: self.initial_age_secs,
            response_delay_secs: self.response_delay_secs,
            freshness_lifetime_secs: self.freshness_lifetime_secs,
            vary_headers: self.vary_headers,
            vary_values: self.vary_values,
            header_map: std::sync::OnceLock::new(),
        };
        let metadata = encode_cached_response_metadata(&envelope)?;
        self.backend
            .put(
                self.namespace.as_str(),
                self.variant_key.as_str(),
                &metadata,
                self.ttl,
            )
            .await?;
        delete_obsolete_variants(
            self.backend.clone(),
            self.namespace.clone(),
            upsert_variant_with_cap(&mut index, &self.variant_key),
        )
        .await;
        let index_payload = serde_json::to_vec(&index)?;
        self.backend
            .put(
                self.namespace.as_str(),
                index_storage_key(self.storage_primary.as_str()).as_str(),
                &index_payload,
                self.ttl.max(INDEX_TTL_SECS),
            )
            .await?;
        Ok(())
    }
}

fn record_cache_writeback_body_stream(bytes: u64) {
    super::metrics::writeback_body_bytes(bytes);
}

async fn delete_obsolete_variants(
    backend: Arc<dyn CacheBackend>,
    namespace: String,
    variants: Vec<String>,
) {
    const DELETE_CONCURRENCY: usize = 16;
    for chunk in variants.chunks(DELETE_CONCURRENCY) {
        let mut tasks = JoinSet::new();
        for variant in chunk {
            let backend = backend.clone();
            let namespace = namespace.clone();
            let variant = variant.clone();
            tasks.spawn(async move {
                let _ = backend.delete(namespace.as_str(), variant.as_str()).await;
                let body_key = cache_body_storage_key(variant.as_str());
                let _ = backend.delete(namespace.as_str(), body_key.as_str()).await;
            });
        }
        while tasks.join_next().await.is_some() {}
    }
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
    let merged_header_map = header_map_from_vec(&merged_headers);
    let directives = parse_response_directives(&merged_header_map);
    let freshness = freshness_lifetime_secs(&merged_header_map, policy, now, &directives)
        .unwrap_or_else(|| policy.default_ttl_secs.unwrap_or(1));
    let vary_headers = state.envelope.vary_headers.clone();
    let initial_age_secs = initial_age_secs(&merged_header_map, now, response_delay_secs);
    let mut storable_response = Response::new(Body::empty());
    *storable_response.status_mut() = qpx_http::protocol::semantics::validate_http_status_class(
        StatusCode::from_u16(state.envelope.status)
            .map_err(|err| anyhow::anyhow!("invalid cached response status: {err}"))?,
        "cached response revalidation",
    )?;
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
            body: state.envelope.body,
            body_len: state.envelope.body_len,
            stored_at_ms: now,
            initial_age_secs,
            response_delay_secs,
            freshness_lifetime_secs: freshness,
            vary_headers: vary_headers.clone(),
            vary_values: vary_values_from_request_headers(request_headers, &vary_headers),
            header_map: std::sync::OnceLock::new(),
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
        body: state.envelope.body,
        body_len: state.envelope.body_len,
        stored_at_ms: now,
        initial_age_secs,
        response_delay_secs,
        freshness_lifetime_secs: freshness,
        vary_headers: vary_headers.clone(),
        vary_values: vary_values_from_request_headers(request_headers, &vary_headers),
        header_map: std::sync::OnceLock::new(),
    };

    let ttl = object_retention_ttl_secs(updated.freshness_lifetime_secs, &directives);
    let payload = encode_cached_response_metadata(&updated)?;
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
mod tests;
