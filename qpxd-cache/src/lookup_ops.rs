use super::directives::parse_request_directives;
use super::entry::{
    not_modified_from_envelope, precondition_failed_response, resolve_range,
    response_from_envelope_for_request, response_from_envelope_for_request_with_body,
};
use super::freshness::{
    active_range, conditional_not_modified, current_age_secs, precondition_failed,
};
use super::types::{
    CACHE_HEADER, CacheBackend, CacheEntryDisposition, CacheRequestKey, CachedResponseEnvelope,
    LookupOutcome, RequestDirectives, RevalidationState, VariantIndex, cache_body_storage_key,
    cache_status_header,
};
use super::util::{cache_namespace, now_millis};
use super::vary::matches_vary;
use anyhow::Result;
use http::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use hyper::{Method, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use qpx_http::body::Body;
use std::collections::HashMap;
use std::sync::Arc;

pub async fn lookup(
    request_method: &hyper::Method,
    request_headers: &http::HeaderMap,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
    revalidations: &Arc<crate::InFlightRevalidations>,
) -> Result<LookupOutcome> {
    if !policy.enabled {
        return Ok(LookupOutcome::Miss);
    }
    let req = parse_request_directives(request_headers);
    if let Some(outcome) = lookup_precheck(request_method, &req) {
        return Ok(outcome);
    }

    let Some(backend) = backends.get(policy.backend.as_str()) else {
        return Ok(LookupOutcome::Miss);
    };

    let namespace = cache_namespace(policy, "default");
    let variant_index =
        load_candidate_variant_keys(backend.as_ref(), namespace.as_str(), key, request_method)
            .await?;
    if variant_index.variants.is_empty() {
        return Ok(miss_or_only_if_cached(&req));
    }
    let metadata = backend
        .get_decoded_response_metadata_many(namespace.as_str(), &variant_index.variants)
        .await?;
    if metadata.len() != variant_index.variants.len() {
        return Err(anyhow::anyhow!(
            "cache backend returned {} metadata values for {} keys",
            metadata.len(),
            variant_index.variants.len()
        ));
    }

    let now = now_millis();
    let mut revalidation: Option<RevalidationState> = None;
    for (variant_key, envelope) in variant_index.variants.iter().zip(metadata) {
        let Some(envelope) = envelope else {
            continue;
        };
        if !matches_vary(request_headers, key.content_digest.as_deref(), &envelope) {
            continue;
        }
        let disposition = classify_for_request(&req, &envelope, now);
        match disposition {
            CacheEntryDisposition::ServeFresh | CacheEntryDisposition::ServeStale => {
                if precondition_failed(&req, &envelope) {
                    return Ok(LookupOutcome::Hit(precondition_failed_response("HIT")?));
                }
                if conditional_not_modified(&req, &envelope) {
                    return Ok(LookupOutcome::Hit(not_modified_from_envelope(
                        request_method,
                        &envelope,
                        now,
                        "HIT",
                    )?));
                }
                if *request_method == Method::HEAD {
                    return Ok(LookupOutcome::Hit(response_from_envelope_for_request(
                        request_method,
                        &req,
                        &envelope,
                        now,
                        "HIT",
                    )?));
                }
                let Some(response) = load_cached_response(
                    backend.as_ref(),
                    namespace.as_str(),
                    variant_key,
                    &envelope,
                    request_method,
                    &req,
                    now,
                )
                .await?
                else {
                    continue;
                };
                return Ok(LookupOutcome::Hit(response));
            }
            CacheEntryDisposition::ServeStaleWhileRevalidate => {
                let stale_if_error_secs = envelope.response_directives().stale_if_error;
                let state = RevalidationState {
                    backend: backend.clone(),
                    namespace: namespace.clone(),
                    variant_key: variant_key.clone(),
                    request_method: request_method.clone(),
                    request_directives: req.clone(),
                    stale_if_error_secs,
                    envelope: (*envelope).clone(),
                    revalidations: revalidations.clone(),
                };
                if precondition_failed(&req, &state.envelope) {
                    return Ok(LookupOutcome::Hit(precondition_failed_response("HIT")?));
                }
                if conditional_not_modified(&req, &state.envelope) {
                    return Ok(LookupOutcome::StaleWhileRevalidate(
                        Box::new(not_modified_from_envelope(
                            request_method,
                            &state.envelope,
                            now,
                            "HIT",
                        )?),
                        state,
                    ));
                }
                if *request_method == Method::HEAD {
                    return Ok(LookupOutcome::StaleWhileRevalidate(
                        Box::new(response_from_envelope_for_request(
                            request_method,
                            &req,
                            &state.envelope,
                            now,
                            "HIT",
                        )?),
                        state,
                    ));
                }
                let Some(response) = load_cached_response(
                    backend.as_ref(),
                    namespace.as_str(),
                    variant_key,
                    &state.envelope,
                    request_method,
                    &req,
                    now,
                )
                .await?
                else {
                    continue;
                };
                return Ok(LookupOutcome::StaleWhileRevalidate(
                    Box::new(response),
                    state,
                ));
            }
            CacheEntryDisposition::RequiresRevalidation => {
                let stale_if_error_secs = envelope.response_directives().stale_if_error;
                revalidation = Some(RevalidationState {
                    backend: backend.clone(),
                    namespace: namespace.clone(),
                    variant_key: variant_key.clone(),
                    request_method: request_method.clone(),
                    request_directives: req.clone(),
                    envelope: (*envelope).clone(),
                    stale_if_error_secs,
                    revalidations: revalidations.clone(),
                });
            }
        }
    }

    if req.only_if_cached {
        return Ok(LookupOutcome::OnlyIfCachedMiss);
    }
    if let Some(state) = revalidation {
        return Ok(LookupOutcome::Revalidate(state));
    }
    Ok(LookupOutcome::Miss)
}

fn lookup_precheck(request_method: &Method, req: &RequestDirectives) -> Option<LookupOutcome> {
    if *request_method != Method::GET
        && *request_method != Method::HEAD
        && request_method.as_str() != "QUERY"
        || req.has_unsupported_conditionals
        || req.no_store
    {
        Some(miss_or_only_if_cached(req))
    } else {
        None
    }
}

fn miss_or_only_if_cached(req: &RequestDirectives) -> LookupOutcome {
    if req.only_if_cached {
        LookupOutcome::OnlyIfCachedMiss
    } else {
        LookupOutcome::Miss
    }
}

async fn load_candidate_variant_keys(
    backend: &dyn CacheBackend,
    namespace: &str,
    key: &CacheRequestKey,
    request_method: &Method,
) -> Result<Arc<VariantIndex>> {
    let primary = key.primary_hash_arc();
    let storage_key = super::vary::index_storage_key(primary.as_ref());
    let mut variants = backend
        .get_decoded_variant_index(namespace, storage_key.as_str())
        .await?
        .unwrap_or_else(|| Arc::new(VariantIndex::default()));
    if variants.variants.is_empty() && *request_method == Method::HEAD {
        let get_key = key.with_method_group("GET");
        let get_primary = get_key.primary_hash_arc();
        let get_storage_key = super::vary::index_storage_key(get_primary.as_ref());
        let get_variants = backend
            .get_decoded_variant_index(namespace, get_storage_key.as_str())
            .await?
            .unwrap_or_else(|| Arc::new(VariantIndex::default()));
        if !get_variants.variants.is_empty() {
            variants = get_variants;
        }
    }
    Ok(variants)
}

async fn load_cached_response(
    backend: &dyn CacheBackend,
    namespace: &str,
    variant_key: &str,
    envelope: &CachedResponseEnvelope,
    request_method: &Method,
    req: &RequestDirectives,
    now: u64,
) -> Result<Option<Response<Body>>> {
    let range = active_range(req, envelope);
    let stream_range = match range {
        Some(range) => {
            let Some((start, end)) = resolve_range(range, envelope.body_len) else {
                return Ok(Some(response_from_envelope_for_request(
                    request_method,
                    req,
                    envelope,
                    now,
                    "HIT",
                )?));
            };
            Some((start, end.min(envelope.body_len.saturating_sub(1))))
        }
        None => None,
    };
    let Some(body) = backend
        .get_object_stream(
            namespace,
            cache_body_storage_key(variant_key).as_str(),
            envelope.body_len,
            stream_range,
        )
        .await?
    else {
        return Ok(None);
    };
    Ok(Some(response_from_envelope_for_request_with_body(
        request_method,
        req,
        envelope,
        now,
        "HIT",
        body.body,
        body.len,
    )?))
}

pub fn attach_revalidation_headers(
    request_headers: &mut http::HeaderMap,
    state: &RevalidationState,
) -> bool {
    // Do not override client-supplied conditions; they are end-to-end semantics.
    if request_headers.contains_key(IF_NONE_MATCH)
        || request_headers.contains_key(IF_MODIFIED_SINCE)
    {
        return false;
    }

    let etag = state.envelope.header_str(&ETAG);
    let last_modified = state.envelope.header_str(&LAST_MODIFIED);
    let mut attached = false;

    if let Some(v) = etag
        && let Ok(hv) = http::HeaderValue::from_str(v)
    {
        request_headers.insert(IF_NONE_MATCH, hv);
        attached = true;
    }
    if let Some(v) = last_modified
        && let Ok(hv) = http::HeaderValue::from_str(v)
    {
        request_headers.insert(IF_MODIFIED_SINCE, hv);
        attached = true;
    }
    attached
}

pub fn build_only_if_cached_miss_response(message: &str) -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::GATEWAY_TIMEOUT)
        .body(Body::from(message.to_owned()))
        .unwrap_or_else(|_| Response::new(Body::from(message.to_owned())));
    response.headers_mut().insert(
        CACHE_HEADER,
        cache_status_header("BYPASS", None)
            .expect("the static bypass Cache-Status value must be valid"),
    );
    response
}

pub async fn maybe_build_stale_if_error_response(
    state: &RevalidationState,
) -> Option<Response<Body>> {
    let directives = state.envelope.response_directives();
    if directives.must_revalidate || directives.proxy_revalidate {
        return None;
    }
    let limit = state.stale_if_error_secs?;
    let now = now_millis();
    let age = current_age_secs(&state.envelope, now);
    let freshness = state.envelope.freshness_lifetime_secs;
    if age <= freshness {
        return None;
    }
    let staleness = age.saturating_sub(freshness);
    if staleness == 0 || staleness > limit {
        return None;
    }
    if state.request_method == Method::HEAD {
        return response_from_envelope_for_request(
            &state.request_method,
            &state.request_directives,
            &state.envelope,
            now,
            "HIT",
        )
        .ok();
    }
    load_cached_response(
        state.backend.as_ref(),
        state.namespace.as_str(),
        state.variant_key.as_str(),
        &state.envelope,
        &state.request_method,
        &state.request_directives,
        now,
    )
    .await
    .ok()
    .flatten()
}

pub fn classify_for_request(
    req: &RequestDirectives,
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
) -> CacheEntryDisposition {
    let resp = envelope.response_directives();
    let age = current_age_secs(envelope, now_ms);
    let freshness = envelope.freshness_lifetime_secs;
    let fresh_by_age = age <= freshness;
    let fresh_by_req = match req.max_age {
        Some(max_age) => age <= max_age,
        None => true,
    };
    let fresh_by_min_fresh = match req.min_fresh {
        Some(min_fresh) => age.saturating_add(min_fresh) <= freshness,
        None => true,
    };
    let fresh = fresh_by_age && fresh_by_req && fresh_by_min_fresh;

    if fresh && (!req.no_cache || resp.immutable) && !resp.no_cache {
        return CacheEntryDisposition::ServeFresh;
    }

    if !fresh {
        let staleness = age.saturating_sub(freshness);
        let can_serve_stale = !req.no_cache
            && !resp.no_cache
            && !resp.must_revalidate
            && !resp.proxy_revalidate
            && match req.max_stale {
                Some(None) => true,
                Some(Some(limit)) => staleness <= limit,
                None => false,
            };
        if can_serve_stale {
            return CacheEntryDisposition::ServeStale;
        }

        if staleness > 0
            && let Some(swr) = resp.stale_while_revalidate
            && !req.no_cache
            && !resp.must_revalidate
            && !resp.proxy_revalidate
            && staleness <= swr
        {
            // RFC 5861: allow serving stale for SWR window. For only-if-cached, do not
            // trigger background network activity.
            return if req.only_if_cached {
                CacheEntryDisposition::ServeStale
            } else {
                CacheEntryDisposition::ServeStaleWhileRevalidate
            };
        }
    }

    CacheEntryDisposition::RequiresRevalidation
}
