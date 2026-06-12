use super::directives::{parse_request_directives, parse_response_directives};
use super::entry::{
    not_modified_from_envelope, precondition_failed_response, resolve_range,
    response_from_envelope_for_request, response_from_envelope_for_request_with_body,
};
use super::freshness::{
    active_range, conditional_not_modified, current_age_secs, precondition_failed,
};
use super::types::{
    CACHE_HEADER, CacheBackend, CacheEntryDisposition, CacheRequestKey, CachedResponseEnvelope,
    LookupOutcome, RequestDirectives, ResponseDirectives, RevalidationState,
    cache_body_storage_key, decode_cached_response_metadata,
};
use super::util::{cache_namespace, load_variant_index, now_millis};
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
    let variant_keys =
        load_candidate_variant_keys(backend.as_ref(), namespace.as_str(), key, request_method)
            .await?;
    if variant_keys.is_empty() {
        return Ok(miss_or_only_if_cached(&req));
    }

    let now = now_millis();
    let mut revalidation: Option<RevalidationState> = None;
    for (variant_key, envelope) in
        load_variant_metadata_batch(backend.as_ref(), namespace.as_str(), &variant_keys).await?
    {
        if !matches_vary(request_headers, &envelope) {
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
                    &variant_key,
                    envelope,
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
                let directives: ResponseDirectives =
                    parse_response_directives(envelope.header_map());
                let state = RevalidationState {
                    backend: backend.clone(),
                    namespace: namespace.clone(),
                    variant_key: variant_key.clone(),
                    request_method: request_method.clone(),
                    request_directives: req.clone(),
                    stale_if_error_secs: directives.stale_if_error,
                    envelope,
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
                    &variant_key,
                    state.envelope.clone(),
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
                let directives: ResponseDirectives =
                    parse_response_directives(envelope.header_map());
                revalidation = Some(RevalidationState {
                    backend: backend.clone(),
                    namespace: namespace.clone(),
                    variant_key,
                    request_method: request_method.clone(),
                    request_directives: req.clone(),
                    envelope,
                    stale_if_error_secs: directives.stale_if_error,
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
    if *request_method != Method::GET && *request_method != Method::HEAD
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
) -> Result<Vec<String>> {
    let primary = key.primary_hash();
    let mut variants = load_variant_index(backend, namespace, primary.as_str()).await?;
    if variants.variants.is_empty() && *request_method == Method::HEAD {
        let get_key = key.with_method_group("GET");
        let get_primary = get_key.primary_hash();
        let get_variants = load_variant_index(backend, namespace, get_primary.as_str()).await?;
        if !get_variants.variants.is_empty() {
            variants = get_variants;
        }
    }
    Ok(variants.variants)
}

async fn load_variant_metadata_batch(
    backend: &dyn CacheBackend,
    namespace: &str,
    variant_keys: &[String],
) -> Result<Vec<(String, CachedResponseEnvelope)>> {
    let values = backend.get_many(namespace, variant_keys).await?;
    Ok(variant_keys
        .iter()
        .cloned()
        .zip(values)
        .filter_map(|(variant_key, raw)| {
            let envelope = decode_cached_response_metadata(raw?).ok()?;
            Some((variant_key, envelope))
        })
        .collect())
}

async fn load_cached_response(
    backend: &dyn CacheBackend,
    namespace: &str,
    variant_key: &str,
    envelope: CachedResponseEnvelope,
    request_method: &Method,
    req: &RequestDirectives,
    now: u64,
) -> Result<Option<Response<Body>>> {
    let range = active_range(req, &envelope);
    let stream_range = match range {
        Some(range) => {
            let Some((start, end)) = resolve_range(range, envelope.body_len) else {
                return Ok(Some(response_from_envelope_for_request(
                    request_method,
                    req,
                    &envelope,
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
        &envelope,
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
    response
        .headers_mut()
        .insert(CACHE_HEADER, http::HeaderValue::from_static("BYPASS"));
    response
}

pub async fn maybe_build_stale_if_error_response(
    state: &RevalidationState,
) -> Option<Response<Body>> {
    let directives = parse_response_directives(state.envelope.header_map());
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
        state.envelope.clone(),
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
    let resp = parse_response_directives(envelope.header_map());
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

    if fresh && !req.no_cache && !resp.no_cache {
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
