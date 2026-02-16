use super::directives::{parse_request_directives, parse_response_directives_from_vec};
use super::entry::{not_modified_from_envelope, response_from_envelope};
use super::freshness::{conditional_not_modified, current_age_secs};
use super::types::{
    CacheBackend, CacheEntryDisposition, CacheRequestKey, CachedResponseEnvelope, LookupOutcome,
    RequestDirectives, RevalidationState, CACHE_HEADER,
};
use super::util::{cache_namespace, has_validators, header_value, load_variant_index, now_millis};
use super::vary::matches_vary;
use anyhow::Result;
use http::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use hyper::{Body, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashMap;
use std::sync::Arc;

pub async fn lookup(
    request_headers: &http::HeaderMap,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<LookupOutcome> {
    if !policy.enabled {
        return Ok(LookupOutcome::Miss);
    }
    let req = parse_request_directives(request_headers);
    if req.has_unsupported_conditionals {
        return if req.only_if_cached {
            Ok(LookupOutcome::OnlyIfCachedMiss)
        } else {
            Ok(LookupOutcome::Miss)
        };
    }
    if req.no_store {
        return if req.only_if_cached {
            Ok(LookupOutcome::OnlyIfCachedMiss)
        } else {
            Ok(LookupOutcome::Miss)
        };
    }

    let Some(backend) = backends.get(policy.backend.as_str()) else {
        return Ok(LookupOutcome::Miss);
    };

    let namespace = cache_namespace(policy, "default");
    let primary = key.primary_hash();
    let variants =
        load_variant_index(backend.as_ref(), namespace.as_str(), primary.as_str()).await?;
    if variants.variants.is_empty() {
        return if req.only_if_cached {
            Ok(LookupOutcome::OnlyIfCachedMiss)
        } else {
            Ok(LookupOutcome::Miss)
        };
    }

    let now = now_millis();
    let mut revalidation: Option<RevalidationState> = None;
    for variant_key in variants.variants {
        let raw = match backend.get(namespace.as_str(), variant_key.as_str()).await {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(raw) = raw else {
            continue;
        };
        let envelope: CachedResponseEnvelope = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if !matches_vary(request_headers, &envelope) {
            continue;
        }
        let disposition = classify_for_request(&req, &envelope, now);
        match disposition {
            CacheEntryDisposition::ServeFresh => {
                if conditional_not_modified(&req, &envelope) {
                    return Ok(LookupOutcome::Hit(not_modified_from_envelope(
                        &envelope, now, "HIT", false,
                    )?));
                }
                return Ok(LookupOutcome::Hit(response_from_envelope(
                    &envelope, now, "HIT", false,
                )?));
            }
            CacheEntryDisposition::ServeStale => {
                if conditional_not_modified(&req, &envelope) {
                    return Ok(LookupOutcome::Hit(not_modified_from_envelope(
                        &envelope, now, "HIT", true,
                    )?));
                }
                return Ok(LookupOutcome::Hit(response_from_envelope(
                    &envelope, now, "HIT", true,
                )?));
            }
            CacheEntryDisposition::RequiresRevalidation => {
                if has_validators(&envelope.headers) {
                    revalidation = Some(RevalidationState {
                        namespace: namespace.clone(),
                        variant_key,
                        envelope,
                    });
                }
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

    let etag = header_value(&state.envelope.headers, ETAG.as_str());
    let last_modified = header_value(&state.envelope.headers, LAST_MODIFIED.as_str());
    let mut attached = false;

    if let Some(v) = etag {
        if let Ok(hv) = http::HeaderValue::from_str(v.as_str()) {
            request_headers.insert(IF_NONE_MATCH, hv);
            attached = true;
        }
    }
    if let Some(v) = last_modified {
        if let Ok(hv) = http::HeaderValue::from_str(v.as_str()) {
            request_headers.insert(IF_MODIFIED_SINCE, hv);
            attached = true;
        }
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

pub(super) fn classify_for_request(
    req: &RequestDirectives,
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
) -> CacheEntryDisposition {
    let resp = parse_response_directives_from_vec(&envelope.headers);
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
    }

    CacheEntryDisposition::RequiresRevalidation
}
