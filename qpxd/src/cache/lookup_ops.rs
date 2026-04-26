use super::directives::{parse_request_directives, parse_response_directives_from_vec};
use super::entry::{
    not_modified_from_envelope, precondition_failed_response, response_from_envelope,
    response_from_envelope_for_request,
};
use super::freshness::{conditional_not_modified, current_age_secs, precondition_failed};
use super::types::{
    CacheBackend, CacheEntryDisposition, CacheRequestKey, CachedResponseEnvelope, LookupOutcome,
    RequestDirectives, ResponseDirectives, RevalidationState, CACHE_HEADER,
};
use super::util::{cache_namespace, header_value, load_variant_index, now_millis};
use super::vary::matches_vary;
use crate::http::body::Body;
use anyhow::Result;
use http::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use hyper::{Method, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashMap;
use std::sync::Arc;

pub async fn lookup(
    request_method: &hyper::Method,
    request_headers: &http::HeaderMap,
    key: &CacheRequestKey,
    policy: &CachePolicyConfig,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
) -> Result<LookupOutcome> {
    if !policy.enabled {
        return Ok(LookupOutcome::Miss);
    }
    let req = parse_request_directives(request_headers);
    if *request_method != Method::GET && *request_method != Method::HEAD {
        return if req.only_if_cached {
            Ok(LookupOutcome::OnlyIfCachedMiss)
        } else {
            Ok(LookupOutcome::Miss)
        };
    }
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
    let mut variants =
        load_variant_index(backend.as_ref(), namespace.as_str(), primary.as_str()).await?;
    if variants.variants.is_empty() && *request_method == Method::HEAD {
        let get_key = key.with_method_group("GET");
        let get_primary = get_key.primary_hash();
        let get_variants =
            load_variant_index(backend.as_ref(), namespace.as_str(), get_primary.as_str()).await?;
        if !get_variants.variants.is_empty() {
            variants = get_variants;
        }
    }
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
                return Ok(LookupOutcome::Hit(response_from_envelope_for_request(
                    request_method,
                    &req,
                    &envelope,
                    now,
                    "HIT",
                )?));
            }
            CacheEntryDisposition::ServeStale => {
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
                return Ok(LookupOutcome::Hit(response_from_envelope_for_request(
                    request_method,
                    &req,
                    &envelope,
                    now,
                    "HIT",
                )?));
            }
            CacheEntryDisposition::ServeStaleWhileRevalidate => {
                let directives: ResponseDirectives =
                    parse_response_directives_from_vec(&envelope.headers);
                let state = RevalidationState {
                    namespace: namespace.clone(),
                    variant_key: variant_key.clone(),
                    stale_if_error_secs: directives.stale_if_error,
                    envelope,
                };
                if precondition_failed(&req, &state.envelope) {
                    return Ok(LookupOutcome::Hit(precondition_failed_response("HIT")?));
                }
                if conditional_not_modified(&req, &state.envelope) {
                    return Ok(LookupOutcome::StaleWhileRevalidate(
                        not_modified_from_envelope(request_method, &state.envelope, now, "HIT")?,
                        state,
                    ));
                }
                return Ok(LookupOutcome::StaleWhileRevalidate(
                    response_from_envelope_for_request(
                        request_method,
                        &req,
                        &state.envelope,
                        now,
                        "HIT",
                    )?,
                    state,
                ));
            }
            CacheEntryDisposition::RequiresRevalidation => {
                let directives: ResponseDirectives =
                    parse_response_directives_from_vec(&envelope.headers);
                revalidation = Some(RevalidationState {
                    namespace: namespace.clone(),
                    variant_key,
                    envelope,
                    stale_if_error_secs: directives.stale_if_error,
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

pub fn maybe_build_stale_if_error_response(state: &RevalidationState) -> Option<Response<Body>> {
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
    response_from_envelope(&state.envelope, now, "HIT").ok()
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

        if staleness > 0 {
            if let Some(swr) = resp.stale_while_revalidate {
                if !req.no_cache && staleness <= swr {
                    // RFC 5861: allow serving stale for SWR window. For only-if-cached, do not
                    // trigger background network activity.
                    return if req.only_if_cached {
                        CacheEntryDisposition::ServeStale
                    } else {
                        CacheEntryDisposition::ServeStaleWhileRevalidate
                    };
                }
            }
        }
    }

    CacheEntryDisposition::RequiresRevalidation
}
