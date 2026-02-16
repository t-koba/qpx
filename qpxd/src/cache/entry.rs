use super::freshness::current_age_secs;
use super::types::{CachedResponseEnvelope, CACHE_HEADER, CACHE_WARNING_STALE};
use anyhow::Result;
use base64::Engine;
use http::header::{AGE, WARNING};
use hyper::{Body, Method, Response, StatusCode};
use std::collections::HashSet;

pub(super) fn header_map_from_vec(headers: &[(String, String)]) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in headers {
        let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::from_str(value.as_str()) else {
            continue;
        };
        out.append(name, value);
    }
    out
}

pub(super) fn primary_from_variant_key(variant_key: &str) -> Option<&str> {
    let rest = variant_key.strip_prefix("obj:")?;
    rest.split(':').next()
}

pub(super) fn response_from_envelope(
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
    is_stale: bool,
) -> Result<Response<Body>> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(envelope.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (name, value) in &envelope.headers {
        let Ok(header_name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        if header_name == AGE {
            continue;
        }
        let Ok(header_value) = http::HeaderValue::from_str(value) else {
            continue;
        };
        builder = builder.header(header_name, header_value);
    }
    let body = base64::engine::general_purpose::STANDARD.decode(&envelope.body_b64)?;
    let mut response = builder.body(Body::from(body))?;
    let age = current_age_secs(envelope, now_ms).to_string();
    if let Ok(age_header) = http::HeaderValue::from_str(age.as_str()) {
        response.headers_mut().insert(AGE, age_header);
    }
    response
        .headers_mut()
        .insert(CACHE_HEADER, http::HeaderValue::from_static(cache_state));
    if is_stale {
        response
            .headers_mut()
            .append(WARNING, http::HeaderValue::from_static(CACHE_WARNING_STALE));
    }
    Ok(response)
}

pub(super) fn not_modified_from_envelope(
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
    is_stale: bool,
) -> Result<Response<Body>> {
    let mut response = response_from_envelope(envelope, now_ms, cache_state, is_stale)?;
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    crate::http::semantics::normalize_response_for_request(&Method::GET, &mut response);
    Ok(response)
}

pub(super) fn merge_headers_after_304(
    cached_headers: &[(String, String)],
    not_modified_headers: &http::HeaderMap,
) -> Vec<(String, String)> {
    // RFC 9111: only update the stored headers with a constrained set of fields from the 304.
    // This avoids persisting representation-specific fields that should not change on a 304.
    let mut nm = std::collections::HashMap::<String, Vec<String>>::new();
    for (name, value) in not_modified_headers {
        let lower = name.as_str().to_ascii_lowercase();
        if crate::http::semantics::is_hop_by_hop_header_name(lower.as_str()) {
            continue;
        }
        if !is_304_mergeable_header(lower.as_str()) {
            continue;
        }
        let Ok(value) = value.to_str() else {
            continue;
        };
        nm.entry(lower).or_default().push(value.to_string());
    }

    let mut out = Vec::new();
    let mut replaced = HashSet::new();
    let mut saw = HashSet::new();

    for (name, value) in cached_headers {
        let lower = name.to_ascii_lowercase();
        if crate::http::semantics::is_hop_by_hop_header_name(lower.as_str()) {
            continue;
        }
        saw.insert(lower.clone());

        if is_304_mergeable_header(lower.as_str()) {
            if let Some(values) = nm.get(lower.as_str()) {
                if replaced.insert(lower.clone()) {
                    for v in values {
                        out.push((name.clone(), v.clone()));
                    }
                }
                continue;
            }
        }
        out.push((name.clone(), value.clone()));
    }

    for (name, values) in nm {
        if saw.contains(name.as_str()) {
            continue;
        }
        for v in values {
            out.push((name.clone(), v));
        }
    }

    out
}

fn is_304_mergeable_header(lower_name: &str) -> bool {
    matches!(
        lower_name,
        "cache-control"
            | "expires"
            | "etag"
            | "last-modified"
            | "date"
            | "vary"
            | "content-location"
            | "warning"
    )
}
