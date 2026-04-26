use super::freshness::active_range;
use super::freshness::current_age_secs;
use super::types::{ByteRangeSpec, CachedResponseEnvelope, RequestDirectives, CACHE_HEADER};
use crate::http::body::Body;
use anyhow::Result;
use base64::Engine;
use http::header::{ACCEPT_RANGES, AGE, CONTENT_LENGTH, CONTENT_RANGE};
use hyper::{Method, Response, StatusCode};
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
) -> Result<Response<Body>> {
    let body = base64::engine::general_purpose::STANDARD.decode(&envelope.body_b64)?;
    build_response(BuildResponseParams {
        envelope,
        now_ms,
        cache_state,
        body,
        status_override: None,
        content_length_override: None,
        content_range: None,
    })
}

pub(super) fn response_from_envelope_for_request(
    request_method: &Method,
    req: &RequestDirectives,
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
) -> Result<Response<Body>> {
    let body = base64::engine::general_purpose::STANDARD.decode(&envelope.body_b64)?;
    let full_len = body.len() as u64;
    let head_response = *request_method == Method::HEAD;
    let Some(range) = active_range(req, envelope) else {
        let content_length =
            head_response.then(|| stored_content_length(envelope).unwrap_or(full_len));
        return build_response(BuildResponseParams {
            envelope,
            now_ms,
            cache_state,
            body: if head_response { Vec::new() } else { body },
            status_override: None,
            content_length_override: content_length,
            content_range: None,
        });
    };
    let len = full_len;
    let Some((start, end)) = resolve_range(range, len) else {
        let content_range = format!("bytes */{len}");
        return build_response(BuildResponseParams {
            envelope,
            now_ms,
            cache_state,
            body: Vec::new(),
            status_override: Some(StatusCode::RANGE_NOT_SATISFIABLE),
            content_length_override: Some(0),
            content_range: Some(content_range.as_str()),
        });
    };
    let end_inclusive = end.min(len.saturating_sub(1));
    let start_usize = start as usize;
    let end_usize = end_inclusive as usize;
    let partial = body[start_usize..=end_usize].to_vec();
    let selected_len = partial.len() as u64;
    let content_range = format!("bytes {start}-{end_inclusive}/{len}");
    build_response(BuildResponseParams {
        envelope,
        now_ms,
        cache_state,
        body: if head_response { Vec::new() } else { partial },
        status_override: Some(StatusCode::PARTIAL_CONTENT),
        content_length_override: Some(selected_len),
        content_range: Some(content_range.as_str()),
    })
}

pub(super) fn precondition_failed_response(cache_state: &'static str) -> Result<Response<Body>> {
    let mut response = Response::builder()
        .status(StatusCode::PRECONDITION_FAILED)
        .body(Body::empty())?;
    response
        .headers_mut()
        .insert(CACHE_HEADER, http::HeaderValue::from_static(cache_state));
    Ok(response)
}

pub(super) fn not_modified_from_envelope(
    request_method: &Method,
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
) -> Result<Response<Body>> {
    let mut response = response_from_envelope(envelope, now_ms, cache_state)?;
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    crate::http::semantics::normalize_response_for_request(request_method, &mut response);
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
    )
}

struct BuildResponseParams<'a> {
    envelope: &'a CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
    body: Vec<u8>,
    status_override: Option<StatusCode>,
    content_length_override: Option<u64>,
    content_range: Option<&'a str>,
}

fn build_response(params: BuildResponseParams<'_>) -> Result<Response<Body>> {
    let mut builder = Response::builder().status(params.status_override.unwrap_or_else(|| {
        StatusCode::from_u16(params.envelope.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }));
    for (name, value) in &params.envelope.headers {
        let Ok(header_name) = http::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        if header_name == AGE || header_name == CONTENT_LENGTH || header_name == CONTENT_RANGE {
            continue;
        }
        let Ok(header_value) = http::HeaderValue::from_str(value) else {
            continue;
        };
        builder = builder.header(header_name, header_value);
    }
    let mut response = builder.body(Body::from(params.body.clone()))?;
    let age = current_age_secs(params.envelope, params.now_ms).to_string();
    if let Ok(age_header) = http::HeaderValue::from_str(age.as_str()) {
        response.headers_mut().insert(AGE, age_header);
    }
    response.headers_mut().insert(
        CACHE_HEADER,
        http::HeaderValue::from_static(params.cache_state),
    );
    let content_length = params
        .content_length_override
        .unwrap_or(params.body.len() as u64);
    if let Ok(length) = http::HeaderValue::from_str(content_length.to_string().as_str()) {
        response.headers_mut().insert(CONTENT_LENGTH, length);
    }
    if let Some(content_range) = params.content_range {
        response
            .headers_mut()
            .insert(ACCEPT_RANGES, http::HeaderValue::from_static("bytes"));
        if let Ok(value) = http::HeaderValue::from_str(content_range) {
            response.headers_mut().insert(CONTENT_RANGE, value);
        }
    }
    Ok(response)
}

fn stored_content_length(envelope: &CachedResponseEnvelope) -> Option<u64> {
    let mut parsed = None;
    for (name, value) in &envelope.headers {
        if !name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()) {
            continue;
        }
        for part in value.split(',') {
            let next = part.trim().parse::<u64>().ok()?;
            match parsed {
                Some(existing) if existing != next => return None,
                Some(_) => {}
                None => parsed = Some(next),
            }
        }
    }
    parsed
}

fn resolve_range(range: &ByteRangeSpec, len: u64) -> Option<(u64, u64)> {
    if len == 0 {
        return None;
    }
    match range {
        ByteRangeSpec::From { start, end } => {
            if *start >= len {
                return None;
            }
            Some((
                *start,
                end.unwrap_or(len.saturating_sub(1))
                    .min(len.saturating_sub(1)),
            ))
        }
        ByteRangeSpec::Suffix { len: suffix_len } => {
            let suffix = (*suffix_len).min(len);
            let start = len.saturating_sub(suffix);
            Some((start, len.saturating_sub(1)))
        }
    }
}
