use super::freshness::active_range;
use super::freshness::current_age_secs;
use super::types::{
    ByteRangeSpec, CACHE_HEADER, CachedResponseEnvelope, RequestDirectives, cache_status_header,
};
use anyhow::Result;
use http::header::{ACCEPT_RANGES, AGE, CONTENT_LENGTH, CONTENT_RANGE};
use hyper::{Method, Response, StatusCode};
use qpx_http::body::Body;
use std::collections::HashSet;

pub fn header_map_from_vec(headers: &[(String, String)]) -> http::HeaderMap {
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

pub fn primary_from_variant_key(variant_key: &str) -> Option<&str> {
    let rest = variant_key.strip_prefix("obj:")?;
    rest.split(':').next()
}

pub fn response_from_envelope(
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
) -> Result<Response<Body>> {
    build_response(BuildResponseParams {
        envelope,
        now_ms,
        cache_state,
        body: envelope.body.to_body(),
        body_len: envelope.body.len(),
        status_override: None,
        content_length_override: None,
        content_range: None,
    })
}

pub fn response_from_envelope_for_request(
    request_method: &Method,
    req: &RequestDirectives,
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
) -> Result<Response<Body>> {
    let full_len = envelope.body_len;
    let head_response = *request_method == Method::HEAD;
    let range = (!head_response)
        .then(|| active_range(req, envelope))
        .flatten();
    let Some(range) = range else {
        let content_length =
            head_response.then(|| stored_content_length(envelope).unwrap_or(full_len));
        return build_response(BuildResponseParams {
            envelope,
            now_ms,
            cache_state,
            body: if head_response {
                Body::empty()
            } else {
                envelope.body.to_body()
            },
            body_len: if head_response {
                0
            } else {
                envelope.body.len()
            },
            status_override: None,
            content_length_override: content_length,
            content_range: None,
        });
    };
    let Some((start, end)) = resolve_range(range, full_len) else {
        let content_range = format!("bytes */{full_len}");
        return build_response(BuildResponseParams {
            envelope,
            now_ms,
            cache_state,
            body: Body::empty(),
            body_len: 0,
            status_override: Some(StatusCode::RANGE_NOT_SATISFIABLE),
            content_length_override: Some(0),
            content_range: Some(content_range.as_str()),
        });
    };
    let end_inclusive = end.min(full_len.saturating_sub(1));
    let selected_len = end_inclusive.saturating_sub(start).saturating_add(1);
    let partial = envelope.body.slice_to_body(start, end_inclusive);
    let content_range = format!("bytes {start}-{end_inclusive}/{full_len}");
    build_response(BuildResponseParams {
        envelope,
        now_ms,
        cache_state,
        body: if head_response {
            Body::empty()
        } else {
            partial
        },
        body_len: if head_response { 0 } else { selected_len },
        status_override: Some(StatusCode::PARTIAL_CONTENT),
        content_length_override: Some(selected_len),
        content_range: Some(content_range.as_str()),
    })
}

pub fn response_from_envelope_for_request_with_body(
    request_method: &Method,
    req: &RequestDirectives,
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
    body: Body,
    body_len: u64,
) -> Result<Response<Body>> {
    let head_response = *request_method == Method::HEAD;
    debug_assert!(!head_response);
    let content_length = (!head_response).then_some(body_len);
    let range = active_range(req, envelope)
        .and_then(|range| resolve_range(range, envelope.body_len))
        .map(|(start, end)| (start, end.min(envelope.body_len.saturating_sub(1))));
    let content_range =
        range.map(|(start, end)| format!("bytes {start}-{end}/{}", envelope.body_len));
    build_response(BuildResponseParams {
        envelope,
        now_ms,
        cache_state,
        body,
        body_len,
        status_override: content_range.as_ref().map(|_| StatusCode::PARTIAL_CONTENT),
        content_length_override: content_length,
        content_range: content_range.as_deref(),
    })
}

pub fn precondition_failed_response(cache_state: &'static str) -> Result<Response<Body>> {
    let mut response = Response::builder()
        .status(StatusCode::PRECONDITION_FAILED)
        .body(Body::empty())?;
    response
        .headers_mut()
        .insert(CACHE_HEADER, cache_status_header(cache_state, None)?);
    Ok(response)
}

pub fn not_modified_from_envelope(
    request_method: &Method,
    envelope: &CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
) -> Result<Response<Body>> {
    let mut response = response_from_envelope(envelope, now_ms, cache_state)?;
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    qpx_http::protocol::semantics::normalize_response_for_request(request_method, &mut response);
    Ok(response)
}

pub fn merge_headers_after_304(
    cached_headers: &[(String, String)],
    not_modified_headers: &http::HeaderMap,
) -> Vec<(String, String)> {
    // RFC 9111 §3.2: update the stored headers with each field provided in the
    // 304, replacing existing values, except fields that must not be persisted
    // for the stored representation (unchanged body bytes).
    let connection_nominated = connection_nominated_headers(not_modified_headers);
    let mut nm = std::collections::HashMap::<String, Vec<String>>::new();
    for (name, value) in not_modified_headers {
        let lower = name.as_str().to_ascii_lowercase();
        if is_304_excluded_header(lower.as_str(), &connection_nominated) {
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
        if qpx_http::protocol::semantics::is_hop_by_hop_header_name(lower.as_str()) {
            continue;
        }
        saw.insert(lower.clone());

        // Excluded 304 fields never reach `nm`, so stored framing labels and
        // other kept fields always survive here unchanged.
        if let Some(values) = nm.get(lower.as_str()) {
            if replaced.insert(lower.clone()) {
                for v in values {
                    out.push((name.clone(), v.clone()));
                }
            }
            continue;
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

/// Header fields that a 304 response must not merge into the stored entry.
///
/// RFC 9111 §3.2 requires updating stored fields except narrowly justified
/// exclusions: hop-by-hop fields (including `Connection`-nominated ones, which
/// describe only the 304 transport), and the framing labels of the unchanged
/// stored body (`content-length`, `content-encoding`, `content-range`).
/// Everything else — freshness metadata, validators, `Content-Type`, security
/// policy and extension fields — is replaced or added. Policy gates such as
/// `no-store`/`private` or cookie storage remain enforced afterwards by the
/// revalidation-time storability check, not by this merge.
fn is_304_excluded_header(lower_name: &str, connection_nominated: &HashSet<String>) -> bool {
    if connection_nominated.contains(lower_name) {
        return true;
    }
    if qpx_http::protocol::semantics::is_hop_by_hop_header_name(lower_name) {
        return true;
    }
    matches!(
        lower_name,
        "content-length" | "content-encoding" | "content-range"
    )
}

fn connection_nominated_headers(not_modified_headers: &http::HeaderMap) -> HashSet<String> {
    let mut out = HashSet::new();
    for value in not_modified_headers
        .get_all(http::header::CONNECTION)
        .iter()
    {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',') {
            let token = token.trim().to_ascii_lowercase();
            if !token.is_empty() {
                out.insert(token);
            }
        }
    }
    out
}

struct BuildResponseParams<'a> {
    envelope: &'a CachedResponseEnvelope,
    now_ms: u64,
    cache_state: &'static str,
    body: Body,
    body_len: u64,
    status_override: Option<StatusCode>,
    content_length_override: Option<u64>,
    content_range: Option<&'a str>,
}

fn build_response(params: BuildResponseParams<'_>) -> Result<Response<Body>> {
    let status = match params.status_override {
        Some(status) => status,
        None => qpx_http::protocol::semantics::validate_http_status_class(
            StatusCode::from_u16(params.envelope.status)
                .map_err(|err| anyhow::anyhow!("invalid cached response status: {err}"))?,
            "cached response",
        )?,
    };
    let mut response = Response::new(params.body);
    *response.status_mut() = status;
    const CACHE_RESPONSE_ADDITIONAL_HEADERS: usize = 5;
    *response.headers_mut() = qpx_http::header_pool::clone_map_with_additional_capacity(
        params.envelope.header_map(),
        CACHE_RESPONSE_ADDITIONAL_HEADERS,
    );
    response.headers_mut().remove(AGE);
    response.headers_mut().remove(CONTENT_LENGTH);
    response.headers_mut().remove(CONTENT_RANGE);
    let current_age = current_age_secs(params.envelope, params.now_ms);
    let ttl = (params.cache_state == "HIT").then(|| {
        params
            .envelope
            .freshness_lifetime_secs
            .saturating_sub(current_age)
    });
    let (age, cache_status) =
        params
            .envelope
            .response_header_values(params.cache_state, current_age, ttl)?;
    response.headers_mut().insert(AGE, age);
    response.headers_mut().insert(CACHE_HEADER, cache_status);
    let content_length = params.content_length_override.unwrap_or(params.body_len);
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, http::HeaderValue::from(content_length));
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

/// The Content-Length that the stored response declares.
///
/// The stored headers are a list of name-value pairs rather than a header
/// map, so the field's values go to the owner's value-level entry point: the
/// member grammar and the conflict rule stay in one place.
fn stored_content_length(envelope: &CachedResponseEnvelope) -> Option<u64> {
    let values = envelope
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()))
        .map(|(_, value)| value.as_str());
    qpx_core::http_content_length::declared_content_length_in_values(values)
        .ok()
        .flatten()
}

pub fn resolve_range(range: &ByteRangeSpec, len: u64) -> Option<(u64, u64)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CachedBody;

    fn envelope_with_headers(headers: Vec<(String, String)>) -> CachedResponseEnvelope {
        CachedResponseEnvelope {
            status: 200,
            headers,
            body: CachedBody::default(),
            body_len: 0,
            stored_at_ms: 0,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            header_map: Default::default(),
            response_directives: Default::default(),
            response_header_values: Default::default(),
        }
    }

    fn envelope_with_content_length(value: &str) -> CachedResponseEnvelope {
        envelope_with_headers(vec![("content-length".to_string(), value.to_string())])
    }

    #[test]
    fn the_stored_length_is_the_owners_reading() {
        assert_eq!(
            stored_content_length(&envelope_with_content_length("42")),
            Some(42)
        );
        assert_eq!(
            stored_content_length(&envelope_with_content_length("42, 42")),
            Some(42)
        );
    }

    #[test]
    fn the_stored_length_refuses_a_signed_member() {
        assert_eq!(
            stored_content_length(&envelope_with_content_length("+42")),
            None
        );
    }

    #[test]
    fn the_stored_length_refuses_conflicting_members() {
        assert_eq!(
            stored_content_length(&envelope_with_content_length("42, 43")),
            None
        );
    }

    #[test]
    fn the_stored_length_of_an_empty_value_is_absent() {
        assert_eq!(
            stored_content_length(&envelope_with_content_length("")),
            None
        );
    }

    #[test]
    fn a_response_without_the_field_declares_no_length() {
        assert_eq!(
            stored_content_length(&envelope_with_headers(Vec::new())),
            None
        );
    }
}
