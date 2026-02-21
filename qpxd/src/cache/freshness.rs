use super::types::{CachedResponseEnvelope, RequestDirectives, ResponseDirectives};
use super::util::header_value;
use http::header::{AGE, DATE, ETAG, EXPIRES, IF_NONE_MATCH, LAST_MODIFIED};
use qpx_core::config::CachePolicyConfig;

pub(super) fn current_age_secs(envelope: &CachedResponseEnvelope, now_ms: u64) -> u64 {
    let resident_ms = now_ms.saturating_sub(envelope.stored_at_ms);
    envelope.initial_age_secs.saturating_add(resident_ms / 1000)
}

pub(super) fn initial_age_secs(
    headers: &http::HeaderMap,
    response_time_ms: u64,
    response_delay_secs: u64,
) -> u64 {
    let age_value = headers
        .get(AGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let apparent_age = headers
        .get(DATE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_date_secs)
        .map(|date_secs| (response_time_ms / 1000).saturating_sub(date_secs))
        .unwrap_or(0);
    let corrected_age_value = age_value.saturating_add(response_delay_secs);
    apparent_age.max(corrected_age_value)
}

pub(super) fn initial_age_secs_from_vec(
    headers: &[(String, String)],
    response_time_ms: u64,
    response_delay_secs: u64,
) -> u64 {
    let mut map = http::HeaderMap::new();
    for (k, v) in headers {
        if let Ok(name) = http::HeaderName::from_bytes(k.as_bytes()) {
            if let Ok(value) = http::HeaderValue::from_str(v) {
                map.append(name, value);
            }
        }
    }
    initial_age_secs(&map, response_time_ms, response_delay_secs)
}

pub(super) fn freshness_lifetime_secs(
    headers: &http::HeaderMap,
    policy: &CachePolicyConfig,
    now_ms: u64,
    directives: &ResponseDirectives,
) -> Option<u64> {
    if let Some(ttl) = directives.s_maxage {
        return Some(ttl);
    }
    if let Some(ttl) = directives.max_age {
        return Some(ttl);
    }
    if let Some(expires_raw) = headers.get(EXPIRES).and_then(|v| v.to_str().ok()) {
        let Some(expires_secs) = parse_http_date_secs(expires_raw) else {
            // RFC 9111: invalid Expires must be treated as already expired (stale), not a
            // reason to fall back to heuristic/default freshness.
            return Some(0);
        };
        let date_secs = headers
            .get(DATE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date_secs)
            .unwrap_or(now_ms / 1000);
        if expires_secs > date_secs {
            return Some(expires_secs - date_secs);
        }
        return Some(0);
    }
    policy.default_ttl_secs
}

pub(super) fn conditional_not_modified(
    req: &RequestDirectives,
    envelope: &CachedResponseEnvelope,
) -> bool {
    if !req.has_conditional {
        return false;
    }

    if !req.if_none_match.is_empty() {
        if req.if_none_match.iter().any(|tag| tag == "*") {
            return true;
        }
        if let Some(etag) = header_value(&envelope.headers, ETAG.as_str()) {
            if req
                .if_none_match
                .iter()
                .any(|candidate| weak_etag_eq(candidate, etag.as_str()))
            {
                return true;
            }
        }
        // RFC 9110: If-None-Match takes precedence over If-Modified-Since.
        return false;
    }

    if let (Some(if_modified_since), Some(last_modified)) = (
        req.if_modified_since,
        header_value(&envelope.headers, LAST_MODIFIED.as_str())
            .and_then(|v| parse_http_date_secs(&v)),
    ) {
        if last_modified <= if_modified_since {
            return true;
        }
    }

    false
}

pub(super) fn parse_if_none_match(headers: &http::HeaderMap) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all(IF_NONE_MATCH).iter() {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for token in raw.split(',') {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

pub(super) fn freshness_lifetime_secs_from_vec(
    headers: &[(String, String)],
    policy: &CachePolicyConfig,
    now_ms: u64,
    directives: &ResponseDirectives,
) -> Option<u64> {
    let mut map = http::HeaderMap::new();
    for (k, v) in headers {
        if let Ok(name) = http::HeaderName::from_bytes(k.as_bytes()) {
            if let Ok(value) = http::HeaderValue::from_str(v) {
                map.append(name, value);
            }
        }
    }
    freshness_lifetime_secs(&map, policy, now_ms, directives)
}

fn weak_etag_eq(lhs: &str, rhs: &str) -> bool {
    fn normalize(tag: &str) -> &str {
        let tag = tag.trim();
        tag.strip_prefix("W/").unwrap_or(tag)
    }
    normalize(lhs) == normalize(rhs)
}

pub(super) fn parse_http_date_secs(value: &str) -> Option<u64> {
    httpdate::parse_http_date(value)
        .ok()
        .and_then(|dt| dt.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|dur| dur.as_secs())
}
