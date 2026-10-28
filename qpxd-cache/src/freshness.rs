use super::types::{
    ByteRangeSpec, CachedResponseEnvelope, IfRangeCondition, RequestDirectives, ResponseDirectives,
};
use http::header::{AGE, DATE, EXPIRES};
use qpx_core::config::CachePolicyConfig;
use qpx_core::http_message::{Headers as OwnedHeaders, OrdinaryHeaderName};

fn ord(name: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(name).expect("ordinary header name")
}

pub fn current_age_secs(envelope: &CachedResponseEnvelope, now_ms: u64) -> u64 {
    let resident_ms = now_ms.saturating_sub(envelope.stored_at_ms);
    envelope.initial_age_secs.saturating_add(resident_ms / 1000)
}

pub fn initial_age_secs(
    headers: &OwnedHeaders,
    response_time_ms: u64,
    response_delay_secs: u64,
) -> u64 {
    let age_value = headers
        .get(&ord(AGE.as_str()))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let apparent_age = headers
        .get(&ord(DATE.as_str()))
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_date_secs)
        .map(|date_secs| (response_time_ms / 1000).saturating_sub(date_secs))
        .unwrap_or(0);
    let corrected_age_value = age_value.saturating_add(response_delay_secs);
    apparent_age.max(corrected_age_value)
}

pub fn freshness_lifetime_secs(
    headers: &OwnedHeaders,
    policy: &CachePolicyConfig,
    now_ms: u64,
    directives: &ResponseDirectives,
) -> Option<u64> {
    if directives.invalid_freshness {
        return Some(0);
    }
    if let Some(ttl) = directives.s_maxage {
        return Some(ttl);
    }
    if let Some(ttl) = directives.max_age {
        return Some(ttl);
    }
    if let Some(expires_raw) = headers
        .get(&ord(EXPIRES.as_str()))
        .and_then(|v| v.to_str().ok())
    {
        let Some(expires_secs) = parse_http_date_secs(expires_raw) else {
            // RFC 9111: invalid Expires must be treated as already expired (stale), not a
            // reason to fall back to heuristic/default freshness.
            return Some(0);
        };
        let date_secs = headers
            .get(&ord(DATE.as_str()))
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

pub fn conditional_not_modified(
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
        if let Some(etag) = envelope.etag()
            && req
                .if_none_match
                .iter()
                .any(|candidate| weak_etag_eq(candidate, etag))
        {
            return true;
        }
        // RFC 9110: If-None-Match takes precedence over If-Modified-Since.
        return false;
    }

    if let (Some(if_modified_since), Some(last_modified)) = (
        req.if_modified_since,
        envelope.last_modified().and_then(parse_http_date_secs),
    ) && last_modified <= if_modified_since
    {
        return true;
    }

    false
}

pub fn precondition_failed(req: &RequestDirectives, envelope: &CachedResponseEnvelope) -> bool {
    if !req.if_match.is_empty() && !if_match_succeeds(req, envelope) {
        return true;
    }

    if let (Some(if_unmodified_since), Some(last_modified)) = (
        req.if_unmodified_since,
        envelope.last_modified().and_then(parse_http_date_secs),
    ) && last_modified > if_unmodified_since
    {
        return true;
    }

    false
}

pub fn active_range<'a>(
    req: &'a RequestDirectives,
    envelope: &CachedResponseEnvelope,
) -> Option<&'a ByteRangeSpec> {
    let range = req.range.as_ref()?;
    if let Some(if_range) = req.if_range.as_ref()
        && !if_range_matches(if_range, envelope)
    {
        return None;
    }
    Some(range)
}

pub fn parse_if_none_match(headers: &OwnedHeaders) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all(&ord("if-none-match")) {
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

fn if_match_succeeds(req: &RequestDirectives, envelope: &CachedResponseEnvelope) -> bool {
    if req.if_match.iter().any(|tag| tag == "*") {
        return true;
    }
    let Some(etag) = envelope.etag() else {
        return false;
    };
    req.if_match
        .iter()
        .any(|candidate| strong_etag_eq(candidate, etag))
}

fn weak_etag_eq(lhs: &str, rhs: &str) -> bool {
    fn normalize(tag: &str) -> &str {
        let tag = tag.trim();
        tag.strip_prefix("W/").unwrap_or(tag)
    }
    normalize(lhs) == normalize(rhs)
}

fn strong_etag_eq(lhs: &str, rhs: &str) -> bool {
    let lhs = lhs.trim();
    let rhs = rhs.trim();
    !lhs.starts_with("W/") && !rhs.starts_with("W/") && lhs == rhs
}

fn if_range_matches(condition: &IfRangeCondition, envelope: &CachedResponseEnvelope) -> bool {
    match condition {
        IfRangeCondition::Etag(expected) => envelope
            .etag()
            .is_some_and(|etag| strong_etag_eq(expected, etag)),
        // RFC 9110 §§13.1.5, 8.8.2.2: an If-Range date matches only on
        // exact equality (unlike If-Unmodified-Since's <= test), and only
        // when the stored date is a strong validator. Last-Modified is
        // implicitly weak, so the cache additionally requires a Date header
        // from the same stored response strictly after Last-Modified:
        // second resolution makes this at least one second of separation,
        // and both stamps come from one origin message, so no cross-clock
        // comparison or invented threshold is involved. Without that
        // evidence the date branch is false and Range is ignored, so a
        // same-second rewrite can never yield a stitched 206.
        IfRangeCondition::Date(expected) => {
            let last_modified = envelope.last_modified().and_then(parse_http_date_secs);
            let date = envelope.date().and_then(parse_http_date_secs);
            match (last_modified, date) {
                (Some(last_modified), Some(date)) => {
                    last_modified == *expected && date > last_modified
                }
                _ => false,
            }
        }
    }
}

pub fn parse_http_date_secs(value: &str) -> Option<u64> {
    httpdate::parse_http_date(value)
        .ok()
        .and_then(|dt| dt.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|dur| dur.as_secs())
}
