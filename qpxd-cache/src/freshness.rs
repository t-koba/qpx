use super::types::{
    ByteRangeSpec, CachedResponseEnvelope, IfRangeCondition, RequestDirectives, ResponseDirectives,
};
use http::header::{AGE, DATE, EXPIRES};
use hyper::StatusCode;
use qpx_core::config::CachePolicyConfig;
use qpx_core::http_message::{Headers as OwnedHeaders, OrdinaryHeaderName};

fn ord(name: &str) -> OrdinaryHeaderName {
    OrdinaryHeaderName::try_from(name).expect("ordinary header name")
}

pub fn current_age_secs(envelope: &CachedResponseEnvelope, now_ms: u64) -> u64 {
    let resident_ms = now_ms.saturating_sub(envelope.stored_at_ms);
    envelope.initial_age_secs.saturating_add(resident_ms / 1000)
}

/// A delta-seconds token classified per RFC 9111 §1.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaSeconds {
    /// A well-formed decimal that fits in `u64`.
    Value(u64),
    /// Well-formed decimal digits too large for `u64`; must saturate.
    Overflow,
    /// Not a delta-seconds value; each caller keeps its own absence policy.
    Malformed,
}

/// Shared owner for delta-seconds parsing, used by both `Age` and the
/// `Cache-Control` numeric directives. A well-formed decimal that overflows is
/// distinct from a malformed token so callers can saturate overflow instead of
/// dropping the directive: RFC 9111 §1.2.2 requires overflowing delta-seconds
/// to become a very large value, never absence or youth. A leading `+` is not
/// all digits but is accepted by the numeric parser; keep that historical
/// acceptance here so only overflow changes behavior.
pub fn parse_delta_seconds(value: &str) -> DeltaSeconds {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return match value.parse::<u64>() {
            Ok(seconds) => DeltaSeconds::Value(seconds),
            Err(_) => DeltaSeconds::Overflow,
        };
    }
    match value.parse::<u64>() {
        Ok(seconds) => DeltaSeconds::Value(seconds),
        Err(_) => DeltaSeconds::Malformed,
    }
}

/// `Age` policy: any invalid or overflowing delta-seconds must not imply youth,
/// so both saturate to `u64::MAX`. The all-digits guard preserves the stricter
/// historical `Age` behavior that rejects a leading `+`.
fn parse_age_delta_seconds(value: &str) -> u64 {
    let value = value.trim();
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return u64::MAX;
    }
    match parse_delta_seconds(value) {
        DeltaSeconds::Value(seconds) => seconds,
        DeltaSeconds::Overflow | DeltaSeconds::Malformed => u64::MAX,
    }
}

pub fn initial_age_secs(
    headers: &OwnedHeaders,
    response_time_ms: u64,
    response_delay_secs: u64,
) -> u64 {
    let age_value = headers
        .get(&ord(AGE.as_str()))
        .map(|v| v.to_str().map(parse_age_delta_seconds).unwrap_or(u64::MAX))
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
    if let Some(expires) = headers.get(&ord(EXPIRES.as_str())) {
        let Some(expires_secs) = expires.to_str().ok().and_then(parse_http_date_secs) else {
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
    // RFC 9110 §13.1.4: If-Match takes precedence over If-Unmodified-Since.
    if !req.if_match.is_empty() {
        return !if_match_succeeds(req, envelope);
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
    // RFC 9110 §14.2: a Range header must be ignored unless the response
    // without it would be 200 OK. This guard also keeps the body consistent:
    // callers slice the body only when they see an active range.
    if envelope.status != StatusCode::OK.as_u16() {
        return None;
    }
    let range = req.range.as_ref()?;
    if let Some(if_range) = req.if_range.as_ref()
        && !if_range_matches(if_range, envelope)
    {
        return None;
    }
    Some(range)
}

pub fn parse_if_none_match(headers: &OwnedHeaders) -> Vec<String> {
    parse_entity_tag_list(headers, "if-none-match")
}

pub fn parse_entity_tag_list(headers: &OwnedHeaders, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for value in headers.get_all(&ord(name)) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        let mut start = 0;
        let mut quoted = false;
        for (index, character) in raw.char_indices() {
            match character {
                '"' => quoted = !quoted,
                ',' if !quoted => {
                    let token = raw[start..index].trim();
                    if !token.is_empty() {
                        out.push(token.to_string());
                    }
                    start = index + 1;
                }
                _ => {}
            }
        }
        let token = raw[start..].trim();
        if !token.is_empty() {
            out.push(token.to_string());
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
