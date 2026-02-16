use super::freshness::{parse_http_date_secs, parse_if_none_match};
use super::types::{RequestDirectives, ResponseDirectives};
use http::header::{
    CACHE_CONTROL, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE,
    PRAGMA, RANGE,
};

pub(super) fn parse_request_directives(headers: &http::HeaderMap) -> RequestDirectives {
    let mut directives = RequestDirectives {
        has_conditional: headers.contains_key(IF_NONE_MATCH)
            || headers.contains_key(IF_MODIFIED_SINCE),
        if_none_match: parse_if_none_match(headers),
        if_modified_since: headers
            .get(IF_MODIFIED_SINCE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date_secs),
        has_unsupported_conditionals: headers.contains_key(RANGE)
            || headers.contains_key(IF_RANGE)
            || headers.contains_key(IF_MATCH)
            || headers.contains_key(IF_UNMODIFIED_SINCE),
        ..RequestDirectives::default()
    };

    let mut saw_cache_control = false;
    for value in headers.get_all(CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        saw_cache_control = true;
        for token in split_cache_control_tokens(value) {
            let Some((directive, value)) = parse_cache_control_directive(token.as_str()) else {
                continue;
            };
            if directive == "no-store" {
                directives.no_store = true;
            } else if directive == "no-cache" {
                directives.no_cache = true;
            } else if directive == "only-if-cached" {
                directives.only_if_cached = true;
            } else if directive == "max-age" {
                if let Some(value) = value.as_deref() {
                    directives.max_age = parse_u64_directive(value);
                }
            } else if directive == "min-fresh" {
                if let Some(value) = value.as_deref() {
                    directives.min_fresh = parse_u64_directive(value);
                }
            } else if directive == "max-stale" {
                match value.as_deref() {
                    Some(v) => {
                        if let Some(parsed) = parse_u64_directive(v) {
                            directives.max_stale = Some(Some(parsed));
                        }
                    }
                    None => directives.max_stale = Some(None),
                }
            }
        }
    }

    if !saw_cache_control {
        for value in headers.get_all(PRAGMA) {
            if let Ok(v) = value.to_str() {
                if v.to_ascii_lowercase().contains("no-cache") {
                    directives.no_cache = true;
                }
            }
        }
    }
    directives
}

pub(super) fn parse_response_directives(headers: &http::HeaderMap) -> ResponseDirectives {
    let mut out = ResponseDirectives::default();
    for value in headers.get_all(CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in split_cache_control_tokens(value) {
            let Some((directive, value)) = parse_cache_control_directive(token.as_str()) else {
                continue;
            };
            if directive == "no-store" {
                out.no_store = true;
            } else if directive == "no-cache" {
                if let Some(value) = value.as_deref() {
                    out.no_cache_fields
                        .extend(parse_cache_field_name_list(value).into_iter());
                } else {
                    out.no_cache = true;
                }
            } else if directive == "private" {
                if let Some(value) = value.as_deref() {
                    out.private_fields
                        .extend(parse_cache_field_name_list(value).into_iter());
                } else {
                    out.private = true;
                }
            } else if directive == "public" {
                out.public = true;
            } else if directive == "must-revalidate" {
                out.must_revalidate = true;
            } else if directive == "proxy-revalidate" {
                out.proxy_revalidate = true;
            } else if directive == "max-age" {
                if let Some(value) = value.as_deref() {
                    out.max_age = parse_u64_directive(value);
                }
            } else if directive == "s-maxage" {
                if let Some(value) = value.as_deref() {
                    out.s_maxage = parse_u64_directive(value);
                }
            }
        }
    }
    out
}

pub(super) fn parse_response_directives_from_vec(
    headers: &[(String, String)],
) -> ResponseDirectives {
    let mut map = http::HeaderMap::new();
    for (k, v) in headers {
        if let Ok(name) = http::HeaderName::from_bytes(k.as_bytes()) {
            if let Ok(value) = http::HeaderValue::from_str(v) {
                map.append(name, value);
            }
        }
    }
    parse_response_directives(&map)
}

fn split_cache_control_tokens(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in value.chars() {
        if in_quotes {
            current.push(ch);
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            continue;
        }
        match ch {
            '"' => {
                in_quotes = true;
                current.push(ch);
            }
            ',' => {
                let token = current.trim();
                if !token.is_empty() {
                    out.push(token.to_string());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let token = current.trim();
    if !token.is_empty() {
        out.push(token.to_string());
    }
    out
}

fn parse_cache_control_directive(token: &str) -> Option<(String, Option<String>)> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let (name, value) = match token.split_once('=') {
        Some((name, value)) => (name.trim(), Some(value.trim().to_string())),
        None => (token, None),
    };
    if name.is_empty() {
        return None;
    }
    Some((name.to_ascii_lowercase(), value))
}

fn parse_u64_directive(value: &str) -> Option<u64> {
    value.trim().trim_matches('"').parse::<u64>().ok()
}

fn parse_cache_field_name_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|token| token.trim().trim_matches('"').to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}
