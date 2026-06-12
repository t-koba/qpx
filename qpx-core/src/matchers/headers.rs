use crate::config::HeaderMatch;
use crate::prefilter::StringInterner;
use anyhow::anyhow;
use regex::Regex;
use std::sync::Arc;

use super::Result;

#[derive(Debug, Clone)]
pub(super) struct HeaderMatcherFast {
    pub(super) name: Arc<str>,
    mode: HeaderFastMode,
}

#[derive(Debug, Clone)]
enum HeaderFastMode {
    Present,
    Exact(Arc<str>),
}

#[derive(Debug, Clone)]
pub(super) struct HeaderMatcherRegex {
    pub(super) name: Arc<str>,
    pub(super) regex: Regex,
}

pub(super) fn build_header_matchers(
    items: &[HeaderMatch],
    interner: &mut StringInterner,
) -> Result<(Vec<HeaderMatcherFast>, Vec<HeaderMatcherRegex>)> {
    let mut fast = Vec::new();
    let mut regex = Vec::new();

    for item in items {
        let name = interner.intern_lower(&item.name);
        if let Some(pattern) = &item.regex {
            regex.push(HeaderMatcherRegex {
                name,
                regex: Regex::new(pattern)
                    .map_err(|e| anyhow!("invalid header regex {}: {}", pattern, e))?,
            });
            continue;
        }

        let mode = if let Some(value) = &item.value {
            HeaderFastMode::Exact(interner.intern(value))
        } else {
            HeaderFastMode::Present
        };
        fast.push(HeaderMatcherFast { name, mode });
    }

    Ok((fast, regex))
}

pub(super) fn fast_headers_match(
    matchers: &[HeaderMatcherFast],
    headers: Option<&http::HeaderMap>,
) -> bool {
    if matchers.is_empty() {
        return true;
    }
    let Some(headers) = headers else {
        return false;
    };
    matchers.iter().all(|matcher| {
        headers
            .get_all(matcher.name.as_ref())
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| match &matcher.mode {
                HeaderFastMode::Present => true,
                HeaderFastMode::Exact(expected) => value == expected.as_ref(),
            })
    })
}

pub(super) fn regex_headers_match(
    matchers: &[HeaderMatcherRegex],
    headers: Option<&http::HeaderMap>,
) -> bool {
    if matchers.is_empty() {
        return true;
    }
    let Some(headers) = headers else {
        return false;
    };
    matchers.iter().all(|matcher| {
        headers
            .get_all(matcher.name.as_ref())
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| matcher.regex.is_match(value))
    })
}

pub(super) fn trace_fast_header(
    matcher: &HeaderMatcherFast,
    headers: Option<&http::HeaderMap>,
) -> (String, Option<String>, bool) {
    let configured = match &matcher.mode {
        HeaderFastMode::Present => "<present>".to_string(),
        HeaderFastMode::Exact(expected) => expected.to_string(),
    };
    let actual = first_header_value(headers, matcher.name.as_ref());
    let result = match &matcher.mode {
        HeaderFastMode::Present => actual.is_some(),
        HeaderFastMode::Exact(expected) => actual.as_deref() == Some(expected.as_ref()),
    };
    (configured, actual, result)
}

pub(super) fn trace_regex_header(
    matcher: &HeaderMatcherRegex,
    headers: Option<&http::HeaderMap>,
) -> (Option<String>, bool) {
    let actual = first_header_value(headers, matcher.name.as_ref());
    let result = actual
        .as_deref()
        .is_some_and(|actual| matcher.regex.is_match(actual));
    (actual, result)
}

fn first_header_value(headers: Option<&http::HeaderMap>, name: &str) -> Option<String> {
    headers.and_then(|headers| {
        headers
            .get_all(name)
            .iter()
            .find_map(|value| value.to_str().ok().map(str::to_string))
    })
}
