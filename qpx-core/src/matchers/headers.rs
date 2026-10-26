use crate::config::HeaderMatch;
use crate::http_content_length::HeaderPredicate;
use crate::prefilter::StringInterner;
use crate::rules::PolicyHeaderView;
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
    headers: Option<PolicyHeaderView<'_>>,
) -> bool {
    if matchers.is_empty() {
        return true;
    }
    let Some(view) = headers else {
        return false;
    };
    matchers.iter().all(|matcher| match &matcher.mode {
        HeaderFastMode::Present => view.matches(matcher.name.as_ref(), HeaderPredicate::Present),
        HeaderFastMode::Exact(expected) => view.matches(
            matcher.name.as_ref(),
            HeaderPredicate::Exact(expected.as_ref()),
        ),
    })
}

pub(super) fn regex_headers_match(
    matchers: &[HeaderMatcherRegex],
    headers: Option<PolicyHeaderView<'_>>,
) -> bool {
    if matchers.is_empty() {
        return true;
    }
    let Some(view) = headers else {
        return false;
    };
    matchers.iter().all(|matcher| {
        view.matches(
            matcher.name.as_ref(),
            HeaderPredicate::Regex(&matcher.regex),
        )
    })
}

pub(super) fn trace_fast_header(
    matcher: &HeaderMatcherFast,
    headers: Option<PolicyHeaderView<'_>>,
) -> (String, Option<String>, bool) {
    let configured = match &matcher.mode {
        HeaderFastMode::Present => "<present>".to_string(),
        HeaderFastMode::Exact(expected) => expected.to_string(),
    };
    let diagnostic = match headers {
        Some(view) => match &matcher.mode {
            HeaderFastMode::Present => view.trace(matcher.name.as_ref(), HeaderPredicate::Present),
            HeaderFastMode::Exact(expected) => view.trace(
                matcher.name.as_ref(),
                HeaderPredicate::Exact(expected.as_ref()),
            ),
        },
        None => crate::http_content_length::HeaderDiagnostic {
            actual: None,
            matched: false,
        },
    };
    (configured, diagnostic.actual, diagnostic.matched)
}

pub(super) fn trace_regex_header(
    matcher: &HeaderMatcherRegex,
    headers: Option<PolicyHeaderView<'_>>,
) -> (Option<String>, bool) {
    let diagnostic = match headers {
        Some(view) => view.trace(
            matcher.name.as_ref(),
            HeaderPredicate::Regex(&matcher.regex),
        ),
        None => crate::http_content_length::HeaderDiagnostic {
            actual: None,
            matched: false,
        },
    };
    (diagnostic.actual, diagnostic.matched)
}
