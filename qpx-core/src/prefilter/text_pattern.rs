use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;

use super::StringInterner;

#[derive(Debug, Clone)]
pub struct TextPatternMatcher {
    exact: HashSet<Arc<str>>,
    suffix: Vec<Arc<str>>,
    glob_patterns: Vec<Arc<str>>,
    glob: Option<GlobSet>,
    regex: Vec<Regex>,
    lowercase_input: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextMatchMode {
    Exact,
    Suffix,
    Glob,
    Regex,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextMatchTrace {
    pub mode: TextMatchMode,
    pub configured: String,
    pub result: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TextPrefilterHint {
    pub any: bool,
    pub complex: bool,
    pub exact: Vec<Arc<str>>,
    pub suffix: Vec<Arc<str>>,
}

impl TextPatternMatcher {
    pub fn matches(&self, input: &str) -> bool {
        let normalized_owned;
        let normalized = if self.lowercase_input {
            normalized_owned = input.to_ascii_lowercase();
            normalized_owned.as_str()
        } else {
            input
        };

        if !self.exact.is_empty() && self.exact.contains(normalized) {
            return true;
        }

        if !self.suffix.is_empty()
            && self
                .suffix
                .iter()
                .any(|suffix| host_matches_suffix(normalized, suffix.as_ref()))
        {
            return true;
        }

        if let Some(glob) = &self.glob
            && glob.is_match(normalized)
        {
            return true;
        }

        if !self.regex.is_empty() {
            return self.regex.iter().any(|regex| regex.is_match(normalized));
        }
        false
    }

    pub fn trace(&self, input: Option<&str>) -> Vec<TextMatchTrace> {
        let normalized_owned;
        let normalized = match input {
            Some(input) if self.lowercase_input => {
                normalized_owned = input.to_ascii_lowercase();
                Some(normalized_owned.as_str())
            }
            Some(input) => Some(input),
            None => None,
        };
        let mut out = Vec::new();
        for exact in &self.exact {
            out.push(TextMatchTrace {
                mode: TextMatchMode::Exact,
                configured: exact.to_string(),
                result: normalized.is_some_and(|input| input == exact.as_ref()),
            });
        }
        for suffix in &self.suffix {
            out.push(TextMatchTrace {
                mode: TextMatchMode::Suffix,
                configured: suffix.to_string(),
                result: normalized.is_some_and(|input| host_matches_suffix(input, suffix.as_ref())),
            });
        }
        for glob in &self.glob_patterns {
            out.push(TextMatchTrace {
                mode: TextMatchMode::Glob,
                configured: glob.to_string(),
                result: normalized.is_some_and(|input| {
                    Glob::new(glob.as_ref())
                        .map(|glob| glob.compile_matcher().is_match(input))
                        .unwrap_or(false)
                }),
            });
        }
        for regex in &self.regex {
            out.push(TextMatchTrace {
                mode: TextMatchMode::Regex,
                configured: regex.as_str().to_string(),
                result: normalized.is_some_and(|input| regex.is_match(input)),
            });
        }
        out
    }
}

pub(super) fn is_exact_pattern(item: &str) -> bool {
    !item.contains('*')
        && !item.contains('?')
        && !item.contains('[')
        && !item.contains(']')
        && !item.contains('{')
        && !item.contains('}')
}

pub(super) fn extract_domain_suffix(pattern: &str) -> Option<&str> {
    let rest = pattern.strip_prefix("*.")?;
    if rest.is_empty() || !is_exact_pattern(rest) {
        return None;
    }
    Some(rest)
}

pub(super) fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host.len() <= suffix.len() {
        return false;
    }
    if !host.ends_with(suffix) {
        return false;
    }
    let boundary = host.len() - suffix.len();
    host.as_bytes().get(boundary.wrapping_sub(1)).copied() == Some(b'.')
}

fn build_globset(items: &[String]) -> Result<Option<GlobSet>> {
    if items.is_empty() {
        return Ok(None);
    }

    let mut builder = GlobSetBuilder::new();
    for item in items {
        builder.add(Glob::new(item)?);
    }
    Ok(Some(builder.build()?))
}

fn extract_regex_pattern(item: &str) -> Option<&str> {
    item.strip_prefix("re:")
        .or_else(|| item.strip_prefix("regex:"))
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
}

pub(crate) fn compile_text_patterns(
    items: &[String],
    lowercase: bool,
    allow_domain_suffix: bool,
    interner: &mut StringInterner,
) -> Result<(Option<TextPatternMatcher>, TextPrefilterHint)> {
    if items.is_empty() {
        return Ok((
            None,
            TextPrefilterHint {
                any: true,
                ..Default::default()
            },
        ));
    }

    let mut exact = HashSet::new();
    let mut suffix = Vec::new();
    let mut suffix_seen = HashSet::new();
    let mut complex = Vec::new();
    let mut glob_patterns = Vec::new();
    let mut regex = Vec::new();
    let mut hint = TextPrefilterHint {
        any: false,
        ..Default::default()
    };

    for item in items {
        let normalized = if lowercase {
            item.to_ascii_lowercase()
        } else {
            item.clone()
        };

        if let Some(pattern) = extract_regex_pattern(&normalized) {
            hint.complex = true;
            regex.push(Regex::new(pattern)?);
            continue;
        }

        if is_exact_pattern(&normalized) {
            let value = interner.intern(normalized.as_str());
            if exact.insert(value.clone()) {
                hint.exact.push(value);
            }
            continue;
        }

        if allow_domain_suffix && let Some(suffix_text) = extract_domain_suffix(&normalized) {
            let suffix_interned = interner.intern(suffix_text);
            if suffix_seen.insert(suffix_interned.clone()) {
                suffix.push(suffix_interned.clone());
                hint.suffix.push(suffix_interned);
            }
            continue;
        }

        hint.complex = true;
        let value = interner.intern(normalized.as_str());
        glob_patterns.push(value);
        complex.push(normalized);
    }

    Ok((
        Some(TextPatternMatcher {
            exact,
            suffix,
            glob_patterns,
            glob: build_globset(&complex)?,
            regex,
            lowercase_input: lowercase,
        }),
        hint,
    ))
}

pub(crate) fn dedup_uppercase_arc(
    items: &[String],
    interner: &mut StringInterner,
) -> Vec<Arc<str>> {
    let mut out = Vec::with_capacity(items.len());
    let mut seen: HashSet<Arc<str>> = HashSet::new();
    for item in items {
        let interned = interner.intern_upper(item);
        if seen.insert(interned.clone()) {
            out.push(interned);
        }
    }
    out
}
