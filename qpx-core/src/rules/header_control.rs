use crate::config::HeaderControl;

use super::Result;

/// Compiled regex replacement for one HTTP header.
#[derive(Debug, Clone)]
pub struct CompiledRegexReplace {
    header: http::header::HeaderName,
    pattern: regex::Regex,
    replace: String,
}

/// Parsed and validated request/response header mutation plan.
#[derive(Debug, Clone)]
pub struct CompiledHeaderControl {
    request_set: Vec<(http::header::HeaderName, http::HeaderValue)>,
    request_add: Vec<(http::header::HeaderName, http::HeaderValue)>,
    request_remove: Vec<http::header::HeaderName>,
    request_regex_replace: Vec<CompiledRegexReplace>,
    response_set: Vec<(http::header::HeaderName, http::HeaderValue)>,
    response_add: Vec<(http::header::HeaderName, http::HeaderValue)>,
    response_remove: Vec<http::header::HeaderName>,
    response_regex_replace: Vec<CompiledRegexReplace>,
}

impl CompiledHeaderControl {
    /// Compiles raw config header mutations into typed header names and values.
    pub fn compile(raw: &HeaderControl) -> Result<Self> {
        Ok(Self {
            request_set: compile_header_set(&raw.request_set, "request_set")?,
            request_add: compile_header_set(&raw.request_add, "request_add")?,
            request_remove: compile_header_remove(&raw.request_remove, "request_remove")?,
            request_regex_replace: compile_regex_replace(
                &raw.request_regex_replace,
                "request_regex_replace",
            )?,
            response_set: compile_header_set(&raw.response_set, "response_set")?,
            response_add: compile_header_set(&raw.response_add, "response_add")?,
            response_remove: compile_header_remove(&raw.response_remove, "response_remove")?,
            response_regex_replace: compile_regex_replace(
                &raw.response_regex_replace,
                "response_regex_replace",
            )?,
        })
    }

    /// Returns request headers that should be replaced or inserted.
    pub fn request_set(&self) -> &[(http::header::HeaderName, http::HeaderValue)] {
        &self.request_set
    }

    /// Returns a new header-control plan with `other` appended after `self`.
    pub fn merged(&self, other: &CompiledHeaderControl) -> Self {
        let mut merged = self.clone();
        merged.request_set.extend(other.request_set.iter().cloned());
        merged.request_add.extend(other.request_add.iter().cloned());
        merged
            .request_remove
            .extend(other.request_remove.iter().cloned());
        merged
            .request_regex_replace
            .extend(other.request_regex_replace.iter().cloned());
        merged
            .response_set
            .extend(other.response_set.iter().cloned());
        merged
            .response_add
            .extend(other.response_add.iter().cloned());
        merged
            .response_remove
            .extend(other.response_remove.iter().cloned());
        merged
            .response_regex_replace
            .extend(other.response_regex_replace.iter().cloned());
        merged
    }

    /// Returns request headers that should be appended.
    pub fn request_add(&self) -> &[(http::header::HeaderName, http::HeaderValue)] {
        &self.request_add
    }

    /// Returns request headers that should be removed.
    pub fn request_remove(&self) -> &[http::header::HeaderName] {
        &self.request_remove
    }

    /// Returns request header regex replacements.
    pub fn request_regex_replace(&self) -> &[CompiledRegexReplace] {
        &self.request_regex_replace
    }

    /// Returns response headers that should be replaced or inserted.
    pub fn response_set(&self) -> &[(http::header::HeaderName, http::HeaderValue)] {
        &self.response_set
    }

    /// Returns response headers that should be appended.
    pub fn response_add(&self) -> &[(http::header::HeaderName, http::HeaderValue)] {
        &self.response_add
    }

    /// Returns response headers that should be removed.
    pub fn response_remove(&self) -> &[http::header::HeaderName] {
        &self.response_remove
    }

    /// Returns response header regex replacements.
    pub fn response_regex_replace(&self) -> &[CompiledRegexReplace] {
        &self.response_regex_replace
    }

    /// Reports whether this plan can modify response headers.
    pub fn has_response_mutations(&self) -> bool {
        !self.response_set.is_empty()
            || !self.response_add.is_empty()
            || !self.response_remove.is_empty()
            || !self.response_regex_replace.is_empty()
    }
}

impl CompiledRegexReplace {
    /// Header to which the regex replacement applies.
    pub fn header(&self) -> &http::header::HeaderName {
        &self.header
    }

    /// Compiled regex pattern.
    pub fn pattern(&self) -> &regex::Regex {
        &self.pattern
    }

    /// Replacement string passed to the regex engine.
    pub fn replace(&self) -> &str {
        &self.replace
    }
}

fn compile_header_set(
    raw: &std::collections::HashMap<String, String>,
    context: &str,
) -> Result<Vec<(http::header::HeaderName, http::HeaderValue)>> {
    let mut out = Vec::with_capacity(raw.len());
    for (name, value) in raw {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow::anyhow!("{context}: invalid header name: {name}"))?;
        let value = http::HeaderValue::from_str(value.as_str())
            .map_err(|_| anyhow::anyhow!("{context}: invalid header value for {name}"))?;
        out.push((name, value));
    }
    Ok(out)
}

fn compile_header_remove(raw: &[String], context: &str) -> Result<Vec<http::header::HeaderName>> {
    let mut out = Vec::with_capacity(raw.len());
    for name in raw {
        let name = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow::anyhow!("{context}: invalid header name: {name}"))?;
        out.push(name);
    }
    Ok(out)
}

fn compile_regex_replace(
    raw: &[crate::config::RegexReplace],
    context: &str,
) -> Result<Vec<CompiledRegexReplace>> {
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let header = http::header::HeaderName::from_bytes(item.header.as_bytes())
            .map_err(|_| anyhow::anyhow!("{context}: invalid header name: {}", item.header))?;
        let pattern = regex::Regex::new(item.pattern.as_str())
            .map_err(|e| anyhow::anyhow!("{context}: invalid regex {}: {}", item.pattern, e))?;
        out.push(CompiledRegexReplace {
            header,
            pattern,
            replace: item.replace.clone(),
        });
    }
    Ok(out)
}
