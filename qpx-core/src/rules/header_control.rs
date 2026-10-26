use crate::config::HeaderControl;
use crate::http_message::{Headers, OrdinaryHeaderName};

use super::Result;

#[derive(Debug, Clone)]
struct CompiledRegexReplace {
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

    /// Applies request mutations to a transitional raw map.
    /// Prefer [`Self::apply_request_owned`] for in-domain messages.
    ///
    /// Returns the header names whose regex replacement produced an invalid
    /// value, in execution order with repetitions preserved. Callers report
    /// one diagnostic per entry.
    pub fn apply_request(&self, headers: &mut http::HeaderMap) -> Vec<http::header::HeaderName> {
        apply_mutations(
            headers,
            &self.request_set,
            &self.request_add,
            &self.request_remove,
            &self.request_regex_replace,
        )
    }

    /// Applies response mutations to a transitional raw map.
    /// Prefer [`Self::apply_response_owned`] for in-domain messages.
    ///
    /// Returns the header names whose regex replacement produced an invalid
    /// value, in execution order with repetitions preserved. Callers report
    /// one diagnostic per entry.
    pub fn apply_response(&self, headers: &mut http::HeaderMap) -> Vec<http::header::HeaderName> {
        apply_mutations(
            headers,
            &self.response_set,
            &self.response_add,
            &self.response_remove,
            &self.response_regex_replace,
        )
    }

    /// Applies request policy to owned headers without exposing stored values.
    ///
    /// Like [`Self::apply_request`], returns invalid replacement names in
    /// execution order, including repetitions. Literal Content-Length set/add
    /// values are preserved; framing validation remains the owner's job.
    pub fn apply_request_owned(&self, headers: &mut Headers) -> Vec<http::header::HeaderName> {
        apply_mutations(
            headers,
            &self.request_set,
            &self.request_add,
            &self.request_remove,
            &self.request_regex_replace,
        )
    }

    /// Applies response policy to owned headers, with the same diagnostics and
    /// literal-value semantics as [`Self::apply_request_owned`].
    pub fn apply_response_owned(&self, headers: &mut Headers) -> Vec<http::header::HeaderName> {
        apply_mutations(
            headers,
            &self.response_set,
            &self.response_add,
            &self.response_remove,
            &self.response_regex_replace,
        )
    }

    /// Number of response `set`/`add` entries, for capacity reservation only.
    pub fn response_reserve_hint(&self) -> usize {
        self.response_set
            .len()
            .saturating_add(self.response_add.len())
    }

    /// Reports whether this plan can modify response headers.
    pub fn has_response_mutations(&self) -> bool {
        !self.response_set.is_empty()
            || !self.response_add.is_empty()
            || !self.response_remove.is_empty()
            || !self.response_regex_replace.is_empty()
    }
}

// Private capability boundary: implementations accept configured literals but
// never return stored field values, even to the shared mutation engine.
trait MutationTarget {
    fn reserve(&mut self, additional: usize);
    fn set(&mut self, name: http::header::HeaderName, value: http::HeaderValue);
    fn add(&mut self, name: http::header::HeaderName, value: http::HeaderValue);
    fn remove(&mut self, name: &http::header::HeaderName);
    fn replace(&mut self, operation: &CompiledRegexReplace) -> bool;
}

impl MutationTarget for http::HeaderMap {
    fn reserve(&mut self, additional: usize) {
        self.reserve(additional);
    }
    fn set(&mut self, name: http::header::HeaderName, value: http::HeaderValue) {
        self.insert(name, value);
    }
    fn add(&mut self, name: http::header::HeaderName, value: http::HeaderValue) {
        self.append(name, value);
    }
    fn remove(&mut self, name: &http::header::HeaderName) {
        self.remove(name);
    }
    fn replace(&mut self, operation: &CompiledRegexReplace) -> bool {
        crate::http_message::replace_header_regex(
            self,
            &operation.header,
            &operation.pattern,
            &operation.replace,
        )
    }
}

impl MutationTarget for Headers {
    fn reserve(&mut self, additional: usize) {
        self.reserve(additional);
    }
    fn set(&mut self, name: http::header::HeaderName, value: http::HeaderValue) {
        if let Ok(name) = OrdinaryHeaderName::try_from(name) {
            self.insert(name, value);
        } else {
            self.set_content_length_value(value);
        }
    }
    fn add(&mut self, name: http::header::HeaderName, value: http::HeaderValue) {
        if let Ok(name) = OrdinaryHeaderName::try_from(name) {
            self.append(name, value);
        } else {
            self.append_content_length_value(value);
        }
    }
    fn remove(&mut self, name: &http::header::HeaderName) {
        if let Ok(name) = OrdinaryHeaderName::try_from(name.clone()) {
            self.remove(&name);
        } else {
            self.remove_content_length();
        }
    }
    fn replace(&mut self, operation: &CompiledRegexReplace) -> bool {
        self.replace_header_regex(&operation.header, &operation.pattern, &operation.replace)
    }
}

fn apply_mutations(
    headers: &mut impl MutationTarget,
    set: &[(http::header::HeaderName, http::HeaderValue)],
    add: &[(http::header::HeaderName, http::HeaderValue)],
    remove: &[http::header::HeaderName],
    regex_replace: &[CompiledRegexReplace],
) -> Vec<http::header::HeaderName> {
    headers.reserve(set.len().saturating_add(add.len()));
    for (name, value) in set {
        headers.set(name.clone(), value.clone());
    }
    for (name, value) in add {
        headers.add(name.clone(), value.clone());
    }
    for name in remove {
        headers.remove(name);
    }
    let mut invalid = Vec::new();
    for replace in regex_replace {
        if headers.replace(replace) {
            invalid.push(replace.header.clone());
        }
    }
    invalid
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RegexReplace;
    use std::collections::HashMap;

    fn empty_control() -> HeaderControl {
        HeaderControl {
            request_set: HashMap::new(),
            request_add: HashMap::new(),
            request_remove: Vec::new(),
            request_regex_replace: Vec::new(),
            response_set: HashMap::new(),
            response_add: HashMap::new(),
            response_remove: Vec::new(),
            response_regex_replace: Vec::new(),
        }
    }

    fn compile(control: &HeaderControl) -> CompiledHeaderControl {
        CompiledHeaderControl::compile(control).expect("compile header control")
    }

    fn response_control(
        set: Vec<(&str, &str)>,
        add: Vec<(&str, &str)>,
        remove: Vec<&str>,
        regex: Vec<(&str, &str, &str)>,
    ) -> CompiledHeaderControl {
        let mut raw = empty_control();
        for (name, value) in set {
            raw.response_set.insert(name.to_string(), value.to_string());
        }
        for (name, value) in add {
            raw.response_add.insert(name.to_string(), value.to_string());
        }
        raw.response_remove = remove.into_iter().map(str::to_string).collect();
        raw.response_regex_replace = regex
            .into_iter()
            .map(|(header, pattern, replace)| RegexReplace {
                header: header.to_string(),
                pattern: pattern.to_string(),
                replace: replace.to_string(),
            })
            .collect();
        compile(&raw)
    }

    fn request_control(
        set: Vec<(&str, &str)>,
        regex: Vec<(&str, &str, &str)>,
    ) -> CompiledHeaderControl {
        let mut raw = empty_control();
        for (name, value) in set {
            raw.request_set.insert(name.to_string(), value.to_string());
        }
        raw.request_regex_replace = regex
            .into_iter()
            .map(|(header, pattern, replace)| RegexReplace {
                header: header.to_string(),
                pattern: pattern.to_string(),
                replace: replace.to_string(),
            })
            .collect();
        compile(&raw)
    }

    #[test]
    fn regex_without_match_collapses_duplicates() {
        let control = response_control(vec![], vec![], vec![], vec![("x-dup", "zzz", "yyy")]);
        let mut headers = http::HeaderMap::new();
        headers.append("x-dup", http::HeaderValue::from_static("a"));
        headers.append("x-dup", http::HeaderValue::from_static("a"));
        assert_eq!(headers.get_all("x-dup").iter().count(), 2);
        let invalid = control.apply_response(&mut headers);
        assert!(invalid.is_empty());
        let values: Vec<_> = headers.get_all("x-dup").iter().collect();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], "a");
    }

    #[test]
    fn invalid_first_value_text_skips_silently() {
        let control = response_control(vec![], vec![], vec![], vec![("x-opaque", "a", "b")]);
        let mut headers = http::HeaderMap::new();
        let opaque = http::HeaderValue::from_bytes(b"\xff").expect("opaque value");
        headers.append("x-opaque", opaque.clone());
        headers.append("x-opaque", http::HeaderValue::from_static("valid"));
        let invalid = control.apply_response(&mut headers);
        assert!(invalid.is_empty());
        let values: Vec<_> = headers.get_all("x-opaque").iter().collect();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], &opaque);
        assert_eq!(values[1], "valid");
    }

    #[test]
    fn invalid_generated_value_leaves_header_and_continues() {
        let control = response_control(
            vec![],
            vec![],
            vec![],
            vec![("x-bad", "ok", "bad\nvalue"), ("x-good", "ok", "fine")],
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("x-bad", http::HeaderValue::from_static("ok"));
        headers.insert("x-good", http::HeaderValue::from_static("ok"));
        let invalid = control.apply_response(&mut headers);
        assert_eq!(invalid, vec!["x-bad"]);
        assert_eq!(headers.get("x-bad").unwrap(), "ok");
        assert_eq!(headers.get("x-good").unwrap(), "fine");
    }

    #[test]
    fn repeated_failures_preserve_order_and_repetition() {
        let control = response_control(
            vec![],
            vec![],
            vec![],
            vec![
                ("x-first", "ok", "bad\none"),
                ("x-second", "ok", "bad\ntwo"),
                ("x-first", "ok", "bad\nthree"),
            ],
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("x-first", http::HeaderValue::from_static("ok"));
        headers.insert("x-second", http::HeaderValue::from_static("ok"));
        let invalid = control.apply_response(&mut headers);
        assert_eq!(invalid.len(), 3);
        assert_eq!(invalid[0], "x-first");
        assert_eq!(invalid[1], "x-second");
        assert_eq!(invalid[2], "x-first");
        assert_eq!(headers.get("x-first").unwrap(), "ok");
        assert_eq!(headers.get("x-second").unwrap(), "ok");
    }

    #[test]
    fn later_replacements_see_earlier_results() {
        let control = response_control(
            vec![],
            vec![],
            vec![],
            vec![("x-chain", "foo", "bar"), ("x-chain", "bar", "baz")],
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("x-chain", http::HeaderValue::from_static("foo"));
        let invalid = control.apply_response(&mut headers);
        assert!(invalid.is_empty());
        assert_eq!(headers.get("x-chain").unwrap(), "baz");
    }

    #[test]
    fn replacement_expands_captures_for_all_matches() {
        let control = response_control(
            vec![],
            vec![],
            vec![],
            vec![("x-expand", "(mid)", "prefix-$1-suffix")],
        );
        let mut headers = http::HeaderMap::new();
        headers.insert("x-expand", http::HeaderValue::from_static("mid mid"));
        let invalid = control.apply_response(&mut headers);
        assert!(invalid.is_empty());
        assert_eq!(
            headers.get("x-expand").unwrap(),
            "prefix-mid-suffix prefix-mid-suffix"
        );
    }

    #[test]
    fn mutation_stages_run_set_add_remove_then_regex() {
        let control = response_control(
            vec![("x-stage", "set"), ("x-remove", "set")],
            vec![("x-stage", "add"), ("x-remove", "add")],
            vec!["x-remove"],
            vec![
                ("x-stage", "set", "regex"),
                ("x-remove", ".*", "reappeared"),
            ],
        );
        let mut headers = http::HeaderMap::new();
        let invalid = control.apply_response(&mut headers);
        assert!(invalid.is_empty());
        let stage_values: Vec<_> = headers.get_all("x-stage").iter().collect();
        assert_eq!(stage_values.len(), 1);
        assert_eq!(stage_values[0], "regex");
        assert!(!headers.contains_key("x-remove"));
    }

    #[test]
    fn merged_conflict_prefers_later_set() {
        let base = response_control(vec![("x-merge", "base")], vec![], vec![], vec![]);
        let extra = response_control(vec![("x-merge", "extra")], vec![], vec![], vec![]);
        let merged = base.merged(&extra);
        let mut headers = http::HeaderMap::new();
        let invalid = merged.apply_response(&mut headers);
        assert!(invalid.is_empty());
        assert_eq!(headers.get("x-merge").unwrap(), "extra");
    }

    #[test]
    fn merged_keeps_set_before_add_across_plans() {
        let mut base_raw = empty_control();
        base_raw
            .response_add
            .insert("x-cross".to_string(), "base-add".to_string());
        let base = compile(&base_raw);
        let mut extra_raw = empty_control();
        extra_raw
            .response_set
            .insert("x-cross".to_string(), "extra-set".to_string());
        let extra = compile(&extra_raw);
        let merged = base.merged(&extra);
        let mut headers = http::HeaderMap::new();
        let invalid = merged.apply_response(&mut headers);
        assert!(invalid.is_empty());
        let values: Vec<_> = headers
            .get_all("x-cross")
            .iter()
            .map(|v| v.to_str().expect("text").to_string())
            .collect();
        assert_eq!(
            values,
            vec!["extra-set".to_string(), "base-add".to_string()]
        );
    }

    #[test]
    fn request_and_response_plans_are_isolated() {
        let mut raw = empty_control();
        raw.request_set
            .insert("x-req".to_string(), "req".to_string());
        raw.response_set
            .insert("x-resp".to_string(), "resp".to_string());
        let control = compile(&raw);
        let mut request_headers = http::HeaderMap::new();
        let mut response_headers = http::HeaderMap::new();
        assert!(control.apply_request(&mut request_headers).is_empty());
        assert!(control.apply_response(&mut response_headers).is_empty());
        assert_eq!(request_headers.get("x-req").unwrap(), "req");
        assert!(request_headers.get("x-resp").is_none());
        assert_eq!(response_headers.get("x-resp").unwrap(), "resp");
        assert!(response_headers.get("x-req").is_none());
    }

    #[test]
    fn configured_content_length_mutation_applies() {
        let request = request_control(vec![("content-length", "5")], vec![]);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            http::HeaderValue::from_static("99"),
        );
        assert!(request.apply_request(&mut headers).is_empty());
        assert_eq!(headers.get(http::header::CONTENT_LENGTH).unwrap(), "5");

        let response = response_control(vec![("content-length", "7")], vec![], vec![], vec![]);
        let mut response_headers = http::HeaderMap::new();
        assert!(response.apply_response(&mut response_headers).is_empty());
        assert_eq!(
            response_headers.get(http::header::CONTENT_LENGTH).unwrap(),
            "7"
        );
    }
}
