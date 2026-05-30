use anyhow::Result;
use cidr::IpCidr;
use globset::{Glob, GlobSet, GlobSetBuilder};
use qpx_core::config::{Config, NamedSetKind};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

use super::patterns::{
    extract_regex_pattern, host_matches_suffix, is_exact_pattern, normalize_regex_pattern,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationClassifier {
    pub(super) category: Vec<LabeledPatternSet>,
    pub(super) reputation: Vec<LabeledPatternSet>,
    pub(super) application: Vec<LabeledPatternSet>,
}

#[derive(Debug, Clone)]
pub(super) struct LabeledPatternSet {
    pub(super) label: String,
    pub(super) kind: NamedSetKind,
    pub(super) patterns: PatternSet,
}

#[derive(Debug, Clone, Default)]
pub(super) struct PatternSet {
    pub(super) exact: HashSet<String>,
    pub(super) suffix: Vec<String>,
    pub(super) glob: Option<GlobSet>,
    pub(super) regex: Vec<Regex>,
    pub(super) cidr: Vec<IpCidr>,
}

impl DestinationClassifier {
    pub(crate) fn from_config(config: &Config) -> Result<Self> {
        let mut classifier = Self::default();
        for set in &config.security.named_sets {
            let Some((kind, label)) = parse_destination_set_name(set.name.as_str()) else {
                continue;
            };
            if !matches!(
                set.kind,
                NamedSetKind::Cidr
                    | NamedSetKind::Domain
                    | NamedSetKind::String
                    | NamedSetKind::Regex
            ) {
                continue;
            }
            let mut values = set.values.clone();
            if let Some(path) = set.file.as_deref() {
                let content = fs::read_to_string(path)?;
                values.extend(
                    content
                        .lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty() && !line.starts_with('#'))
                        .map(str::to_string),
                );
            }
            let patterns = PatternSet::compile(&values, &set.kind)?;
            if patterns.is_empty() {
                continue;
            }
            let entry = LabeledPatternSet {
                label,
                kind: set.kind.clone(),
                patterns,
            };
            match kind {
                DestinationSetKind::Category => classifier.category.push(entry),
                DestinationSetKind::Reputation => classifier.reputation.push(entry),
                DestinationSetKind::Application => classifier.application.push(entry),
            }
        }
        Ok(classifier)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DestinationSetKind {
    Category,
    Reputation,
    Application,
}

fn parse_destination_set_name(name: &str) -> Option<(DestinationSetKind, String)> {
    for (prefix, kind) in [
        ("category:", DestinationSetKind::Category),
        ("category/", DestinationSetKind::Category),
        ("reputation:", DestinationSetKind::Reputation),
        ("reputation/", DestinationSetKind::Reputation),
        ("application:", DestinationSetKind::Application),
        ("application/", DestinationSetKind::Application),
    ] {
        if let Some(label) = name.strip_prefix(prefix) {
            let label = label.trim();
            if !label.is_empty() {
                return Some((kind, label.to_string()));
            }
        }
    }
    None
}

impl PatternSet {
    fn compile(values: &[String], kind: &NamedSetKind) -> Result<Self> {
        let mut exact = HashSet::new();
        let mut suffix = Vec::new();
        let mut glob_values = Vec::new();
        let mut regex = Vec::new();
        let mut cidr = Vec::new();

        for value in values {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match kind {
                NamedSetKind::Regex => {
                    regex.push(Regex::new(normalize_regex_pattern(value))?);
                }
                NamedSetKind::Cidr => {
                    cidr.push(value.parse()?);
                }
                NamedSetKind::Domain => {
                    let normalized = value.trim_end_matches('.').to_ascii_lowercase();
                    if let Some(rest) = normalized.strip_prefix("*.")
                        && !rest.is_empty()
                        && is_exact_pattern(rest)
                    {
                        suffix.push(rest.to_string());
                        continue;
                    }
                    if is_exact_pattern(normalized.as_str()) {
                        exact.insert(normalized);
                    } else if let Some(pattern) = extract_regex_pattern(normalized.as_str()) {
                        regex.push(Regex::new(pattern)?);
                    } else {
                        glob_values.push(normalized);
                    }
                }
                _ => {
                    let normalized = value.to_ascii_lowercase();
                    if let Some(pattern) = extract_regex_pattern(normalized.as_str()) {
                        regex.push(Regex::new(pattern)?);
                    } else if is_exact_pattern(normalized.as_str()) {
                        exact.insert(normalized);
                    } else {
                        glob_values.push(normalized);
                    }
                }
            }
        }

        Ok(Self {
            exact,
            suffix,
            glob: build_globset(&glob_values)?,
            regex,
            cidr,
        })
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.glob.is_none()
            && self.regex.is_empty()
            && self.cidr.is_empty()
    }

    pub(super) fn matches_text(&self, value: &str) -> bool {
        if self.exact.contains(value) {
            return true;
        }
        if self
            .suffix
            .iter()
            .any(|suffix| host_matches_suffix(value, suffix.as_str()))
        {
            return true;
        }
        if self
            .glob
            .as_ref()
            .map(|glob| glob.is_match(value))
            .unwrap_or(false)
        {
            return true;
        }
        self.regex.iter().any(|pattern| pattern.is_match(value))
    }

    pub(super) fn matches_ip(&self, ip: &IpAddr) -> bool {
        self.cidr.iter().any(|cidr| cidr.contains(ip))
    }
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
