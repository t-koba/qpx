use anyhow::Result;
use cidr::IpCidr;
use globset::{Glob, GlobSet, GlobSetBuilder};
use qpx_core::config::{
    Config, DestinationConflictMode, DestinationEvidenceSourceKind, DestinationMergeMode,
    DestinationResolutionOverrideConfig, DestinationResolutionPolicyConfig, NamedSetKind,
};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationMetadata {
    pub(crate) category: Option<String>,
    pub(crate) category_source: Option<String>,
    pub(crate) category_confidence: Option<u8>,
    pub(crate) reputation: Option<String>,
    pub(crate) reputation_source: Option<String>,
    pub(crate) reputation_confidence: Option<u8>,
    pub(crate) application: Option<String>,
    pub(crate) application_source: Option<String>,
    pub(crate) application_confidence: Option<u8>,
    pub(crate) category_trace: Option<String>,
    pub(crate) reputation_trace: Option<String>,
    pub(crate) application_trace: Option<String>,
}

impl DestinationMetadata {
    pub(crate) fn decision_trace(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(trace) = self.category_trace.as_deref() {
            parts.push(trace.to_string());
        }
        if let Some(trace) = self.reputation_trace.as_deref() {
            parts.push(trace.to_string());
        }
        if let Some(trace) = self.application_trace.as_deref() {
            parts.push(trace.to_string());
        }
        (!parts.is_empty()).then(|| parts.join(" | "))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledDestinationResolutionPolicy {
    precedence: Vec<DestinationEvidenceClass>,
    conflict_mode: DestinationConflictMode,
    merge_mode: DestinationMergeMode,
    min_confidence: DestinationMinConfidence,
}

impl Default for CompiledDestinationResolutionPolicy {
    fn default() -> Self {
        Self::from_config(&DestinationResolutionPolicyConfig::default())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DestinationMinConfidence {
    category: Option<u8>,
    reputation: Option<u8>,
    application: Option<u8>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationInputs<'a> {
    pub(crate) host: Option<&'a str>,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) scheme: Option<&'a str>,
    pub(crate) port: Option<u16>,
    pub(crate) alpn: Option<&'a str>,
    pub(crate) ja3: Option<&'a str>,
    pub(crate) ja4: Option<&'a str>,
    pub(crate) cert_subject: Option<&'a str>,
    pub(crate) cert_issuer: Option<&'a str>,
    pub(crate) cert_san_dns: &'a [String],
    pub(crate) cert_san_uri: &'a [String],
    pub(crate) cert_fingerprint_sha256: Option<&'a str>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationClassifier {
    category: Vec<LabeledPatternSet>,
    reputation: Vec<LabeledPatternSet>,
    application: Vec<LabeledPatternSet>,
}

#[derive(Debug, Clone)]
struct LabeledPatternSet {
    label: String,
    kind: NamedSetKind,
    patterns: PatternSet,
}

#[derive(Debug, Clone, Default)]
struct PatternSet {
    exact: HashSet<String>,
    suffix: Vec<String>,
    glob: Option<GlobSet>,
    regex: Vec<Regex>,
    cidr: Vec<IpCidr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationEvidenceKind {
    Category,
    Reputation,
    Application,
}

impl DestinationClassifier {
    pub(crate) fn from_config(config: &Config) -> Result<Self> {
        let mut classifier = Self::default();
        for set in &config.named_sets {
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

    pub(crate) fn classify(
        &self,
        inputs: &DestinationInputs<'_>,
        policy: &CompiledDestinationResolutionPolicy,
    ) -> DestinationMetadata {
        let mut out = DestinationMetadata::default();
        let category = collect_candidates(
            self.category.as_slice(),
            DestinationEvidenceKind::Category,
            inputs,
        );
        if let Some(candidate) = resolve_candidate(
            category.as_slice(),
            DestinationEvidenceKind::Category,
            policy,
        ) {
            out.category = Some(candidate.label);
            out.category_source = Some(candidate.source.as_str().to_string());
            out.category_confidence = Some(candidate.confidence);
        }
        out.category_trace = Some(format_resolution_trace(
            "category",
            category.as_slice(),
            out.category.as_deref(),
            out.category_source.as_deref(),
            out.category_confidence,
        ));
        let reputation = collect_candidates(
            self.reputation.as_slice(),
            DestinationEvidenceKind::Reputation,
            inputs,
        );
        if let Some(candidate) = resolve_candidate(
            reputation.as_slice(),
            DestinationEvidenceKind::Reputation,
            policy,
        ) {
            out.reputation = Some(candidate.label);
            out.reputation_source = Some(candidate.source.as_str().to_string());
            out.reputation_confidence = Some(candidate.confidence);
        }
        out.reputation_trace = Some(format_resolution_trace(
            "reputation",
            reputation.as_slice(),
            out.reputation.as_deref(),
            out.reputation_source.as_deref(),
            out.reputation_confidence,
        ));
        let mut application = collect_candidates(
            self.application.as_slice(),
            DestinationEvidenceKind::Application,
            inputs,
        );
        if let Some(label) = infer_application(inputs.scheme, inputs.port, inputs.alpn) {
            application.push(DestinationCandidate {
                label: label.to_string(),
                confidence: score_for_source(
                    DestinationEvidenceKind::Application,
                    DestinationEvidenceSource::Heuristic,
                ),
                source: DestinationEvidenceSource::Heuristic,
                class: DestinationEvidenceClass::Heuristic,
            });
        }
        if let Some(candidate) = resolve_candidate(
            application.as_slice(),
            DestinationEvidenceKind::Application,
            policy,
        ) {
            out.application = Some(candidate.label);
            out.application_source = Some(candidate.source.as_str().to_string());
            out.application_confidence = Some(candidate.confidence);
        }
        out.application_trace = Some(format_resolution_trace(
            "application",
            application.as_slice(),
            out.application.as_deref(),
            out.application_source.as_deref(),
            out.application_confidence,
        ));
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationSetKind {
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
                    if let Some(rest) = normalized.strip_prefix("*.") {
                        if !rest.is_empty() && is_exact_pattern(rest) {
                            suffix.push(rest.to_string());
                            continue;
                        }
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

    fn matches_text(&self, value: &str) -> bool {
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

    fn matches_ip(&self, ip: &IpAddr) -> bool {
        self.cidr.iter().any(|cidr| cidr.contains(ip))
    }
}

fn collect_candidates(
    entries: &[LabeledPatternSet],
    evidence_kind: DestinationEvidenceKind,
    inputs: &DestinationInputs<'_>,
) -> Vec<DestinationCandidate> {
    entries
        .iter()
        .filter_map(|entry| entry.best_candidate(evidence_kind, inputs))
        .collect()
}

impl LabeledPatternSet {
    fn best_candidate(
        &self,
        evidence_kind: DestinationEvidenceKind,
        inputs: &DestinationInputs<'_>,
    ) -> Option<DestinationCandidate> {
        match self.kind {
            NamedSetKind::Cidr => destination_ip(inputs)
                .filter(|ip| self.patterns.matches_ip(ip))
                .map(|_| DestinationCandidate {
                    label: self.label.clone(),
                    confidence: score_for_source(evidence_kind, DestinationEvidenceSource::Ip),
                    source: DestinationEvidenceSource::Ip,
                    class: DestinationEvidenceClass::Ip,
                }),
            NamedSetKind::Domain => {
                let mut best = None;
                for (value, source) in domain_evidence(inputs) {
                    if self.patterns.matches_text(value.as_str()) {
                        let score = score_for_source(evidence_kind, source);
                        if best
                            .as_ref()
                            .is_none_or(|current: &DestinationCandidate| score > current.confidence)
                        {
                            best = Some(DestinationCandidate {
                                label: self.label.clone(),
                                confidence: score,
                                source,
                                class: source.class(),
                            });
                        }
                    }
                }
                best
            }
            NamedSetKind::String
            | NamedSetKind::Regex
            | NamedSetKind::Category
            | NamedSetKind::Reputation => {
                let mut best = None;
                for (value, source) in string_evidence(inputs, evidence_kind) {
                    if self.patterns.matches_text(value.as_str()) {
                        let score = score_for_source(evidence_kind, source);
                        if best
                            .as_ref()
                            .is_none_or(|current: &DestinationCandidate| score > current.confidence)
                        {
                            best = Some(DestinationCandidate {
                                label: self.label.clone(),
                                confidence: score,
                                source,
                                class: source.class(),
                            });
                        }
                    }
                }
                best
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DestinationEvidenceClass {
    PolicyContext,
    Cert,
    Sni,
    Host,
    Ip,
    TlsFingerprint,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DestinationCandidate {
    label: String,
    confidence: u8,
    source: DestinationEvidenceSource,
    class: DestinationEvidenceClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationEvidenceSource {
    Host,
    Sni,
    Ip,
    Alpn,
    SanDns,
    SanUri,
    CertSubject,
    CertIssuer,
    FingerprintJa4,
    FingerprintJa3,
    CertFingerprint,
    Heuristic,
}

impl DestinationEvidenceSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Sni => "sni",
            Self::Ip => "ip",
            Self::Alpn => "alpn",
            Self::SanDns => "cert_san_dns",
            Self::SanUri => "cert_san_uri",
            Self::CertSubject => "cert_subject",
            Self::CertIssuer => "cert_issuer",
            Self::FingerprintJa4 => "ja4",
            Self::FingerprintJa3 => "ja3",
            Self::CertFingerprint => "cert_fingerprint",
            Self::Heuristic => "heuristic",
        }
    }

    fn class(self) -> DestinationEvidenceClass {
        match self {
            Self::Host => DestinationEvidenceClass::Host,
            Self::Sni => DestinationEvidenceClass::Sni,
            Self::Ip => DestinationEvidenceClass::Ip,
            Self::Alpn => DestinationEvidenceClass::Heuristic,
            Self::SanDns
            | Self::SanUri
            | Self::CertSubject
            | Self::CertIssuer
            | Self::CertFingerprint => DestinationEvidenceClass::Cert,
            Self::FingerprintJa4 | Self::FingerprintJa3 => DestinationEvidenceClass::TlsFingerprint,
            Self::Heuristic => DestinationEvidenceClass::Heuristic,
        }
    }
}

impl CompiledDestinationResolutionPolicy {
    pub(crate) fn from_config(config: &DestinationResolutionPolicyConfig) -> Self {
        Self {
            precedence: config
                .precedence
                .iter()
                .copied()
                .map(DestinationEvidenceClass::from)
                .collect(),
            conflict_mode: config.conflict_mode,
            merge_mode: config.merge_mode,
            min_confidence: DestinationMinConfidence {
                category: config.min_confidence.category,
                reputation: config.min_confidence.reputation,
                application: config.min_confidence.application,
            },
        }
    }

    pub(crate) fn with_override(
        &self,
        override_cfg: Option<&DestinationResolutionOverrideConfig>,
    ) -> Self {
        let Some(override_cfg) = override_cfg else {
            return self.clone();
        };
        let mut merged = self.clone();
        if let Some(precedence) = override_cfg.precedence.as_ref() {
            merged.precedence = precedence
                .iter()
                .copied()
                .map(DestinationEvidenceClass::from)
                .collect();
        }
        if let Some(conflict_mode) = override_cfg.conflict_mode.as_ref() {
            merged.conflict_mode = *conflict_mode;
        }
        if let Some(merge_mode) = override_cfg.merge_mode.as_ref() {
            merged.merge_mode = *merge_mode;
        }
        if let Some(min_confidence) = override_cfg.min_confidence.as_ref() {
            merged.min_confidence = DestinationMinConfidence {
                category: min_confidence.category.or(merged.min_confidence.category),
                reputation: min_confidence
                    .reputation
                    .or(merged.min_confidence.reputation),
                application: min_confidence
                    .application
                    .or(merged.min_confidence.application),
            };
        }
        merged
    }
}

impl From<DestinationEvidenceSourceKind> for DestinationEvidenceClass {
    fn from(value: DestinationEvidenceSourceKind) -> Self {
        match value {
            DestinationEvidenceSourceKind::PolicyContext => Self::PolicyContext,
            DestinationEvidenceSourceKind::Cert => Self::Cert,
            DestinationEvidenceSourceKind::Sni => Self::Sni,
            DestinationEvidenceSourceKind::Host => Self::Host,
            DestinationEvidenceSourceKind::Ip => Self::Ip,
            DestinationEvidenceSourceKind::TlsFingerprint => Self::TlsFingerprint,
            DestinationEvidenceSourceKind::Heuristic => Self::Heuristic,
        }
    }
}

fn resolve_candidate(
    candidates: &[DestinationCandidate],
    kind: DestinationEvidenceKind,
    policy: &CompiledDestinationResolutionPolicy,
) -> Option<DestinationCandidate> {
    let threshold = match kind {
        DestinationEvidenceKind::Category => policy.min_confidence.category,
        DestinationEvidenceKind::Reputation => policy.min_confidence.reputation,
        DestinationEvidenceKind::Application => policy.min_confidence.application,
    };
    let filtered = candidates
        .iter()
        .filter(|candidate| threshold.is_none_or(|min| candidate.confidence >= min))
        .cloned()
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return None;
    }
    if matches!(
        policy.conflict_mode,
        DestinationConflictMode::RequireAgreement
    ) {
        let mut labels = filtered
            .iter()
            .map(|candidate| candidate.label.as_str())
            .collect::<std::collections::HashSet<_>>();
        if labels.len() > 1 {
            return None;
        }
        let _ = labels.drain();
    }
    match policy.merge_mode {
        DestinationMergeMode::FirstWins => {
            for class in &policy.precedence {
                if let Some(best) = filtered
                    .iter()
                    .filter(|candidate| &candidate.class == class)
                    .max_by_key(|candidate| candidate.confidence)
                {
                    return Some(best.clone());
                }
            }
            filtered
                .into_iter()
                .max_by_key(|candidate| candidate.confidence)
        }
        DestinationMergeMode::StrongestPerDimension => match policy.conflict_mode {
            DestinationConflictMode::PreferPrecedence => {
                filtered.into_iter().min_by_key(|candidate| {
                    (
                        precedence_rank(policy, candidate.class),
                        std::cmp::Reverse(candidate.confidence),
                    )
                })
            }
            DestinationConflictMode::PreferHighestConfidence => {
                filtered.into_iter().max_by_key(|candidate| {
                    (
                        candidate.confidence,
                        std::cmp::Reverse(precedence_rank(policy, candidate.class)),
                    )
                })
            }
            DestinationConflictMode::RequireAgreement => {
                filtered.into_iter().max_by_key(|candidate| {
                    (
                        candidate.confidence,
                        std::cmp::Reverse(precedence_rank(policy, candidate.class)),
                    )
                })
            }
        },
    }
}

fn precedence_rank(
    policy: &CompiledDestinationResolutionPolicy,
    class: DestinationEvidenceClass,
) -> usize {
    policy
        .precedence
        .iter()
        .position(|entry| *entry == class)
        .unwrap_or(policy.precedence.len())
}

fn score_for_source(kind: DestinationEvidenceKind, source: DestinationEvidenceSource) -> u8 {
    match kind {
        DestinationEvidenceKind::Category | DestinationEvidenceKind::Reputation => match source {
            DestinationEvidenceSource::Host => 100,
            DestinationEvidenceSource::Sni => 96,
            DestinationEvidenceSource::Ip => 94,
            DestinationEvidenceSource::Alpn => 82,
            DestinationEvidenceSource::SanDns => 90,
            DestinationEvidenceSource::SanUri => 84,
            DestinationEvidenceSource::CertIssuer => 78,
            DestinationEvidenceSource::CertSubject => 74,
            DestinationEvidenceSource::FingerprintJa4 => 72,
            DestinationEvidenceSource::FingerprintJa3 => 70,
            DestinationEvidenceSource::CertFingerprint => 88,
            DestinationEvidenceSource::Heuristic => 40,
        },
        DestinationEvidenceKind::Application => match source {
            DestinationEvidenceSource::FingerprintJa4 => 100,
            DestinationEvidenceSource::FingerprintJa3 => 96,
            DestinationEvidenceSource::Sni => 94,
            DestinationEvidenceSource::Host => 92,
            DestinationEvidenceSource::Alpn => 90,
            DestinationEvidenceSource::SanDns => 88,
            DestinationEvidenceSource::Ip => 84,
            DestinationEvidenceSource::SanUri => 82,
            DestinationEvidenceSource::CertIssuer => 76,
            DestinationEvidenceSource::CertSubject => 72,
            DestinationEvidenceSource::CertFingerprint => 90,
            DestinationEvidenceSource::Heuristic => 40,
        },
    }
}

fn normalized_text(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.');
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
}

fn domain_evidence(inputs: &DestinationInputs<'_>) -> Vec<(String, DestinationEvidenceSource)> {
    let mut out = Vec::new();
    if let Some(value) = inputs.host.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::Host));
    }
    if let Some(value) = inputs.sni.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::Sni));
    }
    for value in inputs.cert_san_dns {
        if let Some(value) = normalized_text(value.as_str()) {
            out.push((value, DestinationEvidenceSource::SanDns));
        }
    }
    out
}

fn string_evidence(
    inputs: &DestinationInputs<'_>,
    evidence_kind: DestinationEvidenceKind,
) -> Vec<(String, DestinationEvidenceSource)> {
    let mut out = domain_evidence(inputs);
    for value in inputs.cert_san_uri {
        if let Some(value) = normalized_text(value.as_str()) {
            out.push((value, DestinationEvidenceSource::SanUri));
        }
    }
    if let Some(value) = inputs.cert_subject.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::CertSubject));
    }
    if let Some(value) = inputs.cert_issuer.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::CertIssuer));
    }
    if let Some(value) = inputs.cert_fingerprint_sha256.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::CertFingerprint));
    }
    if matches!(evidence_kind, DestinationEvidenceKind::Application) {
        if let Some(value) = inputs.alpn.and_then(normalized_text) {
            out.push((value, DestinationEvidenceSource::Alpn));
        }
    }
    if let Some(value) = inputs.ja4.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::FingerprintJa4));
    }
    if let Some(value) = inputs.ja3.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::FingerprintJa3));
    }
    out
}

fn destination_ip(inputs: &DestinationInputs<'_>) -> Option<IpAddr> {
    inputs.ip.or_else(|| {
        inputs
            .host
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
            .or_else(|| {
                inputs
                    .sni
                    .and_then(|value| value.trim().parse::<IpAddr>().ok())
            })
    })
}

fn infer_application(
    scheme: Option<&str>,
    port: Option<u16>,
    alpn: Option<&str>,
) -> Option<&'static str> {
    let alpn = alpn.map(|value| value.trim().to_ascii_lowercase());
    if let Some(alpn) = alpn.as_deref() {
        if alpn.starts_with("h3") {
            return Some("quic");
        }
        if alpn == "h2" || alpn == "http/1.1" || alpn == "http/1.0" {
            return Some("https");
        }
    }

    match scheme.map(|value| value.trim().to_ascii_lowercase()) {
        Some(scheme) if scheme == "ftp" => Some("ftp"),
        Some(scheme) if scheme == "http" => Some("http"),
        Some(scheme) if scheme == "https" || scheme == "wss" || scheme == "h3" => Some("https"),
        Some(scheme) if scheme == "ws" => Some("http"),
        _ => match port {
            Some(21) => Some("ftp"),
            Some(22) => Some("ssh"),
            Some(53) | Some(853) => Some("dns"),
            Some(80) | Some(8080) => Some("http"),
            Some(443) => Some("https"),
            _ => None,
        },
    }
}

fn format_resolution_trace(
    dimension: &str,
    candidates: &[DestinationCandidate],
    selected_value: Option<&str>,
    selected_source: Option<&str>,
    selected_confidence: Option<u8>,
) -> String {
    let selected = selected_value
        .map(|value| {
            format!(
                "selected={value}@{}:{}",
                selected_source.unwrap_or(""),
                selected_confidence.unwrap_or(0)
            )
        })
        .unwrap_or_else(|| "selected=none".to_string());
    let considered = if candidates.is_empty() {
        "candidates=none".to_string()
    } else {
        format!(
            "candidates={}",
            candidates
                .iter()
                .map(|candidate| format!(
                    "{}@{}:{}",
                    candidate.label,
                    candidate.source.as_str(),
                    candidate.confidence
                ))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    format!("{dimension}({selected}; {considered})")
}

fn normalize_regex_pattern(value: &str) -> &str {
    extract_regex_pattern(value).unwrap_or(value)
}

fn extract_regex_pattern(item: &str) -> Option<&str> {
    item.strip_prefix("re:")
        .or_else(|| item.strip_prefix("regex:"))
        .map(str::trim)
        .filter(|pattern| !pattern.is_empty())
}

fn is_exact_pattern(item: &str) -> bool {
    !item.contains('*')
        && !item.contains('?')
        && !item.contains('[')
        && !item.contains(']')
        && !item.contains('{')
        && !item.contains('}')
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host.len() <= suffix.len() || !host.ends_with(suffix) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::{Config, NamedSetConfig};
    use std::net::{IpAddr, Ipv4Addr};

    fn base_config() -> Config {
        Config {
            state_dir: None,
            identity: Default::default(),
            messages: Default::default(),
            runtime: Default::default(),
            system_log: Default::default(),
            access_log: Default::default(),
            audit_log: Default::default(),
            metrics: None,
            otel: None,
            acme: None,
            exporter: None,
            auth: Default::default(),
            identity_sources: Vec::new(),
            ext_authz: Vec::new(),
            destination_resolution: Default::default(),
            named_sets: Vec::new(),
            http_guard_profiles: Vec::new(),
            rate_limit_profiles: Vec::new(),
            upstream_trust_profiles: Vec::new(),
            listeners: Vec::new(),
            reverse: Vec::new(),
            upstreams: Vec::new(),
            cache: Default::default(),
        }
    }

    #[test]
    fn classifier_uses_prefixed_named_sets_and_application_heuristics() {
        let mut config = base_config();
        config.named_sets = vec![
            NamedSetConfig {
                name: "category:ai".to_string(),
                kind: NamedSetKind::Domain,
                values: vec!["*.openai.com".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "reputation/high".to_string(),
                kind: NamedSetKind::Regex,
                values: vec![r"(^|\.)malware\.example$".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "application:slack".to_string(),
                kind: NamedSetKind::String,
                values: vec!["*.slack.com".to_string()],
                file: None,
            },
        ];

        let classifier = DestinationClassifier::from_config(&config).expect("classifier");
        let policy = CompiledDestinationResolutionPolicy::default();
        let openai = classifier.classify(
            &DestinationInputs {
                host: Some("api.openai.com"),
                scheme: Some("https"),
                port: Some(443),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(openai.category.as_deref(), Some("ai"));
        assert_eq!(openai.category_source.as_deref(), Some("host"));
        assert_eq!(openai.category_confidence, Some(100));
        assert_eq!(openai.application.as_deref(), Some("https"));
        assert_eq!(openai.application_source.as_deref(), Some("heuristic"));
        assert_eq!(openai.application_confidence, Some(40));

        let malware = classifier.classify(
            &DestinationInputs {
                host: Some("malware.example"),
                port: Some(443),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(malware.reputation.as_deref(), Some("high"));
        assert_eq!(malware.reputation_source.as_deref(), Some("host"));
        assert_eq!(malware.reputation_confidence, Some(100));

        let slack = classifier.classify(
            &DestinationInputs {
                host: Some("app.slack.com"),
                port: Some(443),
                alpn: Some("h2"),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(slack.application.as_deref(), Some("slack"));
        assert_eq!(slack.application_source.as_deref(), Some("host"));
        assert_eq!(slack.application_confidence, Some(92));

        let dns = classifier.classify(
            &DestinationInputs {
                port: Some(853),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(dns.application.as_deref(), Some("dns"));
        assert_eq!(dns.application_source.as_deref(), Some("heuristic"));
        assert_eq!(dns.application_confidence, Some(40));
    }

    #[test]
    fn classifier_uses_ip_sni_cert_and_fingerprint_precedence() {
        let mut config = base_config();
        config.named_sets = vec![
            NamedSetConfig {
                name: "category:corp".to_string(),
                kind: NamedSetKind::String,
                values: vec!["corp issuer".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "category:web".to_string(),
                kind: NamedSetKind::Domain,
                values: vec!["api.example.com".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "reputation:suspicious".to_string(),
                kind: NamedSetKind::Cidr,
                values: vec!["203.0.113.0/24".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "application:chrome".to_string(),
                kind: NamedSetKind::String,
                values: vec!["ja4-chrome".to_string()],
                file: None,
            },
        ];
        let classifier = DestinationClassifier::from_config(&config).expect("classifier");
        let policy = CompiledDestinationResolutionPolicy::default();
        let cert_san_dns = vec!["download.example.com".to_string()];
        let destination = classifier.classify(
            &DestinationInputs {
                host: Some("api.example.com"),
                ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
                sni: Some("download.example.com"),
                ja4: Some("ja4-chrome"),
                cert_issuer: Some("Corp Issuer"),
                cert_san_dns: cert_san_dns.as_slice(),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(destination.category.as_deref(), Some("web"));
        assert_eq!(destination.category_source.as_deref(), Some("host"));
        assert_eq!(destination.category_confidence, Some(100));
        assert_eq!(destination.reputation.as_deref(), Some("suspicious"));
        assert_eq!(destination.reputation_source.as_deref(), Some("ip"));
        assert_eq!(destination.reputation_confidence, Some(94));
        assert_eq!(destination.application.as_deref(), Some("chrome"));
        assert_eq!(destination.application_source.as_deref(), Some("ja4"));
        assert_eq!(destination.application_confidence, Some(100));
    }

    #[test]
    fn resolution_override_can_prefer_certificate_evidence() {
        let mut config = base_config();
        config.named_sets = vec![
            NamedSetConfig {
                name: "category:host".to_string(),
                kind: NamedSetKind::Domain,
                values: vec!["api.example.com".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "category:cert".to_string(),
                kind: NamedSetKind::String,
                values: vec!["corp issuer".to_string()],
                file: None,
            },
        ];
        let classifier = DestinationClassifier::from_config(&config).expect("classifier");
        let override_policy = CompiledDestinationResolutionPolicy::default().with_override(Some(
            &qpx_core::config::DestinationResolutionOverrideConfig {
                precedence: Some(vec![
                    qpx_core::config::DestinationEvidenceSourceKind::Cert,
                    qpx_core::config::DestinationEvidenceSourceKind::Host,
                ]),
                conflict_mode: Some(qpx_core::config::DestinationConflictMode::PreferPrecedence),
                merge_mode: None,
                min_confidence: None,
            },
        ));
        let destination = classifier.classify(
            &DestinationInputs {
                host: Some("api.example.com"),
                cert_issuer: Some("Corp Issuer"),
                ..Default::default()
            },
            &override_policy,
        );
        assert_eq!(destination.category.as_deref(), Some("cert"));
        assert_eq!(destination.category_source.as_deref(), Some("cert_issuer"));
    }
}
