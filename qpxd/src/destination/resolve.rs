use qpx_core::config::{
    DestinationConflictMode, DestinationEvidenceSourceKind, DestinationMergeMode,
    DestinationResolutionOverrideConfig, DestinationResolutionPolicyConfig, NamedSetKind,
};
use std::net::IpAddr;

use super::compile::{DestinationClassifier, LabeledPatternSet};
use super::{DestinationInputs, DestinationMetadata};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DestinationEvidenceKind {
    Category,
    Reputation,
    Application,
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

impl DestinationClassifier {
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
pub(super) enum DestinationEvidenceClass {
    PolicyContext,
    Cert,
    Sni,
    Host,
    Ip,
    TlsFingerprint,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DestinationCandidate {
    label: String,
    confidence: u8,
    source: DestinationEvidenceSource,
    class: DestinationEvidenceClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DestinationEvidenceSource {
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

pub(super) fn score_for_source(
    kind: DestinationEvidenceKind,
    source: DestinationEvidenceSource,
) -> u8 {
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

pub(super) fn domain_evidence(
    inputs: &DestinationInputs<'_>,
) -> Vec<(String, DestinationEvidenceSource)> {
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

pub(super) fn string_evidence(
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
    if matches!(evidence_kind, DestinationEvidenceKind::Application)
        && let Some(value) = inputs.alpn.and_then(normalized_text)
    {
        out.push((value, DestinationEvidenceSource::Alpn));
    }
    if let Some(value) = inputs.ja4.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::FingerprintJa4));
    }
    if let Some(value) = inputs.ja3.and_then(normalized_text) {
        out.push((value, DestinationEvidenceSource::FingerprintJa3));
    }
    out
}

pub(super) fn destination_ip(inputs: &DestinationInputs<'_>) -> Option<IpAddr> {
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
