use super::super::defaults::*;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DestinationEvidenceSourceKind {
    PolicyContext,
    Cert,
    Sni,
    Host,
    Ip,
    TlsFingerprint,
    Heuristic,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationConflictMode {
    PreferPrecedence,
    PreferHighestConfidence,
    RequireAgreement,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationMergeMode {
    FirstWins,
    StrongestPerDimension,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DestinationMinConfidenceConfig {
    #[serde(default)]
    pub category: Option<u8>,
    #[serde(default)]
    pub reputation: Option<u8>,
    #[serde(default)]
    pub application: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DestinationResolutionPolicyConfig {
    #[serde(default = "default_destination_resolution_precedence")]
    pub precedence: Vec<DestinationEvidenceSourceKind>,
    #[serde(default = "default_destination_conflict_mode")]
    pub conflict_mode: DestinationConflictMode,
    #[serde(default = "default_destination_merge_mode")]
    pub merge_mode: DestinationMergeMode,
    #[serde(default)]
    pub min_confidence: DestinationMinConfidenceConfig,
}

impl Default for DestinationResolutionPolicyConfig {
    fn default() -> Self {
        Self {
            precedence: default_destination_resolution_precedence(),
            conflict_mode: default_destination_conflict_mode(),
            merge_mode: default_destination_merge_mode(),
            min_confidence: DestinationMinConfidenceConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DestinationResolutionOverrideConfig {
    #[serde(default)]
    pub precedence: Option<Vec<DestinationEvidenceSourceKind>>,
    #[serde(default)]
    pub conflict_mode: Option<DestinationConflictMode>,
    #[serde(default)]
    pub merge_mode: Option<DestinationMergeMode>,
    #[serde(default)]
    pub min_confidence: Option<DestinationMinConfidenceConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DestinationResolutionConfig {
    #[serde(default)]
    pub defaults: DestinationResolutionPolicyConfig,
}
