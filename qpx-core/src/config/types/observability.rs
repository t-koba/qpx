use super::super::defaults::*;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SystemLogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for SystemLogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LogOutputConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_log_output_format")]
    pub format: String,
    #[serde(default = "default_log_rotation")]
    pub rotation: String,
    #[serde(default = "default_log_rotation_count")]
    pub rotation_count: usize,
}

impl Default for LogOutputConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            format: default_log_output_format(),
            rotation: default_log_rotation(),
            rotation_count: default_log_rotation_count(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessLogConfig {
    #[serde(flatten)]
    pub output: LogOutputConfig,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditLogConfig {
    #[serde(flatten)]
    pub output: LogOutputConfig,
    #[serde(default)]
    pub include: Vec<AuditIncludeField>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditIncludeField {
    Subject,
    Groups,
    DeviceId,
    Posture,
    Tenant,
    AuthStrength,
    Idp,
    IdentitySource,
    PolicyTags,
    ExtAuthzPolicyId,
    MatchedRule,
    MatchedRoute,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MetricsConfig {
    pub listen: String,
    #[serde(default = "default_metrics_path")]
    pub path: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default = "default_metrics_max_concurrent_connections")]
    pub max_concurrent_connections: usize,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub staging: bool,
    #[serde(default)]
    pub directory_url: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    #[serde(default)]
    pub http01_listen: Option<String>,
    #[serde(default = "default_acme_renew_before_days")]
    pub renew_before_days: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OtelConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_otel_protocol")]
    pub protocol: String,
    #[serde(default = "default_otel_level")]
    pub level: String,
    #[serde(default = "default_otel_sample_percent")]
    pub sample_percent: u32,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub service_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ExporterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub shm_path: String,
    #[serde(default = "default_exporter_shm_size_mb")]
    pub shm_size_mb: usize,
    #[serde(default)]
    pub lossy: bool,
    #[serde(default = "default_exporter_max_queue_events")]
    pub max_queue_events: usize,
    #[serde(default)]
    pub capture: ExporterCaptureConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ExporterCaptureConfig {
    #[serde(default = "default_exporter_capture_plaintext")]
    pub plaintext: bool,
    #[serde(default = "default_exporter_capture_encrypted")]
    pub encrypted: bool,
    #[serde(default = "default_exporter_max_chunk_bytes")]
    pub max_chunk_bytes: usize,
}

impl Default for ExporterCaptureConfig {
    fn default() -> Self {
        Self {
            plaintext: default_exporter_capture_plaintext(),
            encrypted: default_exporter_capture_encrypted(),
            max_chunk_bytes: default_exporter_max_chunk_bytes(),
        }
    }
}
