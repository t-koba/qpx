use super::super::defaults::*;
use super::{
    ActionConfig, CachePolicyConfig, DestinationResolutionOverrideConfig, HttpModuleConfig,
    PolicyContextConfig, RateLimitConfig, UpstreamTlsTrustConfig,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub name: String,
    pub mode: ListenerMode,
    pub listen: String,
    pub default_action: ActionConfig,
    #[serde(default)]
    pub tls_inspection: Option<TlsInspectionConfig>,
    #[serde(default)]
    pub rules: Vec<super::RuleConfig>,
    #[serde(default)]
    pub connection_filter: Vec<super::RuleConfig>,
    #[serde(default)]
    pub upstream_proxy: Option<String>,
    #[serde(default)]
    pub http3: Option<Http3ListenerConfig>,
    #[serde(default)]
    pub ftp: FtpConfig,
    #[serde(default)]
    pub xdp: Option<XdpConfig>,
    #[serde(default)]
    pub cache: Option<CachePolicyConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub policy_context: Option<PolicyContextConfig>,
    #[serde(default)]
    pub destination_resolution: Option<DestinationResolutionOverrideConfig>,
    #[serde(default)]
    pub http: Option<super::HttpPolicyConfig>,
    #[serde(default)]
    pub http_guard_profile: Option<String>,
    #[serde(default)]
    pub http_modules: Vec<HttpModuleConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerMode {
    Forward,
    Transparent,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TlsInspectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ca: Option<String>,
    #[serde(default = "default_verify_upstream")]
    pub verify_upstream: bool,
    #[serde(default)]
    pub verify_exceptions: Vec<String>,
    #[serde(default)]
    pub upstream_trust_profile: Option<String>,
    #[serde(default)]
    pub upstream_trust: Option<UpstreamTlsTrustConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Http3ListenerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub connect_udp: Option<ConnectUdpConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct XdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_xdp_metadata_mode")]
    pub metadata_mode: String,
    #[serde(default = "default_xdp_require_metadata")]
    pub require_metadata: bool,
    #[serde(default)]
    pub trusted_peers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ConnectUdpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_connect_udp_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_connect_udp_max_capsule_buffer_bytes")]
    pub max_capsule_buffer_bytes: usize,
    #[serde(default)]
    pub uri_template: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct FtpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ftp_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_ftp_max_download_bytes")]
    pub max_download_bytes: usize,
    #[serde(default = "default_ftp_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for FtpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_request_body_bytes: default_ftp_max_request_body_bytes(),
            max_download_bytes: default_ftp_max_download_bytes(),
            timeout_ms: default_ftp_timeout_ms(),
        }
    }
}
