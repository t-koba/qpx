use super::super::defaults::*;
use super::{ResilienceConfig, UpstreamTlsTrustConfig};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub tls_trust_profile: Option<String>,
    #[serde(default)]
    pub tls_trust: Option<UpstreamTlsTrustConfig>,
    #[serde(default)]
    pub discovery: Option<UpstreamDiscoveryConfig>,
    #[serde(default)]
    pub resilience: Option<ResilienceConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamDiscoveryConfig {
    #[serde(default)]
    pub kind: UpstreamDiscoveryKind,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "default_upstream_discovery_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_upstream_discovery_min_ttl_ms")]
    pub min_ttl_ms: u64,
    #[serde(default = "default_upstream_discovery_max_ttl_ms")]
    pub max_ttl_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamDiscoveryKind {
    #[default]
    Dns,
    Srv,
}
