use super::super::defaults::*;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct CacheConfig {
    #[serde(default)]
    pub backends: Vec<CacheBackendConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CacheBackendConfig {
    pub name: String,
    #[serde(default = "default_cache_backend_kind")]
    pub kind: String,
    pub endpoint: String,
    #[serde(default = "default_cache_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_cache_max_object_bytes")]
    pub max_object_bytes: usize,
    #[serde(default)]
    pub auth_header_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CachePolicyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub default_ttl_secs: Option<u64>,
    #[serde(default = "default_cache_max_object_bytes")]
    pub max_object_bytes: usize,
    #[serde(default)]
    pub allow_set_cookie_store: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rate_limit_apply_to")]
    pub apply_to: Vec<RateLimitApplyTo>,
    #[serde(default = "default_rate_limit_key")]
    pub key: String,
    #[serde(default)]
    pub requests: Option<RateLimitRequestsConfig>,
    #[serde(default)]
    pub traffic: Option<RateLimitTrafficConfig>,
    #[serde(default)]
    pub sessions: Option<RateLimitSessionsConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitApplyTo {
    Request,
    Connect,
    Udp,
    Http3Datagram,
    Webtransport,
    WebtransportBidi,
    WebtransportBidiDownstream,
    WebtransportBidiUpstream,
    WebtransportUni,
    WebtransportUniDownstream,
    WebtransportUniUpstream,
    WebtransportDatagram,
    WebtransportDatagramDownstream,
    WebtransportDatagramUpstream,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitRequestsConfig {
    #[serde(default)]
    pub rps: Option<u64>,
    #[serde(default)]
    pub burst: Option<u64>,
    #[serde(default)]
    pub quota: Option<RateLimitQuotaConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitTrafficConfig {
    #[serde(default)]
    pub bytes_per_sec: Option<u64>,
    #[serde(default)]
    pub burst_bytes: Option<u64>,
    #[serde(default)]
    pub quota_bytes: Option<RateLimitQuotaConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSessionsConfig {
    #[serde(default)]
    pub max_concurrency: Option<u64>,
    #[serde(default)]
    pub quota_sessions: Option<RateLimitQuotaConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitQuotaConfig {
    #[serde(default = "default_rate_limit_quota_interval_secs")]
    pub interval_secs: u64,
    #[serde(default)]
    pub amount: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitProfileConfig {
    pub name: String,
    #[serde(flatten)]
    pub limit: RateLimitConfig,
}
