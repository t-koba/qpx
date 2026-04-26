use super::super::defaults::*;
use super::{
    CachePolicyConfig, DestinationResolutionOverrideConfig, HeaderControl, HttpModuleConfig,
    LocalResponseConfig, MatchConfig, PolicyContextConfig, RateLimitConfig, UpstreamTlsTrustConfig,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReverseConfig {
    pub name: String,
    pub listen: String,
    #[serde(default)]
    pub tls: Option<ReverseTlsConfig>,
    #[serde(default)]
    pub http3: Option<ReverseHttp3Config>,
    #[serde(default)]
    pub xdp: Option<super::XdpConfig>,
    #[serde(default = "default_reverse_enforce_sni_host_match")]
    pub enforce_sni_host_match: bool,
    #[serde(default)]
    pub sni_host_exceptions: Vec<String>,
    #[serde(default)]
    pub policy_context: Option<PolicyContextConfig>,
    #[serde(default)]
    pub destination_resolution: Option<DestinationResolutionOverrideConfig>,
    #[serde(default)]
    pub connection_filter: Vec<super::RuleConfig>,
    #[serde(default)]
    pub routes: Vec<ReverseRouteConfig>,
    #[serde(default)]
    pub tls_passthrough_routes: Vec<ReverseTlsPassthroughRouteConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReverseHttp3Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub passthrough_upstreams: Vec<String>,
    #[serde(default = "default_reverse_h3_passthrough_max_sessions")]
    pub passthrough_max_sessions: usize,
    #[serde(default = "default_reverse_h3_passthrough_idle_timeout_secs")]
    pub passthrough_idle_timeout_secs: u64,
    #[serde(default = "default_reverse_h3_passthrough_max_new_sessions_per_sec")]
    pub passthrough_max_new_sessions_per_sec: u64,
    #[serde(default = "default_reverse_h3_passthrough_min_client_bytes")]
    pub passthrough_min_client_bytes: usize,
    #[serde(default = "default_reverse_h3_passthrough_max_amplification")]
    pub passthrough_max_amplification: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ReverseTlsConfig {
    #[serde(default)]
    pub certificates: Vec<TlsCertConfig>,
    #[serde(default)]
    pub client_ca: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TlsCertConfig {
    pub sni: String,
    #[serde(default)]
    pub pkcs12: Option<String>,
    #[serde(default)]
    pub pkcs12_password_env: Option<String>,
    #[serde(default)]
    pub cert: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReverseRouteConfig {
    #[serde(default)]
    pub name: Option<String>,
    pub r#match: MatchConfig,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub backends: Vec<ReverseRouteBackendConfig>,
    #[serde(default)]
    pub mirrors: Vec<ReverseRouteMirrorConfig>,
    #[serde(default)]
    pub local_response: Option<LocalResponseConfig>,
    #[serde(default)]
    pub headers: Option<HeaderControl>,
    #[serde(default = "default_lb")]
    pub lb: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub resilience: Option<ResilienceConfig>,
    #[serde(default)]
    pub cache: Option<CachePolicyConfig>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub path_rewrite: Option<PathRewriteConfig>,
    #[serde(default)]
    pub upstream_trust_profile: Option<String>,
    #[serde(default)]
    pub upstream_trust: Option<UpstreamTlsTrustConfig>,
    #[serde(default)]
    pub lifecycle: Option<EndpointLifecycleConfig>,
    #[serde(default)]
    pub ipc: Option<IpcUpstreamConfig>,
    #[serde(default)]
    pub affinity: Option<ReverseAffinityConfig>,
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IpcMode {
    #[default]
    Shm,
    Tcp,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IpcUpstreamConfig {
    #[serde(default)]
    pub mode: IpcMode,
    pub address: String,
    #[serde(default = "default_ipc_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReverseRouteBackendConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_reverse_backend_weight")]
    pub weight: u32,
    #[serde(default)]
    pub upstreams: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReverseRouteMirrorConfig {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_reverse_mirror_percent")]
    pub percent: u32,
    #[serde(default)]
    pub upstreams: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EndpointLifecycleConfig {
    #[serde(default)]
    pub slow_start_ms: Option<u64>,
    #[serde(default)]
    pub warmup_ms: Option<u64>,
    #[serde(default)]
    pub drain_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PathRewriteConfig {
    #[serde(default)]
    pub strip_prefix: Option<String>,
    #[serde(default)]
    pub add_prefix: Option<String>,
    #[serde(default)]
    pub regex: Option<RegexPathRewriteConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegexPathRewriteConfig {
    pub pattern: String,
    pub replace: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TlsPassthroughMatchConfig {
    #[serde(default)]
    pub src_ip: Vec<String>,
    #[serde(default)]
    pub dst_port: Vec<u16>,
    #[serde(default)]
    pub sni: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReverseTlsPassthroughRouteConfig {
    pub r#match: TlsPassthroughMatchConfig,
    pub upstreams: Vec<String>,
    #[serde(default = "default_lb")]
    pub lb: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub resilience: Option<ResilienceConfig>,
    #[serde(default)]
    pub lifecycle: Option<EndpointLifecycleConfig>,
    #[serde(default)]
    pub affinity: Option<ReverseAffinityConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ResilienceConfig {
    #[serde(default)]
    pub outlier_detection: Option<OutlierDetectionConfig>,
    #[serde(default)]
    pub retry: Option<ResilienceRetryConfig>,
    #[serde(default)]
    pub max_upstream_concurrency: Option<usize>,
    #[serde(default)]
    pub half_open: Option<HalfOpenConfig>,
    #[serde(default)]
    pub ejection: Option<EjectionConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct OutlierDetectionConfig {
    #[serde(default)]
    pub consecutive_failures: Option<ConsecutiveFailuresConfig>,
    #[serde(default)]
    pub success_rate: Option<AdaptiveThresholdConfig>,
    #[serde(default)]
    pub latency: Option<LatencyThresholdConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ConsecutiveFailuresConfig {
    #[serde(default)]
    pub http_5xx: Option<u32>,
    #[serde(default)]
    pub timeouts: Option<u32>,
    #[serde(default)]
    pub connect_errors: Option<u32>,
    #[serde(default)]
    pub resets: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveThresholdConfig {
    #[serde(default)]
    pub min_requests: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct LatencyThresholdConfig {
    #[serde(default)]
    pub p95_ms: Option<u64>,
    #[serde(default)]
    pub min_requests: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ResilienceRetryConfig {
    #[serde(default = "default_retry_attempts")]
    pub attempts: usize,
    #[serde(default = "default_retry_backoff")]
    pub backoff_ms: u64,
    #[serde(default)]
    pub budget: Option<RetryBudgetConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct RetryBudgetConfig {
    #[serde(default)]
    pub ratio: Option<u32>,
    #[serde(default)]
    pub min_retry_tokens: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct HalfOpenConfig {
    #[serde(default)]
    pub max_probes: Option<usize>,
    #[serde(default)]
    pub successes_to_close: Option<u32>,
    #[serde(default)]
    pub probe_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct EjectionConfig {
    #[serde(default)]
    pub base_ms: Option<u64>,
    #[serde(default)]
    pub max_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HealthCheckConfig {
    #[serde(default = "default_health_check_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_health_check_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_health_check_fail_threshold")]
    pub fail_threshold: u32,
    #[serde(default = "default_health_check_cooldown_ms")]
    pub cooldown_ms: u64,
    #[serde(default)]
    pub http: Option<HttpHealthCheckConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReverseAffinityConfig {
    #[serde(default = "default_reverse_affinity_key")]
    pub key: String,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub cookie: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpHealthCheckConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub expected_status: Option<Vec<u16>>,
}
