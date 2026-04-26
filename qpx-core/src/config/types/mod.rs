use serde::Deserialize;

mod cache;
mod core;
mod http;
mod listener;
mod observability;
mod policy;
mod reverse;
mod rules;
mod security;
mod upstream;

pub use self::cache::*;
pub use self::core::*;
pub use self::http::*;
pub use self::listener::*;
pub use self::observability::*;
pub use self::policy::*;
pub use self::reverse::*;
pub use self::rules::*;
pub use self::security::*;
pub use self::upstream::*;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default)]
    pub state_dir: Option<String>,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub messages: MessagesConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub system_log: SystemLogConfig,
    #[serde(default)]
    pub access_log: AccessLogConfig,
    #[serde(default)]
    pub audit_log: AuditLogConfig,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub otel: Option<OtelConfig>,
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    #[serde(default)]
    pub exporter: Option<ExporterConfig>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub identity_sources: Vec<IdentitySourceConfig>,
    #[serde(default)]
    pub ext_authz: Vec<ExtAuthzConfig>,
    #[serde(default)]
    pub destination_resolution: DestinationResolutionConfig,
    #[serde(default)]
    pub named_sets: Vec<NamedSetConfig>,
    #[serde(default)]
    pub http_guard_profiles: Vec<HttpGuardProfileConfig>,
    #[serde(default)]
    pub rate_limit_profiles: Vec<RateLimitProfileConfig>,
    #[serde(default)]
    pub upstream_trust_profiles: Vec<UpstreamTlsTrustProfileConfig>,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub reverse: Vec<ReverseConfig>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub cache: CacheConfig,
}
