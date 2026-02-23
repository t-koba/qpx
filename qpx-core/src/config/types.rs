use super::defaults::*;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub version: u32,
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
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub reverse: Vec<ReverseConfig>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IdentityConfig {
    #[serde(default = "default_identity_proxy_name")]
    pub proxy_name: String,
    #[serde(default = "default_identity_auth_realm")]
    pub auth_realm: String,
    #[serde(default = "default_identity_metrics_prefix")]
    pub metrics_prefix: String,
    #[serde(default)]
    pub generated_user_agent: Option<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            proxy_name: default_identity_proxy_name(),
            auth_realm: default_identity_auth_realm(),
            metrics_prefix: default_identity_metrics_prefix(),
            generated_user_agent: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MessagesConfig {
    #[serde(default = "default_message_blocked")]
    pub blocked: String,
    #[serde(default = "default_message_forbidden")]
    pub forbidden: String,
    #[serde(default = "default_message_trace_disabled")]
    pub trace_disabled: String,
    #[serde(default = "default_message_proxy_error")]
    pub proxy_error: String,
    #[serde(default = "default_message_proxy_auth_required")]
    pub proxy_auth_required: String,
    #[serde(default = "default_message_reverse_error")]
    pub reverse_error: String,
    #[serde(default = "default_message_cache_miss")]
    pub cache_miss: String,
    #[serde(default = "default_message_unsupported_ftp_method")]
    pub unsupported_ftp_method: String,
    #[serde(default = "default_message_ftp_disabled")]
    pub ftp_disabled: String,
    #[serde(default = "default_message_connect_udp_disabled")]
    pub connect_udp_disabled: String,
    #[serde(default = "default_message_upstream_connect_udp_failed")]
    pub upstream_connect_udp_failed: String,
}

impl Default for MessagesConfig {
    fn default() -> Self {
        Self {
            blocked: default_message_blocked(),
            forbidden: default_message_forbidden(),
            trace_disabled: default_message_trace_disabled(),
            proxy_error: default_message_proxy_error(),
            proxy_auth_required: default_message_proxy_auth_required(),
            reverse_error: default_message_reverse_error(),
            cache_miss: default_message_cache_miss(),
            unsupported_ftp_method: default_message_unsupported_ftp_method(),
            ftp_disabled: default_message_ftp_disabled(),
            connect_udp_disabled: default_message_connect_udp_disabled(),
            upstream_connect_udp_failed: default_message_upstream_connect_udp_failed(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub worker_threads: Option<usize>,
    #[serde(default)]
    pub max_blocking_threads: Option<usize>,
    #[serde(default = "default_runtime_max_ftp_concurrency")]
    pub max_ftp_concurrency: usize,
    #[serde(default = "default_runtime_max_concurrent_connections")]
    pub max_concurrent_connections: usize,
    #[serde(default = "default_runtime_max_h3_streams_per_connection")]
    pub max_h3_streams_per_connection: usize,
    #[serde(default)]
    pub trace_enabled: bool,
    #[serde(default)]
    pub trace_reflect_all_headers: bool,
    #[serde(default)]
    pub acceptor_tasks_per_listener: Option<usize>,
    #[serde(default = "default_runtime_reuse_port")]
    pub reuse_port: bool,
    #[serde(default = "default_runtime_tcp_backlog")]
    pub tcp_backlog: i32,
    #[serde(default = "default_runtime_max_h3_request_body_bytes")]
    pub max_h3_request_body_bytes: usize,
    #[serde(default = "default_runtime_max_h3_response_body_bytes")]
    pub max_h3_response_body_bytes: usize,
    #[serde(default = "default_runtime_max_reverse_retry_template_body_bytes")]
    pub max_reverse_retry_template_body_bytes: usize,
    #[serde(default = "default_runtime_upstream_http_timeout_ms")]
    pub upstream_http_timeout_ms: u64,
    #[serde(default = "default_runtime_upstream_proxy_max_concurrent_per_endpoint")]
    pub upstream_proxy_max_concurrent_per_endpoint: usize,
    #[serde(default = "default_runtime_tls_peek_timeout_ms")]
    pub tls_peek_timeout_ms: u64,
    #[serde(default = "default_runtime_http_header_read_timeout_ms")]
    pub http_header_read_timeout_ms: u64,
    #[serde(default = "default_runtime_upgrade_wait_timeout_ms")]
    pub upgrade_wait_timeout_ms: u64,
    #[serde(default = "default_runtime_tunnel_idle_timeout_ms")]
    pub tunnel_idle_timeout_ms: u64,
    #[serde(default = "default_runtime_h3_read_timeout_ms")]
    pub h3_read_timeout_ms: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: None,
            max_blocking_threads: None,
            max_ftp_concurrency: default_runtime_max_ftp_concurrency(),
            max_concurrent_connections: default_runtime_max_concurrent_connections(),
            max_h3_streams_per_connection: default_runtime_max_h3_streams_per_connection(),
            trace_enabled: false,
            trace_reflect_all_headers: false,
            acceptor_tasks_per_listener: None,
            reuse_port: default_runtime_reuse_port(),
            tcp_backlog: default_runtime_tcp_backlog(),
            max_h3_request_body_bytes: default_runtime_max_h3_request_body_bytes(),
            max_h3_response_body_bytes: default_runtime_max_h3_response_body_bytes(),
            max_reverse_retry_template_body_bytes:
                default_runtime_max_reverse_retry_template_body_bytes(),
            upstream_http_timeout_ms: default_runtime_upstream_http_timeout_ms(),
            upstream_proxy_max_concurrent_per_endpoint:
                default_runtime_upstream_proxy_max_concurrent_per_endpoint(),
            tls_peek_timeout_ms: default_runtime_tls_peek_timeout_ms(),
            http_header_read_timeout_ms: default_runtime_http_header_read_timeout_ms(),
            upgrade_wait_timeout_ms: default_runtime_upgrade_wait_timeout_ms(),
            tunnel_idle_timeout_ms: default_runtime_tunnel_idle_timeout_ms(),
            h3_read_timeout_ms: default_runtime_h3_read_timeout_ms(),
        }
    }
}

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
    /// Use the Let's Encrypt staging environment (DANGEROUS for production).
    #[serde(default)]
    pub staging: bool,
    /// Override the ACME directory URL (defaults to Let's Encrypt).
    #[serde(default)]
    pub directory_url: Option<String>,
    /// Optional account contact email (recommended).
    #[serde(default)]
    pub email: Option<String>,
    /// Required to enable ACME issuance.
    #[serde(default)]
    pub terms_of_service_agreed: bool,
    /// Address for serving HTTP-01 challenge responses (e.g. "0.0.0.0:80").
    #[serde(default)]
    pub http01_listen: Option<String>,
    /// Renew certificates this many days before expiry.
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
    /// Sampling percentage (0-100).
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

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct AuthConfig {
    #[serde(default)]
    pub users: Vec<LocalUser>,
    #[serde(default)]
    pub ldap: Option<LdapConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LocalUser {
    pub username: String,
    pub password: Option<String>,
    pub ha1: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password_env: String,
    pub user_base_dn: String,
    pub group_base_dn: String,
    #[serde(default = "default_ldap_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_ldap_require_starttls")]
    pub require_starttls: bool,
    #[serde(default = "default_user_filter")]
    pub user_filter: String,
    #[serde(default = "default_group_filter")]
    pub group_filter: String,
    #[serde(default = "default_group_attr")]
    pub group_attr: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UpstreamConfig {
    pub name: String,
    pub url: String,
}

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
    /// Keying strategy for the limiter state.
    ///
    /// Supported values: "global", "src_ip".
    #[serde(default = "default_rate_limit_key")]
    pub key: String,
    /// Requests per second.
    #[serde(default)]
    pub rps: Option<u64>,
    /// Token bucket capacity for requests (defaults to rps when omitted).
    #[serde(default)]
    pub burst: Option<u64>,
    /// Bandwidth limit in bytes per second (applies to tunnel copy paths).
    #[serde(default)]
    pub bytes_per_sec: Option<u64>,
    /// Token bucket capacity for bytes (defaults to bytes_per_sec when omitted).
    #[serde(default)]
    pub bytes_burst: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ListenerConfig {
    pub name: String,
    pub mode: ListenerMode,
    pub listen: String,
    pub default_action: ActionConfig,
    #[serde(default)]
    pub tls_inspection: Option<TlsInspectionConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
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
    /// Optional RFC 9298 URI Template used to extract target_host/target_port from CONNECT-UDP.
    /// If set, only this template is accepted (no fallback to default/query forms).
    /// If unset, the default template and query-based forms are accepted.
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

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuleConfig {
    pub name: String,
    #[serde(default)]
    pub r#match: Option<MatchConfig>,
    #[serde(default)]
    pub auth: Option<RuleAuthConfig>,
    #[serde(default)]
    pub action: Option<ActionConfig>,
    #[serde(default)]
    pub headers: Option<HeaderControl>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RuleAuthConfig {
    #[serde(default)]
    pub require: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct HeaderControl {
    #[serde(default)]
    pub request_set: HashMap<String, String>,
    #[serde(default)]
    pub request_add: HashMap<String, String>,
    #[serde(default)]
    pub request_remove: Vec<String>,
    #[serde(default)]
    pub request_regex_replace: Vec<RegexReplace>,
    #[serde(default)]
    pub response_set: HashMap<String, String>,
    #[serde(default)]
    pub response_add: HashMap<String, String>,
    #[serde(default)]
    pub response_remove: Vec<String>,
    #[serde(default)]
    pub response_regex_replace: Vec<RegexReplace>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RegexReplace {
    pub header: String,
    pub pattern: String,
    pub replace: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct MatchConfig {
    #[serde(default)]
    pub src_ip: Vec<String>,
    #[serde(default)]
    pub dst_port: Vec<u16>,
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default)]
    pub sni: Vec<String>,
    #[serde(default)]
    pub method: Vec<String>,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub headers: Vec<HeaderMatch>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HeaderMatch {
    pub name: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionConfig {
    #[serde(rename = "type")]
    pub kind: ActionKind,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub local_response: Option<LocalResponseConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    Inspect,
    Tunnel,
    Block,
    Direct,
    Proxy,
    Respond,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct LocalResponseConfig {
    #[serde(default = "default_local_response_status")]
    pub status: u16,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

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
    pub xdp: Option<XdpConfig>,
    #[serde(default = "default_reverse_enforce_sni_host_match")]
    pub enforce_sni_host_match: bool,
    #[serde(default)]
    pub sni_host_exceptions: Vec<String>,
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
    /// Optional client CA bundle (PEM). When set, reverse TLS termination requires client certs.
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
    pub r#match: MatchConfig,
    /// Simple (non-splitting) upstream list.
    ///
    /// Use either `upstreams` (single backend) OR `backends` (weighted splitting).
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Weighted backend sets for canary / traffic splitting.
    #[serde(default)]
    pub backends: Vec<ReverseRouteBackendConfig>,
    /// Shadow requests to one or more mirror upstream sets (best-effort).
    #[serde(default)]
    pub mirrors: Vec<ReverseRouteMirrorConfig>,
    #[serde(default)]
    pub local_response: Option<LocalResponseConfig>,
    /// Route-level request/response header control (same syntax as forward rules).
    #[serde(default)]
    pub headers: Option<HeaderControl>,
    #[serde(default = "default_lb")]
    pub lb: String,
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub cache: Option<CachePolicyConfig>,
    #[serde(default)]
    pub path_rewrite: Option<PathRewriteConfig>,
    #[serde(default)]
    pub ipc: Option<IpcUpstreamConfig>,
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
    /// IPC mode: "shm" or "tcp"
    #[serde(default)]
    pub mode: IpcMode,
    /// Target address for network IPC ("127.0.0.1:9000") or base path for SHM IPC.
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
    pub retry: Option<RetryConfig>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RetryConfig {
    #[serde(default = "default_retry_attempts")]
    pub attempts: usize,
    #[serde(default = "default_retry_backoff")]
    pub backoff_ms: u64,
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
pub struct HttpHealthCheckConfig {
    /// Probe path (absolute path, may include query), defaults to "/".
    #[serde(default)]
    pub path: Option<String>,
    /// HTTP method to use ("HEAD" or "GET"), defaults to "HEAD".
    #[serde(default)]
    pub method: Option<String>,
    /// Expected status codes (exact match). If omitted, 2xx/3xx are treated as healthy.
    #[serde(default)]
    pub expected_status: Option<Vec<u16>>,
}
