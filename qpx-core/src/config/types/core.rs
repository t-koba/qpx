use super::super::defaults::*;
use serde::Deserialize;

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
    #[serde(default = "default_runtime_max_observed_request_body_bytes")]
    pub max_observed_request_body_bytes: usize,
    #[serde(default = "default_runtime_max_observed_response_body_bytes")]
    pub max_observed_response_body_bytes: usize,
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
            max_observed_request_body_bytes: default_runtime_max_observed_request_body_bytes(),
            max_observed_response_body_bytes: default_runtime_max_observed_response_body_bytes(),
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
