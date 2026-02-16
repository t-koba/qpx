pub(super) fn default_log_level() -> String {
    "info".to_string()
}

pub(super) fn default_log_format() -> String {
    "json".to_string()
}

pub(super) fn default_metrics_path() -> String {
    "/metrics".to_string()
}

pub(super) fn default_user_filter() -> String {
    "(|(uid={username})(sAMAccountName={username})(userPrincipalName={username}))".to_string()
}

pub(super) fn default_group_filter() -> String {
    "(|(member={user_dn})(memberUid={username}))".to_string()
}

pub(super) fn default_group_attr() -> String {
    "cn".to_string()
}

pub(super) fn default_ldap_require_starttls() -> bool {
    true
}

pub(super) fn default_ldap_timeout_ms() -> u64 {
    5_000
}

pub(super) fn default_verify_upstream() -> bool {
    true
}

pub(super) fn default_lb() -> String {
    "round_robin".to_string()
}

pub(super) fn default_retry_attempts() -> usize {
    2
}

pub(super) fn default_retry_backoff() -> u64 {
    100
}

pub(super) fn default_health_check_interval_ms() -> u64 {
    5000
}

pub(super) fn default_health_check_timeout_ms() -> u64 {
    1000
}

pub(super) fn default_health_check_fail_threshold() -> u32 {
    3
}

pub(super) fn default_health_check_cooldown_ms() -> u64 {
    30000
}

pub(super) fn default_connect_udp_idle_timeout_secs() -> u64 {
    30
}

pub(super) fn default_connect_udp_max_capsule_buffer_bytes() -> usize {
    256 * 1024
}

pub(super) fn default_ftp_max_request_body_bytes() -> usize {
    8 * 1024 * 1024
}

pub(super) fn default_ftp_max_download_bytes() -> usize {
    64 * 1024 * 1024
}

pub(super) fn default_ftp_timeout_ms() -> u64 {
    10_000
}

pub(super) fn default_xdp_metadata_mode() -> String {
    "proxy-v1".to_string()
}

pub(super) fn default_xdp_require_metadata() -> bool {
    true
}

pub(super) fn default_local_response_status() -> u16 {
    200
}

pub(super) fn default_reverse_enforce_sni_host_match() -> bool {
    true
}

pub(super) fn default_reverse_backend_weight() -> u32 {
    100
}

pub(super) fn default_reverse_mirror_percent() -> u32 {
    100
}

pub(super) fn default_reverse_h3_passthrough_max_sessions() -> usize {
    4096
}

pub(super) fn default_reverse_h3_passthrough_idle_timeout_secs() -> u64 {
    60
}

pub(super) fn default_reverse_h3_passthrough_max_new_sessions_per_sec() -> u64 {
    1024
}

pub(super) fn default_reverse_h3_passthrough_min_client_bytes() -> usize {
    1200
}

pub(super) fn default_reverse_h3_passthrough_max_amplification() -> u32 {
    3
}

pub(super) fn default_runtime_reuse_port() -> bool {
    true
}

pub(super) fn default_runtime_tcp_backlog() -> i32 {
    4096
}

pub(super) fn default_runtime_max_ftp_concurrency() -> usize {
    32
}

pub(super) fn default_runtime_max_h3_request_body_bytes() -> usize {
    16 * 1024 * 1024
}

pub(super) fn default_runtime_max_h3_response_body_bytes() -> usize {
    16 * 1024 * 1024
}

pub(super) fn default_runtime_max_reverse_retry_template_body_bytes() -> usize {
    8 * 1024 * 1024
}

pub(super) fn default_runtime_upstream_http_timeout_ms() -> u64 {
    30_000
}

pub(super) fn default_runtime_tls_peek_timeout_ms() -> u64 {
    1_000
}

pub(super) fn default_runtime_http_header_read_timeout_ms() -> u64 {
    10_000
}

pub(super) fn default_runtime_upgrade_wait_timeout_ms() -> u64 {
    10_000
}

pub(super) fn default_runtime_tunnel_idle_timeout_ms() -> u64 {
    300_000
}

pub(super) fn default_runtime_h3_read_timeout_ms() -> u64 {
    10_000
}

pub(super) fn default_identity_proxy_name() -> String {
    "qpx".to_string()
}

pub(super) fn default_identity_auth_realm() -> String {
    "qpx".to_string()
}

pub(super) fn default_identity_metrics_prefix() -> String {
    "qpx".to_string()
}

pub(super) fn default_message_blocked() -> String {
    "blocked".to_string()
}

pub(super) fn default_message_forbidden() -> String {
    "forbidden".to_string()
}

pub(super) fn default_message_trace_disabled() -> String {
    "trace disabled".to_string()
}

pub(super) fn default_message_proxy_error() -> String {
    "proxy error".to_string()
}

pub(super) fn default_message_proxy_auth_required() -> String {
    "proxy auth required".to_string()
}

pub(super) fn default_message_reverse_error() -> String {
    "reverse error".to_string()
}

pub(super) fn default_message_cache_miss() -> String {
    "cache miss".to_string()
}

pub(super) fn default_message_unsupported_ftp_method() -> String {
    "unsupported ftp method".to_string()
}

pub(super) fn default_message_ftp_disabled() -> String {
    "ftp over http disabled".to_string()
}

pub(super) fn default_message_connect_udp_disabled() -> String {
    "connect-udp disabled".to_string()
}

pub(super) fn default_message_upstream_connect_udp_failed() -> String {
    "upstream connect-udp failed".to_string()
}

pub(super) fn default_metrics_max_concurrent_connections() -> usize {
    32
}

pub(super) fn default_exporter_max_queue_events() -> usize {
    4096
}

pub(super) fn default_exporter_capture_plaintext() -> bool {
    true
}

pub(super) fn default_exporter_capture_encrypted() -> bool {
    true
}

pub(super) fn default_exporter_max_chunk_bytes() -> usize {
    16 * 1024
}

pub(super) fn default_cache_backend_kind() -> String {
    "redis".to_string()
}

pub(super) fn default_cache_timeout_ms() -> u64 {
    1500
}

pub(super) fn default_cache_max_object_bytes() -> usize {
    1024 * 1024
}
