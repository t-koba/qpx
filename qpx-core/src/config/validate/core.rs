use anyhow::{anyhow, Result};

use super::super::types::{Config, IdentityConfig, MessagesConfig, RuntimeConfig};

pub(super) fn validate_listener_topology(config: &Config) -> Result<()> {
    if config.listeners.is_empty() && config.reverse.is_empty() {
        return Err(anyhow!("no listeners or reverse proxies configured"));
    }
    Ok(())
}

pub(super) fn validate_identity_config(identity: &IdentityConfig) -> Result<()> {
    if identity.proxy_name.trim().is_empty() {
        return Err(anyhow!("identity.proxy_name must not be empty"));
    }
    if !is_http_token(identity.proxy_name.as_str()) {
        return Err(anyhow!("identity.proxy_name must be a valid HTTP token"));
    }
    if identity.auth_realm.trim().is_empty() {
        return Err(anyhow!("identity.auth_realm must not be empty"));
    }
    if identity.metrics_prefix.trim().is_empty() {
        return Err(anyhow!("identity.metrics_prefix must not be empty"));
    }
    let first = identity
        .metrics_prefix
        .chars()
        .next()
        .ok_or_else(|| anyhow!("identity.metrics_prefix must not be empty"))?;
    if !(first.is_ascii_alphabetic() || first == '_' || first == ':') {
        return Err(anyhow!(
            "identity.metrics_prefix must start with [A-Za-z_:]"
        ));
    }
    if !identity
        .metrics_prefix
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    {
        return Err(anyhow!(
            "identity.metrics_prefix must contain only [A-Za-z0-9_:]"
        ));
    }
    if let Some(ua) = identity.generated_user_agent.as_deref() {
        if ua.trim().is_empty() {
            return Err(anyhow!(
                "identity.generated_user_agent must not be empty when set"
            ));
        }
    }
    Ok(())
}

fn is_http_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

pub(super) fn validate_messages_config(messages: &MessagesConfig) -> Result<()> {
    for (field, value) in [
        ("messages.blocked", messages.blocked.as_str()),
        ("messages.forbidden", messages.forbidden.as_str()),
        ("messages.trace_disabled", messages.trace_disabled.as_str()),
        ("messages.proxy_error", messages.proxy_error.as_str()),
        (
            "messages.proxy_auth_required",
            messages.proxy_auth_required.as_str(),
        ),
        ("messages.reverse_error", messages.reverse_error.as_str()),
        ("messages.cache_miss", messages.cache_miss.as_str()),
        (
            "messages.unsupported_ftp_method",
            messages.unsupported_ftp_method.as_str(),
        ),
        ("messages.ftp_disabled", messages.ftp_disabled.as_str()),
        (
            "messages.connect_udp_disabled",
            messages.connect_udp_disabled.as_str(),
        ),
        (
            "messages.upstream_connect_udp_failed",
            messages.upstream_connect_udp_failed.as_str(),
        ),
    ] {
        if value.trim().is_empty() {
            return Err(anyhow!("{field} must not be empty"));
        }
    }
    Ok(())
}

pub(super) fn validate_runtime_config(runtime: &RuntimeConfig) -> Result<()> {
    if runtime.max_h3_request_body_bytes == 0 {
        return Err(anyhow!("runtime.max_h3_request_body_bytes must be >= 1"));
    }
    if runtime.max_h3_response_body_bytes == 0 {
        return Err(anyhow!("runtime.max_h3_response_body_bytes must be >= 1"));
    }
    if runtime.max_reverse_retry_template_body_bytes == 0 {
        return Err(anyhow!(
            "runtime.max_reverse_retry_template_body_bytes must be >= 1"
        ));
    }
    if runtime.max_observed_request_body_bytes == 0 {
        return Err(anyhow!(
            "runtime.max_observed_request_body_bytes must be >= 1"
        ));
    }
    if runtime.max_observed_response_body_bytes == 0 {
        return Err(anyhow!(
            "runtime.max_observed_response_body_bytes must be >= 1"
        ));
    }
    if runtime.max_ftp_concurrency == 0 {
        return Err(anyhow!("runtime.max_ftp_concurrency must be >= 1"));
    }
    if runtime.max_concurrent_connections == 0 {
        return Err(anyhow!("runtime.max_concurrent_connections must be >= 1"));
    }
    if runtime.max_h3_streams_per_connection == 0 {
        return Err(anyhow!(
            "runtime.max_h3_streams_per_connection must be >= 1"
        ));
    }
    if runtime.upstream_http_timeout_ms == 0 {
        return Err(anyhow!("runtime.upstream_http_timeout_ms must be >= 1"));
    }
    if runtime.upstream_proxy_max_concurrent_per_endpoint == 0 {
        return Err(anyhow!(
            "runtime.upstream_proxy_max_concurrent_per_endpoint must be >= 1"
        ));
    }
    if runtime.tls_peek_timeout_ms == 0 {
        return Err(anyhow!("runtime.tls_peek_timeout_ms must be >= 1"));
    }
    if runtime.http_header_read_timeout_ms == 0 {
        return Err(anyhow!("runtime.http_header_read_timeout_ms must be >= 1"));
    }
    if runtime.upgrade_wait_timeout_ms == 0 {
        return Err(anyhow!("runtime.upgrade_wait_timeout_ms must be >= 1"));
    }
    if runtime.tunnel_idle_timeout_ms == 0 {
        return Err(anyhow!("runtime.tunnel_idle_timeout_ms must be >= 1"));
    }
    if runtime.h3_read_timeout_ms == 0 {
        return Err(anyhow!("runtime.h3_read_timeout_ms must be >= 1"));
    }
    if let Some(worker_threads) = runtime.worker_threads {
        if worker_threads == 0 {
            return Err(anyhow!("runtime.worker_threads must be >= 1"));
        }
    }
    if let Some(max_blocking_threads) = runtime.max_blocking_threads {
        if max_blocking_threads == 0 {
            return Err(anyhow!("runtime.max_blocking_threads must be >= 1"));
        }
    }
    if let Some(acceptor_tasks) = runtime.acceptor_tasks_per_listener {
        if acceptor_tasks == 0 {
            return Err(anyhow!("runtime.acceptor_tasks_per_listener must be >= 1"));
        }
    }
    if runtime.tcp_backlog <= 0 {
        return Err(anyhow!("runtime.tcp_backlog must be >= 1"));
    }
    Ok(())
}
