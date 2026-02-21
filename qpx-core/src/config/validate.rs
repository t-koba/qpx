use anyhow::{anyhow, Result};
use cidr::IpCidr;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use super::types::*;

const UPSTREAM_URL_SCHEMES: &[&str] = &[
    "http",
    "https",
    "h3",
    "ws",
    "wss",
    "fastcgi",
    "fastcgi+unix",
];

const UPSTREAM_PROXY_URL_SCHEMES: &[&str] = &["http", "https"];

const REVERSE_UPSTREAM_URL_SCHEMES: &[&str] = &[
    "http",
    "https",
    "ws",
    "wss",
    "fastcgi",
    "fastcgi+unix",
];

const REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES: &[&str] = &["https", "h3"];

pub(super) fn validate_config(config: &Config) -> Result<()> {
    if config.version != 1 {
        return Err(anyhow!(
            "unsupported config.version {} (expected 1)",
            config.version
        ));
    }
    validate_listener_topology(config)?;
    validate_identity_config(&config.identity)?;
    validate_messages_config(&config.messages)?;
    validate_runtime_config(&config.runtime)?;
    validate_system_log_config(&config.system_log)?;
    validate_access_log_config(&config.access_log)?;
    validate_audit_log_config(&config.audit_log)?;
    if let Some(metrics) = config.metrics.as_ref() {
        validate_metrics_config(metrics)?;
    }
    if let Some(otel) = config.otel.as_ref() {
        validate_otel_config(otel)?;
    }
    if let Some(exporter) = config.exporter.as_ref() {
        validate_exporter_config(exporter)?;
    }
    validate_auth_config(&config.auth)?;
    let upstreams = validate_upstream_configs(config)?;
    let cache_backends = validate_cache_backends(&config.cache)?;
    validate_listener_configs(config, &cache_backends, &upstreams)?;
    validate_reverse_configs(config, &cache_backends, &upstreams)?;
    Ok(())
}

fn validate_system_log_config(system: &SystemLogConfig) -> Result<()> {
    let level = system.level.trim();
    if level.is_empty() {
        return Err(anyhow!("system_log.level must not be empty"));
    }
    tracing_subscriber::EnvFilter::try_new(level)
        .map_err(|e| anyhow!("system_log.level is invalid: {e}"))?;
    let format = system.format.trim().to_ascii_lowercase();
    if format != "json" && format != "text" {
        return Err(anyhow!("system_log.format must be one of: json, text"));
    }
    Ok(())
}

fn validate_log_output_config(
    output: &LogOutputConfig,
    context: &str,
    allow_combined: bool,
) -> Result<()> {
    let format = output.format.trim().to_ascii_lowercase();
    let format_ok = match format.as_str() {
        "json" | "text" => true,
        "combined" => allow_combined,
        _ => false,
    };
    if !format_ok {
        if allow_combined {
            return Err(anyhow!(
                "{context}.format must be one of: json, combined, text"
            ));
        }
        return Err(anyhow!("{context}.format must be one of: json, text"));
    }

    let rotation = output.rotation.trim().to_ascii_lowercase();
    if rotation != "hourly" && rotation != "daily" && rotation != "never" {
        return Err(anyhow!(
            "{context}.rotation must be one of: hourly, daily, never"
        ));
    }
    if output.rotation_count == 0 {
        return Err(anyhow!("{context}.rotation_count must be >= 1"));
    }
    if let Some(path) = output.path.as_deref() {
        let path = path.trim();
        if path.is_empty() {
            return Err(anyhow!("{context}.path must not be empty when set"));
        }
        let p = std::path::Path::new(path);
        if p.file_name().is_none() {
            return Err(anyhow!("{context}.path must include a file name"));
        }
    }
    Ok(())
}

fn validate_access_log_config(access: &AccessLogConfig) -> Result<()> {
    validate_log_output_config(&access.output, "access_log", true)?;
    for prefix in &access.exclude {
        let prefix = prefix.trim();
        if prefix.is_empty() {
            return Err(anyhow!("access_log.exclude entries must not be empty"));
        }
        if !prefix.starts_with('/') {
            return Err(anyhow!(
                "access_log.exclude entries must be absolute paths (start with /): {prefix}"
            ));
        }
        if prefix.contains('?') || prefix.contains('#') {
            return Err(anyhow!(
                "access_log.exclude entries must not include '?' or '#': {prefix}"
            ));
        }
    }
    Ok(())
}

fn validate_audit_log_config(audit: &AuditLogConfig) -> Result<()> {
    validate_log_output_config(&audit.output, "audit_log", false)?;
    Ok(())
}

fn validate_listener_topology(config: &Config) -> Result<()> {
    if config.listeners.is_empty() && config.reverse.is_empty() {
        return Err(anyhow!("no listeners or reverse proxies configured"));
    }
    Ok(())
}

fn validate_identity_config(identity: &IdentityConfig) -> Result<()> {
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

fn validate_metrics_config(metrics: &MetricsConfig) -> Result<()> {
    let listen: std::net::SocketAddr = metrics
        .listen
        .parse()
        .map_err(|e| anyhow!("metrics.listen is invalid: {}", e))?;
    if metrics.max_concurrent_connections == 0 {
        return Err(anyhow!("metrics.max_concurrent_connections must be >= 1"));
    }
    if metrics.allow.is_empty() {
        if !listen.ip().is_loopback() {
            return Err(anyhow!(
                "metrics.listen must be loopback unless metrics.allow is configured"
            ));
        }
        return Ok(());
    }
    for cidr in &metrics.allow {
        if cidr.trim().is_empty() {
            return Err(anyhow!("metrics.allow entries must not be empty"));
        }
        let _: IpCidr = cidr
            .parse()
            .map_err(|_| anyhow!("metrics.allow has invalid CIDR: {}", cidr))?;
    }
    Ok(())
}

fn validate_otel_config(otel: &OtelConfig) -> Result<()> {
    let protocol = otel.protocol.trim().to_ascii_lowercase();
    if protocol != "grpc" {
        return Err(anyhow!("otel.protocol must be grpc"));
    }
    let level = otel.level.trim();
    if level.is_empty() {
        return Err(anyhow!("otel.level must not be empty"));
    }
    tracing_subscriber::EnvFilter::try_new(level)
        .map_err(|e| anyhow!("otel.level is invalid: {e}"))?;
    if otel.sample_percent > 100 {
        return Err(anyhow!("otel.sample_percent must be between 0 and 100"));
    }
    if let Some(service) = otel.service_name.as_deref() {
        if service.trim().is_empty() {
            return Err(anyhow!("otel.service_name must not be empty when set"));
        }
    }
    for (key, value) in &otel.headers {
        let key = key.trim();
        if key.is_empty() {
            return Err(anyhow!("otel.headers keys must not be empty"));
        }
        http::header::HeaderName::from_bytes(key.as_bytes())
            .map_err(|_| anyhow!("otel.headers has invalid header name: {key}"))?;
        http::HeaderValue::from_str(value.trim()).map_err(|_| {
            anyhow!(
                "otel.headers has invalid header value for {key}: {}",
                value.trim()
            )
        })?;
    }

    let Some(endpoint) = otel.endpoint.as_deref() else {
        if otel.enabled {
            return Err(anyhow!(
                "otel.endpoint must be set when otel.enabled=true"
            ));
        }
        return Ok(());
    };
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(anyhow!("otel.endpoint must not be empty"));
    }
    let raw = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("http://{}", endpoint)
    };
    let url = url::Url::parse(&raw)
        .map_err(|e| anyhow!("otel.endpoint is invalid: {e}"))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(anyhow!(
            "otel.endpoint must use http:// or https:// (got {})",
            url.scheme()
        ));
    }
    if url.host_str().is_none() {
        return Err(anyhow!("otel.endpoint is invalid: missing host"));
    }
    if url.port_or_known_default().is_none() {
        return Err(anyhow!("otel.endpoint is invalid: missing port"));
    }
    Ok(())
}

fn validate_exporter_config(exporter: &ExporterConfig) -> Result<()> {
    if exporter.endpoint.trim().is_empty() {
        return Err(anyhow!("exporter.endpoint must not be empty"));
    }
    let authority: http::uri::Authority = exporter
        .endpoint
        .parse()
        .map_err(|_| anyhow!("exporter.endpoint is invalid: expected host:port"))?;
    if authority.port_u16().is_none() {
        return Err(anyhow!("exporter.endpoint is invalid: missing port"));
    }
    if exporter.max_queue_events == 0 {
        return Err(anyhow!("exporter.max_queue_events must be >= 1"));
    }
    if exporter.capture.max_chunk_bytes == 0 {
        return Err(anyhow!("exporter.capture.max_chunk_bytes must be >= 1"));
    }

    if let Some(auth) = exporter.auth.as_ref() {
        if let Some(env) = auth.token_env.as_deref() {
            if env.trim().is_empty() {
                return Err(anyhow!(
                    "exporter.auth.token_env must not be empty when set"
                ));
            }
        }
    }
    if let Some(tls) = exporter.tls.as_ref() {
        if tls.enabled {
            #[cfg(feature = "tls-rustls")]
            {
                match (tls.client_cert.as_deref(), tls.client_key.as_deref()) {
                    (Some(cert), Some(key)) => {
                        if cert.trim().is_empty() || key.trim().is_empty() {
                            return Err(anyhow!(
                                "exporter.tls.client_cert/client_key must not be empty when set"
                            ));
                        }
                    }
                    (None, None) => {}
                    _ => {
                        return Err(anyhow!(
                            "exporter.tls.client_cert and exporter.tls.client_key must be set together"
                        ));
                    }
                }
                let pkcs12_set = !tls.client_pkcs12.as_deref().unwrap_or("").trim().is_empty();
                let pkcs12_password_env_set = !tls
                    .client_pkcs12_password_env
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty();
                if pkcs12_set || pkcs12_password_env_set {
                    return Err(anyhow!(
                        "exporter.tls.client_pkcs12 is not supported on rustls builds (use client_cert/client_key)"
                    ));
                }
            }

            #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
            {
                if !tls.client_cert.as_deref().unwrap_or("").trim().is_empty()
                    || !tls.client_key.as_deref().unwrap_or("").trim().is_empty()
                {
                    return Err(anyhow!(
                        "exporter.tls.client_cert/client_key is not supported on tls-native builds (use client_pkcs12)"
                    ));
                }
                if let Some(path) = tls.client_pkcs12.as_deref() {
                    if path.trim().is_empty() {
                        return Err(anyhow!(
                            "exporter.tls.client_pkcs12 must not be empty when set"
                        ));
                    }
                }
                if let Some(env) = tls.client_pkcs12_password_env.as_deref() {
                    if env.trim().is_empty() {
                        return Err(anyhow!(
                            "exporter.tls.client_pkcs12_password_env must not be empty when set"
                        ));
                    }
                    if tls.client_pkcs12.as_deref().unwrap_or("").trim().is_empty() {
                        return Err(anyhow!(
                            "exporter.tls.client_pkcs12_password_env requires exporter.tls.client_pkcs12"
                        ));
                    }
                }
            }

            #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
            {
                return Err(anyhow!(
                    "exporter.tls is enabled, but this build has no TLS backend enabled"
                ));
            }

            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            {
                if let Some(ca) = tls.ca_cert.as_deref() {
                    if ca.trim().is_empty() {
                        return Err(anyhow!("exporter.tls.ca_cert must not be empty when set"));
                    }
                }
                if let Some(name) = tls.server_name.as_deref() {
                    if name.trim().is_empty() {
                        return Err(anyhow!(
                            "exporter.tls.server_name must not be empty when set"
                        ));
                    }
                }
            }
        }
    }

    let host = authority.host();
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    let tls_enabled = exporter.tls.as_ref().map(|t| t.enabled).unwrap_or(false);
    let tls_insecure = exporter
        .tls
        .as_ref()
        .map(|t| t.insecure_skip_verify)
        .unwrap_or(false);
    if tls_insecure && !exporter.allow_insecure {
        return Err(anyhow!(
            "exporter.tls.insecure_skip_verify requires exporter.allow_insecure: true"
        ));
    }
    if !exporter.enabled {
        return Ok(());
    }
    if !tls_enabled && !is_loopback && !exporter.allow_insecure {
        return Err(anyhow!(
            "exporter.endpoint is not loopback; enable exporter.tls or set exporter.allow_insecure: true"
        ));
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

fn validate_messages_config(messages: &MessagesConfig) -> Result<()> {
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

fn validate_runtime_config(runtime: &RuntimeConfig) -> Result<()> {
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
    if runtime.max_ftp_concurrency == 0 {
        return Err(anyhow!("runtime.max_ftp_concurrency must be >= 1"));
    }
    if runtime.max_concurrent_connections == 0 {
        return Err(anyhow!(
            "runtime.max_concurrent_connections must be >= 1"
        ));
    }
    if runtime.upstream_http_timeout_ms == 0 {
        return Err(anyhow!("runtime.upstream_http_timeout_ms must be >= 1"));
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

fn validate_auth_config(auth: &AuthConfig) -> Result<()> {
    let mut local_usernames = HashSet::new();
    for user in &auth.users {
        if user.username.trim().is_empty() {
            return Err(anyhow!("auth.users[].username must not be empty"));
        }
        if !local_usernames.insert(user.username.clone()) {
            return Err(anyhow!("duplicate auth.users username: {}", user.username));
        }
        if let Some(password) = user.password.as_deref() {
            if password.trim().is_empty() {
                return Err(anyhow!(
                    "auth.users {} password must not be empty when set",
                    user.username
                ));
            }
        }
        if let Some(ha1) = user.ha1.as_deref() {
            if ha1.trim().is_empty() {
                return Err(anyhow!(
                    "auth.users {} ha1 must not be empty when set",
                    user.username
                ));
            }
            if !is_valid_sha256_ha1(ha1) {
                return Err(anyhow!(
                    "auth.users {} ha1 must be SHA-256 HA1 hex (64 chars) or sha-256:<hex>",
                    user.username
                ));
            }
            #[cfg(not(feature = "digest-auth"))]
            {
                return Err(anyhow!(
                    "auth.users {} ha1 requires build feature digest-auth",
                    user.username
                ));
            }
        }
        if user.password.is_none() && user.ha1.is_none() {
            return Err(anyhow!(
                "auth.users {} must set either password or ha1",
                user.username
            ));
        }
    }

    if let Some(ldap) = auth.ldap.as_ref() {
        if ldap.url.starts_with("ldap://") && !ldap.require_starttls {
            return Err(anyhow!(
                "auth.ldap.require_starttls must be true when auth.ldap.url uses ldap://"
            ));
        }
        if ldap.timeout_ms == 0 {
            return Err(anyhow!("auth.ldap.timeout_ms must be >= 1"));
        }
    }
    Ok(())
}

fn is_valid_sha256_ha1(raw: &str) -> bool {
    let raw = raw.trim();
    let hex = if raw.len() > 8 && raw[..8].eq_ignore_ascii_case("sha-256:") {
        &raw[8..]
    } else {
        raw
    };
    let hex = hex.trim();
    hex.len() == 64 && hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
}

fn validate_cache_backends(cache: &CacheConfig) -> Result<HashSet<String>> {
    let mut cache_backends = HashSet::new();
    for backend in &cache.backends {
        if backend.name.trim().is_empty() {
            return Err(anyhow!("cache backend name must not be empty"));
        }
        if !cache_backends.insert(backend.name.clone()) {
            return Err(anyhow!("duplicate cache backend name: {}", backend.name));
        }
        if backend.kind != "http" && backend.kind != "redis" {
            return Err(anyhow!(
                "cache backend {} has unsupported kind: {}",
                backend.name,
                backend.kind
            ));
        }
        if backend.endpoint.trim().is_empty() {
            return Err(anyhow!(
                "cache backend {} endpoint must not be empty",
                backend.name
            ));
        }
        if backend.kind == "http" {
            let url = url::Url::parse(backend.endpoint.as_str()).map_err(|e| {
                anyhow!(
                    "cache backend {} has invalid endpoint url {} ({})",
                    backend.name,
                    backend.endpoint,
                    e
                )
            })?;
            if !url.username().is_empty() || url.password().is_some() {
                return Err(anyhow!(
                    "cache backend {} endpoint must not include userinfo",
                    backend.name
                ));
            }
            let scheme = url.scheme();
            if scheme != "http" && scheme != "https" {
                return Err(anyhow!(
                    "cache backend {} has unsupported http endpoint scheme: {}",
                    backend.name,
                    scheme
                ));
            }
        }
        if backend.timeout_ms == 0 {
            return Err(anyhow!(
                "cache backend {} timeout_ms must be >= 1",
                backend.name
            ));
        }
        if backend.max_object_bytes == 0 {
            return Err(anyhow!(
                "cache backend {} max_object_bytes must be >= 1",
                backend.name
            ));
        }
    }
    Ok(cache_backends)
}

fn validate_upstream_configs(config: &Config) -> Result<HashMap<String, url::Url>> {
    let mut upstreams = HashMap::new();
    for upstream in &config.upstreams {
        if upstream.name.trim().is_empty() {
            return Err(anyhow!("upstream name must not be empty"));
        }
        if upstreams.contains_key(&upstream.name) {
            return Err(anyhow!("duplicate upstream name: {}", upstream.name));
        }
        if upstream.url.trim().is_empty() {
            return Err(anyhow!("upstream {} url must not be empty", upstream.name));
        }
        let url = url::Url::parse(upstream.url.as_str()).map_err(|e| {
            anyhow!(
                "upstream {} has invalid url {} ({})",
                upstream.name,
                upstream.url,
                e
            )
        })?;
        let scheme = url.scheme();
        if !UPSTREAM_URL_SCHEMES
            .iter()
            .copied()
            .any(|allowed| allowed == scheme)
        {
            return Err(anyhow!(
                "upstream {} has unsupported url scheme: {}",
                upstream.name,
                scheme
            ));
        }
        if (!url.username().is_empty() || url.password().is_some())
            && !scheme.eq_ignore_ascii_case("http")
            && !scheme.eq_ignore_ascii_case("https")
        {
            return Err(anyhow!(
                "upstream {} url includes userinfo but scheme is not http/https",
                upstream.name
            ));
        }
        upstreams.insert(upstream.name.clone(), url);
    }
    Ok(upstreams)
}

fn validate_listener_configs(
    config: &Config,
    cache_backends: &HashSet<String>,
    upstreams: &HashMap<String, url::Url>,
) -> Result<()> {
    let mut listener_names = HashSet::new();
    for listener in &config.listeners {
        if listener.name.trim().is_empty() {
            return Err(anyhow!("listener name must not be empty"));
        }
        if !listener_names.insert(listener.name.clone()) {
            return Err(anyhow!("duplicate listener name: {}", listener.name));
        }
        let _: std::net::SocketAddr = listener
            .listen
            .parse()
            .map_err(|e| anyhow!("listener {} listen is invalid: {}", listener.name, e))?;
        validate_rate_limit_config(listener.rate_limit.as_ref(), &format!("listener {}", listener.name))?;
        validate_action_config(
            &listener.default_action,
            &format!("listener {}", listener.name),
        )?;
        let mut uses_inspect = matches!(listener.default_action.kind, ActionKind::Inspect);
        if let Some(upstream_ref) = listener.default_action.upstream.as_deref() {
            validate_named_upstream_ref(
                upstream_ref,
                upstreams,
                format!("listener {} default_action.upstream", listener.name).as_str(),
                UPSTREAM_PROXY_URL_SCHEMES,
                true,
                true,
            )?;
        }
        if let Some(upstream_proxy) = listener.upstream_proxy.as_deref() {
            validate_named_upstream_ref(
                upstream_proxy,
                upstreams,
                format!("listener {} upstream_proxy", listener.name).as_str(),
                UPSTREAM_PROXY_URL_SCHEMES,
                true,
                true,
            )?;
        }
        for rule in &listener.rules {
            validate_rate_limit_config(
                rule.rate_limit.as_ref(),
                &format!("listener {} rule {}", listener.name, rule.name),
            )?;
            if let Some(action) = rule.action.as_ref() {
                validate_action_config(
                    action,
                    &format!("listener {} rule {}", listener.name, rule.name),
                )?;
                uses_inspect = uses_inspect || matches!(action.kind, ActionKind::Inspect);
                if let Some(upstream_ref) = action.upstream.as_deref() {
                    validate_named_upstream_ref(
                        upstream_ref,
                        upstreams,
                        format!(
                            "listener {} rule {} action.upstream",
                            listener.name, rule.name
                        )
                        .as_str(),
                        UPSTREAM_PROXY_URL_SCHEMES,
                        true,
                        true,
                    )?;
                }
            }
            if let Some(headers) = rule.headers.as_ref() {
                validate_header_control(
                    headers,
                    &format!("listener {} rule {}", listener.name, rule.name),
                )?;
            }
        }
        if uses_inspect
            && !listener
                .tls_inspection
                .as_ref()
                .map(|t| t.enabled)
                .unwrap_or(false)
        {
            return Err(anyhow!(
                "listener {} uses inspect action but tls_inspection.enabled is not true",
                listener.name
            ));
        }
        if let Some(tls) = listener.tls_inspection.as_ref() {
            for pattern in &tls.verify_exceptions {
                if pattern.trim().is_empty() {
                    return Err(anyhow!(
                        "listener {} has empty tls_inspection.verify_exceptions pattern",
                        listener.name
                    ));
                }
                globset::Glob::new(pattern).map_err(|e| {
                    anyhow!(
                        "listener {} invalid tls_inspection.verify_exceptions glob {}: {}",
                        listener.name,
                        pattern,
                        e
                    )
                })?;
            }
        }
        validate_xdp_config("listener", &listener.name, listener.xdp.as_ref())?;
        if let Some(cache) = listener.cache.as_ref().filter(|cache| cache.enabled) {
            validate_cache_policy(
                cache,
                cache_backends,
                &format!("listener {}", listener.name),
            )?;
        }
        if listener.ftp.max_request_body_bytes == 0 {
            return Err(anyhow!(
                "listener {} ftp.max_request_body_bytes must be >= 1",
                listener.name
            ));
        }
        if listener.ftp.max_download_bytes == 0 {
            return Err(anyhow!(
                "listener {} ftp.max_download_bytes must be >= 1",
                listener.name
            ));
        }
        if listener.ftp.timeout_ms == 0 {
            return Err(anyhow!(
                "listener {} ftp.timeout_ms must be >= 1",
                listener.name
            ));
        }
        if let Some(http3) = listener.http3.as_ref() {
            if matches!(listener.mode, ListenerMode::Transparent) && http3.enabled {
                return Err(anyhow!(
                    "listener {} mode=transparent does not support http3 listeners",
                    listener.name
                ));
            }
            if http3.enabled {
                if let Some(http3_listen) = http3.listen.as_deref() {
                    let _: std::net::SocketAddr = http3_listen.parse().map_err(|e| {
                        anyhow!(
                            "listener {} http3.listen is invalid: {}",
                            listener.name,
                            e
                        )
                    })?;
                }
            }
            if let Some(connect_udp) = http3.connect_udp.as_ref() {
                if connect_udp.idle_timeout_secs == 0 {
                    return Err(anyhow!(
                        "listener {} http3.connect_udp.idle_timeout_secs must be >= 1",
                        listener.name
                    ));
                }
                if connect_udp.max_capsule_buffer_bytes == 0 {
                    return Err(anyhow!(
                        "listener {} http3.connect_udp.max_capsule_buffer_bytes must be >= 1",
                        listener.name
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_rate_limit_config(rate: Option<&RateLimitConfig>, context: &str) -> Result<()> {
    let Some(rate) = rate else {
        return Ok(());
    };
    let key = rate.key.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err(anyhow!("{context} rate_limit.key must not be empty"));
    }
    if key != "global" && key != "src_ip" {
        return Err(anyhow!(
            "{context} rate_limit.key must be one of: global, src_ip"
        ));
    }

    if matches!(rate.rps, Some(0)) {
        return Err(anyhow!("{context} rate_limit.rps must be >= 1"));
    }
    if matches!(rate.burst, Some(0)) {
        return Err(anyhow!("{context} rate_limit.burst must be >= 1"));
    }
    if rate.burst.is_some() && rate.rps.is_none() {
        return Err(anyhow!(
            "{context} rate_limit.burst requires rate_limit.rps"
        ));
    }

    if matches!(rate.bytes_per_sec, Some(0)) {
        return Err(anyhow!(
            "{context} rate_limit.bytes_per_sec must be >= 1"
        ));
    }
    if matches!(rate.bytes_burst, Some(0)) {
        return Err(anyhow!(
            "{context} rate_limit.bytes_burst must be >= 1"
        ));
    }
    if rate.bytes_burst.is_some() && rate.bytes_per_sec.is_none() {
        return Err(anyhow!(
            "{context} rate_limit.bytes_burst requires rate_limit.bytes_per_sec"
        ));
    }

    if rate.enabled && rate.rps.is_none() && rate.bytes_per_sec.is_none() {
        return Err(anyhow!(
            "{context} rate_limit.enabled requires at least one of rate_limit.rps or rate_limit.bytes_per_sec"
        ));
    }
    Ok(())
}

fn validate_named_upstream_ref(
    upstream_ref: &str,
    upstreams: &HashMap<String, url::Url>,
    context: &str,
    allowed_schemes: &[&str],
    allow_userinfo: bool,
    allow_authority: bool,
) -> Result<()> {
    if !upstream_ref.contains("://") && allow_authority {
        // Treat bare "host:port" (and "[::1]:port") as a direct upstream target.
        if upstream_ref.contains(':') || upstream_ref.starts_with('[') {
            upstream_ref.parse::<http::uri::Authority>().map_err(|_| {
                anyhow!(
                    "{context} has invalid upstream authority reference: {}",
                    upstream_ref
                )
            })?;
            return Ok(());
        }
    }

    let url = if upstream_ref.contains("://") {
        url::Url::parse(upstream_ref).map_err(|e| {
            anyhow!(
                "{context} has invalid upstream URL reference: {} ({})",
                upstream_ref,
                e
            )
        })?
    } else {
        upstreams.get(upstream_ref).cloned().ok_or_else(|| {
            anyhow!(
                "{} references unknown upstream: {}",
                context,
                upstream_ref
            )
        })?
    };

    if (!url.username().is_empty() || url.password().is_some()) && !allow_userinfo {
        return Err(anyhow!("{context} upstream URL must not include userinfo"));
    }

    let scheme = url.scheme();
    if !allowed_schemes.iter().copied().any(|allowed| allowed == scheme) {
        return Err(anyhow!(
            "{context} has unsupported upstream URL scheme: {}",
            scheme
        ));
    }
    Ok(())
}

fn validate_lb_config(lb: &str, context: &str) -> Result<()> {
    let lb = lb.trim().to_ascii_lowercase();
    match lb.as_str() {
        "round_robin"
        | "roundrobin"
        | "random"
        | "least_conn"
        | "least_connections"
        | "consistent_hash"
        | "consistent-hash"
        | "sticky"
        | "sticky_ip"
        | "sticky-src-ip" => Ok(()),
        other => Err(anyhow!("{context} has unknown lb strategy: {other}")),
    }
}

fn validate_retry_config(retry: Option<&RetryConfig>, context: &str) -> Result<()> {
    let Some(retry) = retry else {
        return Ok(());
    };
    if retry.attempts == 0 {
        return Err(anyhow!("{context} retry.attempts must be >= 1"));
    }
    Ok(())
}

fn validate_reverse_configs(
    config: &Config,
    cache_backends: &HashSet<String>,
    upstreams: &HashMap<String, url::Url>,
) -> Result<()> {
    let mut seen_reverse_names: HashSet<String> = HashSet::new();
    for reverse in &config.reverse {
        if reverse.name.trim().is_empty() {
            return Err(anyhow!("reverse name must not be empty"));
        }
        if !seen_reverse_names.insert(reverse.name.clone()) {
            return Err(anyhow!("duplicate reverse name: {}", reverse.name));
        }
        if reverse.listen.trim().is_empty() {
            return Err(anyhow!("reverse {} listen must not be empty", reverse.name));
        }
        reverse
            .listen
            .parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow!("reverse {} listen is invalid: {}", reverse.name, e))?;

        validate_xdp_config("reverse", &reverse.name, reverse.xdp.as_ref())?;
        for pattern in &reverse.sni_host_exceptions {
            if pattern.trim().is_empty() {
                return Err(anyhow!(
                    "reverse {} has empty sni_host_exceptions pattern",
                    reverse.name
                ));
            }
            globset::Glob::new(pattern).map_err(|e| {
                anyhow!(
                    "reverse {} invalid sni_host_exceptions glob {}: {}",
                    reverse.name,
                    pattern,
                    e
                )
            })?;
        }

        if let Some(tls) = reverse.tls.as_ref() {
            if tls.certificates.is_empty() {
                return Err(anyhow!(
                    "reverse {} tls.certificates must contain at least one entry",
                    reverse.name
                ));
            }
            #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
            {
                return Err(anyhow!(
                    "reverse {} configures tls certificates, but this build has no TLS backend enabled",
                    reverse.name
                ));
            }

            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            {
                let mut seen: HashSet<String> = HashSet::new();
                for cert in &tls.certificates {
                    if cert.sni.trim().is_empty() {
                        return Err(anyhow!(
                            "reverse {} tls.certificates[].sni must not be empty",
                            reverse.name
                        ));
                    }
                    #[cfg(feature = "tls-rustls")]
                    {
                        let cert_path = cert.cert.as_deref().unwrap_or("").trim();
                        let key_path = cert.key.as_deref().unwrap_or("").trim();
                        if cert_path.is_empty() || key_path.is_empty() {
                            return Err(anyhow!(
                                "reverse {} tls.certificates[] must set cert+key (PEM) on rustls builds",
                                reverse.name
                            ));
                        }
                        if !cert.pkcs12.as_deref().unwrap_or("").trim().is_empty()
                            || !cert
                                .pkcs12_password_env
                                .as_deref()
                                .unwrap_or("")
                                .trim()
                                .is_empty()
                        {
                            return Err(anyhow!(
                                "reverse {} tls.certificates[] must not set pkcs12 fields on rustls builds",
                                reverse.name
                            ));
                        }
                    }
                    #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
                    {
                        let pkcs12_path = cert.pkcs12.as_deref().unwrap_or("").trim();
                        if pkcs12_path.is_empty() {
                            return Err(anyhow!(
                                "reverse {} tls.certificates[] must set pkcs12 on tls-native builds",
                                reverse.name
                            ));
                        }
                        if !cert.cert.as_deref().unwrap_or("").trim().is_empty()
                            || !cert.key.as_deref().unwrap_or("").trim().is_empty()
                        {
                            return Err(anyhow!(
                                "reverse {} tls.certificates[] must not set cert/key on tls-native builds",
                                reverse.name
                            ));
                        }
                        if let Some(env) = cert.pkcs12_password_env.as_deref() {
                            if env.trim().is_empty() {
                                return Err(anyhow!(
                                    "reverse {} tls.certificates[].pkcs12_password_env must not be empty when set",
                                    reverse.name
                                ));
                            }
                        }
                    }
                    let sni = cert.sni.to_ascii_lowercase();
                    if !seen.insert(sni.clone()) {
                        return Err(anyhow!(
                            "reverse {} has duplicate tls certificate sni: {}",
                            reverse.name,
                            sni
                        ));
                    }
                }
            }

            #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
            if let Some(ca) = tls.client_ca.as_deref() {
                let ca = ca.trim();
                if ca.is_empty() {
                    return Err(anyhow!(
                        "reverse {} tls.client_ca must not be empty when set",
                        reverse.name
                    ));
                }
                #[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
                {
                    return Err(anyhow!(
                        "reverse {} tls.client_ca is not supported on tls-native builds",
                        reverse.name
                    ));
                }
            }
        }

        let h3_enabled = reverse.http3.as_ref().map(|h| h.enabled).unwrap_or(false);
        let h3_passthrough = reverse
            .http3
            .as_ref()
            .map(|h| !h.passthrough_upstreams.is_empty())
            .unwrap_or(false);
        if let Some(h3) = reverse.http3.as_ref() {
            if h3.enabled {
                if let Some(listen) = h3.listen.as_deref() {
                    let listen = listen.trim();
                    if listen.is_empty() {
                        return Err(anyhow!(
                            "reverse {} http3.listen must not be empty when set",
                            reverse.name
                        ));
                    }
                    listen.parse::<std::net::SocketAddr>().map_err(|e| {
                        anyhow!("reverse {} http3.listen is invalid: {}", reverse.name, e)
                    })?;
                }
                if h3.passthrough_max_sessions == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_max_sessions must be >= 1",
                        reverse.name
                    ));
                }
                if h3.passthrough_idle_timeout_secs == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_idle_timeout_secs must be >= 1",
                        reverse.name
                    ));
                }
                if h3.passthrough_max_new_sessions_per_sec == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_max_new_sessions_per_sec must be >= 1",
                        reverse.name
                    ));
                }
                if h3.passthrough_min_client_bytes == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_min_client_bytes must be >= 1",
                        reverse.name
                    ));
                }
                if h3.passthrough_max_amplification == 0 {
                    return Err(anyhow!(
                        "reverse {} http3.passthrough_max_amplification must be >= 1",
                        reverse.name
                    ));
                }
            }
        }
        if h3_passthrough {
            let targets = reverse
                .http3
                .as_ref()
                .map(|h| h.passthrough_upstreams.as_slice())
                .unwrap_or_default();
            for upstream_ref in targets {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!("reverse {} http3.passthrough_upstreams", reverse.name),
                    REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES,
                    false,
                    true,
                )?;
            }
        }

        if reverse.routes.is_empty()
            && reverse.tls_passthrough_routes.is_empty()
            && !(h3_enabled && h3_passthrough)
        {
            return Err(anyhow!("reverse {} has no routes", reverse.name));
        }

        if !reverse.tls_passthrough_routes.is_empty() && reverse.tls.is_none() {
            return Err(anyhow!(
                "reverse {} tls_passthrough_routes requires reverse.tls certificates",
                reverse.name
            ));
        }

        for route in &reverse.routes {
            let has_upstream = !route.upstreams.is_empty();
            let has_backends = !route.backends.is_empty();
            let has_local = route.local_response.is_some();
            let has_fastcgi = route.fastcgi.is_some();
            let configured_kinds = (has_upstream as u8)
                + (has_backends as u8)
                + (has_local as u8)
                + (has_fastcgi as u8);
            if configured_kinds != 1 {
                return Err(anyhow!(
                    "reverse {} route must set exactly one of upstreams, backends, fastcgi, or local_response",
                    reverse.name
                ));
            }
            if let Some(fcgi) = route.fastcgi.as_ref() {
                if fcgi.address.trim().is_empty() {
                    return Err(anyhow!(
                        "reverse {} route fastcgi.address must not be empty",
                        reverse.name
                    ));
                }
                if fcgi.timeout_ms == 0 {
                    return Err(anyhow!(
                        "reverse {} route fastcgi.timeout_ms must be >= 1",
                        reverse.name
                    ));
                }
            }
            validate_lb_config(
                route.lb.as_str(),
                &format!("reverse {} route", reverse.name),
            )?;
            validate_retry_config(
                route.retry.as_ref(),
                &format!("reverse {} route", reverse.name),
            )?;
            for upstream_ref in &route.upstreams {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!("reverse {} route upstreams", reverse.name),
                    REVERSE_UPSTREAM_URL_SCHEMES,
                    false,
                    false,
                )?;
            }
            if has_backends {
                for backend in &route.backends {
                    if backend.weight == 0 {
                        return Err(anyhow!(
                            "reverse {} route backend weight must be >= 1",
                            reverse.name
                        ));
                    }
                    if backend.upstreams.is_empty() {
                        return Err(anyhow!(
                            "reverse {} route backend must set upstreams",
                            reverse.name
                        ));
                    }
                    for upstream_ref in &backend.upstreams {
                        validate_named_upstream_ref(
                            upstream_ref,
                            upstreams,
                            &format!("reverse {} route backends", reverse.name),
                            REVERSE_UPSTREAM_URL_SCHEMES,
                            false,
                            false,
                        )?;
                    }
                    if let Some(name) = backend.name.as_deref() {
                        if name.trim().is_empty() {
                            return Err(anyhow!(
                                "reverse {} route backend name must not be empty when set",
                                reverse.name
                            ));
                        }
                    }
                }
            }
            for mirror in &route.mirrors {
                if mirror.percent == 0 || mirror.percent > 100 {
                    return Err(anyhow!(
                        "reverse {} route mirror percent must be 1..=100",
                        reverse.name
                    ));
                }
                if mirror.upstreams.is_empty() {
                    return Err(anyhow!(
                        "reverse {} route mirror must set upstreams",
                        reverse.name
                    ));
                }
                for upstream_ref in &mirror.upstreams {
                    validate_named_upstream_ref(
                        upstream_ref,
                        upstreams,
                        &format!("reverse {} route mirrors", reverse.name),
                        REVERSE_UPSTREAM_URL_SCHEMES,
                        false,
                        false,
                    )?;
                }
                if let Some(name) = mirror.name.as_deref() {
                    if name.trim().is_empty() {
                        return Err(anyhow!(
                            "reverse {} route mirror name must not be empty when set",
                            reverse.name
                        ));
                    }
                }
            }
            if has_local && !route.mirrors.is_empty() {
                return Err(anyhow!(
                    "reverse {} route with local_response cannot configure mirrors",
                    reverse.name
                ));
            }
            if let Some(headers) = route.headers.as_ref() {
                crate::rules::CompiledHeaderControl::compile(headers).map_err(|e| {
                    anyhow!(
                        "reverse {} route header control is invalid: {}",
                        reverse.name,
                        e
                    )
                })?;
            }
            if let Some(regex) = route.path_rewrite.as_ref().and_then(|rw| rw.regex.as_ref()) {
                let pattern = regex.pattern.trim();
                if pattern.is_empty() {
                    return Err(anyhow!(
                        "reverse {} route path_rewrite.regex.pattern must not be empty",
                        reverse.name
                    ));
                }
                regex::Regex::new(pattern).map_err(|e| {
                    anyhow!(
                        "reverse {} route path_rewrite.regex.pattern is invalid: {}",
                        reverse.name,
                        e
                    )
                })?;
                if regex.replace.contains('?') || regex.replace.contains('#') {
                    return Err(anyhow!(
                        "reverse {} route path_rewrite.regex.replace must not contain '?' or '#'",
                        reverse.name
                    ));
                }
            }
            if let Some(cache) = route.cache.as_ref().filter(|cache| cache.enabled) {
                if has_local {
                    return Err(anyhow!(
                        "reverse {} route with local_response cannot enable cache",
                        reverse.name
                    ));
                }
                validate_cache_policy(
                    cache,
                    cache_backends,
                    &format!("reverse {} route", reverse.name),
                )?;
            }
            validate_health_check_config(
                &reverse.name,
                route.health_check.as_ref(),
                "reverse route",
            )?;
        }

        for route in &reverse.tls_passthrough_routes {
            if route.upstreams.is_empty() {
                return Err(anyhow!(
                    "reverse {} tls_passthrough_routes entry must set upstreams",
                    reverse.name
                ));
            }
            validate_lb_config(
                route.lb.as_str(),
                &format!("reverse {} tls_passthrough route", reverse.name),
            )?;
            validate_retry_config(
                route.retry.as_ref(),
                &format!("reverse {} tls_passthrough route", reverse.name),
            )?;
            for upstream_ref in &route.upstreams {
                validate_named_upstream_ref(
                    upstream_ref,
                    upstreams,
                    &format!("reverse {} tls_passthrough_routes", reverse.name),
                    REVERSE_PASSTHROUGH_UPSTREAM_URL_SCHEMES,
                    false,
                    true,
                )?;
            }
            validate_health_check_config(
                &reverse.name,
                route.health_check.as_ref(),
                "reverse tls_passthrough route",
            )?;
        }
    }
    Ok(())
}

fn validate_health_check_config(
    reverse_name: &str,
    health: Option<&HealthCheckConfig>,
    context: &str,
) -> Result<()> {
    let Some(health) = health else {
        return Ok(());
    };
    if health.interval_ms == 0 {
        return Err(anyhow!(
            "{} {} health_check.interval_ms must be >= 1",
            context,
            reverse_name
        ));
    }
    if health.timeout_ms == 0 {
        return Err(anyhow!(
            "{} {} health_check.timeout_ms must be >= 1",
            context,
            reverse_name
        ));
    }
    if health.fail_threshold == 0 {
        return Err(anyhow!(
            "{} {} health_check.fail_threshold must be >= 1",
            context,
            reverse_name
        ));
    }
    if health.cooldown_ms == 0 {
        return Err(anyhow!(
            "{} {} health_check.cooldown_ms must be >= 1",
            context,
            reverse_name
        ));
    }
    if let Some(http) = health.http.as_ref() {
        if let Some(path) = http.path.as_deref() {
            let path = path.trim();
            if path.is_empty() {
                return Err(anyhow!(
                    "{} {} health_check.http.path must not be empty when set",
                    context,
                    reverse_name
                ));
            }
            if !path.starts_with('/') {
                return Err(anyhow!(
                    "{} {} health_check.http.path must start with '/'",
                    context,
                    reverse_name
                ));
            }
            path.parse::<http::uri::PathAndQuery>().map_err(|_| {
                anyhow!(
                    "{} {} health_check.http.path is invalid: {}",
                    context,
                    reverse_name,
                    path
                )
            })?;
        }
        if let Some(method) = http.method.as_deref() {
            let normalized = method.trim().to_ascii_uppercase();
            if normalized != "HEAD" && normalized != "GET" {
                return Err(anyhow!(
                    "{} {} health_check.http.method must be HEAD or GET",
                    context,
                    reverse_name
                ));
            }
        }
        if let Some(statuses) = http.expected_status.as_ref() {
            if statuses.is_empty() {
                return Err(anyhow!(
                    "{} {} health_check.http.expected_status must not be empty when set",
                    context,
                    reverse_name
                ));
            }
            for code in statuses {
                if !(100..=599).contains(code) {
                    return Err(anyhow!(
                        "{} {} health_check.http.expected_status has invalid status code: {}",
                        context,
                        reverse_name,
                        code
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_xdp_config(kind: &str, name: &str, xdp: Option<&XdpConfig>) -> Result<()> {
    let Some(xdp) = xdp else {
        return Ok(());
    };
    if xdp.enabled && xdp.metadata_mode != "proxy-v2" {
        return Err(anyhow!(
            "{kind} {} has unsupported xdp metadata_mode: {}",
            name,
            xdp.metadata_mode
        ));
    }
    if xdp.enabled {
        if xdp.trusted_peers.is_empty() {
            return Err(anyhow!(
                "{kind} {} xdp.enabled requires xdp.trusted_peers",
                name
            ));
        }
        for peer in &xdp.trusted_peers {
            let _: IpCidr = peer
                .parse()
                .map_err(|_| anyhow!("{kind} {} invalid xdp trusted peer CIDR: {}", name, peer))?;
        }
    }
    Ok(())
}

fn validate_action_config(action: &ActionConfig, context: &str) -> Result<()> {
    let has_local = action.local_response.is_some();
    match action.kind {
        ActionKind::Respond => {
            if !has_local {
                return Err(anyhow!(
                    "{context}: action type respond requires local_response"
                ));
            }
            if action.upstream.is_some() {
                return Err(anyhow!(
                    "{context}: action type respond must not set upstream"
                ));
            }
        }
        ActionKind::Direct | ActionKind::Block => {
            if action.upstream.is_some() {
                return Err(anyhow!(
                    "{context}: action type {:?} must not set upstream",
                    action.kind
                ));
            }
            if has_local {
                return Err(anyhow!(
                    "{context}: local_response is only valid for action type respond"
                ));
            }
        }
        ActionKind::Inspect | ActionKind::Proxy | ActionKind::Tunnel => {
            if has_local {
                return Err(anyhow!(
                    "{context}: local_response is only valid for action type respond"
                ));
            }
        }
    }
    Ok(())
}

fn validate_header_control(control: &HeaderControl, context: &str) -> Result<()> {
    validate_header_map(&control.request_set, &format!("{} request_set", context))?;
    validate_header_map(&control.request_add, &format!("{} request_add", context))?;
    validate_header_remove(
        &control.request_remove,
        &format!("{} request_remove", context),
    )?;

    for (idx, item) in control.request_regex_replace.iter().enumerate() {
        if item.header.trim().is_empty() {
            return Err(anyhow!(
                "{} request_regex_replace[{}] header must not be empty",
                context,
                idx
            ));
        }
        http::header::HeaderName::from_bytes(item.header.as_bytes()).map_err(|_| {
            anyhow!(
                "{} request_regex_replace[{}] invalid header name: {}",
                context,
                idx,
                item.header
            )
        })?;
        regex::Regex::new(item.pattern.as_str()).map_err(|err| {
            anyhow!(
                "{} request_regex_replace[{}] invalid regex {}: {}",
                context,
                idx,
                item.pattern,
                err
            )
        })?;
    }

    validate_header_map(&control.response_set, &format!("{} response_set", context))?;
    validate_header_map(&control.response_add, &format!("{} response_add", context))?;
    validate_header_remove(
        &control.response_remove,
        &format!("{} response_remove", context),
    )?;

    for (idx, item) in control.response_regex_replace.iter().enumerate() {
        if item.header.trim().is_empty() {
            return Err(anyhow!(
                "{} response_regex_replace[{}] header must not be empty",
                context,
                idx
            ));
        }
        http::header::HeaderName::from_bytes(item.header.as_bytes()).map_err(|_| {
            anyhow!(
                "{} response_regex_replace[{}] invalid header name: {}",
                context,
                idx,
                item.header
            )
        })?;
        regex::Regex::new(item.pattern.as_str()).map_err(|err| {
            anyhow!(
                "{} response_regex_replace[{}] invalid regex {}: {}",
                context,
                idx,
                item.pattern,
                err
            )
        })?;
    }
    Ok(())
}

fn validate_header_map(map: &HashMap<String, String>, context: &str) -> Result<()> {
    for (name, value) in map {
        if name.trim().is_empty() {
            return Err(anyhow!("{context}: header name must not be empty"));
        }
        let parsed = http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow!("{context}: invalid header name: {name}"))?;
        http::HeaderValue::from_str(value.as_str())
            .map_err(|_| anyhow!("{context}: invalid header value for {parsed}"))?;
    }
    Ok(())
}

fn validate_header_remove(names: &[String], context: &str) -> Result<()> {
    for name in names {
        if name.trim().is_empty() {
            return Err(anyhow!("{context}: header name must not be empty"));
        }
        http::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow!("{context}: invalid header name: {name}"))?;
    }
    Ok(())
}

fn validate_cache_policy(
    policy: &CachePolicyConfig,
    backends: &std::collections::HashSet<String>,
    context: &str,
) -> Result<()> {
    if policy.backend.trim().is_empty() {
        return Err(anyhow!("{context}: cache.backend must not be empty"));
    }
    if !backends.contains(policy.backend.as_str()) {
        return Err(anyhow!(
            "{context}: cache backend not found: {}",
            policy.backend
        ));
    }
    if policy.max_object_bytes == 0 {
        return Err(anyhow!("{context}: cache.max_object_bytes must be >= 1"));
    }
    if matches!(policy.default_ttl_secs, Some(0)) {
        return Err(anyhow!("{context}: cache.default_ttl_secs must be >= 1"));
    }
    if let Some(ns) = policy.namespace.as_deref() {
        let ns = ns.trim();
        if ns.is_empty() {
            return Err(anyhow!("{context}: cache.namespace must not be empty"));
        }
        if !ns
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(anyhow!(
                "{context}: cache.namespace must contain only [A-Za-z0-9-_.]"
            ));
        }
    }
    Ok(())
}
