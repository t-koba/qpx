use anyhow::{anyhow, Result};
use cidr::IpCidr;

use super::super::types::{
    AccessLogConfig, AcmeConfig, AuditLogConfig, Config, ExporterConfig, LogOutputConfig,
    MetricsConfig, OtelConfig, SystemLogConfig,
};

pub(super) fn validate_system_log_config(system: &SystemLogConfig) -> Result<()> {
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

pub(super) fn validate_access_log_config(access: &AccessLogConfig) -> Result<()> {
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

pub(super) fn validate_audit_log_config(audit: &AuditLogConfig) -> Result<()> {
    validate_log_output_config(&audit.output, "audit_log", false)?;
    let mut seen = std::collections::HashSet::new();
    for field in &audit.include {
        if !seen.insert(std::mem::discriminant(field)) {
            return Err(anyhow!("audit_log.include contains duplicate field"));
        }
    }
    Ok(())
}

pub(super) fn validate_metrics_config(metrics: &MetricsConfig) -> Result<()> {
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

pub(super) fn validate_otel_config(otel: &OtelConfig) -> Result<()> {
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
            return Err(anyhow!("otel.endpoint must be set when otel.enabled=true"));
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
    let url = url::Url::parse(&raw).map_err(|e| anyhow!("otel.endpoint is invalid: {e}"))?;
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

#[cfg(feature = "tls-rustls")]
pub(super) fn validate_acme_config(config: &Config, acme: &AcmeConfig) -> Result<()> {
    if !acme.enabled {
        return Ok(());
    }
    if config
        .state_dir
        .as_deref()
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(anyhow!(
            "state_dir must be set when acme.enabled=true (used for account/cert persistence)"
        ));
    }
    if !acme.terms_of_service_agreed {
        return Err(anyhow!(
            "acme.terms_of_service_agreed must be true when acme.enabled=true"
        ));
    }
    if acme.renew_before_days == 0 {
        return Err(anyhow!("acme.renew_before_days must be >= 1"));
    }
    if acme.staging && acme.directory_url.is_some() {
        return Err(anyhow!(
            "acme.staging and acme.directory_url are mutually exclusive"
        ));
    }
    if let Some(email) = acme.email.as_deref() {
        if email.trim().is_empty() {
            return Err(anyhow!("acme.email must not be empty when set"));
        }
    }
    let Some(listen) = acme.http01_listen.as_deref() else {
        return Err(anyhow!(
            "acme.http01_listen must be set when acme.enabled=true (HTTP-01 challenge server)"
        ));
    };
    let _: std::net::SocketAddr = listen
        .parse()
        .map_err(|e| anyhow!("acme.http01_listen is invalid: {}", e))?;

    if let Some(dir) = acme.directory_url.as_deref() {
        let raw = dir.trim();
        if raw.is_empty() {
            return Err(anyhow!("acme.directory_url must not be empty when set"));
        }
        let url =
            url::Url::parse(raw).map_err(|e| anyhow!("acme.directory_url is invalid: {e}"))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(anyhow!(
                "acme.directory_url must use http:// or https:// (got {})",
                url.scheme()
            ));
        }
    }
    Ok(())
}

#[cfg(not(feature = "tls-rustls"))]
pub(super) fn validate_acme_config(_config: &Config, acme: &AcmeConfig) -> Result<()> {
    if acme.enabled {
        return Err(anyhow!(
            "acme is only supported on tls-rustls builds (this build does not enable tls-rustls)"
        ));
    }
    Ok(())
}

pub(super) fn validate_exporter_config(exporter: &ExporterConfig) -> Result<()> {
    if !exporter.enabled {
        return Ok(());
    }
    if exporter.shm_size_mb == 0 {
        return Err(anyhow!("exporter.shm_size_mb must be >= 1"));
    }
    if exporter.max_queue_events == 0 {
        return Err(anyhow!("exporter.max_queue_events must be >= 1"));
    }
    if exporter.capture.max_chunk_bytes == 0 {
        return Err(anyhow!("exporter.capture.max_chunk_bytes must be >= 1"));
    }
    Ok(())
}
