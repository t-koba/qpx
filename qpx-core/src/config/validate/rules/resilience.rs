use anyhow::{Result, anyhow};
use cidr::IpCidr;

use crate::config::types::{
    EndpointLifecycleConfig, GrpcConfig, HealthCheckConfig, ResilienceConfig,
    ReverseAffinityConfig, SseStreamingPolicy, StreamingConfig, XdpConfig,
};

use super::header::validate_header_name;
use super::{Validate, validate_optional};

impl Validate for ResilienceConfig {
    fn validate(&self, context: &str) -> Result<()> {
        validate_resilience_fields(self, context)
    }
}

pub(crate) fn validate_resilience_config(
    resilience: Option<&ResilienceConfig>,
    context: &str,
) -> Result<()> {
    validate_optional(resilience, context)
}

pub(crate) fn validate_streaming_config(
    streaming: Option<&StreamingConfig>,
    context: &str,
) -> Result<()> {
    let Some(streaming) = streaming else {
        return Ok(());
    };
    if matches!(streaming.body_channel_capacity, Some(0)) {
        return Err(anyhow!(
            "{context} streaming.body_channel_capacity must be >= 1"
        ));
    }
    if matches!(streaming.body_read_timeout_ms, Some(0)) {
        return Err(anyhow!(
            "{context} streaming.body_read_timeout_ms must be >= 1"
        ));
    }
    if matches!(streaming.body_send_timeout_ms, Some(0)) {
        return Err(anyhow!(
            "{context} streaming.body_send_timeout_ms must be >= 1"
        ));
    }
    if matches!(streaming.max_request_body_bytes, Some(0)) {
        return Err(anyhow!(
            "{context} streaming.max_request_body_bytes must be >= 1"
        ));
    }
    if matches!(streaming.max_response_body_bytes, Some(0)) {
        return Err(anyhow!(
            "{context} streaming.max_response_body_bytes must be >= 1"
        ));
    }
    Ok(())
}

pub(crate) fn validate_grpc_config(grpc: Option<&GrpcConfig>, context: &str) -> Result<()> {
    let Some(grpc) = grpc else {
        return Ok(());
    };
    if matches!(grpc.max_message_bytes, Some(0)) {
        return Err(anyhow!("{context} grpc.max_message_bytes must be >= 1"));
    }
    if matches!(grpc.max_web_trailer_bytes, Some(0)) {
        return Err(anyhow!("{context} grpc.max_web_trailer_bytes must be >= 1"));
    }
    if let Some(max_web_trailer_bytes) = grpc.max_web_trailer_bytes
        && max_web_trailer_bytes > crate::config::MAX_GRPC_WEB_TRAILER_BYTES
    {
        return Err(anyhow!(
            "{context} grpc.max_web_trailer_bytes must be <= {}",
            crate::config::MAX_GRPC_WEB_TRAILER_BYTES
        ));
    }
    if matches!(grpc.max_stream_duration_ms, Some(0)) {
        return Err(anyhow!(
            "{context} grpc.max_stream_duration_ms must be >= 1"
        ));
    }
    if let Some(duration_ms) = grpc.max_stream_duration_ms
        && duration_ms > crate::config::MAX_GRPC_STREAM_DURATION_MS
    {
        return Err(anyhow!(
            "{context} grpc.max_stream_duration_ms must be <= {}",
            crate::config::MAX_GRPC_STREAM_DURATION_MS
        ));
    }
    Ok(())
}

pub(crate) fn validate_sse_policy(sse: Option<&SseStreamingPolicy>, context: &str) -> Result<()> {
    let Some(sse) = sse else {
        return Ok(());
    };
    validate_sse_policy_fields(sse, context)
}

pub(crate) fn validate_sse_policy_fields(sse: &SseStreamingPolicy, context: &str) -> Result<()> {
    if sse.idle_timeout_ms == 0 {
        return Err(anyhow!("{context} sse.idle_timeout_ms must be >= 1"));
    }
    if sse.max_stream_duration_ms == 0 {
        return Err(anyhow!("{context} sse.max_stream_duration_ms must be >= 1"));
    }
    if sse.max_stream_duration_ms > crate::config::MAX_SSE_STREAM_DURATION_MS {
        return Err(anyhow!(
            "{context} sse.max_stream_duration_ms must be <= {}",
            crate::config::MAX_SSE_STREAM_DURATION_MS
        ));
    }
    if sse.idle_timeout_ms > sse.max_stream_duration_ms {
        return Err(anyhow!(
            "{context} sse.idle_timeout_ms must be <= sse.max_stream_duration_ms"
        ));
    }
    Ok(())
}

fn validate_resilience_fields(resilience: &ResilienceConfig, context: &str) -> Result<()> {
    if let Some(retry) = resilience.retry.as_ref() {
        if retry.attempts == 0 {
            return Err(anyhow!("{context} resilience.retry.attempts must be >= 1"));
        }
        if retry.retry_body_threshold_bytes == 0 {
            return Err(anyhow!(
                "{context} resilience.retry.retry_body_threshold_bytes must be >= 1"
            ));
        }
        if let Some(budget) = retry.budget.as_ref() {
            if matches!(budget.ratio, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.retry.budget.ratio must be >= 1"
                ));
            }
            if matches!(budget.min_retry_tokens, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.retry.budget.min_retry_tokens must be >= 1"
                ));
            }
        }
    }
    if matches!(resilience.max_upstream_concurrency, Some(0)) {
        return Err(anyhow!(
            "{context} resilience.max_upstream_concurrency must be >= 1"
        ));
    }
    if let Some(outlier) = resilience.outlier_detection.as_ref() {
        if let Some(failures) = outlier.consecutive_failures.as_ref() {
            for (name, value) in [
                ("http_5xx", failures.http_5xx),
                ("timeouts", failures.timeouts),
                ("connect_errors", failures.connect_errors),
                ("resets", failures.resets),
            ] {
                if matches!(value, Some(0)) {
                    return Err(anyhow!(
                        "{context} resilience.outlier_detection.consecutive_failures.{name} must be >= 1"
                    ));
                }
            }
        }
        if let Some(success_rate) = outlier.success_rate.as_ref()
            && matches!(success_rate.min_requests, Some(0))
        {
            return Err(anyhow!(
                "{context} resilience.outlier_detection.success_rate.min_requests must be >= 1"
            ));
        }
        if let Some(latency) = outlier.latency.as_ref() {
            if matches!(latency.p95_ms, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.outlier_detection.latency.p95_ms must be >= 1"
                ));
            }
            if matches!(latency.min_requests, Some(0)) {
                return Err(anyhow!(
                    "{context} resilience.outlier_detection.latency.min_requests must be >= 1"
                ));
            }
        }
    }
    if let Some(half_open) = resilience.half_open.as_ref() {
        if matches!(half_open.max_probes, Some(0)) {
            return Err(anyhow!(
                "{context} resilience.half_open.max_probes must be >= 1"
            ));
        }
        if matches!(half_open.successes_to_close, Some(0)) {
            return Err(anyhow!(
                "{context} resilience.half_open.successes_to_close must be >= 1"
            ));
        }
        if matches!(half_open.probe_timeout_ms, Some(0)) {
            return Err(anyhow!(
                "{context} resilience.half_open.probe_timeout_ms must be >= 1"
            ));
        }
    }
    if let Some(ejection) = resilience.ejection.as_ref() {
        if matches!(ejection.base_ms, Some(0)) {
            return Err(anyhow!(
                "{context} resilience.ejection.base_ms must be >= 1"
            ));
        }
        if matches!(ejection.max_ms, Some(0)) {
            return Err(anyhow!("{context} resilience.ejection.max_ms must be >= 1"));
        }
    }
    Ok(())
}
pub(crate) fn validate_health_check_config(
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

pub(crate) fn validate_endpoint_lifecycle_config(
    config: Option<&EndpointLifecycleConfig>,
    context: &str,
) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    if config.slow_start_ms.is_none()
        && config.warmup_ms.is_none()
        && config.drain_timeout_ms.is_none()
    {
        return Err(anyhow!(
            "{context} lifecycle must set at least one of slow_start_ms, warmup_ms, or drain_timeout_ms"
        ));
    }
    if matches!(config.slow_start_ms, Some(0)) {
        return Err(anyhow!("{context} lifecycle.slow_start_ms must be >= 1"));
    }
    if matches!(config.warmup_ms, Some(0)) {
        return Err(anyhow!("{context} lifecycle.warmup_ms must be >= 1"));
    }
    if matches!(config.drain_timeout_ms, Some(0)) {
        return Err(anyhow!("{context} lifecycle.drain_timeout_ms must be >= 1"));
    }
    Ok(())
}

pub(crate) fn validate_affinity_config(
    config: Option<&ReverseAffinityConfig>,
    context: &str,
) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    let key = config.key.trim().to_ascii_lowercase();
    match key.as_str() {
        "src_ip" | "source_ip" | "host" | "user" | "tenant" => {}
        "header" => {
            let header = config.header.as_deref().unwrap_or("").trim();
            if header.is_empty() {
                return Err(anyhow!(
                    "{context} affinity.key=header requires affinity.header"
                ));
            }
            validate_header_name(header, &format!("{context} affinity.header"))?;
        }
        "cookie" => {
            if config.cookie.as_deref().unwrap_or("").trim().is_empty() {
                return Err(anyhow!(
                    "{context} affinity.key=cookie requires affinity.cookie"
                ));
            }
        }
        "query" => {
            if config.query.as_deref().unwrap_or("").trim().is_empty() {
                return Err(anyhow!(
                    "{context} affinity.key=query requires affinity.query"
                ));
            }
        }
        other => {
            return Err(anyhow!(
                "{context} affinity.key must be one of: src_ip, host, header, cookie, user, tenant, query (got {other})"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_xdp_config(kind: &str, name: &str, xdp: Option<&XdpConfig>) -> Result<()> {
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
