use anyhow::{Result, anyhow};

use crate::config::types::{
    ActionConfig, ActionKind, HttpResponseEffectsConfig, LocalResponseConfig,
    RpcLocalResponseConfig,
};

use super::Validate;
use super::header::{
    validate_header_control, validate_header_map, validate_header_name, validate_non_empty_ascii,
};

impl Validate for ActionConfig {
    fn validate(&self, context: &str) -> Result<()> {
        validate_action_fields(self, context)
    }
}

pub(crate) fn validate_action_config(action: &ActionConfig, context: &str) -> Result<()> {
    action.validate(context)
}

fn validate_action_fields(action: &ActionConfig, context: &str) -> Result<()> {
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
            validate_local_response_config(
                action.local_response.as_ref(),
                &format!("{context}: local_response"),
            )?;
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

pub(crate) fn validate_local_response_config(
    local: Option<&LocalResponseConfig>,
    context: &str,
) -> Result<()> {
    let Some(local) = local else {
        return Ok(());
    };
    if !(200..=599).contains(&local.status) {
        return Err(anyhow!("{context}.status must be in 200..=599"));
    }
    if let Some(content_type) = local.content_type.as_deref() {
        http::HeaderValue::from_str(content_type)
            .map_err(|_| anyhow!("{context}.content_type has invalid header value"))?;
    }
    validate_header_map(&local.headers, &format!("{context}.headers"))?;
    if let Some(rpc) = local.rpc.as_ref() {
        validate_rpc_local_response_config(rpc, &format!("{context}.rpc"))?;
    }
    Ok(())
}

pub(crate) fn validate_http_response_effects(
    effects: &HttpResponseEffectsConfig,
    context: &str,
) -> Result<()> {
    validate_local_response_config(
        effects.local_response.as_ref(),
        &format!("{context}.local_response"),
    )?;
    if let Some(headers) = effects.headers.as_ref() {
        validate_header_control(headers, &format!("{context}.headers"))?;
    }
    if let Some(mirror) = effects.mirror.as_ref() {
        for (idx, upstream) in mirror.upstreams.iter().enumerate() {
            if upstream.trim().is_empty() {
                return Err(anyhow!(
                    "{context}.mirror.upstreams[{idx}] must not be empty"
                ));
            }
        }
    }
    for (idx, tag) in effects.tags.iter().enumerate() {
        if tag.trim().is_empty() {
            return Err(anyhow!("{context}.tags[{idx}] must not be empty"));
        }
    }
    let has_effect = effects.local_response.is_some()
        || effects.headers.is_some()
        || effects
            .cache
            .as_ref()
            .map(|cache| cache.bypass)
            .unwrap_or(false)
        || effects
            .retry
            .as_ref()
            .map(|retry| retry.suppress)
            .unwrap_or(false)
        || effects
            .mirror
            .as_ref()
            .map(|mirror| mirror.enabled.is_some() || !mirror.upstreams.is_empty())
            .unwrap_or(false)
        || !effects.tags.is_empty();
    if !has_effect {
        return Err(anyhow!("{context} must configure at least one effect"));
    }
    Ok(())
}

fn validate_rpc_local_response_config(raw: &RpcLocalResponseConfig, context: &str) -> Result<()> {
    let protocol = raw.protocol.trim().to_ascii_lowercase();
    if protocol.is_empty() {
        return Err(anyhow!("{context}.protocol must not be empty"));
    }
    if !matches!(protocol.as_str(), "grpc" | "connect" | "grpc_web") {
        return Err(anyhow!(
            "{context}.protocol must be one of: grpc, connect, grpc_web"
        ));
    }
    if let Some(status) = raw.status.as_deref() {
        validate_non_empty_ascii(status, &format!("{context}.status"))?;
        match protocol.as_str() {
            "grpc" | "grpc_web" => validate_grpc_status_code(status, context)?,
            "connect" => validate_connect_status_code(status, context)?,
            _ => unreachable!("protocol was validated above"),
        }
    }
    if let Some(message) = raw.message.as_deref()
        && message.trim().is_empty()
    {
        return Err(anyhow!("{context}.message must not be empty when set"));
    }
    if let Some(http_status) = raw.http_status
        && !(200..=599).contains(&http_status)
    {
        return Err(anyhow!("{context}.http_status must be in 200..=599"));
    }
    for (name, value) in &raw.headers {
        validate_header_name(name, &format!("{context}.headers"))?;
        http::HeaderValue::from_str(value.as_str())
            .map_err(|_| anyhow!("{context}.headers[{name}] has invalid header value"))?;
    }
    for (name, value) in &raw.trailers {
        validate_header_name(name, &format!("{context}.trailers"))?;
        http::HeaderValue::from_str(value.as_str())
            .map_err(|_| anyhow!("{context}.trailers[{name}] has invalid header value"))?;
    }
    Ok(())
}

fn validate_grpc_status_code(status: &str, context: &str) -> Result<()> {
    let code = status
        .parse::<u16>()
        .map_err(|_| anyhow!("{context}.status must be a gRPC status code 0..=16"))?;
    if code > 16 {
        return Err(anyhow!(
            "{context}.status must be a gRPC status code 0..=16"
        ));
    }
    Ok(())
}

fn validate_connect_status_code(status: &str, context: &str) -> Result<()> {
    const CONNECT_CODES: &[&str] = &[
        "canceled",
        "unknown",
        "invalid_argument",
        "deadline_exceeded",
        "not_found",
        "already_exists",
        "permission_denied",
        "resource_exhausted",
        "failed_precondition",
        "aborted",
        "out_of_range",
        "unimplemented",
        "internal",
        "unavailable",
        "data_loss",
        "unauthenticated",
    ];
    if status == "ok" || CONNECT_CODES.contains(&status) {
        return Ok(());
    }
    Err(anyhow!("{context}.status must be a Connect code name"))
}

pub(crate) fn validate_proxy_tunnel_upstream_requirement(
    action: &ActionConfig,
    listener_upstream_proxy: Option<&str>,
    context: &str,
) -> Result<()> {
    if matches!(action.kind, ActionKind::Proxy | ActionKind::Tunnel)
        && action.upstream.is_none()
        && listener_upstream_proxy.is_none()
    {
        return Err(anyhow!(
            "{context}: action type {:?} requires action.upstream or edges[].upstream_proxy",
            action.kind
        ));
    }
    Ok(())
}
