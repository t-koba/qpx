use anyhow::{Result, anyhow};
use http::header::HeaderName;
use http::{HeaderValue, StatusCode};
use qpx_core::config::{LocalResponseConfig, RpcLocalResponseConfig};
use url::Url;

use super::{DecisionServiceAllow, DecisionServiceMode};

pub(super) fn validate_decision_service_upstream_value(
    value: String,
    field: &'static str,
) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(anyhow!("decision_service {field} must not be empty"));
    }
    let url =
        Url::parse(value).map_err(|err| anyhow!("decision_service {field} is invalid: {err}"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!(
            "decision_service {field} must not include userinfo"
        ));
    }
    if url.host_str().is_none() {
        return Err(anyhow!("decision_service {field} must include a host"));
    }
    match url.scheme() {
        "http" | "https" | "h2c" | "h2" | "h3" => Ok(value.to_string()),
        other => Err(anyhow!(
            "decision_service {field} has unsupported upstream scheme: {other}"
        )),
    }
}

pub(super) fn validate_decision_service_local_response(
    local: LocalResponseConfig,
) -> Result<LocalResponseConfig> {
    if !(200..=599).contains(&local.status) {
        return Err(anyhow!(
            "decision_service local_response.status must be in 200..=599"
        ));
    }
    StatusCode::from_u16(local.status)
        .map_err(|_| anyhow!("decision_service local_response.status is invalid"))?;
    if let Some(content_type) = local.content_type.as_deref() {
        HeaderValue::from_str(content_type)
            .map_err(|_| anyhow!("decision_service local_response.content_type is invalid"))?;
    }
    for (name, value) in &local.headers {
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            anyhow!("decision_service local_response.headers contains invalid name")
        })?;
        HeaderValue::from_str(value).map_err(|_| {
            anyhow!("decision_service local_response.headers contains invalid value")
        })?;
    }
    if local.status == 451
        && !local.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("link")
                && value.split(';').skip(1).any(|parameter| {
                    parameter
                        .trim()
                        .strip_prefix("rel=")
                        .map(|value| value.trim_matches('"').split_ascii_whitespace())
                        .is_some_and(|mut relations| {
                            relations.any(|relation| relation.eq_ignore_ascii_case("blocked-by"))
                        })
                })
        })
    {
        return Err(anyhow!(
            "decision_service local_response status 451 requires Link rel=blocked-by"
        ));
    }
    if local.status == 511 {
        return Err(anyhow!(
            "decision_service local_response status 511 is reserved for CAPPORT routes"
        ));
    }
    if let Some(rpc) = local.rpc.as_ref() {
        validate_decision_service_rpc_local_response(rpc)?;
    }
    Ok(local)
}

fn validate_decision_service_rpc_local_response(rpc: &RpcLocalResponseConfig) -> Result<()> {
    let protocol = rpc.protocol.trim().to_ascii_lowercase();
    if !matches!(protocol.as_str(), "grpc" | "grpc_web" | "connect") {
        return Err(anyhow!(
            "decision_service local_response.rpc.protocol must be one of: grpc, grpc_web, connect"
        ));
    }
    if let Some(http_status) = rpc.http_status
        && !(200..=599).contains(&http_status)
    {
        return Err(anyhow!(
            "decision_service local_response.rpc.http_status must be in 200..=599"
        ));
    }
    if let Some(status) = rpc.status.as_deref() {
        match protocol.as_str() {
            "grpc" | "grpc_web" => {
                let code = status.parse::<u16>().map_err(|_| {
                    anyhow!("decision_service local_response.rpc.status must be a gRPC code")
                })?;
                if code > 16 {
                    return Err(anyhow!(
                        "decision_service local_response.rpc.status must be in 0..=16"
                    ));
                }
            }
            "connect" => validate_connect_code_name(status)?,
            _ => unreachable!("protocol validated above"),
        }
    }
    for (name, value) in &rpc.headers {
        HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| anyhow!("decision_service local_response.rpc.headers has invalid name"))?;
        HeaderValue::from_str(value).map_err(|_| {
            anyhow!("decision_service local_response.rpc.headers has invalid value")
        })?;
    }
    for (name, value) in &rpc.trailers {
        HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            anyhow!("decision_service local_response.rpc.trailers has invalid name")
        })?;
        HeaderValue::from_str(value).map_err(|_| {
            anyhow!("decision_service local_response.rpc.trailers has invalid value")
        })?;
    }
    Ok(())
}

fn validate_connect_code_name(status: &str) -> Result<()> {
    const CONNECT_CODES: &[&str] = &[
        "ok",
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
    if CONNECT_CODES.contains(&status) {
        return Ok(());
    }
    Err(anyhow!(
        "decision_service local_response.rpc.status must be a Connect code name"
    ))
}

#[derive(Debug, Clone, Copy)]
struct DecisionServiceModeCapabilities {
    name: &'static str,
    inject_headers: bool,
    override_upstream: bool,
    timeout_override: bool,
    cache_bypass: bool,
    mirror_upstreams: bool,
    rate_limit_profile: bool,
    force_inspect: bool,
    force_tunnel: bool,
}

impl DecisionServiceMode {
    fn capabilities(self) -> DecisionServiceModeCapabilities {
        match self {
            Self::ForwardHttp => DecisionServiceModeCapabilities {
                name: "forward_http",
                inject_headers: true,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: true,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
            Self::ForwardConnect => DecisionServiceModeCapabilities {
                name: "forward_connect",
                inject_headers: true,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: true,
                force_tunnel: true,
            },
            #[cfg(feature = "mitm")]
            Self::ForwardMitmHttp => DecisionServiceModeCapabilities {
                name: "forward_mitm_http",
                inject_headers: true,
                override_upstream: false,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
            Self::ReverseHttp => DecisionServiceModeCapabilities {
                name: "reverse_http",
                inject_headers: true,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: true,
                mirror_upstreams: true,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
            Self::TransparentHttp => DecisionServiceModeCapabilities {
                name: "transparent_http",
                inject_headers: true,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
            Self::TransparentTls => DecisionServiceModeCapabilities {
                name: "transparent_tls",
                inject_headers: false,
                override_upstream: true,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: true,
                force_tunnel: true,
            },
            #[cfg(feature = "http3")]
            Self::TransparentUdp => DecisionServiceModeCapabilities {
                name: "transparent_udp",
                inject_headers: false,
                override_upstream: false,
                timeout_override: true,
                cache_bypass: false,
                mirror_upstreams: false,
                rate_limit_profile: true,
                force_inspect: false,
                force_tunnel: false,
            },
        }
    }
}

pub(crate) fn validate_decision_service_allow_mode(
    allow: &DecisionServiceAllow,
    mode: DecisionServiceMode,
) -> Result<()> {
    let caps = mode.capabilities();
    let mut unsupported = Vec::new();
    if allow.headers.is_some() && !caps.inject_headers {
        unsupported.push("inject_headers");
    }
    if allow.override_upstream.is_some() && !caps.override_upstream {
        unsupported.push("override_upstream");
    }
    if allow.timeout_override.is_some() && !caps.timeout_override {
        unsupported.push("timeout_override_ms");
    }
    if allow.cache_bypass && !caps.cache_bypass {
        unsupported.push("cache_bypass");
    }
    if !allow.mirror_upstreams.is_empty() && !caps.mirror_upstreams {
        unsupported.push("mirror_upstreams");
    }
    if allow.rate_limit_profile.is_some() && !caps.rate_limit_profile {
        unsupported.push("rate_limit_profile");
    }
    if allow.force_inspect && !caps.force_inspect {
        unsupported.push("force_inspect");
    }
    if allow.force_tunnel && !caps.force_tunnel {
        unsupported.push("force_tunnel");
    }
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "decision_service fields [{}] are not supported for {}",
        unsupported.join(", "),
        caps.name
    ))
}
