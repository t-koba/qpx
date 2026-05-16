use crate::http::body::Body;
use crate::http::dispatch::ProxyKind;
use crate::runtime::RuntimeState;
use anyhow::{Context, Result, anyhow};
use http::header::HeaderName;
use hyper::{HeaderMap, Request};
use qpx_core::config::{
    ActionConfig, ActionKind, ExtAuthzConfig, ExtAuthzOnError, HeaderControl, LocalResponseConfig,
};
use qpx_core::rules::CompiledHeaderControl;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tracing::warn;
use url::Url;

use super::identity::{EffectivePolicyContext, ResolvedIdentity};
use super::util::{normalize_string_list, selected_headers_map};

#[derive(Debug, Clone)]
pub(crate) struct CompiledExtAuthz {
    endpoint: Url,
    timeout: Duration,
    send_request: bool,
    send_identity: bool,
    selected_headers: Vec<HeaderName>,
    on_error: ExtAuthzOnError,
    max_response_bytes: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExtAuthzAllow {
    pub(crate) policy_id: Option<String>,
    pub(crate) override_upstream: Option<String>,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) timeout_override: Option<Duration>,
    pub(crate) cache_bypass: bool,
    pub(crate) mirror_upstreams: Vec<String>,
    pub(crate) rate_limit_profile: Option<String>,
    pub(crate) force_inspect: bool,
    pub(crate) force_tunnel: bool,
    pub(crate) policy_tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtAuthzMode {
    ForwardHttp,
    ForwardConnect,
    #[cfg(feature = "mitm")]
    ForwardMitmHttp,
    ReverseHttp,
    TransparentHttp,
    TransparentTls,
    #[cfg(feature = "http3")]
    TransparentUdp,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExtAuthzDeny {
    pub(crate) policy_id: Option<String>,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) local_response: Option<LocalResponseConfig>,
    pub(crate) policy_tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum ExtAuthzEnforcement {
    Continue(ExtAuthzAllow),
    Deny(ExtAuthzDeny),
}

#[derive(Debug, Clone)]
pub(crate) struct ExtAuthzInput<'a> {
    pub(crate) proxy_kind: ProxyKind,
    pub(crate) proxy_name: &'a str,
    pub(crate) scope_name: &'a str,
    pub(crate) remote_ip: IpAddr,
    pub(crate) dst_port: Option<u16>,
    pub(crate) host: Option<&'a str>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) method: Option<&'a str>,
    pub(crate) path: Option<&'a str>,
    pub(crate) uri: Option<&'a str>,
    pub(crate) matched_rule: Option<&'a str>,
    pub(crate) matched_route: Option<&'a str>,
    pub(crate) action: Option<&'a ActionConfig>,
    pub(crate) headers: Option<&'a HeaderMap>,
    pub(crate) identity: &'a ResolvedIdentity,
}

impl CompiledExtAuthz {
    pub(crate) fn from_config(config: &ExtAuthzConfig) -> Result<Self> {
        Ok(Self {
            endpoint: Url::parse(&config.endpoint)?,
            timeout: Duration::from_millis(config.timeout_ms),
            send_request: config.send.request,
            send_identity: config.send.identity,
            selected_headers: config
                .send
                .selected_headers
                .iter()
                .map(|name| HeaderName::from_bytes(name.as_bytes()))
                .collect::<Result<Vec<_>, _>>()?,
            on_error: config.on_error.clone(),
            max_response_bytes: config.max_response_bytes,
        })
    }
}

pub(crate) async fn enforce_ext_authz(
    state: &RuntimeState,
    policy: &EffectivePolicyContext,
    input: ExtAuthzInput<'_>,
) -> Result<ExtAuthzEnforcement> {
    let Some(name) = policy.ext_authz.as_deref() else {
        return Ok(ExtAuthzEnforcement::Continue(ExtAuthzAllow::default()));
    };
    let cfg = state
        .security
        .decisions
        .ext_authz
        .get(name)
        .ok_or_else(|| anyhow!("ext_authz missing at runtime: {}", name))?;

    let result = ext_authz_round_trip(cfg, input).await;
    match result {
        Ok(enforcement) => Ok(enforcement),
        Err(err) => {
            warn!(ext_authz = %name, error = ?err, "ext_authz evaluation failed");
            match cfg.on_error {
                ExtAuthzOnError::Allow => {
                    Ok(ExtAuthzEnforcement::Continue(ExtAuthzAllow::default()))
                }
                ExtAuthzOnError::Deny => Ok(ExtAuthzEnforcement::Deny(ExtAuthzDeny::default())),
            }
        }
    }
}

async fn ext_authz_round_trip(
    cfg: &CompiledExtAuthz,
    input: ExtAuthzInput<'_>,
) -> Result<ExtAuthzEnforcement> {
    let body = serde_json::to_vec(&build_ext_authz_request(cfg, input))?;
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(cfg.endpoint.as_str())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))?;

    let (status, body) = match cfg.endpoint.scheme() {
        "http" => {
            timeout(cfg.timeout, async {
                let response = crate::upstream::origin::shared_reverse_http_client()
                    .request(request)
                    .await?;
                let status = response.status();
                let body = crate::http::body::to_bytes_limited(
                    response.into_body(),
                    cfg.max_response_bytes,
                )
                .await?;
                anyhow::Ok((status, body))
            })
            .await??
        }
        "https" => {
            timeout(cfg.timeout, async {
                let response = crate::upstream::origin::shared_reverse_https_client()
                    .request(request)
                    .await?;
                let status = response.status();
                let body = crate::http::body::to_bytes_limited(
                    response.into_body(),
                    cfg.max_response_bytes,
                )
                .await?;
                anyhow::Ok((status, body))
            })
            .await??
        }
        other => return Err(anyhow!("unsupported ext_authz scheme: {}", other)),
    };
    if !status.is_success() {
        return Err(anyhow!("ext_authz returned {}", status));
    }
    let parsed: ExtAuthzResponse = serde_json::from_slice(&body)
        .with_context(|| "failed to parse ext_authz response body as JSON")?;
    parsed.into_enforcement()
}

#[derive(Debug, Serialize)]
struct ExtAuthzRequestBody {
    proxy: ExtAuthzProxyBody,
    request: Option<ExtAuthzRequestMeta>,
    identity: Option<ExtAuthzIdentityBody>,
}

#[derive(Debug, Serialize)]
struct ExtAuthzProxyBody {
    kind: ProxyKind,
    proxy_name: String,
    scope_name: String,
    matched_rule: Option<String>,
    matched_route: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExtAuthzRequestMeta {
    remote_ip: String,
    dst_port: Option<u16>,
    host: Option<String>,
    sni: Option<String>,
    method: Option<String>,
    path: Option<String>,
    uri: Option<String>,
    headers: HashMap<String, Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ExtAuthzIdentityBody {
    user: Option<String>,
    groups: Vec<String>,
    device_id: Option<String>,
    posture: Vec<String>,
    tenant: Option<String>,
    auth_strength: Option<String>,
    idp: Option<String>,
    source: Option<String>,
}

fn build_ext_authz_request(
    cfg: &CompiledExtAuthz,
    input: ExtAuthzInput<'_>,
) -> ExtAuthzRequestBody {
    let request = cfg.send_request.then(|| ExtAuthzRequestMeta {
        remote_ip: input.remote_ip.to_string(),
        dst_port: input.dst_port,
        host: input.host.map(str::to_string),
        sni: input.sni.map(str::to_string),
        method: input.method.map(str::to_string),
        path: input.path.map(str::to_string),
        uri: input.uri.map(str::to_string),
        headers: selected_headers_map(input.headers, &cfg.selected_headers),
    });
    let identity = cfg.send_identity.then(|| ExtAuthzIdentityBody {
        user: input.identity.user.clone(),
        groups: input.identity.groups.clone(),
        device_id: input.identity.device_id.clone(),
        posture: input.identity.posture.clone(),
        tenant: input.identity.tenant.clone(),
        auth_strength: input.identity.auth_strength.clone(),
        idp: input.identity.idp.clone(),
        source: input.identity.identity_source.clone(),
    });
    ExtAuthzRequestBody {
        proxy: ExtAuthzProxyBody {
            kind: input.proxy_kind,
            proxy_name: input.proxy_name.to_string(),
            scope_name: input.scope_name.to_string(),
            matched_rule: input.matched_rule.map(str::to_string),
            matched_route: input.matched_route.map(str::to_string),
            action: input
                .action
                .map(|action| format!("{:?}", action.kind).to_ascii_lowercase()),
        },
        request,
        identity,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtAuthzResponse {
    decision: String,
    #[serde(default)]
    policy_id: Option<String>,
    #[serde(default)]
    override_upstream: Option<String>,
    #[serde(default)]
    inject_headers: Option<HeaderControl>,
    #[serde(default)]
    local_response: Option<LocalResponseConfig>,
    #[serde(default)]
    timeout_override_ms: Option<u64>,
    #[serde(default)]
    cache_bypass: bool,
    #[serde(default)]
    mirror_upstreams: Vec<String>,
    #[serde(default)]
    rate_limit_profile: Option<String>,
    #[serde(default)]
    force_inspect: bool,
    #[serde(default)]
    force_tunnel: bool,
    #[serde(default)]
    policy_tags: Vec<String>,
}

impl ExtAuthzResponse {
    fn into_enforcement(self) -> Result<ExtAuthzEnforcement> {
        if self.force_inspect && self.force_tunnel {
            return Err(anyhow!(
                "ext_authz response cannot set both force_inspect and force_tunnel"
            ));
        }
        let headers = self
            .inject_headers
            .as_ref()
            .map(CompiledHeaderControl::compile)
            .transpose()?
            .map(Arc::new);
        let timeout_override = self
            .timeout_override_ms
            .map(|timeout_ms| Duration::from_millis(timeout_ms.max(1)));
        let rate_limit_profile = self
            .rate_limit_profile
            .map(|profile| profile.trim().to_string())
            .filter(|profile| !profile.is_empty());
        let mirror_upstreams = normalize_string_list(self.mirror_upstreams);
        let policy_tags = normalize_string_list(self.policy_tags);
        match self.decision.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(ExtAuthzEnforcement::Continue(ExtAuthzAllow {
                policy_id: self.policy_id,
                override_upstream: self.override_upstream,
                headers,
                timeout_override,
                cache_bypass: self.cache_bypass,
                mirror_upstreams,
                rate_limit_profile,
                force_inspect: self.force_inspect,
                force_tunnel: self.force_tunnel,
                policy_tags,
            })),
            "deny" => Ok(ExtAuthzEnforcement::Deny(ExtAuthzDeny {
                policy_id: self.policy_id,
                headers,
                local_response: self.local_response,
                policy_tags,
            })),
            "local_response" => {
                let local_response = self.local_response.ok_or_else(|| {
                    anyhow!("ext_authz local_response decision requires local_response")
                })?;
                Ok(ExtAuthzEnforcement::Deny(ExtAuthzDeny {
                    policy_id: self.policy_id,
                    headers,
                    local_response: Some(local_response),
                    policy_tags,
                }))
            }
            "challenge" => {
                let local_response = self.local_response.ok_or_else(|| {
                    anyhow!("ext_authz challenge decision requires local_response")
                })?;
                Ok(ExtAuthzEnforcement::Deny(ExtAuthzDeny {
                    policy_id: self.policy_id,
                    headers,
                    local_response: Some(local_response),
                    policy_tags,
                }))
            }
            other => Err(anyhow!("unsupported ext_authz decision: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ExtAuthzModeCapabilities {
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

impl ExtAuthzMode {
    fn capabilities(self) -> ExtAuthzModeCapabilities {
        match self {
            Self::ForwardHttp => ExtAuthzModeCapabilities {
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
            Self::ForwardConnect => ExtAuthzModeCapabilities {
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
            Self::ForwardMitmHttp => ExtAuthzModeCapabilities {
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
            Self::ReverseHttp => ExtAuthzModeCapabilities {
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
            Self::TransparentHttp => ExtAuthzModeCapabilities {
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
            Self::TransparentTls => ExtAuthzModeCapabilities {
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
            Self::TransparentUdp => ExtAuthzModeCapabilities {
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

pub(crate) fn validate_ext_authz_allow_mode(
    allow: &ExtAuthzAllow,
    mode: ExtAuthzMode,
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
        "ext_authz fields [{}] are not supported for {}",
        unsupported.join(", "),
        caps.name
    ))
}

pub(crate) fn merge_header_controls(
    base: Option<Arc<CompiledHeaderControl>>,
    extra: Option<Arc<CompiledHeaderControl>>,
) -> Option<Arc<CompiledHeaderControl>> {
    match (base, extra) {
        (Some(base), Some(extra)) => Some(Arc::new(base.as_ref().merged(extra.as_ref()))),
        (Some(base), None) => Some(base),
        (None, Some(extra)) => Some(extra),
        (None, None) => None,
    }
}

pub(crate) fn apply_override_upstream(
    action: &mut ActionConfig,
    override_upstream: Option<String>,
) {
    let Some(override_upstream) = override_upstream else {
        return;
    };
    if matches!(action.kind, ActionKind::Direct) {
        action.kind = ActionKind::Proxy;
    }
    action.upstream = Some(override_upstream);
}

pub(crate) fn apply_ext_authz_action_overrides(action: &mut ActionConfig, allow: &ExtAuthzAllow) {
    apply_override_upstream(action, allow.override_upstream.clone());
    if allow.force_inspect {
        action.kind = ActionKind::Inspect;
    } else if allow.force_tunnel {
        action.kind = ActionKind::Tunnel;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::HeaderControl;

    #[test]
    fn ext_authz_mode_validation_rejects_unsupported_fields() {
        let allow = ExtAuthzAllow {
            force_inspect: true,
            ..Default::default()
        };
        let err = validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ReverseHttp)
            .expect_err("reverse_edges should reject force_inspect");
        assert!(err.to_string().contains("force_inspect"));

        let allow = ExtAuthzAllow {
            headers: Some(Arc::new(
                CompiledHeaderControl::compile(&HeaderControl::default()).expect("headers"),
            )),
            ..Default::default()
        };
        let err = validate_ext_authz_allow_mode(&allow, ExtAuthzMode::TransparentTls)
            .expect_err("transparent tls should reject header injection");
        assert!(err.to_string().contains("inject_headers"));
    }

    #[test]
    fn ext_authz_mode_validation_accepts_supported_fields() {
        let connect_allow = ExtAuthzAllow {
            headers: Some(Arc::new(
                CompiledHeaderControl::compile(&HeaderControl::default()).expect("headers"),
            )),
            override_upstream: Some("http://upstream.internal:8080".to_string()),
            timeout_override: Some(Duration::from_millis(250)),
            rate_limit_profile: Some("subject-egress".to_string()),
            force_inspect: true,
            force_tunnel: false,
            ..Default::default()
        };

        validate_ext_authz_allow_mode(&connect_allow, ExtAuthzMode::ForwardConnect)
            .expect("forward connect should accept force_inspect");

        let transparent_tls_allow = ExtAuthzAllow {
            override_upstream: connect_allow.override_upstream.clone(),
            timeout_override: connect_allow.timeout_override,
            rate_limit_profile: connect_allow.rate_limit_profile.clone(),
            force_inspect: true,
            ..Default::default()
        };
        validate_ext_authz_allow_mode(&transparent_tls_allow, ExtAuthzMode::TransparentTls)
            .expect("transparent tls should accept force_inspect");

        let http_allow = ExtAuthzAllow {
            headers: connect_allow.headers.clone(),
            override_upstream: connect_allow.override_upstream.clone(),
            timeout_override: connect_allow.timeout_override,
            cache_bypass: true,
            rate_limit_profile: connect_allow.rate_limit_profile.clone(),
            ..Default::default()
        };
        validate_ext_authz_allow_mode(&http_allow, ExtAuthzMode::ForwardHttp)
            .expect("forward http should accept cache_bypass");
        validate_ext_authz_allow_mode(&http_allow, ExtAuthzMode::ReverseHttp)
            .expect("reverse_edges http should accept cache_bypass");

        let reverse_allow = ExtAuthzAllow {
            headers: connect_allow.headers.clone(),
            override_upstream: connect_allow.override_upstream.clone(),
            timeout_override: connect_allow.timeout_override,
            mirror_upstreams: vec!["http://mirror.internal:8080".to_string()],
            rate_limit_profile: connect_allow.rate_limit_profile.clone(),
            ..Default::default()
        };
        validate_ext_authz_allow_mode(&reverse_allow, ExtAuthzMode::ReverseHttp)
            .expect("reverse_edges http should accept mirror_upstreams");
    }

    #[test]
    fn ext_authz_action_overrides_apply_force_modes() {
        let mut action = ActionConfig {
            kind: ActionKind::Tunnel,
            upstream: Some("baseline".to_string()),
            local_response: None,
        };
        apply_ext_authz_action_overrides(
            &mut action,
            &ExtAuthzAllow {
                override_upstream: Some("http://override.internal:8080".to_string()),
                force_inspect: true,
                ..Default::default()
            },
        );
        assert!(matches!(action.kind, ActionKind::Inspect));
        assert_eq!(
            action.upstream.as_deref(),
            Some("http://override.internal:8080")
        );

        let mut action = ActionConfig {
            kind: ActionKind::Inspect,
            upstream: None,
            local_response: None,
        };
        apply_ext_authz_action_overrides(
            &mut action,
            &ExtAuthzAllow {
                force_tunnel: true,
                ..Default::default()
            },
        );
        assert!(matches!(action.kind, ActionKind::Tunnel));
    }
}
