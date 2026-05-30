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

mod validation;

pub(crate) use self::validation::validate_ext_authz_allow_mode;
use self::validation::{validate_ext_authz_local_response, validate_ext_authz_upstream_value};

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
        let override_upstream = self
            .override_upstream
            .map(|value| validate_ext_authz_upstream_value(value, "override_upstream"))
            .transpose()?;
        let mirror_upstreams = normalize_string_list(self.mirror_upstreams);
        for upstream in &mirror_upstreams {
            validate_ext_authz_upstream_value(upstream.clone(), "mirror_upstreams")?;
        }
        let policy_tags = normalize_string_list(self.policy_tags);
        let local_response = self
            .local_response
            .map(validate_ext_authz_local_response)
            .transpose()?;
        match self.decision.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(ExtAuthzEnforcement::Continue(ExtAuthzAllow {
                policy_id: self.policy_id,
                override_upstream,
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
                local_response,
                policy_tags,
            })),
            "local_response" => {
                let local_response = local_response.ok_or_else(|| {
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
                let local_response = local_response.ok_or_else(|| {
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
mod tests;
