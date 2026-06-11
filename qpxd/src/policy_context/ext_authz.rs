use crate::http::dispatch::ProxyKind;
use crate::runtime::RuntimeState;
use anyhow::{Context, Result, anyhow};
use http::header::HeaderName;
use http_body_util::BodyExt;
use hyper::{HeaderMap, Request};
use qpx_core::config::{
    ActionConfig, ActionKind, ExtAuthzConfig, ExtAuthzOnError, HeaderControl, LocalResponseConfig,
};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex};
use tokio::time::{Duration, timeout};
use tracing::warn;
use url::Url;

use super::identity::{EffectivePolicyContext, ResolvedIdentity};
use super::util::{normalize_string_list, selected_headers_map};

mod validation;

/// Inline-first capacity for ext_authz response bodies. Most authorization
/// decisions fit here, so the steady-state round trip allocates nothing.
const EXT_AUTHZ_INLINE_RESPONSE_BYTES: usize = 4096;
/// Maximum number of spill buffers retained for reuse across round trips.
const EXT_AUTHZ_RESPONSE_BUFFER_POOL_LIMIT: usize = 8;
/// Spill buffers above this capacity are dropped instead of pooled so a single
/// oversized response cannot pin memory for the process lifetime.
const EXT_AUTHZ_RESPONSE_BUFFER_RETAIN_BYTES: usize = 256 * 1024;

static EXT_AUTHZ_RESPONSE_BUFFERS: LazyLock<Mutex<Vec<Vec<u8>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));

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

pub(crate) struct ExtAuthzAllowControls {
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) override_upstream: Option<String>,
    pub(crate) timeout_override: Option<Duration>,
    pub(crate) cache_bypass: bool,
    pub(crate) mirror_upstreams: Vec<String>,
    pub(crate) rate_limit_profile: Option<String>,
    force_inspect: bool,
    force_tunnel: bool,
}

impl ExtAuthzAllowControls {
    pub(crate) fn apply_action_overrides(&self, action: &mut ActionConfig) {
        apply_override_upstream(action, self.override_upstream.clone());
        if self.force_inspect {
            action.kind = ActionKind::Inspect;
        } else if self.force_tunnel {
            action.kind = ActionKind::Tunnel;
        }
    }
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

impl ExtAuthzEnforcement {
    pub(crate) fn policy_id(&self) -> Option<&str> {
        match self {
            Self::Continue(allow) => allow.policy_id.as_deref(),
            Self::Deny(deny) => deny.policy_id.as_deref(),
        }
    }

    pub(crate) fn policy_tags(&self) -> &[String] {
        match self {
            Self::Continue(allow) => &allow.policy_tags,
            Self::Deny(deny) => &deny.policy_tags,
        }
    }
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

    let result = ext_authz_round_trip(&state.pools, cfg, input).await;
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
    pools: &crate::pool::PoolRegistry,
    cfg: &CompiledExtAuthz,
    input: ExtAuthzInput<'_>,
) -> Result<ExtAuthzEnforcement> {
    let body = serde_json::to_vec(&build_ext_authz_request(cfg, input))?;
    let request = Request::builder()
        .method(http::Method::POST)
        .uri(cfg.endpoint.as_str())
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))?;

    let (status, body_len, enforcement) = match cfg.endpoint.scheme() {
        "http" => {
            timeout(cfg.timeout, async {
                let response =
                    crate::http::protocol::common::request_with_shared_client(request).await?;
                let status = response.status();
                let (body_len, enforcement) =
                    parse_ext_authz_response_body(response.into_body(), cfg.max_response_bytes)
                        .await?;
                anyhow::Ok((status, body_len, enforcement))
            })
            .await??
        }
        "https" => {
            timeout(cfg.timeout, async {
                let response =
                    crate::upstream::origin::shared_reverse_https_request(pools, request).await?;
                let status = response.status();
                let (body_len, enforcement) =
                    parse_ext_authz_response_body(response.into_body(), cfg.max_response_bytes)
                        .await?;
                anyhow::Ok((status, body_len, enforcement))
            })
            .await??
        }
        other => return Err(anyhow!("unsupported ext_authz scheme: {}", other)),
    };
    if !status.is_success() {
        return Err(anyhow!("ext_authz returned {}", status));
    }
    super::metrics::ext_authz_response_body_bytes(cfg.endpoint.scheme(), body_len);
    Ok(enforcement)
}

fn parse_ext_authz_response(body: &[u8]) -> Result<ExtAuthzEnforcement> {
    if let Some(enforcement) = parse_minimal_ext_authz_decision(body) {
        return Ok(enforcement);
    }
    parse_ext_authz_response_reader(body)
}

fn parse_ext_authz_response_reader<R>(reader: R) -> Result<ExtAuthzEnforcement>
where
    R: Read,
{
    let mut de = serde_json::Deserializer::from_reader(reader);
    let parsed = ExtAuthzResponse::deserialize(&mut de)
        .with_context(|| "failed to parse ext_authz response body as JSON")?;
    de.end()
        .with_context(|| "failed to parse ext_authz response body as JSON")?;
    parsed.into_enforcement()
}

fn parse_minimal_ext_authz_decision(body: &[u8]) -> Option<ExtAuthzEnforcement> {
    let mut cursor = JsonCursor::new(body);
    cursor.skip_ws();
    cursor.consume(b'{')?;
    cursor.skip_ws();
    let key = cursor.simple_string()?;
    if key != "decision" {
        return None;
    }
    cursor.skip_ws();
    cursor.consume(b':')?;
    cursor.skip_ws();
    let decision = cursor.simple_string()?;
    cursor.skip_ws();
    cursor.consume(b'}')?;
    cursor.skip_ws();
    if !cursor.is_eof() {
        return None;
    }
    match decision {
        "allow" => Some(ExtAuthzEnforcement::Continue(ExtAuthzAllow::default())),
        "deny" => Some(ExtAuthzEnforcement::Deny(ExtAuthzDeny::default())),
        _ => None,
    }
}

struct JsonCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn skip_ws(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.pos += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> Option<()> {
        if self.bytes.get(self.pos).copied()? != expected {
            return None;
        }
        self.pos += 1;
        Some(())
    }

    fn simple_string(&mut self) -> Option<&'a str> {
        self.consume(b'"')?;
        let start = self.pos;
        while let Some(byte) = self.bytes.get(self.pos).copied() {
            match byte {
                b'"' => {
                    let end = self.pos;
                    self.pos += 1;
                    return std::str::from_utf8(&self.bytes[start..end]).ok();
                }
                b'\\' | 0x00..=0x1f => return None,
                _ => self.pos += 1,
            }
        }
        None
    }
}

/// Inline-first response collector: bodies up to
/// `EXT_AUTHZ_INLINE_RESPONSE_BYTES` stay on the stack; larger bodies spill
/// into a pooled heap buffer that is recycled on drop.
struct ExtAuthzBodyBuffer {
    inline: [u8; EXT_AUTHZ_INLINE_RESPONSE_BYTES],
    inline_len: usize,
    heap: Option<Vec<u8>>,
}

impl ExtAuthzBodyBuffer {
    fn new() -> Self {
        Self {
            inline: [0; EXT_AUTHZ_INLINE_RESPONSE_BYTES],
            inline_len: 0,
            heap: None,
        }
    }

    fn len(&self) -> usize {
        match &self.heap {
            Some(heap) => heap.len(),
            None => self.inline_len,
        }
    }

    fn as_slice(&self) -> &[u8] {
        match &self.heap {
            Some(heap) => heap,
            None => &self.inline[..self.inline_len],
        }
    }

    fn extend(&mut self, data: &[u8]) -> Result<()> {
        if let Some(heap) = self.heap.as_mut() {
            heap.extend_from_slice(data);
            return Ok(());
        }
        let next = self
            .inline_len
            .checked_add(data.len())
            .ok_or_else(|| anyhow!("ext_authz response body size overflow"))?;
        if next <= EXT_AUTHZ_INLINE_RESPONSE_BYTES {
            self.inline[self.inline_len..next].copy_from_slice(data);
            self.inline_len = next;
            return Ok(());
        }
        let mut heap = checkout_ext_authz_response_buffer();
        heap.extend_from_slice(&self.inline[..self.inline_len]);
        heap.extend_from_slice(data);
        self.heap = Some(heap);
        Ok(())
    }
}

impl Drop for ExtAuthzBodyBuffer {
    fn drop(&mut self) {
        if let Some(heap) = self.heap.take() {
            recycle_ext_authz_response_buffer(heap);
        }
    }
}

fn checkout_ext_authz_response_buffer() -> Vec<u8> {
    if let Ok(mut pool) = EXT_AUTHZ_RESPONSE_BUFFERS.lock() {
        if let Some(buffer) = pool.pop() {
            return buffer;
        }
    }
    Vec::new()
}

fn recycle_ext_authz_response_buffer(mut buffer: Vec<u8>) {
    if buffer.capacity() > EXT_AUTHZ_RESPONSE_BUFFER_RETAIN_BYTES {
        return;
    }
    buffer.clear();
    if let Ok(mut pool) = EXT_AUTHZ_RESPONSE_BUFFERS.lock() {
        if pool.len() < EXT_AUTHZ_RESPONSE_BUFFER_POOL_LIMIT {
            pool.push(buffer);
        }
    }
}

async fn parse_ext_authz_response_body<B>(
    body: B,
    max_bytes: usize,
) -> Result<(usize, ExtAuthzEnforcement)>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: Into<qpx_http::body::BodyError>,
{
    let buffer = collect_ext_authz_response_body(body, max_bytes).await?;
    let enforcement = parse_ext_authz_response(buffer.as_slice())?;
    Ok((buffer.len(), enforcement))
}

async fn collect_ext_authz_response_body<B>(
    mut body: B,
    max_bytes: usize,
) -> Result<ExtAuthzBodyBuffer>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: Into<qpx_http::body::BodyError>,
{
    let mut out = ExtAuthzBodyBuffer::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(Into::into)?;
        if let Ok(data) = frame.into_data() {
            let next = out
                .len()
                .checked_add(data.len())
                .ok_or_else(|| anyhow!("ext_authz response body size overflow"))?;
            if next > max_bytes {
                return Err(anyhow!(
                    "ext_authz response body exceeds hard cap of {} bytes",
                    max_bytes
                ));
            }
            out.extend(&data)?;
        }
    }
    Ok(out)
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

pub(crate) fn prepare_ext_authz_allow_controls(
    allow: ExtAuthzAllow,
    mode: ExtAuthzMode,
    base_headers: Option<Arc<CompiledHeaderControl>>,
) -> Result<ExtAuthzAllowControls> {
    validate_ext_authz_allow_mode(&allow, mode)?;
    Ok(ExtAuthzAllowControls {
        headers: merge_header_controls(base_headers, allow.headers),
        override_upstream: allow.override_upstream,
        timeout_override: allow.timeout_override,
        cache_bypass: allow.cache_bypass,
        mirror_upstreams: allow.mirror_upstreams,
        rate_limit_profile: allow.rate_limit_profile,
        force_inspect: allow.force_inspect,
        force_tunnel: allow.force_tunnel,
    })
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

#[cfg(test)]
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
