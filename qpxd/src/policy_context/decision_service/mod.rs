use crate::http::dispatch::ProxyKind;
use crate::runtime::RuntimeState;
use anyhow::{Context, Result, anyhow};
use http::header::HeaderName;
use http_body_util::BodyExt;
use hyper::{HeaderMap, Request};
use jsonschema::Validator;
use qpx_core::config::{
    ActionConfig, ActionKind, DecisionServiceAuthorityConfig, DecisionServiceConfig,
    DecisionServiceConstraintsConfig, DecisionServiceDriver, DecisionServiceMappingRuleConfig,
    DecisionServiceMappingTargetDocument, HeaderControl, LocalResponseConfig,
    UpstreamTlsTrustConfig,
};
use qpx_core::rules::CompiledHeaderControl;
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_http::body::Body;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use serde_json_path::JsonPath;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use tracing::warn;
use url::Url;

use super::identity::{EffectivePolicyContext, ResolvedIdentity};
use super::util::{normalize_string_list, selected_headers_map};

mod cache;
mod signature;
mod validation;

use self::cache::{DecisionServiceCache, compile_cache, decision_cache_key};
use self::signature::{CompiledSignature, apply_http_message_signature, compile_signature};
pub(crate) use self::validation::validate_decision_service_allow_mode;
use self::validation::{
    validate_decision_service_local_response, validate_decision_service_upstream_value,
};

#[derive(Debug)]
pub(crate) struct CompiledDecisionService {
    name: String,
    endpoint: Url,
    timeout: Duration,
    max_response_bytes: usize,
    profile_id: String,
    contract_id: Option<String>,
    selected_headers: Vec<HeaderName>,
    sensitive_headers: HashSet<HeaderName>,
    signal_extensions: Value,
    expected_auth_context: Value,
    request_mapping: Vec<CompiledMappingRule>,
    response_mapping: Vec<CompiledMappingRule>,
    remote_request_schema: Option<Validator>,
    remote_response_schema: Option<Validator>,
    remote_auth_context_schema: Option<Validator>,
    qpx_enforceable_effect_schema: Validator,
    authority: DecisionServiceAuthorityConfig,
    constraints: DecisionServiceConstraintsConfig,
    allowed_modes: HashSet<String>,
    allowed_effects: HashSet<String>,
    upstream_trust: Option<Arc<CompiledUpstreamTlsTrust>>,
    bearer_token: Option<String>,
    signature: Option<CompiledSignature>,
    cache: Option<Arc<DecisionServiceCache>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DecisionServiceAllow {
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

impl DecisionServiceAllow {
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
pub(crate) enum DecisionServiceMode {
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

impl DecisionServiceMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ForwardHttp => "forward_http",
            Self::ForwardConnect => "forward_connect",
            #[cfg(feature = "mitm")]
            Self::ForwardMitmHttp => "forward_mitm_http",
            Self::ReverseHttp => "reverse_http",
            Self::TransparentHttp => "transparent_http",
            Self::TransparentTls => "transparent_tls",
            #[cfg(feature = "http3")]
            Self::TransparentUdp => "transparent_udp",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DecisionServiceDeny {
    pub(crate) policy_id: Option<String>,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) local_response: Option<LocalResponseConfig>,
    pub(crate) policy_tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum DecisionServiceEnforcement {
    Continue(DecisionServiceAllow),
    Deny(DecisionServiceDeny),
}

impl DecisionServiceEnforcement {
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
pub(crate) struct DecisionServiceInput<'a> {
    pub(crate) mode: DecisionServiceMode,
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

impl CompiledDecisionService {
    pub(crate) fn from_config(
        config: &DecisionServiceConfig,
        trust_profiles: &HashMap<String, UpstreamTlsTrustConfig>,
    ) -> Result<Self> {
        match config.contract.driver {
            DecisionServiceDriver::SchemaMappedHttp => {}
        }
        let selected_headers = config
            .pep_signal
            .selected_headers
            .iter()
            .map(|name| HeaderName::from_bytes(name.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let sensitive_headers = config
            .pep_signal
            .sensitive_headers
            .iter()
            .map(|name| HeaderName::from_bytes(name.as_bytes()))
            .collect::<std::result::Result<HashSet<_>, _>>()?;
        let remote_request_schema = load_schema_ref(
            config.schema_resolution.local_bundle.as_deref(),
            config.contract.schemas.remote.decision_request.as_ref(),
        )?
        .map(|schema| compile_schema(schema, "decision_request"))
        .transpose()?;
        let remote_response_schema = load_schema_ref(
            config.schema_resolution.local_bundle.as_deref(),
            config.contract.schemas.remote.decision_response.as_ref(),
        )?
        .map(|schema| compile_schema(schema, "decision_response"))
        .transpose()?;
        let remote_auth_context_schema = load_schema_ref(
            config.schema_resolution.local_bundle.as_deref(),
            config.contract.schemas.remote.auth_context.as_ref(),
        )?
        .map(|schema| compile_schema(schema, "auth_context"))
        .transpose()?;
        let qpx_enforceable_effect_schema = qpx_enforceable_effect_schema();
        verify_builtin_schema_ref(
            config.contract.schemas.qpx.enforceable_effect.as_ref(),
            &qpx_enforceable_effect_schema,
        )?;
        let qpx_enforceable_effect_schema =
            compile_schema(qpx_enforceable_effect_schema, "enforceable_effect")?;
        let upstream_trust = compile_mtls(config, trust_profiles)?;
        let signature = compile_signature(config)?;
        let cache = compile_cache(config)?;
        Ok(Self {
            name: config.name.clone(),
            endpoint: Url::parse(&config.endpoint)?,
            timeout: Duration::from_millis(config.timeout_ms),
            max_response_bytes: config.max_response_bytes,
            profile_id: config.contract.profile_id.clone(),
            contract_id: config.contract.contract_id.clone(),
            selected_headers,
            sensitive_headers,
            signal_extensions: config.signal_extensions.clone(),
            expected_auth_context: config.auth.expected_auth_context.clone(),
            request_mapping: compile_mapping_rules(&config.request_mapping)?,
            response_mapping: compile_mapping_rules(&config.response_mapping)?,
            remote_request_schema,
            remote_response_schema,
            remote_auth_context_schema,
            qpx_enforceable_effect_schema,
            authority: config.capability.authority.clone(),
            constraints: config.capability.constraints.clone(),
            allowed_modes: config
                .capability
                .modes
                .iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
            allowed_effects: config
                .capability
                .effects
                .iter()
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .collect(),
            upstream_trust,
            bearer_token: config
                .auth
                .bearer_token_env
                .as_ref()
                .map(std::env::var)
                .transpose()
                .with_context(|| {
                    format!(
                        "decision_service {} auth.bearer_token_env could not be read",
                        config.name
                    )
                })?,
            signature,
            cache,
        })
    }
}

pub(crate) async fn enforce_decision_service(
    state: &RuntimeState,
    policy: &EffectivePolicyContext,
    input: DecisionServiceInput<'_>,
) -> Result<DecisionServiceEnforcement> {
    let Some(name) = policy.decision_service.as_deref() else {
        return Ok(DecisionServiceEnforcement::Continue(
            DecisionServiceAllow::default(),
        ));
    };
    let cfg = state
        .security
        .decisions
        .services
        .get(name)
        .ok_or_else(|| anyhow!("decision_service missing at runtime: {}", name))?;

    let result = decision_service_round_trip(&state.pools, cfg, input).await;
    match result {
        Ok(enforcement) => Ok(enforcement),
        Err(err) => {
            warn!(decision_service = %name, error = ?err, "decision_service evaluation failed");
            Ok(DecisionServiceEnforcement::Deny(
                DecisionServiceDeny::default(),
            ))
        }
    }
}

async fn decision_service_round_trip(
    pools: &crate::pool::PoolRegistry,
    cfg: &CompiledDecisionService,
    input: DecisionServiceInput<'_>,
) -> Result<DecisionServiceEnforcement> {
    cfg.validate_mode(input.mode)?;
    let request_value = build_remote_decision_request(cfg, &input)?;
    let body = serde_json::to_vec(&request_value)?;
    let cache_key = cfg.cache.as_ref().map(|_| decision_cache_key(cfg, &body));
    if let (Some(cache), Some(key)) = (cfg.cache.as_ref(), cache_key.as_deref())
        && let Some(enforcement) = cache.get(key)
    {
        return Ok(enforcement);
    }
    let mut builder = Request::builder()
        .method(http::Method::POST)
        .uri(cfg.endpoint.as_str())
        .header(http::header::CONTENT_TYPE, "application/json");
    if let Some(token) = cfg.bearer_token.as_deref() {
        builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder = apply_http_message_signature(builder, cfg, &body)?;
    let request = builder.body(Body::from(body))?;

    let (status, body_len, raw_response) = match cfg.endpoint.scheme() {
        "http" => {
            timeout(cfg.timeout, async {
                let response =
                    crate::http::protocol::common::request_with_shared_client(request).await?;
                let status = response.status();
                validate_decision_service_content_length(
                    response.headers(),
                    cfg.max_response_bytes,
                )?;
                let (body_len, response) = parse_decision_service_response_body(
                    response.into_body(),
                    cfg.max_response_bytes,
                )
                .await?;
                anyhow::Ok((status, body_len, response))
            })
            .await??
        }
        "https" => {
            timeout(cfg.timeout, async {
                let response = crate::upstream::origin::shared_reverse_https_request_with_trust(
                    pools,
                    request,
                    cfg.upstream_trust.as_deref(),
                )
                .await?;
                let status = response.status();
                validate_decision_service_content_length(
                    response.headers(),
                    cfg.max_response_bytes,
                )?;
                let (body_len, response) = parse_decision_service_response_body(
                    response.into_body(),
                    cfg.max_response_bytes,
                )
                .await?;
                anyhow::Ok((status, body_len, response))
            })
            .await??
        }
        other => return Err(anyhow!("unsupported decision_service scheme: {}", other)),
    };
    if !status.is_success() {
        return Err(anyhow!("decision_service returned {}", status));
    }
    super::metrics::decision_service_response_body_bytes(cfg.endpoint.scheme(), body_len);
    let enforcement = map_remote_decision_response(cfg, raw_response)?;
    if let (Some(cache), Some(key)) = (cfg.cache.as_ref(), cache_key) {
        cache.insert(key, enforcement.clone());
    }
    Ok(enforcement)
}

fn build_remote_decision_request(
    cfg: &CompiledDecisionService,
    input: &DecisionServiceInput<'_>,
) -> Result<Value> {
    let source = if mapping_rules_need_json_source(&cfg.request_mapping) {
        let pep_signal = build_pep_signal(cfg, input);
        let effect_capability = build_effect_capability(cfg, input.mode);
        Some(json!({
            "pep_signal": pep_signal,
            "effect_capability": effect_capability
        }))
    } else {
        None
    };
    let mut docs = MappingDocuments::default();
    let builtins = MappingBuiltins {
        cfg,
        input: Some(input),
        decision_response: None,
    };
    apply_mapping(&cfg.request_mapping, source.as_ref(), builtins, &mut docs)?;
    let request = docs.decision_request;
    if let Some(schema) = cfg.remote_auth_context_schema.as_ref() {
        validate_schema(schema, &docs.auth_assertions, "auth_context")?;
    }
    if !is_empty_json_value(&cfg.expected_auth_context)
        && docs.auth_assertions != cfg.expected_auth_context
    {
        return Err(anyhow!(
            "decision_service {} auth_assertions did not match expected_auth_context",
            cfg.name
        ));
    }
    if let Some(schema) = cfg.remote_request_schema.as_ref() {
        validate_schema(schema, &request, "decision_request")?;
    }
    Ok(request)
}

impl CompiledDecisionService {
    fn validate_mode(&self, mode: DecisionServiceMode) -> Result<()> {
        if self.allowed_modes.is_empty() || self.allowed_modes.contains(mode.as_str()) {
            return Ok(());
        }
        Err(anyhow!(
            "decision_service {} is not configured for mode {}",
            self.name,
            mode.as_str()
        ))
    }

    fn validate_effect_allowed(&self, effect: &'static str) -> Result<()> {
        if self.allowed_effects.is_empty() && effect == "allow" {
            return Ok(());
        }
        if self.allowed_effects.contains(effect) {
            return Ok(());
        }
        Err(anyhow!(
            "decision_service {} effect {} is outside configured capability",
            self.name,
            effect
        ))
    }
}

fn map_remote_decision_response(
    cfg: &CompiledDecisionService,
    raw_response: Value,
) -> Result<DecisionServiceEnforcement> {
    if let Some(schema) = cfg.remote_response_schema.as_ref() {
        validate_schema(schema, &raw_response, "decision_response")?;
    }
    let source = if mapping_rules_need_json_source(&cfg.response_mapping) {
        Some(json!({ "decision_response": raw_response }))
    } else {
        None
    };
    let mut docs = MappingDocuments::default();
    let builtins = MappingBuiltins {
        cfg,
        input: None,
        decision_response: Some(&raw_response),
    };
    apply_mapping(&cfg.response_mapping, source.as_ref(), builtins, &mut docs)?;
    validate_schema(
        &cfg.qpx_enforceable_effect_schema,
        &docs.enforceable_effect,
        "enforceable_effect",
    )?;
    let effect: EnforceableEffect = serde_json::from_value(docs.enforceable_effect)
        .with_context(|| "failed to parse qpx enforceable_effect")?;
    effect.into_enforcement(cfg)
}

fn build_pep_signal(cfg: &CompiledDecisionService, input: &DecisionServiceInput<'_>) -> Value {
    let mut headers = selected_headers_map(input.headers, &cfg.selected_headers);
    for sensitive in &cfg.sensitive_headers {
        if let Some(values) = headers.get_mut(sensitive.as_str()) {
            values.clear();
            values.push("[redacted]".to_string());
        }
    }
    json!({
        "proxy": {
            "kind": input.proxy_kind,
            "name": input.proxy_name,
            "scope": input.scope_name,
            "matched_rule": input.matched_rule,
            "matched_route": input.matched_route,
            "action": input.action.map(|action| format!("{:?}", action.kind).to_ascii_lowercase()),
            "mode": input.mode.as_str()
        },
        "request": {
            "remote_ip": input.remote_ip.to_string(),
            "dst_port": input.dst_port,
            "host": input.host,
            "sni": input.sni,
            "method": input.method,
            "path": input.path,
            "uri": input.uri,
            "headers": headers
        },
        "identity": {
            "user": &input.identity.user,
            "groups": &input.identity.groups,
            "device_id": &input.identity.device_id,
            "posture": &input.identity.posture,
            "tenant": &input.identity.tenant,
            "auth_strength": &input.identity.auth_strength,
            "idp": &input.identity.idp,
            "source": &input.identity.identity_source
        },
        "extensions": &cfg.signal_extensions
    })
}

fn build_effect_capability(cfg: &CompiledDecisionService, mode: DecisionServiceMode) -> Value {
    json!({
        "driver": "schema_mapped_http",
        "profile_id": cfg.profile_id,
        "contract_id": cfg.contract_id,
        "mode": mode.as_str(),
        "phase": "request_headers_after_route",
        "authority": {
            "can_allow": cfg.authority.can_allow,
            "can_deny": cfg.authority.can_deny,
            "can_override_route": cfg.authority.can_override_route,
            "can_weaken_local_policy": cfg.authority.can_weaken_local_policy
        },
        "constraints": {
            "allowed_request_headers_to_add": &cfg.constraints.allowed_request_headers_to_add,
            "allowed_response_headers_to_add": &cfg.constraints.allowed_response_headers_to_add,
            "override_upstreams": &cfg.constraints.override_upstreams,
            "max_timeout_override_ms": cfg.constraints.max_timeout_override_ms
        }
    })
}

#[derive(Debug)]
struct CompiledMappingRule {
    target_document: DecisionServiceMappingTargetDocument,
    target: String,
    source: Option<CompiledMappingSource>,
    literal: Option<Value>,
    optional: bool,
}

#[derive(Debug)]
enum CompiledMappingSource {
    JsonPath(JsonPath),
    Builtin(BuiltinMappingSource),
}

#[derive(Debug)]
enum BuiltinMappingSource {
    PepSignal(BuiltinPepSignalSource),
    EffectCapability(BuiltinEffectCapabilitySource),
    DecisionResponsePointer(String),
}

#[derive(Debug, Clone, Copy)]
enum BuiltinPepSignalSource {
    ProxyKind,
    ProxyName,
    ProxyScope,
    ProxyMatchedRule,
    ProxyMatchedRoute,
    ProxyAction,
    ProxyMode,
    RequestRemoteIp,
    RequestDstPort,
    RequestHost,
    RequestSni,
    RequestMethod,
    RequestPath,
    RequestUri,
    RequestHeaders,
    IdentityUser,
    IdentityGroups,
    IdentityDeviceId,
    IdentityPosture,
    IdentityTenant,
    IdentityAuthStrength,
    IdentityIdp,
    IdentitySource,
    Extensions,
}

#[derive(Debug, Clone, Copy)]
enum BuiltinEffectCapabilitySource {
    Driver,
    ProfileId,
    ContractId,
    Mode,
    Phase,
    AuthorityCanAllow,
    AuthorityCanDeny,
    AuthorityCanOverrideRoute,
    AuthorityCanWeakenLocalPolicy,
    ConstraintsAllowedRequestHeadersToAdd,
    ConstraintsAllowedResponseHeadersToAdd,
    ConstraintsOverrideUpstreams,
    ConstraintsMaxTimeoutOverrideMs,
}

#[derive(Debug)]
struct MappingDocuments {
    decision_request: Value,
    enforceable_effect: Value,
    auth_assertions: Value,
}

impl Default for MappingDocuments {
    fn default() -> Self {
        Self {
            decision_request: Value::Object(Map::new()),
            enforceable_effect: Value::Object(Map::new()),
            auth_assertions: Value::Object(Map::new()),
        }
    }
}

fn compile_mapping_rules(
    rules: &[DecisionServiceMappingRuleConfig],
) -> Result<Vec<CompiledMappingRule>> {
    let mut out = Vec::with_capacity(rules.len());
    for rule in rules {
        let source = match rule.source.as_deref() {
            Some(source) => Some(compile_mapping_source(source)?),
            None => None,
        };
        out.push(CompiledMappingRule {
            target_document: rule.target_document.clone(),
            target: rule.target.clone(),
            source,
            literal: rule.literal.clone(),
            optional: rule.optional,
        });
    }
    Ok(out)
}

fn compile_mapping_source(source: &str) -> Result<CompiledMappingSource> {
    if let Some(builtin) = compile_builtin_mapping_source(source) {
        return Ok(CompiledMappingSource::Builtin(builtin));
    }
    JsonPath::parse(source)
        .map(CompiledMappingSource::JsonPath)
        .map_err(|err| anyhow!("invalid JSONPath {source}: {err}"))
}

fn compile_builtin_mapping_source(source: &str) -> Option<BuiltinMappingSource> {
    match source {
        "$.pep_signal.proxy.kind" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::ProxyKind,
        )),
        "$.pep_signal.proxy.name" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::ProxyName,
        )),
        "$.pep_signal.proxy.scope" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::ProxyScope,
        )),
        "$.pep_signal.proxy.matched_rule" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::ProxyMatchedRule,
        )),
        "$.pep_signal.proxy.matched_route" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::ProxyMatchedRoute,
        )),
        "$.pep_signal.proxy.action" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::ProxyAction,
        )),
        "$.pep_signal.proxy.mode" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::ProxyMode,
        )),
        "$.pep_signal.request.remote_ip" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::RequestRemoteIp,
        )),
        "$.pep_signal.request.dst_port" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::RequestDstPort,
        )),
        "$.pep_signal.request.host" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::RequestHost,
        )),
        "$.pep_signal.request.sni" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::RequestSni,
        )),
        "$.pep_signal.request.method" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::RequestMethod,
        )),
        "$.pep_signal.request.path" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::RequestPath,
        )),
        "$.pep_signal.request.uri" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::RequestUri,
        )),
        "$.pep_signal.request.headers" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::RequestHeaders,
        )),
        "$.pep_signal.identity.user" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::IdentityUser,
        )),
        "$.pep_signal.identity.groups" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::IdentityGroups,
        )),
        "$.pep_signal.identity.device_id" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::IdentityDeviceId,
        )),
        "$.pep_signal.identity.posture" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::IdentityPosture,
        )),
        "$.pep_signal.identity.tenant" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::IdentityTenant,
        )),
        "$.pep_signal.identity.auth_strength" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::IdentityAuthStrength,
        )),
        "$.pep_signal.identity.idp" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::IdentityIdp,
        )),
        "$.pep_signal.identity.source" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::IdentitySource,
        )),
        "$.pep_signal.extensions" => Some(BuiltinMappingSource::PepSignal(
            BuiltinPepSignalSource::Extensions,
        )),
        "$.effect_capability.driver" => Some(BuiltinMappingSource::EffectCapability(
            BuiltinEffectCapabilitySource::Driver,
        )),
        "$.effect_capability.profile_id" => Some(BuiltinMappingSource::EffectCapability(
            BuiltinEffectCapabilitySource::ProfileId,
        )),
        "$.effect_capability.contract_id" => Some(BuiltinMappingSource::EffectCapability(
            BuiltinEffectCapabilitySource::ContractId,
        )),
        "$.effect_capability.mode" => Some(BuiltinMappingSource::EffectCapability(
            BuiltinEffectCapabilitySource::Mode,
        )),
        "$.effect_capability.phase" => Some(BuiltinMappingSource::EffectCapability(
            BuiltinEffectCapabilitySource::Phase,
        )),
        "$.effect_capability.authority.can_allow" => Some(BuiltinMappingSource::EffectCapability(
            BuiltinEffectCapabilitySource::AuthorityCanAllow,
        )),
        "$.effect_capability.authority.can_deny" => Some(BuiltinMappingSource::EffectCapability(
            BuiltinEffectCapabilitySource::AuthorityCanDeny,
        )),
        "$.effect_capability.authority.can_override_route" => {
            Some(BuiltinMappingSource::EffectCapability(
                BuiltinEffectCapabilitySource::AuthorityCanOverrideRoute,
            ))
        }
        "$.effect_capability.authority.can_weaken_local_policy" => {
            Some(BuiltinMappingSource::EffectCapability(
                BuiltinEffectCapabilitySource::AuthorityCanWeakenLocalPolicy,
            ))
        }
        "$.effect_capability.constraints.allowed_request_headers_to_add" => {
            Some(BuiltinMappingSource::EffectCapability(
                BuiltinEffectCapabilitySource::ConstraintsAllowedRequestHeadersToAdd,
            ))
        }
        "$.effect_capability.constraints.allowed_response_headers_to_add" => {
            Some(BuiltinMappingSource::EffectCapability(
                BuiltinEffectCapabilitySource::ConstraintsAllowedResponseHeadersToAdd,
            ))
        }
        "$.effect_capability.constraints.override_upstreams" => {
            Some(BuiltinMappingSource::EffectCapability(
                BuiltinEffectCapabilitySource::ConstraintsOverrideUpstreams,
            ))
        }
        "$.effect_capability.constraints.max_timeout_override_ms" => {
            Some(BuiltinMappingSource::EffectCapability(
                BuiltinEffectCapabilitySource::ConstraintsMaxTimeoutOverrideMs,
            ))
        }
        "$.decision_response" => Some(BuiltinMappingSource::DecisionResponsePointer(String::new())),
        _ => source
            .strip_prefix("$.decision_response.")
            .filter(|suffix| is_simple_jsonpath_property_suffix(suffix))
            .map(json_path_suffix_to_pointer)
            .map(BuiltinMappingSource::DecisionResponsePointer),
    }
}

fn is_simple_jsonpath_property_suffix(suffix: &str) -> bool {
    suffix.split('.').all(is_simple_jsonpath_property_segment)
}

fn is_simple_jsonpath_property_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn json_path_suffix_to_pointer(suffix: &str) -> String {
    let mut pointer = String::new();
    for segment in suffix.split('.') {
        pointer.push('/');
        pointer.push_str(&segment.replace('~', "~0").replace('/', "~1"));
    }
    pointer
}

fn mapping_rules_need_json_source(rules: &[CompiledMappingRule]) -> bool {
    rules
        .iter()
        .any(|rule| matches!(rule.source, Some(CompiledMappingSource::JsonPath(_))))
}

#[derive(Clone, Copy)]
struct MappingBuiltins<'a, 'b> {
    cfg: &'a CompiledDecisionService,
    input: Option<&'b DecisionServiceInput<'b>>,
    decision_response: Option<&'b Value>,
}

fn apply_mapping(
    rules: &[CompiledMappingRule],
    source: Option<&Value>,
    builtins: MappingBuiltins<'_, '_>,
    docs: &mut MappingDocuments,
) -> Result<()> {
    for rule in rules {
        let value = match (&rule.literal, &rule.source) {
            (Some(value), None) => value.clone(),
            (None, Some(CompiledMappingSource::Builtin(builtin))) => {
                let Some(value) = builtin_mapping_value(builtin, builtins) else {
                    if rule.optional {
                        continue;
                    }
                    return Err(anyhow!(
                        "mapping source for {} matched no values",
                        rule.target
                    ));
                };
                value
            }
            (None, Some(CompiledMappingSource::JsonPath(path))) => {
                let Some(value) = query_jsonpath_mapping_value(path, source, rule)? else {
                    continue;
                };
                value
            }
            _ => {
                return Err(anyhow!(
                    "mapping rule must set exactly one of source or literal"
                ));
            }
        };
        let target = match rule.target_document {
            DecisionServiceMappingTargetDocument::DecisionRequest => &mut docs.decision_request,
            DecisionServiceMappingTargetDocument::EnforceableEffect => &mut docs.enforceable_effect,
            DecisionServiceMappingTargetDocument::AuthAssertions => &mut docs.auth_assertions,
        };
        insert_json_pointer(target, &rule.target, value)?;
    }
    Ok(())
}

fn query_jsonpath_mapping_value(
    path: &JsonPath,
    source: Option<&Value>,
    rule: &CompiledMappingRule,
) -> Result<Option<Value>> {
    let source = source.ok_or_else(|| {
        anyhow!(
            "mapping source for {} requires generic JSONPath source",
            rule.target
        )
    })?;
    let values = path.query(source).all();
    match values.len() {
        0 if rule.optional => Ok(None),
        0 => Err(anyhow!(
            "mapping source for {} matched no values",
            rule.target
        )),
        1 => Ok(Some((*values[0]).clone())),
        count => Err(anyhow!(
            "mapping source for {} matched {} values",
            rule.target,
            count
        )),
    }
}

fn builtin_mapping_value(
    source: &BuiltinMappingSource,
    builtins: MappingBuiltins<'_, '_>,
) -> Option<Value> {
    match source {
        BuiltinMappingSource::PepSignal(source) => {
            builtin_pep_signal_value(*source, builtins.cfg, builtins.input?)
        }
        BuiltinMappingSource::EffectCapability(source) => {
            builtin_effect_capability_value(*source, builtins.cfg, builtins.input?.mode)
        }
        BuiltinMappingSource::DecisionResponsePointer(pointer) => {
            let response = builtins.decision_response?;
            if pointer.is_empty() {
                Some(response.clone())
            } else {
                response.pointer(pointer).cloned()
            }
        }
    }
}

fn builtin_pep_signal_value(
    source: BuiltinPepSignalSource,
    cfg: &CompiledDecisionService,
    input: &DecisionServiceInput<'_>,
) -> Option<Value> {
    match source {
        BuiltinPepSignalSource::ProxyKind => Some(json!(input.proxy_kind)),
        BuiltinPepSignalSource::ProxyName => Some(json!(input.proxy_name)),
        BuiltinPepSignalSource::ProxyScope => Some(json!(input.scope_name)),
        BuiltinPepSignalSource::ProxyMatchedRule => input.matched_rule.map(Value::from),
        BuiltinPepSignalSource::ProxyMatchedRoute => input.matched_route.map(Value::from),
        BuiltinPepSignalSource::ProxyAction => input
            .action
            .map(|action| Value::from(format!("{:?}", action.kind).to_ascii_lowercase())),
        BuiltinPepSignalSource::ProxyMode => Some(json!(input.mode.as_str())),
        BuiltinPepSignalSource::RequestRemoteIp => Some(json!(input.remote_ip.to_string())),
        BuiltinPepSignalSource::RequestDstPort => input.dst_port.map(Value::from),
        BuiltinPepSignalSource::RequestHost => input.host.map(Value::from),
        BuiltinPepSignalSource::RequestSni => input.sni.map(Value::from),
        BuiltinPepSignalSource::RequestMethod => input.method.map(Value::from),
        BuiltinPepSignalSource::RequestPath => input.path.map(Value::from),
        BuiltinPepSignalSource::RequestUri => input.uri.map(Value::from),
        BuiltinPepSignalSource::RequestHeaders => {
            Some(json!(build_selected_headers(cfg, input.headers)))
        }
        BuiltinPepSignalSource::IdentityUser => input.identity.user.as_deref().map(Value::from),
        BuiltinPepSignalSource::IdentityGroups => Some(json!(&input.identity.groups)),
        BuiltinPepSignalSource::IdentityDeviceId => {
            input.identity.device_id.as_deref().map(Value::from)
        }
        BuiltinPepSignalSource::IdentityPosture => Some(json!(&input.identity.posture)),
        BuiltinPepSignalSource::IdentityTenant => input.identity.tenant.as_deref().map(Value::from),
        BuiltinPepSignalSource::IdentityAuthStrength => {
            input.identity.auth_strength.as_deref().map(Value::from)
        }
        BuiltinPepSignalSource::IdentityIdp => input.identity.idp.as_deref().map(Value::from),
        BuiltinPepSignalSource::IdentitySource => {
            input.identity.identity_source.as_deref().map(Value::from)
        }
        BuiltinPepSignalSource::Extensions => Some(cfg.signal_extensions.clone()),
    }
}

fn builtin_effect_capability_value(
    source: BuiltinEffectCapabilitySource,
    cfg: &CompiledDecisionService,
    mode: DecisionServiceMode,
) -> Option<Value> {
    match source {
        BuiltinEffectCapabilitySource::Driver => Some(json!("schema_mapped_http")),
        BuiltinEffectCapabilitySource::ProfileId => Some(json!(cfg.profile_id)),
        BuiltinEffectCapabilitySource::ContractId => cfg.contract_id.as_deref().map(Value::from),
        BuiltinEffectCapabilitySource::Mode => Some(json!(mode.as_str())),
        BuiltinEffectCapabilitySource::Phase => Some(json!("request_headers_after_route")),
        BuiltinEffectCapabilitySource::AuthorityCanAllow => Some(json!(cfg.authority.can_allow)),
        BuiltinEffectCapabilitySource::AuthorityCanDeny => Some(json!(cfg.authority.can_deny)),
        BuiltinEffectCapabilitySource::AuthorityCanOverrideRoute => {
            Some(json!(cfg.authority.can_override_route))
        }
        BuiltinEffectCapabilitySource::AuthorityCanWeakenLocalPolicy => {
            Some(json!(cfg.authority.can_weaken_local_policy))
        }
        BuiltinEffectCapabilitySource::ConstraintsAllowedRequestHeadersToAdd => {
            Some(json!(&cfg.constraints.allowed_request_headers_to_add))
        }
        BuiltinEffectCapabilitySource::ConstraintsAllowedResponseHeadersToAdd => {
            Some(json!(&cfg.constraints.allowed_response_headers_to_add))
        }
        BuiltinEffectCapabilitySource::ConstraintsOverrideUpstreams => {
            Some(json!(&cfg.constraints.override_upstreams))
        }
        BuiltinEffectCapabilitySource::ConstraintsMaxTimeoutOverrideMs => {
            cfg.constraints.max_timeout_override_ms.map(Value::from)
        }
    }
}

fn build_selected_headers(
    cfg: &CompiledDecisionService,
    headers: Option<&HeaderMap>,
) -> Map<String, Value> {
    let mut selected = selected_headers_map(headers, &cfg.selected_headers);
    for sensitive in &cfg.sensitive_headers {
        if let Some(values) = selected.get_mut(sensitive.as_str()) {
            values.clear();
            values.push("[redacted]".to_string());
        }
    }
    selected
        .into_iter()
        .map(|(name, values)| (name, json!(values)))
        .collect()
}

fn insert_json_pointer(root: &mut Value, pointer: &str, value: Value) -> Result<()> {
    if !pointer.starts_with('/') {
        return Err(anyhow!("mapping target must be a JSON Pointer: {pointer}"));
    }
    let tokens = pointer
        .split('/')
        .skip(1)
        .map(unescape_json_pointer_token)
        .collect::<Result<Vec<_>>>()?;
    insert_pointer_tokens(root, &tokens, value)
}

fn insert_pointer_tokens(current: &mut Value, tokens: &[String], value: Value) -> Result<()> {
    let Some((head, tail)) = tokens.split_first() else {
        *current = value;
        return Ok(());
    };
    if tail.is_empty() {
        match current {
            Value::Object(map) => {
                if map.contains_key(head) {
                    return Err(anyhow!("mapping target /{} is duplicated", head));
                }
                map.insert(head.clone(), value);
                Ok(())
            }
            Value::Array(items) => {
                let index = parse_array_index(head)?;
                if index != items.len() {
                    return Err(anyhow!("array mapping targets must append in order"));
                }
                items.push(value);
                Ok(())
            }
            Value::Null => {
                let mut map = Map::new();
                map.insert(head.clone(), value);
                *current = Value::Object(map);
                Ok(())
            }
            _ => Err(anyhow!("mapping target crosses a scalar value")),
        }
    } else {
        match current {
            Value::Object(map) => {
                let next = map.entry(head.clone()).or_insert_with(|| {
                    if tail[0].parse::<usize>().is_ok() {
                        Value::Array(Vec::new())
                    } else {
                        Value::Object(Map::new())
                    }
                });
                insert_pointer_tokens(next, tail, value)
            }
            Value::Array(items) => {
                let index = parse_array_index(head)?;
                if index > items.len() {
                    return Err(anyhow!("array mapping target skips index {index}"));
                }
                if index == items.len() {
                    items.push(if tail[0].parse::<usize>().is_ok() {
                        Value::Array(Vec::new())
                    } else {
                        Value::Object(Map::new())
                    });
                }
                insert_pointer_tokens(&mut items[index], tail, value)
            }
            Value::Null => {
                *current = Value::Object(Map::new());
                insert_pointer_tokens(current, tokens, value)
            }
            _ => Err(anyhow!("mapping target crosses a scalar value")),
        }
    }
}

fn parse_array_index(token: &str) -> Result<usize> {
    token
        .parse::<usize>()
        .map_err(|_| anyhow!("array mapping target must be a numeric index"))
}

fn unescape_json_pointer_token(token: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = token.chars();
    while let Some(ch) = chars.next() {
        if ch != '~' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            Some(other) => return Err(anyhow!("invalid JSON Pointer escape: ~{other}")),
            None => return Err(anyhow!("invalid trailing JSON Pointer escape")),
        }
    }
    Ok(out)
}

fn validate_decision_service_content_length(headers: &HeaderMap, max_bytes: usize) -> Result<()> {
    let Some(value) = headers.get(http::header::CONTENT_LENGTH) else {
        return Ok(());
    };
    let len = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    if let Some(len) = len
        && len > max_bytes
    {
        return Err(anyhow!(
            "decision_service response body exceeds hard cap of {} bytes",
            max_bytes
        ));
    }
    Ok(())
}

async fn parse_decision_service_response_body<B>(
    body: B,
    max_bytes: usize,
) -> Result<(usize, Value)>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: Into<qpx_http::body::BodyError>,
{
    let bytes = collect_decision_service_response_body(body, max_bytes).await?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| "failed to parse decision_service response body as JSON")?;
    Ok((bytes.len(), value))
}

async fn collect_decision_service_response_body<B>(mut body: B, max_bytes: usize) -> Result<Vec<u8>>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin,
    B::Error: Into<qpx_http::body::BodyError>,
{
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(Into::into)?;
        if let Ok(data) = frame.into_data() {
            let next = out
                .len()
                .checked_add(data.len())
                .ok_or_else(|| anyhow!("decision_service response body size overflow"))?;
            if next > max_bytes {
                return Err(anyhow!(
                    "decision_service response body exceeds hard cap of {} bytes",
                    max_bytes
                ));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnforceableEffect {
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

impl EnforceableEffect {
    fn into_enforcement(self, cfg: &CompiledDecisionService) -> Result<DecisionServiceEnforcement> {
        if self.force_inspect && self.force_tunnel {
            return Err(anyhow!(
                "decision_service enforceable_effect cannot set both force_inspect and force_tunnel"
            ));
        }
        self.validate_effect_capabilities(cfg)?;
        let headers = self
            .inject_headers
            .as_ref()
            .map(|headers| {
                let headers = validate_header_constraints(headers, cfg)?;
                Ok::<Arc<CompiledHeaderControl>, anyhow::Error>(Arc::new(
                    CompiledHeaderControl::compile(&headers)?,
                ))
            })
            .transpose()?;
        let timeout_override = self
            .timeout_override_ms
            .map(|timeout_ms| Duration::from_millis(timeout_ms.max(1)));
        if let Some(timeout_ms) = self.timeout_override_ms
            && let Some(max) = cfg.constraints.max_timeout_override_ms
            && timeout_ms > max
        {
            return Err(anyhow!(
                "decision_service timeout_override_ms exceeds capability constraint"
            ));
        }
        let rate_limit_profile = self
            .rate_limit_profile
            .map(|profile| profile.trim().to_string())
            .filter(|profile| !profile.is_empty());
        let override_upstream = self
            .override_upstream
            .map(|value| validate_override_upstream(value, cfg))
            .transpose()?;
        let mirror_upstreams = normalize_string_list(self.mirror_upstreams);
        for upstream in &mirror_upstreams {
            validate_decision_service_upstream_value(upstream.clone(), "mirror_upstreams")?;
        }
        let policy_tags = normalize_string_list(self.policy_tags);
        let local_response = self
            .local_response
            .map(validate_decision_service_local_response)
            .transpose()?;
        let decision = self.decision.trim().to_ascii_lowercase();
        match decision.as_str() {
            "allow" => {
                cfg.validate_effect_allowed("allow")?;
                if !cfg.authority.can_allow {
                    return Err(anyhow!("decision_service is not authorized to allow"));
                }
                Ok(DecisionServiceEnforcement::Continue(DecisionServiceAllow {
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
                }))
            }
            "deny" => {
                cfg.validate_effect_allowed("deny")?;
                if !cfg.authority.can_deny {
                    return Err(anyhow!("decision_service is not authorized to deny"));
                }
                Ok(DecisionServiceEnforcement::Deny(DecisionServiceDeny {
                    policy_id: self.policy_id,
                    headers,
                    local_response,
                    policy_tags,
                }))
            }
            "local_response" | "challenge" => {
                cfg.validate_effect_allowed(if decision == "challenge" {
                    "challenge"
                } else {
                    "local_response"
                })?;
                if !cfg.authority.can_deny {
                    return Err(anyhow!(
                        "decision_service is not authorized to produce local responses"
                    ));
                }
                let local_response = local_response.ok_or_else(|| {
                    anyhow!("decision_service local_response decision requires local_response")
                })?;
                Ok(DecisionServiceEnforcement::Deny(DecisionServiceDeny {
                    policy_id: self.policy_id,
                    headers,
                    local_response: Some(local_response),
                    policy_tags,
                }))
            }
            other => Err(anyhow!(
                "unsupported enforceable_effect decision: {}",
                other
            )),
        }
    }

    fn validate_effect_capabilities(&self, cfg: &CompiledDecisionService) -> Result<()> {
        if self.inject_headers.is_some() {
            cfg.validate_effect_allowed("inject_headers")?;
        }
        if self.override_upstream.is_some() {
            cfg.validate_effect_allowed("override_upstream")?;
        }
        if self.timeout_override_ms.is_some() {
            cfg.validate_effect_allowed("timeout_override")?;
        }
        if self.cache_bypass {
            cfg.validate_effect_allowed("cache_bypass")?;
        }
        if !self.mirror_upstreams.is_empty() {
            cfg.validate_effect_allowed("mirror_upstreams")?;
        }
        if self.rate_limit_profile.is_some() {
            cfg.validate_effect_allowed("rate_limit_profile")?;
        }
        if self.force_inspect {
            cfg.validate_effect_allowed("force_inspect")?;
        }
        if self.force_tunnel {
            cfg.validate_effect_allowed("force_tunnel")?;
            if !cfg.authority.can_weaken_local_policy {
                return Err(anyhow!(
                    "decision_service is not authorized to weaken local policy"
                ));
            }
        }
        Ok(())
    }
}

fn validate_header_constraints(
    headers: &HeaderControl,
    cfg: &CompiledDecisionService,
) -> Result<HeaderControl> {
    let allowed_request = cfg
        .constraints
        .allowed_request_headers_to_add
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let allowed_response = cfg
        .constraints
        .allowed_response_headers_to_add
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    for name in headers
        .request_set
        .keys()
        .chain(headers.request_add.keys())
        .chain(headers.request_remove.iter())
    {
        if !allowed_request.contains(&name.to_ascii_lowercase()) {
            return Err(anyhow!(
                "decision_service attempted request header mutation outside capability: {name}"
            ));
        }
    }
    for name in headers
        .response_set
        .keys()
        .chain(headers.response_add.keys())
        .chain(headers.response_remove.iter())
    {
        if !allowed_response.contains(&name.to_ascii_lowercase()) {
            return Err(anyhow!(
                "decision_service attempted response header mutation outside capability: {name}"
            ));
        }
    }
    Ok(headers.clone())
}

fn validate_override_upstream(value: String, cfg: &CompiledDecisionService) -> Result<String> {
    let value = validate_decision_service_upstream_value(value, "override_upstream")?;
    if cfg.authority.can_override_route {
        return Ok(value);
    }
    if cfg
        .constraints
        .override_upstreams
        .iter()
        .any(|allowed| allowed == &value)
    {
        return Ok(value);
    }
    Err(anyhow!(
        "decision_service attempted override_upstream outside capability"
    ))
}

fn compile_schema(schema: Value, context: &str) -> Result<Validator> {
    jsonschema::validator_for(&schema)
        .with_context(|| format!("failed to compile {context} schema"))
}

fn validate_schema(validator: &Validator, instance: &Value, context: &str) -> Result<()> {
    validator
        .validate(instance)
        .map_err(|err| anyhow!("{context} schema validation failed: {err}"))
}

#[derive(Debug, Deserialize)]
struct SchemaBundleManifest {
    schemas: Vec<SchemaBundleEntry>,
}

#[derive(Debug, Deserialize)]
struct SchemaBundleEntry {
    id: String,
    path: String,
    digest: String,
}

fn load_schema_ref(
    local_bundle: Option<&str>,
    schema_ref: Option<&qpx_core::config::DecisionServiceSchemaRefConfig>,
) -> Result<Option<Value>> {
    let Some(schema_ref) = schema_ref else {
        return Ok(None);
    };
    let bundle = local_bundle.ok_or_else(|| {
        anyhow!(
            "schema_resolution.local_bundle is required for remote schema {}",
            schema_ref.id
        )
    })?;
    let manifest_path = schema_manifest_path(bundle);
    let manifest_bytes = fs::read(&manifest_path).with_context(|| {
        format!(
            "failed to read decision_service schema manifest {}",
            manifest_path.display()
        )
    })?;
    let manifest: SchemaBundleManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| "failed to parse decision_service schema manifest")?;
    let entry = manifest
        .schemas
        .iter()
        .find(|entry| entry.id == schema_ref.id)
        .ok_or_else(|| anyhow!("schema bundle does not contain schema id {}", schema_ref.id))?;
    if entry.digest != schema_ref.digest {
        return Err(anyhow!(
            "schema bundle digest for {} does not match config",
            schema_ref.id
        ));
    }
    let schema_path = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(&entry.path);
    let schema_bytes = fs::read(&schema_path)
        .with_context(|| format!("failed to read schema {}", schema_path.display()))?;
    let digest = sha256_digest(&schema_bytes);
    if digest != schema_ref.digest {
        return Err(anyhow!(
            "schema {} digest mismatch: expected {}, got {}",
            schema_ref.id,
            schema_ref.digest,
            digest
        ));
    }
    let schema: Value = serde_json::from_slice(&schema_bytes)
        .with_context(|| format!("failed to parse schema {}", schema_path.display()))?;
    if let Some(id) = schema.get("$id").and_then(Value::as_str)
        && id != schema_ref.id
    {
        return Err(anyhow!(
            "schema {} has mismatched $id {}",
            schema_ref.id,
            id
        ));
    }
    Ok(Some(schema))
}

fn schema_manifest_path(bundle: &str) -> PathBuf {
    let path = PathBuf::from(bundle);
    if path.is_dir() {
        path.join("manifest.json")
    } else {
        path
    }
}

fn verify_builtin_schema_ref(
    schema_ref: Option<&qpx_core::config::DecisionServiceSchemaRefConfig>,
    schema: &Value,
) -> Result<()> {
    let Some(schema_ref) = schema_ref else {
        return Ok(());
    };
    if let Some(id) = schema.get("$id").and_then(Value::as_str)
        && id != schema_ref.id
    {
        return Err(anyhow!(
            "qpx schema id mismatch: expected {}, got {}",
            schema_ref.id,
            id
        ));
    }
    let bytes = serde_json::to_vec(schema)?;
    let digest = sha256_digest(&bytes);
    if digest != schema_ref.digest {
        return Err(anyhow!(
            "qpx schema {} digest mismatch: expected {}, got {}",
            schema_ref.id,
            schema_ref.digest,
            digest
        ));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> String {
    sha256_output_to_digest(Sha256::digest(bytes))
}

pub(super) fn sha256_output_to_digest(digest: impl AsRef<[u8]>) -> String {
    let mut out = String::with_capacity("sha256:".len() + 64);
    out.push_str("sha256:");
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", *byte);
    }
    out
}

fn qpx_enforceable_effect_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:qpx:schema:enforceable_effect:v1",
        "type": "object",
        "required": ["decision"],
        "additionalProperties": false,
        "properties": {
            "decision": {"enum": ["allow", "deny", "local_response", "challenge"]},
            "policy_id": {"type": "string"},
            "override_upstream": {"type": "string"},
            "inject_headers": {"type": "object"},
            "local_response": {"type": "object"},
            "timeout_override_ms": {"type": "integer", "minimum": 1},
            "cache_bypass": {"type": "boolean"},
            "mirror_upstreams": {"type": "array", "items": {"type": "string"}},
            "rate_limit_profile": {"type": "string"},
            "force_inspect": {"type": "boolean"},
            "force_tunnel": {"type": "boolean"},
            "policy_tags": {"type": "array", "items": {"type": "string"}}
        }
    })
}

fn compile_mtls(
    config: &DecisionServiceConfig,
    trust_profiles: &HashMap<String, UpstreamTlsTrustConfig>,
) -> Result<Option<Arc<CompiledUpstreamTlsTrust>>> {
    let Some(mtls) = config.auth.mtls.as_ref() else {
        return Ok(None);
    };
    let profile_name = mtls
        .upstream_trust_profile
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "decision_service {} auth.mtls.upstream_trust_profile is required",
                config.name
            )
        })?;
    let trust = trust_profiles.get(profile_name).ok_or_else(|| {
        anyhow!(
            "decision_service {} auth.mtls references unknown upstream_trust_profile: {}",
            config.name,
            profile_name
        )
    })?;
    if trust
        .client_cert
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
        || trust
            .client_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(anyhow!(
            "decision_service {} auth.mtls upstream_trust_profile must configure client_cert and client_key",
            config.name
        ));
    }
    CompiledUpstreamTlsTrust::from_config(Some(trust)).with_context(|| {
        format!(
            "decision_service {} failed to compile auth.mtls upstream_trust_profile {}",
            config.name, profile_name
        )
    })
}

fn is_empty_json_value(value: &Value) -> bool {
    value.is_null() || value.as_object().is_some_and(Map::is_empty)
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

pub(crate) fn prepare_decision_service_allow(
    mut allow: DecisionServiceAllow,
    mode: DecisionServiceMode,
    base_headers: Option<Arc<CompiledHeaderControl>>,
) -> Result<DecisionServiceAllow> {
    validate_decision_service_allow_mode(&allow, mode)?;
    allow.headers = merge_header_controls(base_headers, allow.headers);
    Ok(allow)
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
mod tests;
