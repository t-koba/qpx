use super::RuntimeResources;
use crate::http::guard::{compile_http_guard_profile, CompiledHttpGuardProfile};
use crate::http::modules::{compile_http_modules, CompiledHttpModuleChain};
use crate::http::response_policy::HttpResponseRuleEngine;
use crate::policy_context::EffectivePolicyContext;
use crate::rate_limit::{CompiledRateLimitPlan, RateLimitSet};
use crate::tls::trust::CompiledUpstreamTlsTrust;
use anyhow::{anyhow, Result};
use qpx_core::config::{
    ActionKind, CaptureRedactionConfig, DestinationResolutionOverrideConfig, FtpConfig,
    IngressEdgeConfig, IngressEdgeMode, ReverseRouteConfig, SubrequestPhase,
};
use qpx_core::matchers::CompiledMatch;
use qpx_core::prefilter::StringInterner;
use qpx_core::rules::RuleMatchContext;
use std::sync::Arc;

#[derive(Clone)]
pub struct RuntimePlan {
    pub edges: Arc<[CompiledEdge]>,
    pub identity: CompiledRuntimeIdentity,
    pub limits: CompiledRuntimeLimits,
}

#[derive(Clone)]
pub struct CompiledRuntimeIdentity {
    pub proxy_name: Arc<str>,
}

#[derive(Clone, Copy)]
pub struct CompiledRuntimeLimits {
    pub reuse_port: bool,
    pub trace_enabled: bool,
    pub trace_reflect_all_headers: bool,
    pub max_observed_request_body_bytes: usize,
    pub max_observed_response_body_bytes: usize,
    pub max_h3_request_body_bytes: usize,
    pub max_h3_response_body_bytes: usize,
    pub max_h3_streams_per_connection: usize,
    pub max_concurrent_connections: usize,
    pub upstream_proxy_max_concurrent_per_endpoint: usize,
    pub max_reverse_retry_template_body_bytes: usize,
    pub upstream_http_timeout_ms: u64,
    pub tls_peek_timeout_ms: u64,
    pub http_header_read_timeout_ms: u64,
    pub upgrade_wait_timeout_ms: u64,
    pub tunnel_idle_timeout_ms: u64,
    pub h3_read_timeout_ms: u64,
}

impl RuntimePlan {
    pub fn forward_edge(&self, name: &str) -> Option<&CompiledForwardEdge> {
        self.edges.iter().find_map(|edge| match edge {
            CompiledEdge::Forward(edge) if edge.name.as_ref() == name => Some(edge),
            _ => None,
        })
    }

    pub fn transparent_edge(&self, name: &str) -> Option<&CompiledTransparentEdge> {
        self.edges.iter().find_map(|edge| match edge {
            CompiledEdge::Transparent(edge) if edge.name.as_ref() == name => Some(edge),
            _ => None,
        })
    }

    pub fn reverse_edge(&self, name: &str) -> Option<&CompiledReverseEdge> {
        self.edges.iter().find_map(|edge| match edge {
            CompiledEdge::Reverse(edge) if edge.name.as_ref() == name => Some(edge),
            _ => None,
        })
    }

    pub fn ingress_edge_execution_plan(
        &self,
        name: &str,
        matched_rule: Option<&str>,
    ) -> Option<&ExecutionPlan> {
        if let Some(edge) = self.forward_edge(name) {
            return Some(edge.execution_plan_for_rule(matched_rule));
        }
        self.transparent_edge(name)
            .map(|edge| edge.execution_plan_for_rule(matched_rule))
    }

    pub fn mitm_plan(
        &self,
        name: &str,
        matched_rule: Option<&str>,
    ) -> Option<CompiledMitmPlan<'_>> {
        self.ingress_edge_execution_plan(name, matched_rule)
            .map(|http| CompiledMitmPlan { http })
    }
}

#[derive(Clone, Copy)]
pub struct CompiledMitmPlan<'a> {
    pub http: &'a ExecutionPlan,
}

#[derive(Clone)]
pub enum CompiledEdge {
    Forward(CompiledForwardEdge),
    Reverse(CompiledReverseEdge),
    Transparent(CompiledTransparentEdge),
}

#[derive(Clone)]
pub struct CompiledForwardEdge {
    pub name: Arc<str>,
    pub listener: CompiledListenerSettings,
    pub flags: PlanFlags,
    pub default_plan: ExecutionPlan,
    pub rules: Arc<[CompiledForwardRule]>,
}

#[derive(Clone)]
pub struct CompiledTransparentEdge {
    pub name: Arc<str>,
    pub listener: CompiledListenerSettings,
    pub flags: PlanFlags,
    pub default_plan: ExecutionPlan,
    pub rules: Arc<[CompiledTransparentRule]>,
}

#[derive(Clone)]
pub struct CompiledListenerSettings {
    pub upstream_proxy: Option<Arc<str>>,
    pub ftp: FtpConfig,
    pub tls_inspection: Option<CompiledTlsInspectionSettings>,
    pub requires_upstream_cert_preview: bool,
}

#[derive(Clone)]
pub struct CompiledTlsInspectionSettings {
    pub enabled: bool,
    pub verify_upstream: bool,
    pub(crate) upstream_trust: Option<Arc<CompiledUpstreamTlsTrust>>,
}

#[derive(Clone)]
pub struct CompiledReverseEdge {
    pub name: Arc<str>,
    pub flags: PlanFlags,
    pub routes: Arc<[CompiledReverseRoute]>,
}

#[derive(Clone)]
pub struct CompiledForwardRule {
    pub name: Arc<str>,
    pub matcher: CompiledMatch,
    pub plan: ExecutionPlan,
}

#[derive(Clone)]
pub struct CompiledTransparentRule {
    pub name: Arc<str>,
    pub matcher: CompiledMatch,
    pub plan: ExecutionPlan,
}

#[derive(Clone)]
pub struct CompiledReverseRoute {
    pub name: Arc<str>,
    pub matcher: CompiledMatch,
    pub plan: ExecutionPlan,
}

impl CompiledForwardRule {
    pub fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }
}

impl CompiledForwardEdge {
    pub fn execution_plan_for_rule(&self, matched_rule: Option<&str>) -> &ExecutionPlan {
        matched_rule
            .and_then(|name| self.rules.iter().find(|rule| rule.name.as_ref() == name))
            .map(|rule| &rule.plan)
            .unwrap_or(&self.default_plan)
    }

    pub(crate) fn body_observation_limit(&self, default_limit: usize) -> usize {
        self.rules.iter().fold(
            self.default_plan.body_observation_limit(default_limit),
            |limit, rule| rule.plan.body_observation_limit(limit),
        )
    }
}

impl CompiledTransparentRule {
    pub fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }
}

impl CompiledTransparentEdge {
    pub fn execution_plan_for_rule(&self, matched_rule: Option<&str>) -> &ExecutionPlan {
        matched_rule
            .and_then(|name| self.rules.iter().find(|rule| rule.name.as_ref() == name))
            .map(|rule| &rule.plan)
            .unwrap_or(&self.default_plan)
    }

    pub(crate) fn body_observation_limit(&self, default_limit: usize) -> usize {
        self.rules.iter().fold(
            self.default_plan.body_observation_limit(default_limit),
            |limit, rule| rule.plan.body_observation_limit(limit),
        )
    }
}

impl CompiledReverseRoute {
    pub fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PlanFlags(u64);

impl PlanFlags {
    pub const AUTH: Self = Self(1 << 0);
    pub const IDENTITY_SOURCES: Self = Self(1 << 1);
    pub const EXT_AUTHZ: Self = Self(1 << 2);
    pub const DESTINATION_INTEL: Self = Self(1 << 3);
    pub const HTTP_GUARD: Self = Self(1 << 4);
    pub const CACHE_LOOKUP: Self = Self(1 << 5);
    pub const CACHE_STORE: Self = Self(1 << 6);
    pub const REQUEST_MODULES: Self = Self(1 << 7);
    pub const RESPONSE_MODULES: Self = Self(1 << 8);
    pub const RESPONSE_RULES: Self = Self(1 << 9);
    pub const CAPTURE_ENCRYPTED: Self = Self(1 << 10);
    pub const CAPTURE_PLAINTEXT: Self = Self(1 << 11);
    pub const REQUEST_BODY_OBSERVE: Self = Self(1 << 12);
    pub const RESPONSE_BODY_OBSERVE: Self = Self(1 << 13);
    pub const RETRY_BODY_BUFFER: Self = Self(1 << 14);
    pub const MIRRORING: Self = Self(1 << 15);
    pub const WEBSOCKET: Self = Self(1 << 16);
    pub const IPC: Self = Self(1 << 17);
    pub const CAPTURE_BODY: Self = Self(1 << 18);

    pub fn empty() -> Self {
        Self(0)
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub fn bits(self) -> u64 {
        self.0
    }
}

#[derive(Clone)]
pub struct ExecutionPlan {
    pub flags: PlanFlags,
    pub capture: CompiledCapturePlan,
    pub(crate) modules: Arc<CompiledHttpModuleChain>,
    pub(crate) cache: Option<qpx_core::config::CachePolicyConfig>,
    pub(crate) response_rules: Option<Arc<HttpResponseRuleEngine>>,
    pub(crate) guard: Option<Arc<CompiledHttpGuardProfile>>,
    pub(crate) destination_resolution: Option<DestinationResolutionOverrideConfig>,
    pub(crate) policy_context: EffectivePolicyContext,
    pub(crate) rate_limits: CompiledRateLimitPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CompiledCapturePlan {
    pub encrypted: bool,
    pub plaintext: Option<CompiledPlaintextCapturePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPlaintextCapturePlan {
    pub headers: bool,
    pub body: bool,
    pub sample_percent: Option<u32>,
    pub max_body_bytes: Option<usize>,
    pub redact: CaptureRedactionConfig,
}

impl ExecutionPlan {
    fn empty() -> Self {
        Self {
            flags: PlanFlags::empty(),
            capture: CompiledCapturePlan::default(),
            modules: Arc::new(CompiledHttpModuleChain::default()),
            cache: None,
            response_rules: None,
            guard: None,
            destination_resolution: None,
            policy_context: EffectivePolicyContext::default(),
            rate_limits: CompiledRateLimitPlan::default(),
        }
    }

    pub(crate) fn capture_body_max_bytes(&self) -> Option<usize> {
        self.capture
            .plaintext
            .as_ref()
            .filter(|plaintext| plaintext.body)
            .and_then(|plaintext| plaintext.max_body_bytes)
    }

    pub(crate) fn body_observation_limit(&self, default_limit: usize) -> usize {
        self.capture_body_max_bytes()
            .map(|limit| limit.min(default_limit))
            .unwrap_or(default_limit)
    }
}

pub struct PlanCompiler<'a> {
    pub config: &'a RuntimeResources,
}

impl<'a> PlanCompiler<'a> {
    pub fn compile(&self) -> Result<RuntimePlan> {
        let mut edges = Vec::new();
        let mut interner = StringInterner::default();
        for listener in self.config.operational.ingress_edge_configs() {
            let ingress_edge_settings = compile_ingress_edge_settings(listener)?;
            let default_plan = execution_plan_for_forward_action(
                self.config,
                EffectivePolicyContext::from_single(listener.policy_context.as_ref()),
                listener.destination_resolution.as_ref(),
                listener.http_guard_profile.as_deref(),
                listener.cache.as_ref(),
                listener.capture.as_ref(),
                listener.rate_limit.as_ref(),
                listener.http.as_ref(),
                listener.http_modules.as_slice(),
                Some(&listener.default_action.kind),
            )?;
            let listener_rate_limits = RateLimitSet::from_config(listener.rate_limit.as_ref());
            let mut default_plan = default_plan;
            default_plan.rate_limits = CompiledRateLimitPlan::from_sets(
                listener_rate_limits.clone(),
                RateLimitSet::default(),
            );
            let rules = listener
                .rules
                .iter()
                .map(|rule| {
                    let match_cfg = rule.r#match.clone().unwrap_or_default();
                    let (matcher, _) = CompiledMatch::compile(&match_cfg, &mut interner)?;
                    let mut plan = execution_plan_for_forward_action(
                        self.config,
                        EffectivePolicyContext::from_single(listener.policy_context.as_ref()),
                        listener.destination_resolution.as_ref(),
                        listener.http_guard_profile.as_deref(),
                        listener.cache.as_ref(),
                        listener.capture.as_ref(),
                        rule.rate_limit.as_ref().or(listener.rate_limit.as_ref()),
                        listener.http.as_ref(),
                        listener.http_modules.as_slice(),
                        rule.action.as_ref().map(|a| &a.kind),
                    )?;
                    plan.rate_limits = CompiledRateLimitPlan::from_sets(
                        listener_rate_limits.clone(),
                        RateLimitSet::from_config(rule.rate_limit.as_ref()),
                    );
                    if rule
                        .auth
                        .as_ref()
                        .map(|auth| !auth.require.is_empty())
                        .unwrap_or(false)
                    {
                        plan.flags.insert(PlanFlags::AUTH);
                    }
                    apply_matcher_flags(&matcher, &mut plan);
                    Ok(CompiledForwardRule {
                        name: Arc::from(rule.name.as_str()),
                        matcher,
                        plan,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let flags = rules.iter().fold(default_plan.flags, |flags, rule| {
                flags.union(rule.plan.flags)
            });
            match listener.mode {
                IngressEdgeMode::Forward => {
                    edges.push(CompiledEdge::Forward(CompiledForwardEdge {
                        name: Arc::from(listener.name.as_str()),
                        listener: ingress_edge_settings,
                        flags,
                        default_plan,
                        rules: rules.into_iter().collect::<Vec<_>>().into(),
                    }))
                }
                IngressEdgeMode::Transparent => {
                    edges.push(CompiledEdge::Transparent(CompiledTransparentEdge {
                        name: Arc::from(listener.name.as_str()),
                        listener: ingress_edge_settings,
                        flags,
                        default_plan,
                        rules: rules
                            .into_iter()
                            .map(|rule| CompiledTransparentRule {
                                name: rule.name,
                                matcher: rule.matcher,
                                plan: rule.plan,
                            })
                            .collect::<Vec<_>>()
                            .into(),
                    }))
                }
            }
        }

        for reverse_edges in self.config.operational.reverse_edge_configs() {
            let routes = reverse_edges
                .routes
                .iter()
                .map(|route| {
                    let (matcher, _) = CompiledMatch::compile(&route.r#match, &mut interner)?;
                    let mut plan =
                        execution_plan_for_reverse_route(self.config, reverse_edges, route)?;
                    apply_matcher_flags(&matcher, &mut plan);
                    Ok(CompiledReverseRoute {
                        name: Arc::from(route.name.as_deref().unwrap_or("<unnamed>")),
                        matcher,
                        plan,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let flags = routes.iter().fold(PlanFlags::empty(), |flags, route| {
                flags.union(route.plan.flags)
            });
            edges.push(CompiledEdge::Reverse(CompiledReverseEdge {
                name: Arc::from(reverse_edges.name.as_str()),
                flags,
                routes: routes.into(),
            }));
        }

        Ok(RuntimePlan {
            edges: edges.into(),
            identity: CompiledRuntimeIdentity {
                proxy_name: Arc::from(self.config.operational.identity.proxy_name.as_str()),
            },
            limits: CompiledRuntimeLimits {
                reuse_port: self.config.operational.runtime.reuse_port,
                trace_enabled: self.config.operational.runtime.trace_enabled,
                trace_reflect_all_headers: self
                    .config
                    .operational
                    .runtime
                    .trace_reflect_all_headers,
                max_observed_request_body_bytes: self
                    .config
                    .operational
                    .runtime
                    .max_observed_request_body_bytes,
                max_observed_response_body_bytes: self
                    .config
                    .operational
                    .runtime
                    .max_observed_response_body_bytes,
                max_h3_request_body_bytes: self
                    .config
                    .operational
                    .runtime
                    .max_h3_request_body_bytes,
                max_h3_response_body_bytes: self
                    .config
                    .operational
                    .runtime
                    .max_h3_response_body_bytes,
                max_h3_streams_per_connection: self
                    .config
                    .operational
                    .runtime
                    .max_h3_streams_per_connection,
                max_concurrent_connections: self
                    .config
                    .operational
                    .runtime
                    .max_concurrent_connections,
                upstream_proxy_max_concurrent_per_endpoint: self
                    .config
                    .operational
                    .runtime
                    .upstream_proxy_max_concurrent_per_endpoint,
                max_reverse_retry_template_body_bytes: self
                    .config
                    .operational
                    .runtime
                    .max_reverse_retry_template_body_bytes,
                upstream_http_timeout_ms: self.config.operational.runtime.upstream_http_timeout_ms,
                tls_peek_timeout_ms: self.config.operational.runtime.tls_peek_timeout_ms,
                http_header_read_timeout_ms: self
                    .config
                    .operational
                    .runtime
                    .http_header_read_timeout_ms,
                upgrade_wait_timeout_ms: self.config.operational.runtime.upgrade_wait_timeout_ms,
                tunnel_idle_timeout_ms: self.config.operational.runtime.tunnel_idle_timeout_ms,
                h3_read_timeout_ms: self.config.operational.runtime.h3_read_timeout_ms,
            },
        })
    }
}

fn apply_matcher_flags(matcher: &CompiledMatch, plan: &mut ExecutionPlan) {
    if matcher.requires_request_body_observation() || matcher.requires_request_rpc_context() {
        plan.flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
    }
    if matcher.requires_response_body_observation() || matcher.requires_response_rpc_observation() {
        plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
    }
}

fn execution_plan_for_reverse_route(
    config: &RuntimeResources,
    reverse_edges: &qpx_core::config::ReverseEdgeConfig,
    route: &ReverseRouteConfig,
) -> Result<ExecutionPlan> {
    let mut plan = execution_plan_for_common(
        config,
        EffectivePolicyContext::merged(
            reverse_edges.policy_context.as_ref(),
            route.policy_context.as_ref(),
        ),
        merge_destination_resolution_override(
            reverse_edges.destination_resolution.as_ref(),
            route.destination_resolution.as_ref(),
        )
        .as_ref(),
        route.http_guard_profile.as_deref(),
        route.cache.as_ref(),
        route.capture.as_ref(),
        route.rate_limit.as_ref(),
        route.http.as_ref(),
        route.http_modules.as_slice(),
    )?;
    plan.rate_limits = CompiledRateLimitPlan::from_sets(
        RateLimitSet::default(),
        RateLimitSet::from_config(route.rate_limit.as_ref()),
    );
    if route.ipc.is_some() {
        plan.flags.insert(PlanFlags::IPC);
    }
    if !route.mirrors.is_empty() {
        plan.flags.insert(PlanFlags::MIRRORING);
    }
    if route
        .resilience
        .as_ref()
        .and_then(|r| r.retry.as_ref())
        .is_some()
    {
        plan.flags.insert(PlanFlags::RETRY_BODY_BUFFER);
    }
    Ok(plan)
}

fn execution_plan_for_forward_action(
    config: &RuntimeResources,
    policy_context: EffectivePolicyContext,
    destination_resolution: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
    http_guard_profile: Option<&str>,
    cache: Option<&qpx_core::config::CachePolicyConfig>,
    capture: Option<&qpx_core::config::CapturePolicyConfig>,
    rate_limit: Option<&qpx_core::config::RateLimitConfig>,
    http: Option<&qpx_core::config::HttpPolicyConfig>,
    http_modules: &[qpx_core::config::HttpModuleConfig],
    action_kind: Option<&ActionKind>,
) -> Result<ExecutionPlan> {
    let mut plan = execution_plan_for_common(
        config,
        policy_context,
        destination_resolution,
        http_guard_profile,
        cache,
        capture,
        rate_limit,
        http,
        http_modules,
    )?;
    if matches!(action_kind, Some(ActionKind::Tunnel)) {
        plan.flags.insert(PlanFlags::WEBSOCKET);
    }
    Ok(plan)
}

fn compile_ingress_edge_settings(listener: &IngressEdgeConfig) -> Result<CompiledListenerSettings> {
    let upstream_trust = CompiledUpstreamTlsTrust::from_config(
        listener
            .tls_inspection
            .as_ref()
            .and_then(|cfg| cfg.upstream_trust.as_ref()),
    )?;
    let requires_upstream_cert_preview = listener.rules.iter().any(|rule| {
        rule.r#match
            .as_ref()
            .and_then(|m| m.upstream_cert.as_ref())
            .is_some()
    }) || upstream_trust.is_some();
    Ok(CompiledListenerSettings {
        upstream_proxy: listener.upstream_proxy.as_deref().map(Arc::from),
        ftp: listener.ftp.clone(),
        tls_inspection: listener
            .tls_inspection
            .as_ref()
            .map(|cfg| CompiledTlsInspectionSettings {
                enabled: cfg.enabled,
                verify_upstream: cfg.verify_upstream,
                upstream_trust: upstream_trust.clone(),
            }),
        requires_upstream_cert_preview,
    })
}

fn execution_plan_for_common(
    config: &RuntimeResources,
    policy_context: EffectivePolicyContext,
    destination_resolution: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
    http_guard_profile: Option<&str>,
    cache: Option<&qpx_core::config::CachePolicyConfig>,
    capture: Option<&qpx_core::config::CapturePolicyConfig>,
    rate_limit: Option<&qpx_core::config::RateLimitConfig>,
    http: Option<&qpx_core::config::HttpPolicyConfig>,
    http_modules: &[qpx_core::config::HttpModuleConfig],
) -> Result<ExecutionPlan> {
    let mut plan = ExecutionPlan::empty();
    plan.modules = compile_http_modules(http_modules, config.http_module_registry().as_ref())?;
    plan.cache = cache.filter(|cache| cache.enabled).cloned();
    plan.destination_resolution = destination_resolution.cloned();
    plan.policy_context = policy_context;
    if let Some(exporter) = config
        .operational
        .telemetry
        .exporter
        .as_ref()
        .filter(|exporter| exporter.enabled)
    {
        if exporter.capture.encrypted {
            plan.flags.insert(PlanFlags::CAPTURE_ENCRYPTED);
            plan.capture.encrypted = true;
        }
        if exporter.capture.plaintext {
            plan.flags.insert(PlanFlags::CAPTURE_PLAINTEXT);
            plan.flags.insert(PlanFlags::CAPTURE_BODY);
            plan.flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
            plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
            plan.capture.plaintext = Some(CompiledPlaintextCapturePlan {
                headers: true,
                body: true,
                sample_percent: None,
                max_body_bytes: None,
                redact: exporter.capture.redact.clone(),
            });
        }
    }
    if !plan.policy_context.identity_sources.is_empty() {
        plan.flags.insert(PlanFlags::IDENTITY_SOURCES);
    }
    if plan.policy_context.ext_authz.is_some() {
        plan.flags.insert(PlanFlags::EXT_AUTHZ);
    }
    if plan.destination_resolution.is_some() {
        plan.flags.insert(PlanFlags::DESTINATION_INTEL);
    }
    plan.guard = http_guard_profile
        .map(|name| {
            config
                .operational
                .http
                .guard_profiles
                .iter()
                .find(|profile| profile.name == name)
                .map(compile_http_guard_profile)
                .ok_or_else(|| anyhow!("http_guard_profile not found: {name}"))
        })
        .transpose()?;
    if plan.guard.is_some() {
        plan.flags.insert(PlanFlags::HTTP_GUARD);
    }
    if plan.cache.is_some() {
        plan.flags.insert(PlanFlags::CACHE_LOOKUP);
        plan.flags.insert(PlanFlags::CACHE_STORE);
    }
    if let Some(capture) = capture {
        if capture.encrypted {
            plan.flags.insert(PlanFlags::CAPTURE_ENCRYPTED);
            plan.capture.encrypted = true;
        }
        if capture.plaintext.enabled {
            plan.flags.insert(PlanFlags::CAPTURE_PLAINTEXT);
            plan.capture.plaintext = Some(CompiledPlaintextCapturePlan {
                headers: capture.plaintext.headers,
                body: capture.plaintext.body,
                sample_percent: capture.plaintext.sample_percent,
                max_body_bytes: capture.plaintext.max_body_bytes,
                redact: capture.plaintext.redact.clone(),
            });
            if capture.plaintext.body {
                plan.flags.insert(PlanFlags::CAPTURE_BODY);
                plan.flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
                plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
            }
        }
    }
    if rate_limit.as_ref().map(|r| r.enabled).unwrap_or(false) {
        plan.flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
    }
    plan.response_rules = http
        .as_ref()
        .and_then(|http| HttpResponseRuleEngine::new(http.response_rules.as_slice()).transpose())
        .transpose()?
        .map(Arc::new);
    if plan.response_rules.is_some() {
        plan.flags.insert(PlanFlags::RESPONSE_RULES);
        plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
    }
    compile_module_flags(config, http_modules, &mut plan)?;
    Ok(plan)
}

fn merge_destination_resolution_override(
    base: Option<&DestinationResolutionOverrideConfig>,
    route: Option<&DestinationResolutionOverrideConfig>,
) -> Option<DestinationResolutionOverrideConfig> {
    match (base, route) {
        (None, None) => None,
        (Some(base), None) => Some(base.clone()),
        (None, Some(route)) => Some(route.clone()),
        (Some(base), Some(route)) => Some(DestinationResolutionOverrideConfig {
            precedence: route.precedence.clone().or_else(|| base.precedence.clone()),
            conflict_mode: route.conflict_mode.or(base.conflict_mode),
            merge_mode: route.merge_mode.or(base.merge_mode),
            min_confidence: match (&base.min_confidence, &route.min_confidence) {
                (None, None) => None,
                (Some(base), None) => Some(base.clone()),
                (None, Some(route)) => Some(route.clone()),
                (Some(base), Some(route)) => {
                    Some(qpx_core::config::DestinationMinConfidenceConfig {
                        category: route.category.or(base.category),
                        reputation: route.reputation.or(base.reputation),
                        application: route.application.or(base.application),
                    })
                }
            },
        }),
    }
}

fn compile_module_flags(
    config: &RuntimeResources,
    modules: &[qpx_core::config::HttpModuleConfig],
    plan: &mut ExecutionPlan,
) -> Result<()> {
    for module in modules {
        if config
            .http_module_registry()
            .get(module.r#type.as_str())
            .is_none()
        {
            return Err(anyhow!("unknown http module type: {}", module.r#type));
        }
        match module.r#type.as_str() {
            "response_compression" => {
                plan.flags.insert(PlanFlags::RESPONSE_MODULES);
                plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
            }
            "subrequest" => {
                let settings: qpx_core::config::SubrequestModuleConfig = module.parse_settings()?;
                match settings.phase {
                    SubrequestPhase::RequestHeaders => {
                        plan.flags.insert(PlanFlags::REQUEST_MODULES);
                    }
                    SubrequestPhase::ResponseHeaders => {
                        plan.flags.insert(PlanFlags::RESPONSE_MODULES);
                        plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
                    }
                }
            }
            "cache_purge" => plan.flags.insert(PlanFlags::REQUEST_MODULES),
            _ => {
                plan.flags.insert(PlanFlags::REQUEST_MODULES);
                plan.flags.insert(PlanFlags::RESPONSE_MODULES);
            }
        }
    }
    Ok(())
}
