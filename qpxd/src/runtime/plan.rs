use super::RuntimeResources;
use crate::http::guard::{CompiledHttpGuardProfile, compile_http_guard_profile};
use crate::http::modules::{CompiledHttpModuleChain, compile_http_modules};
use crate::http::response_policy::HttpResponseRuleEngine;
use crate::policy_context::EffectivePolicyContext;
use crate::rate_limit::{CompiledRateLimitPlan, RateLimitSet};
use crate::tls::trust::CompiledUpstreamTlsTrust;
use anyhow::{Result, anyhow};
use qpx_core::config::{
    ActionConfig, ActionKind, CaptureRedactionConfig, DestinationResolutionOverrideConfig,
    FtpConfig, IngressEdgeConfig, IngressEdgeMode, LocalResponseConfig, ReverseRouteConfig,
    ReverseRouteTargetConfig,
};
use qpx_core::matchers::CompiledMatch;
use qpx_core::prefilter::{MatchPrefilterHint, StringInterner};
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
    pub datagram_channel_capacity: usize,
    pub webtransport_datagram_channel_capacity: usize,
    pub webtransport_stream_channel_capacity: usize,
    pub max_grpc_message_bytes: u64,
    pub max_grpc_stream_duration_ms: u64,
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
    pub default_action_kind: ActionKind,
    pub default_plan: ExecutionPlan,
    pub rules: Arc<[CompiledForwardRule]>,
}

#[derive(Clone)]
pub struct CompiledTransparentEdge {
    pub name: Arc<str>,
    pub listener: CompiledListenerSettings,
    pub flags: PlanFlags,
    pub default_action_kind: ActionKind,
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
    pub tls_passthrough_routes: Arc<[CompiledTlsPassthroughRoute]>,
}

#[derive(Clone)]
pub struct CompiledForwardRule {
    pub name: Arc<str>,
    pub matcher: CompiledMatch,
    pub action_kind: ActionKind,
    pub plan: ExecutionPlan,
}

#[derive(Clone)]
pub struct CompiledTransparentRule {
    pub name: Arc<str>,
    pub matcher: CompiledMatch,
    pub action_kind: ActionKind,
    pub plan: ExecutionPlan,
}

#[derive(Clone)]
pub struct CompiledReverseRoute {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub matcher: CompiledMatch,
    pub(crate) hint: MatchPrefilterHint,
    pub target: CompiledReverseRouteTarget,
    pub plan: ExecutionPlan,
}

#[derive(Clone)]
pub enum CompiledReverseRouteTarget {
    Upstream {
        upstreams: Arc<[Arc<str>]>,
        lb: Arc<str>,
    },
    Weighted {
        backends: Arc<[CompiledRouteBackend]>,
        lb: Arc<str>,
    },
    Ipc {
        mode: Arc<str>,
        address: Arc<str>,
    },
    LocalResponse {
        status: u16,
    },
    TlsPassthrough {
        upstreams: Arc<[Arc<str>]>,
        lb: Arc<str>,
    },
}

impl CompiledReverseRouteTarget {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Upstream { .. } => "upstream",
            Self::Weighted { .. } => "weighted",
            Self::Ipc { .. } => "ipc",
            Self::LocalResponse { .. } => "local_response",
            Self::TlsPassthrough { .. } => "tls_passthrough",
        }
    }
}

#[derive(Clone)]
pub struct CompiledRouteBackend {
    pub name: Option<Arc<str>>,
    pub weight: u32,
    pub upstreams: Arc<[Arc<str>]>,
}

#[derive(Clone)]
pub struct CompiledTlsPassthroughRoute {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub matcher: CompiledMatch,
    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(crate) hint: MatchPrefilterHint,
    pub target: CompiledReverseRouteTarget,
}

impl CompiledTlsPassthroughRoute {
    pub fn matches(&self, ctx: &RuleMatchContext<'_>) -> bool {
        self.matcher.matches(ctx)
    }
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

fn compile_reverse_route_target(target: &ReverseRouteTargetConfig) -> CompiledReverseRouteTarget {
    match target {
        ReverseRouteTargetConfig::Upstream { upstreams, lb } => {
            CompiledReverseRouteTarget::Upstream {
                upstreams: upstreams
                    .iter()
                    .map(|upstream| Arc::<str>::from(upstream.as_str()))
                    .collect::<Vec<_>>()
                    .into(),
                lb: Arc::from(lb.as_str()),
            }
        }
        ReverseRouteTargetConfig::Weighted { backends, lb } => {
            CompiledReverseRouteTarget::Weighted {
                backends: backends
                    .iter()
                    .map(|backend| CompiledRouteBackend {
                        name: backend.name.as_deref().map(Arc::<str>::from),
                        weight: backend.weight,
                        upstreams: backend
                            .upstreams
                            .iter()
                            .map(|upstream| Arc::<str>::from(upstream.as_str()))
                            .collect::<Vec<_>>()
                            .into(),
                    })
                    .collect::<Vec<_>>()
                    .into(),
                lb: Arc::from(lb.as_str()),
            }
        }
        ReverseRouteTargetConfig::Ipc { config } => CompiledReverseRouteTarget::Ipc {
            mode: Arc::from(match config.mode {
                qpx_core::config::IpcMode::Shm => "shm",
                qpx_core::config::IpcMode::Tcp => "tcp",
            }),
            address: Arc::from(config.address.as_str()),
        },
        ReverseRouteTargetConfig::LocalResponse { response } => {
            CompiledReverseRouteTarget::LocalResponse {
                status: response.status,
            }
        }
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
    pub const FROZEN_REQUEST: Self = Self(1 << 19);

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
    pub local_response: Option<CompiledLocalResponsePlan>,
    pub(crate) modules: Arc<CompiledHttpModuleChain>,
    pub(crate) cache: Option<qpx_core::config::CachePolicyConfig>,
    pub(crate) response_rules: Option<Arc<HttpResponseRuleEngine>>,
    pub(crate) guard: Option<Arc<CompiledHttpGuardProfile>>,
    pub(crate) destination_resolution: Option<DestinationResolutionOverrideConfig>,
    pub(crate) policy_context: EffectivePolicyContext,
    pub(crate) rate_limits: CompiledRateLimitPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledLocalResponsePlan {
    pub status: u16,
    pub content_type: Option<Arc<str>>,
    pub header_count: usize,
    pub body_bytes: usize,
    pub rpc_protocol: Option<Arc<str>>,
    pub rpc_status: Option<Arc<str>>,
    pub rpc_http_status: Option<u16>,
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
            local_response: None,
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

struct ExecutionPlanInputs<'a> {
    policy_context: EffectivePolicyContext,
    destination_resolution: Option<&'a qpx_core::config::DestinationResolutionOverrideConfig>,
    http_guard_profile: Option<&'a str>,
    cache: Option<&'a qpx_core::config::CachePolicyConfig>,
    capture: Option<&'a qpx_core::config::CapturePolicyConfig>,
    rate_limit: Option<&'a qpx_core::config::RateLimitConfig>,
    http: Option<&'a qpx_core::config::HttpPolicyConfig>,
    http_modules: &'a [qpx_core::config::HttpModuleConfig],
}

impl<'a> PlanCompiler<'a> {
    pub fn compile(&self) -> Result<RuntimePlan> {
        let mut edges = Vec::new();
        let mut interner = StringInterner::default();
        for listener in self.config.operational.ingress_edge_configs() {
            let ingress_edge_settings = compile_ingress_edge_settings(listener)?;
            let default_action_kind = listener.default_action.kind.clone();
            let default_plan = execution_plan_for_forward_action(
                self.config,
                ExecutionPlanInputs {
                    policy_context: EffectivePolicyContext::from_single(
                        listener.policy_context.as_ref(),
                    ),
                    destination_resolution: listener.destination_resolution.as_ref(),
                    http_guard_profile: listener.http_guard_profile.as_deref(),
                    cache: listener.cache.as_ref(),
                    capture: listener.capture.as_ref(),
                    rate_limit: listener.rate_limit.as_ref(),
                    http: listener.http.as_ref(),
                    http_modules: listener.http_modules.as_slice(),
                },
                Some(&listener.default_action),
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
                    let action = rule.action.as_ref().unwrap_or(&listener.default_action);
                    let action_kind = action.kind.clone();
                    let mut plan = execution_plan_for_forward_action(
                        self.config,
                        ExecutionPlanInputs {
                            policy_context: EffectivePolicyContext::from_single(
                                listener.policy_context.as_ref(),
                            ),
                            destination_resolution: listener.destination_resolution.as_ref(),
                            http_guard_profile: listener.http_guard_profile.as_deref(),
                            cache: listener.cache.as_ref(),
                            capture: listener.capture.as_ref(),
                            rate_limit: rule.rate_limit.as_ref().or(listener.rate_limit.as_ref()),
                            http: listener.http.as_ref(),
                            http_modules: listener.http_modules.as_slice(),
                        },
                        Some(action),
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
                        action_kind,
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
                        default_action_kind,
                        default_plan,
                        rules: rules.into_iter().collect::<Vec<_>>().into(),
                    }))
                }
                IngressEdgeMode::Transparent => {
                    edges.push(CompiledEdge::Transparent(CompiledTransparentEdge {
                        name: Arc::from(listener.name.as_str()),
                        listener: ingress_edge_settings,
                        flags,
                        default_action_kind,
                        default_plan,
                        rules: rules
                            .into_iter()
                            .map(|rule| CompiledTransparentRule {
                                name: rule.name,
                                matcher: rule.matcher,
                                action_kind: rule.action_kind,
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
                .enumerate()
                .map(|(idx, route)| {
                    let (matcher, hint) = CompiledMatch::compile(&route.r#match, &mut interner)?;
                    let mut plan =
                        execution_plan_for_reverse_route(self.config, reverse_edges, route)?;
                    apply_matcher_flags(&matcher, &mut plan);
                    let id = Arc::<str>::from(route_id(idx, route.name.as_deref()));
                    Ok(CompiledReverseRoute {
                        id: id.clone(),
                        name: id,
                        matcher,
                        hint,
                        target: compile_reverse_route_target(&route.target),
                        plan,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let tls_passthrough_routes = reverse_edges
                .tls_passthrough_routes
                .iter()
                .enumerate()
                .map(|(idx, route)| {
                    let (matcher, tls_passthrough_hint) =
                        CompiledMatch::compile_tls_passthrough(&route.r#match, &mut interner)?;
                    #[cfg(not(any(feature = "tls-rustls", feature = "tls-native")))]
                    let _ = tls_passthrough_hint;
                    Ok(CompiledTlsPassthroughRoute {
                        id: Arc::from(format!("tls_passthrough[{idx}]")),
                        name: Arc::from(format!("tls_passthrough[{idx}]")),
                        matcher,
                        #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
                        hint: tls_passthrough_hint,
                        target: CompiledReverseRouteTarget::TlsPassthrough {
                            upstreams: route
                                .upstreams
                                .iter()
                                .map(|upstream| Arc::from(upstream.as_str()))
                                .collect::<Vec<_>>()
                                .into(),
                            lb: Arc::from(route.lb.as_str()),
                        },
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
                tls_passthrough_routes: tls_passthrough_routes.into(),
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
                datagram_channel_capacity: self
                    .config
                    .operational
                    .runtime
                    .datagram_channel_capacity,
                webtransport_datagram_channel_capacity: self
                    .config
                    .operational
                    .runtime
                    .webtransport_datagram_channel_capacity,
                webtransport_stream_channel_capacity: self
                    .config
                    .operational
                    .runtime
                    .webtransport_stream_channel_capacity,
                max_grpc_message_bytes: self.config.operational.runtime.max_grpc_message_bytes,
                max_grpc_stream_duration_ms: self
                    .config
                    .operational
                    .runtime
                    .max_grpc_stream_duration_ms,
            },
        })
    }
}

fn route_id(idx: usize, name: Option<&str>) -> String {
    name.map(str::to_string)
        .unwrap_or_else(|| format!("route[{idx}]"))
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
        ExecutionPlanInputs {
            policy_context: EffectivePolicyContext::merged(
                reverse_edges.policy_context.as_ref(),
                route.policy_context.as_ref(),
            ),
            destination_resolution: merge_destination_resolution_override(
                reverse_edges.destination_resolution.as_ref(),
                route.destination_resolution.as_ref(),
            )
            .as_ref(),
            http_guard_profile: route.http_guard_profile.as_deref(),
            cache: route.cache.as_ref(),
            capture: route.capture.as_ref(),
            rate_limit: route.rate_limit.as_ref(),
            http: route.http.as_ref(),
            http_modules: route.http_modules.as_slice(),
        },
    )?;
    plan.rate_limits = CompiledRateLimitPlan::from_sets(
        RateLimitSet::default(),
        RateLimitSet::from_config(route.rate_limit.as_ref()),
    );
    if route.target.is_ipc() {
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
    inputs: ExecutionPlanInputs<'_>,
    action: Option<&ActionConfig>,
) -> Result<ExecutionPlan> {
    let mut plan = execution_plan_for_common(config, inputs)?;
    if action
        .map(|action| matches!(&action.kind, ActionKind::Tunnel))
        .unwrap_or(false)
    {
        plan.flags.insert(PlanFlags::WEBSOCKET);
    }
    if let Some(local_response) = action.and_then(|action| action.local_response.as_ref()) {
        plan.local_response = Some(compile_local_response_plan(local_response));
    }
    Ok(plan)
}

fn compile_local_response_plan(local: &LocalResponseConfig) -> CompiledLocalResponsePlan {
    CompiledLocalResponsePlan {
        status: local.status,
        content_type: local.content_type.as_deref().map(Arc::<str>::from),
        header_count: local.headers.len(),
        body_bytes: local.body.len(),
        rpc_protocol: local
            .rpc
            .as_ref()
            .map(|rpc| Arc::<str>::from(rpc.protocol.as_str())),
        rpc_status: local
            .rpc
            .as_ref()
            .and_then(|rpc| rpc.status.as_deref().map(Arc::<str>::from)),
        rpc_http_status: local.rpc.as_ref().and_then(|rpc| rpc.http_status),
    }
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
    inputs: ExecutionPlanInputs<'_>,
) -> Result<ExecutionPlan> {
    let mut plan = ExecutionPlan::empty();
    plan.modules =
        compile_http_modules(inputs.http_modules, config.http_module_registry().as_ref())?;
    plan.cache = inputs.cache.filter(|cache| cache.enabled).cloned();
    plan.destination_resolution = inputs.destination_resolution.cloned();
    plan.policy_context = inputs.policy_context;
    if let Some(exporter) = config
        .operational
        .telemetry
        .exporter
        .as_ref()
        .filter(|exporter| exporter.enabled)
        && exporter.capture.encrypted
    {
        plan.flags.insert(PlanFlags::CAPTURE_ENCRYPTED);
        plan.capture.encrypted = true;
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
    plan.guard = inputs
        .http_guard_profile
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
    if let Some(capture) = inputs.capture {
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
                if plan
                    .capture
                    .plaintext
                    .as_ref()
                    .and_then(|plaintext| plaintext.max_body_bytes)
                    .is_none()
                {
                    return Err(anyhow!(
                        "plaintext body capture requires plaintext.max_body_bytes"
                    ));
                }
                plan.flags.insert(PlanFlags::CAPTURE_BODY);
                plan.flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
                plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
            }
        }
    }
    if inputs
        .rate_limit
        .as_ref()
        .map(|r| r.enabled)
        .unwrap_or(false)
    {
        plan.flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
    }
    plan.response_rules = inputs
        .http
        .as_ref()
        .and_then(|http| HttpResponseRuleEngine::new(http.response_rules.as_slice()).transpose())
        .transpose()?
        .map(Arc::new);
    if plan.response_rules.is_some() {
        plan.flags.insert(PlanFlags::RESPONSE_RULES);
        if plan
            .response_rules
            .as_ref()
            .map(|rules| {
                rules.any_rule_requires_response_body_observation()
                    || rules.any_rule_requires_response_size()
                    || rules.any_rule_requires_response_rpc_observation()
            })
            .unwrap_or(false)
        {
            plan.flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
        }
    }
    apply_module_flags(plan.modules.as_ref(), &mut plan.flags);
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

fn apply_module_flags(
    chain: &crate::http::modules::CompiledHttpModuleChain,
    flags: &mut PlanFlags,
) {
    let aggregate = chain.aggregate();
    if chain.has_request_side_modules() {
        flags.insert(PlanFlags::REQUEST_MODULES);
    }
    if chain.has_response_side_modules() {
        flags.insert(PlanFlags::RESPONSE_MODULES);
    }
    match aggregate.body_access {
        crate::http::modules::BodyAccess::HeadersOnly => {}
        crate::http::modules::BodyAccess::RequestBodyBuffered { .. } => {
            flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
        }
        crate::http::modules::BodyAccess::ResponseBodyBuffered { .. } => {
            flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
        }
        crate::http::modules::BodyAccess::RequestAndResponseBodyBuffered { .. }
        | crate::http::modules::BodyAccess::Streaming => {
            flags.insert(PlanFlags::REQUEST_BODY_OBSERVE);
            flags.insert(PlanFlags::RESPONSE_BODY_OBSERVE);
        }
    }
    if chain.needs_frozen_request() {
        flags.insert(PlanFlags::FROZEN_REQUEST);
    }
}
