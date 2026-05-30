// Extracted from runtime/plan.rs; public surface is re-exported by mod.rs.
use super::compiler::resolve_streaming_limits;
use crate::http::modules::CompiledHttpModuleChain;
use crate::http::policy::guard::CompiledHttpGuardProfile;
use crate::http::policy::response_policy::HttpResponseRuleEngine;
use crate::policy_context::EffectivePolicyContext;
use crate::rate_limit::CompiledRateLimitPlan;
use crate::tls::trust::CompiledUpstreamTlsTrust;
use qpx_core::config::{
    ActionKind, CaptureRedactionConfig, DestinationResolutionOverrideConfig, FtpConfig,
    RuntimeConfig, SseStreamingPolicy,
};
use qpx_core::matchers::CompiledMatch;
use qpx_core::prefilter::MatchPrefilterHint;
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
    pub general: GeneralLimits,
    pub timeouts: TimeoutLimits,
    pub body: BodyLimits,
    pub grpc: GrpcLimits,
    pub h3: H3ChannelLimits,
    pub upstream: UpstreamLimits,
    pub sse: SseStreamingPolicy,
}

#[derive(Clone, Copy)]
pub struct GeneralLimits {
    pub reuse_port: bool,
    pub trace_enabled: bool,
    pub trace_reflect_all_headers: bool,
    pub max_concurrent_connections: usize,
}

#[derive(Clone, Copy)]
pub struct TimeoutLimits {
    pub upstream_http_timeout_ms: u64,
    pub tls_peek_timeout_ms: u64,
    pub http_header_read_timeout_ms: u64,
    pub upgrade_wait_timeout_ms: u64,
    pub tunnel_idle_timeout_ms: u64,
    pub h3_read_timeout_ms: u64,
}

#[derive(Clone, Copy)]
pub struct BodyLimits {
    pub max_observed_request_body_bytes: usize,
    pub max_observed_response_body_bytes: usize,
    pub max_h3_request_body_bytes: usize,
    pub max_h3_response_body_bytes: usize,
    pub body_channel_capacity: usize,
}

#[derive(Clone, Copy)]
pub struct GrpcLimits {
    pub max_grpc_message_bytes: u64,
    pub max_grpc_web_trailer_bytes: u64,
    pub max_grpc_stream_duration_ms: u64,
}

#[derive(Clone, Copy)]
pub struct H3ChannelLimits {
    pub max_h3_streams_per_connection: usize,
    pub datagram_channel_capacity: usize,
    pub webtransport_datagram_channel_capacity: usize,
    pub webtransport_stream_channel_capacity: usize,
}

#[derive(Clone, Copy)]
pub struct UpstreamLimits {
    pub upstream_proxy_max_concurrent_per_endpoint: usize,
    pub max_reverse_retry_template_body_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedStreamingLimits {
    pub body_channel_capacity: usize,
    pub body_read_timeout_ms: u64,
    pub body_send_timeout_ms: u64,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    pub max_grpc_message_bytes: u64,
    pub max_grpc_web_trailer_bytes: u64,
    pub max_grpc_stream_duration_ms: u64,
    pub observe_grpc_messages: bool,
    pub sse: SseStreamingPolicy,
}

impl ResolvedStreamingLimits {
    fn from_runtime(runtime: &RuntimeConfig) -> Self {
        resolve_streaming_limits(runtime, None, None, None, None, None, None)
    }
}

impl From<CompiledRuntimeLimits> for ResolvedStreamingLimits {
    fn from(limits: CompiledRuntimeLimits) -> Self {
        Self {
            body_channel_capacity: limits.body.body_channel_capacity.max(1),
            body_read_timeout_ms: limits.timeouts.h3_read_timeout_ms.max(1),
            body_send_timeout_ms: limits.timeouts.h3_read_timeout_ms.max(1),
            max_request_body_bytes: limits.body.max_h3_request_body_bytes,
            max_response_body_bytes: limits.body.max_h3_response_body_bytes,
            max_grpc_message_bytes: limits.grpc.max_grpc_message_bytes,
            max_grpc_web_trailer_bytes: limits.grpc.max_grpc_web_trailer_bytes,
            max_grpc_stream_duration_ms: limits.grpc.max_grpc_stream_duration_ms,
            observe_grpc_messages: true,
            sse: limits.sse,
        }
    }
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
    pub streaming: ResolvedStreamingLimits,
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
    pub const TLS_FINGERPRINT: Self = Self(1 << 20);

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
    pub streaming: ResolvedStreamingLimits,
    pub buffering_reasons: Vec<Arc<str>>,
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
    pub body: qpx_core::config::CaptureBodyMode,
    pub body_sample_bytes: Option<usize>,
    pub sample_percent: Option<u32>,
    pub max_body_bytes: Option<usize>,
    pub redact: CaptureRedactionConfig,
}

impl ExecutionPlan {
    pub(super) fn empty() -> Self {
        Self {
            flags: PlanFlags::empty(),
            streaming: ResolvedStreamingLimits::from_runtime(&RuntimeConfig::default()),
            buffering_reasons: Vec::new(),
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
            .filter(|plaintext| plaintext.body.is_full())
            .and_then(|plaintext| plaintext.max_body_bytes)
    }

    pub(crate) fn capture_stream_sample_bytes(&self) -> Option<usize> {
        self.capture
            .plaintext
            .as_ref()
            .filter(|plaintext| plaintext.body.is_stream_sample())
            .and_then(|plaintext| plaintext.body_sample_bytes)
    }

    pub(crate) fn capture_full_body_bytes(&self) -> Option<usize> {
        self.capture_body_max_bytes()
    }

    pub(crate) fn body_observation_limit(&self, default_limit: usize) -> usize {
        default_limit
    }

    pub(super) fn add_buffering_reason(&mut self, reason: &'static str) {
        if !self
            .buffering_reasons
            .iter()
            .any(|existing| existing.as_ref() == reason)
        {
            self.buffering_reasons.push(Arc::from(reason));
        }
    }
}
