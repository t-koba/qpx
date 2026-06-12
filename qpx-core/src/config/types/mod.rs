//! Serde-facing canonical configuration data transfer objects.
//!
//! These structs mirror the YAML schema one-to-one. Field-level user
//! documentation is generated from `canonical/schema.rs` and the configuration
//! guide, so this module keeps the Rust DTOs compact instead of duplicating the
//! full schema prose on every public field.

#![allow(missing_docs)]

mod cache;
mod canonical;
mod core;
mod http;
mod listener;
mod observability;
mod policy;
mod reverse;
mod rules;
mod security;
mod upstream;

pub use self::cache::{
    CacheBackendConfig, CachePolicyConfig, RateLimitApplyTo, RateLimitConfig,
    RateLimitProfileConfig, RateLimitQuotaConfig, RateLimitRequestsConfig, RateLimitSessionsConfig,
    RateLimitTrafficConfig,
};
pub use self::canonical::{
    DecisionConfig, HttpGlobalConfig, HttpModuleChainConfig, SecurityConfig, TelemetryConfig,
    TrafficConfig, canonical_schema_value,
};
pub use self::core::{
    DatagramOverflowStrategyConfig, GrpcConfig, H3RequestBodyDrainConfig, H3RequestBodyDrainMode,
    IdentityConfig, MAX_GRPC_STREAM_DURATION_MS, MAX_GRPC_WEB_TRAILER_BYTES,
    MAX_OBSERVED_BODY_BYTES, MAX_REVERSE_RETRY_TEMPLATE_BODY_BYTES, MAX_SSE_EVENT_ID_BYTES,
    MAX_SSE_LINE_BYTES, MAX_SSE_STREAM_DURATION_MS, MessagesConfig, RuntimeConfig, SseFlushPolicy,
    SseStreamingPolicy, StreamingConfig, StreamingRequirement, UnknownLengthExactSizePolicy,
};
pub use self::http::{
    CachePurgeModuleConfig, HeaderCaptureConfig, HttpGuardJsonConfig, HttpGuardLimitsConfig,
    HttpGuardMultipartConfig, HttpGuardNormalizeConfig, HttpGuardProfileConfig,
    HttpGuardProtocolSafetyConfig, HttpModuleConfig, HttpPolicyConfig,
    HttpResponseCacheEffectsConfig, HttpResponseEffectsConfig, HttpResponseMirrorEffectsConfig,
    HttpResponseRetryEffectsConfig, HttpResponseRuleConfig, ResponseCompressionModuleConfig,
    SubrequestModuleConfig, SubrequestPhase, SubrequestResponseMode,
};
pub use self::listener::{
    ConnectUdpConfig, FtpConfig, Http3IngressEdgeConfig, IngressEdgeConfig, IngressEdgeMode,
    OriginalDstConfig, OriginalDstSource, TlsInspectionConfig, XdpConfig,
};
pub use self::observability::{
    AccessLogConfig, AcmeConfig, AuditIncludeField, AuditLogConfig, CaptureBodyMode,
    CapturePlaintextPolicyConfig, CapturePolicyConfig, CaptureRedactionConfig,
    ExporterCaptureConfig, ExporterConfig, LogOutputConfig, MetricsConfig, OtelConfig,
    SystemLogConfig,
};
pub use self::policy::{
    DestinationConflictMode, DestinationEvidenceSourceKind, DestinationMergeMode,
    DestinationMinConfidenceConfig, DestinationResolutionConfig,
    DestinationResolutionOverrideConfig, DestinationResolutionPolicyConfig,
};
pub use self::reverse::{
    AdaptiveThresholdConfig, ConsecutiveFailuresConfig, EjectionConfig, EndpointLifecycleConfig,
    HalfOpenConfig, HealthCheckConfig, HttpHealthCheckConfig, IpcBodyLimitConfig, IpcMode,
    IpcUpstreamConfig, LatencyThresholdConfig, OutlierDetectionConfig, PathRewriteConfig,
    RegexPathRewriteConfig, ResilienceConfig, ResilienceRetryConfig, RetryBudgetConfig,
    ReverseAffinityConfig, ReverseEdgeConfig, ReverseHttp3Config, ReverseRouteBackendConfig,
    ReverseRouteConfig, ReverseRouteMirrorConfig, ReverseRouteTargetConfig, ReverseTlsConfig,
    ReverseTlsPassthroughRouteConfig, TlsCertConfig, TlsPassthroughMatchConfig,
};
pub use self::rules::{
    ActionConfig, ActionKind, CertificateMatchConfig, DestinationDimensionMatchConfig,
    DestinationMatchConfig, HeaderControl, HeaderMatch, IdentityMatchConfig, LocalResponseConfig,
    MatchConfig, RegexReplace, RpcLocalResponseConfig, RpcMatchConfig, RuleAuthConfig, RuleConfig,
    TlsFingerprintMatchConfig,
};
pub use self::security::{
    AssertionClaimsMapConfig, AuthConfig, ExtAuthzConfig, ExtAuthzKind, ExtAuthzOnError,
    ExtAuthzSendConfig, IdentitySourceConfig, IdentitySourceFromConfig,
    IdentitySourceHeadersConfig, IdentitySourceKind, LdapConfig, LocalUser, MtlsIdentityMapConfig,
    NamedSetConfig, NamedSetKind, PolicyContextConfig, SignedAssertionConfig,
    UpstreamTlsTrustConfig, UpstreamTlsTrustProfileConfig,
};
pub use self::upstream::{UpstreamConfig, UpstreamDiscoveryConfig, UpstreamDiscoveryKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub state_dir: Option<String>,
    pub identity: IdentityConfig,
    pub messages: MessagesConfig,
    pub runtime: RuntimeConfig,
    pub telemetry: TelemetryConfig,
    pub security: SecurityConfig,
    pub http: HttpGlobalConfig,
    pub traffic: TrafficConfig,
    pub acme: Option<AcmeConfig>,
    pub edges: Vec<EdgeConfig>,
    pub upstreams: Vec<UpstreamConfig>,
    pub caches: Vec<CacheBackendConfig>,
}

impl Config {
    pub fn ingress_edges(&self) -> impl Iterator<Item = &IngressEdgeConfig> {
        self.edges.iter().filter_map(EdgeConfig::as_ingress)
    }

    pub fn ingress_edge_configs(&self) -> Vec<&IngressEdgeConfig> {
        self.ingress_edges().collect()
    }

    pub fn ingress_edges_mut(&mut self) -> impl Iterator<Item = &mut IngressEdgeConfig> {
        self.edges.iter_mut().filter_map(EdgeConfig::as_ingress_mut)
    }

    pub fn reverse_edges(&self) -> impl Iterator<Item = &ReverseEdgeConfig> {
        self.edges.iter().filter_map(EdgeConfig::as_reverse)
    }

    pub fn reverse_edge_configs(&self) -> Vec<&ReverseEdgeConfig> {
        self.reverse_edges().collect()
    }

    pub fn reverse_edges_mut(&mut self) -> impl Iterator<Item = &mut ReverseEdgeConfig> {
        self.edges.iter_mut().filter_map(EdgeConfig::as_reverse_mut)
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeConfig {
    Forward(IngressEdgeConfig),
    Reverse(ReverseEdgeConfig),
    Transparent(IngressEdgeConfig),
}

impl EdgeConfig {
    pub fn as_ingress(&self) -> Option<&IngressEdgeConfig> {
        match self {
            Self::Forward(edge) | Self::Transparent(edge) => Some(edge),
            Self::Reverse(_) => None,
        }
    }

    pub fn as_ingress_mut(&mut self) -> Option<&mut IngressEdgeConfig> {
        match self {
            Self::Forward(edge) | Self::Transparent(edge) => Some(edge),
            Self::Reverse(_) => None,
        }
    }

    pub fn as_reverse(&self) -> Option<&ReverseEdgeConfig> {
        match self {
            Self::Reverse(edge) => Some(edge),
            Self::Forward(_) | Self::Transparent(_) => None,
        }
    }

    pub fn as_reverse_mut(&mut self) -> Option<&mut ReverseEdgeConfig> {
        match self {
            Self::Reverse(edge) => Some(edge),
            Self::Forward(_) | Self::Transparent(_) => None,
        }
    }
}
