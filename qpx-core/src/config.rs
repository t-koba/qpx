mod defaults;
mod load;
mod types;
mod validate;

pub use load::{load_config, load_config_with_sources, load_configs, load_configs_with_sources};
pub use types::{
    AccessLogConfig, AcmeConfig, ActionConfig, ActionKind, AdaptiveThresholdConfig,
    AssertionClaimsMapConfig, AuditIncludeField, AuditLogConfig, AuthConfig, CacheBackendConfig,
    CachePolicyConfig, CachePurgeModuleConfig, CaptureBodyMode, CapturePlaintextPolicyConfig,
    CapturePolicyConfig, CaptureRedactionConfig, CertificateMatchConfig, Config, ConnectUdpConfig,
    ConsecutiveFailuresConfig, DatagramOverflowStrategyConfig, DecisionConfig,
    DestinationConflictMode, DestinationDimensionMatchConfig, DestinationEvidenceSourceKind,
    DestinationMatchConfig, DestinationMergeMode, DestinationMinConfidenceConfig,
    DestinationResolutionConfig, DestinationResolutionOverrideConfig,
    DestinationResolutionPolicyConfig, EdgeConfig, EjectionConfig, EndpointLifecycleConfig,
    ExporterCaptureConfig, ExporterConfig, ExtAuthzConfig, ExtAuthzKind, ExtAuthzOnError,
    ExtAuthzSendConfig, FtpConfig, GrpcConfig, HalfOpenConfig, HeaderCaptureConfig, HeaderControl,
    HeaderMatch, HealthCheckConfig, Http3IngressEdgeConfig, HttpGlobalConfig, HttpGuardJsonConfig,
    HttpGuardLimitsConfig, HttpGuardMultipartConfig, HttpGuardNormalizeConfig,
    HttpGuardProfileConfig, HttpGuardProtocolSafetyConfig, HttpHealthCheckConfig,
    HttpModuleChainConfig, HttpModuleConfig, HttpPolicyConfig, HttpResponseCacheEffectsConfig,
    HttpResponseEffectsConfig, HttpResponseMirrorEffectsConfig, HttpResponseRetryEffectsConfig,
    HttpResponseRuleConfig, IdentityConfig, IdentityMatchConfig, IdentitySourceConfig,
    IdentitySourceFromConfig, IdentitySourceHeadersConfig, IdentitySourceKind, IngressEdgeConfig,
    IngressEdgeMode, IpcBodyLimitConfig, IpcMode, IpcUpstreamConfig, LatencyThresholdConfig,
    LdapConfig, LocalResponseConfig, LocalUser, LogOutputConfig, MAX_GRPC_STREAM_DURATION_MS,
    MAX_GRPC_WEB_TRAILER_BYTES, MAX_OBSERVED_BODY_BYTES, MAX_REVERSE_RETRY_TEMPLATE_BODY_BYTES,
    MAX_SSE_STREAM_DURATION_MS, MatchConfig, MessagesConfig, MetricsConfig, MtlsIdentityMapConfig,
    NamedSetConfig, NamedSetKind, OriginalDstConfig, OriginalDstSource, OtelConfig,
    OutlierDetectionConfig, PathRewriteConfig, PolicyContextConfig, RateLimitApplyTo,
    RateLimitConfig, RateLimitProfileConfig, RateLimitQuotaConfig, RateLimitRequestsConfig,
    RateLimitSessionsConfig, RateLimitTrafficConfig, RegexPathRewriteConfig, RegexReplace,
    ResilienceConfig, ResilienceRetryConfig, ResponseCompressionModuleConfig, RetryBudgetConfig,
    ReverseAffinityConfig, ReverseEdgeConfig, ReverseHttp3Config, ReverseRouteBackendConfig,
    ReverseRouteConfig, ReverseRouteMirrorConfig, ReverseRouteTargetConfig, ReverseTlsConfig,
    ReverseTlsPassthroughRouteConfig, RpcLocalResponseConfig, RpcMatchConfig, RuleAuthConfig,
    RuleConfig, RuntimeConfig, SecurityConfig, SignedAssertionConfig, SseFlushPolicy,
    SseStreamingPolicy, StreamingConfig, StreamingRequirement, SubrequestModuleConfig,
    SubrequestPhase, SubrequestResponseMode, SystemLogConfig, TelemetryConfig, TlsCertConfig,
    TlsFingerprintMatchConfig, TlsInspectionConfig, TlsPassthroughMatchConfig, TrafficConfig,
    UnknownLengthExactSizePolicy, UpstreamConfig, UpstreamDiscoveryConfig, UpstreamDiscoveryKind,
    UpstreamTlsTrustConfig, UpstreamTlsTrustProfileConfig, XdpConfig, canonical_schema_value,
};

#[cfg(test)]
mod tests;
