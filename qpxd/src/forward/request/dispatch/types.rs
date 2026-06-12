use super::super::HostPort;
use crate::http::dispatch::DispatchAuditContext;
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use hyper::{Method, Request};
use qpx_http::body::Body;
use qpxd_cache::CacheRequestKey;
use std::sync::Arc;
use tokio::time::Duration;

pub(super) type ForwardPrepareOutcome =
    crate::http::pipeline::PrepareOutcome<ForwardPreparedRequest>;

pub(super) type ForwardPreparedRequest = crate::http::pipeline::PreparedRequestParts<
    crate::http::pipeline::types::ResolvedPolicy,
    ForwardPreparedMode,
>;

pub(super) struct ForwardPreparedMode {
    pub(super) host: HostPort,
    pub(super) is_ftp_request: bool,
}

pub(super) type ForwardPolicyOutcome =
    crate::http::pipeline::PolicyStage<Box<ForwardAllowedPolicy>>;

pub(super) struct ForwardAllowedPolicy {
    pub(super) action: qpx_core::config::ActionConfig,
    pub(super) headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    pub(super) matched_rule: Option<String>,
    pub(super) identity: crate::policy_context::ResolvedIdentity,
}

pub(super) type ForwardDispatchPrepareOutcome =
    crate::http::pipeline::PrepareOutcome<ForwardDispatchReady>;

pub(super) struct ForwardDispatchReady {
    pub(super) req: Request<Body>,
    pub(super) http_modules: crate::http::modules::HttpModuleExecution,
    pub(super) request_headers_snapshot: Option<http::HeaderMap>,
    pub(super) cache_lookup_key: Option<CacheRequestKey>,
    pub(super) cache_target_key: Option<CacheRequestKey>,
    pub(super) upstream: Option<crate::upstream::pool::ResolvedUpstreamProxy>,
    pub(super) upstream_timeout: Duration,
    pub(super) http_authority: String,
    pub(super) export_session: Option<crate::exporter::ExportSession>,
    pub(super) _concurrency_permits: crate::rate_limit::ConcurrencyPermits,
}

pub(super) struct ForwardPolicyOutcomeInput<'a> {
    pub(super) runtime: &'a Runtime,
    pub(super) listener_name: &'a str,
    pub(super) ctx: qpx_core::rules::RuleMatchContext<'a>,
    pub(super) sanitized_headers: &'a http::HeaderMap,
    pub(super) response: ForwardPolicyResponseInput<'a>,
    pub(super) auth_method: &'a str,
    pub(super) auth_uri: &'a str,
    pub(super) stage_observation: bool,
}

#[derive(Clone, Copy)]
pub(super) struct ForwardPolicyResponseInput<'a> {
    #[cfg(feature = "auth-basic")]
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    #[cfg(feature = "auth-basic")]
    pub(super) proxy_name: &'a str,
    pub(super) listener_name: &'a str,
    pub(super) remote_addr: std::net::SocketAddr,
    pub(super) host: &'a str,
    #[cfg(feature = "auth-basic")]
    pub(super) request_method: &'a Method,
    #[cfg(feature = "auth-basic")]
    pub(super) request_version: http::Version,
    pub(super) path: Option<&'a str>,
}

pub(super) struct ForwardDispatchPrepareInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) state: Arc<crate::runtime::RuntimeState>,
    pub(super) effective_policy: &'a crate::policy_context::EffectivePolicyContext,
    pub(super) remote_addr: std::net::SocketAddr,
    pub(super) proxy_name: &'a str,
    pub(super) listener_name: &'a str,
    pub(super) selected_plan: &'a crate::runtime::ExecutionPlan,
    pub(super) action: &'a qpx_core::config::ActionConfig,
    pub(super) headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) request_limits: crate::rate_limit::AppliedRateLimits,
    pub(super) request_limit_ctx: RateLimitContext,
    pub(super) timeout_override: Option<Duration>,
    pub(super) host: &'a HostPort,
    pub(super) request_method: &'a Method,
    pub(super) audit: &'a DispatchAuditContext,
}
