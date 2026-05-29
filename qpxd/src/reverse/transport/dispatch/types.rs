use crate::cache::CacheRequestKey;
use crate::http::body::Body;
use crate::http::dispatch::DispatchAuditContext;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::policy_context::EffectivePolicyContext;
use crate::rate_limit::RateLimitContext;
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::{HttpRoute, SelectedMirrorTarget};
use crate::reverse::transport::request_template::ReverseRequestTemplate;
use crate::reverse::transport::{
    ResponseRuleDecision, ReverseConnInfo, ReverseInterimResponses, ReverseRouter,
};
use crate::runtime::{self, Runtime};
use hyper::{Method, Request, Response};
use qpx_core::rules::CompiledHeaderControl;
use qpx_observability::access_log::RequestLogContext;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

pub(super) struct PreparedReverseRequest {
    pub(super) req: Request<Body>,
    pub(super) context: ReversePreparedContext,
    pub(super) route: ReversePreparedRoute,
    pub(super) observation: crate::http::pipeline::types::RequestObservation,
}

pub(super) struct ReversePreparedContext {
    pub(super) router: Arc<ReverseRouter>,
    pub(super) state: Arc<runtime::RuntimeState>,
    pub(super) proxy_name: String,
}

pub(super) struct ReversePreparedRoute {
    pub(super) host: String,
    pub(super) request_method: Method,
    pub(super) request_version: http::Version,
    pub(super) path_owned: Option<String>,
    pub(super) request_uri: String,
    pub(super) route_idx: usize,
    pub(super) selected_policy: EffectivePolicyContext,
    pub(super) identity: crate::policy_context::ResolvedIdentity,
    pub(super) sanitized_headers: http::HeaderMap,
    pub(super) request_destination_cache:
        std::collections::HashMap<String, crate::destination::DestinationMetadata>,
    pub(super) max_observed_request_body_bytes: usize,
}

pub(super) struct ReverseWebsocketDispatch<'a> {
    pub(super) req: Request<Body>,
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) route: &'a HttpRoute,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) override_upstream: Option<&'a str>,
    pub(super) seed: u64,
    pub(super) sticky_seed: u64,
    pub(super) request_limit_ctx: &'a RateLimitContext,
    pub(super) request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) route_headers: Option<&'a CompiledHeaderControl>,
    pub(super) request_method: &'a Method,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a DispatchAuditContext,
}

pub(super) type ReverseAccessOutcome = crate::http::pipeline::AccessOutcome<ReverseAccessControl>;

pub(super) struct ReverseAccessControl {
    pub(super) req: Request<Body>,
    pub(super) log_context: RequestLogContext,
    pub(super) ext_authz_policy_id: Option<String>,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) override_upstream: Option<String>,
    pub(super) route_timeout: Duration,
    pub(super) cache_bypass: bool,
    pub(super) ext_authz_mirror_upstreams: Vec<String>,
    pub(super) request_limit_ctx: RateLimitContext,
    pub(super) request_limits: crate::rate_limit::AppliedRateLimits,
}

pub(super) struct ReverseExtAuthzAllow {
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) override_upstream: Option<String>,
    pub(super) timeout_override: Option<Duration>,
    pub(super) cache_bypass: bool,
    pub(super) mirror_upstreams: Vec<String>,
    pub(super) rate_limit_profile: Option<String>,
}

pub(super) struct ReverseAccessInput<'a> {
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) reverse_name: &'a str,
    pub(super) proxy_name: &'a str,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) host: &'a str,
    pub(super) request_method: &'a Method,
    pub(super) path: Option<&'a str>,
    pub(super) request_uri: &'a str,
    pub(super) req: Request<Body>,
    pub(super) route: &'a HttpRoute,
    pub(super) selected_policy: &'a EffectivePolicyContext,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) sanitized_headers: &'a http::HeaderMap,
    pub(super) request_destination: &'a crate::destination::DestinationMetadata,
}

pub(super) enum ReverseModuleOutcome {
    Response(Box<Response<Body>>),
    Continue(Box<ReverseModuleDispatch>),
}

pub(super) struct ReverseModuleDispatch {
    pub(super) req: Request<Body>,
    pub(super) http_modules: crate::http::modules::HttpModuleExecution,
    pub(super) request_cache_policy: Option<qpx_core::config::CachePolicyConfig>,
}

pub(super) struct ReverseModuleInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) selected_policy: &'a EffectivePolicyContext,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) route: &'a HttpRoute,
    pub(super) reverse_name: &'a str,
    pub(super) proxy_name: &'a str,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) route_headers: Option<&'a CompiledHeaderControl>,
    pub(super) cache_bypass: bool,
    pub(super) audit_ctx: &'a DispatchAuditContext,
}

pub(super) enum ReverseCacheOutcome {
    Response(Box<Response<Body>>),
    Continue(Box<ReverseCacheState>),
}

pub(super) struct ReverseCacheState {
    pub(super) req: Request<Body>,
    pub(super) request_headers_snapshot: Option<http::HeaderMap>,
    pub(super) cache_lookup_key: Option<CacheRequestKey>,
    pub(super) cache_target_key: Option<CacheRequestKey>,
    pub(super) revalidation_state: Option<crate::cache::RevalidationState>,
    pub(super) cache_collapse_guard: Option<crate::cache::RequestCollapseGuard>,
}

pub(super) struct ReverseCacheInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) runtime: &'a Runtime,
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) route: &'a HttpRoute,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) request_method: &'a Method,
    pub(super) request_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) route_headers: Option<&'a CompiledHeaderControl>,
    pub(super) request_cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) override_upstream: Option<&'a str>,
    pub(super) seed: u64,
    pub(super) sticky_seed: u64,
    pub(super) route_timeout: Duration,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a DispatchAuditContext,
}

pub(super) struct ReverseRetryDispatch {
    pub(super) attempts: usize,
    pub(super) first_request: Option<Request<Body>>,
    pub(super) template: Option<ReverseRequestTemplate>,
    pub(super) mirror_upstreams: Vec<SelectedMirrorTarget>,
}

pub(super) struct ReverseRetryPrepareInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) route: &'a HttpRoute,
    pub(super) state: &'a runtime::RuntimeState,
    pub(super) request_method: &'a Method,
    pub(super) seed: u64,
    pub(super) sticky_seed: u64,
    pub(super) ext_authz_mirror_upstreams: Vec<String>,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
}

pub(super) struct ReverseHttpDispatchInput<'a> {
    pub(super) base: &'a BaseRequestFields,
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) host: &'a str,
    pub(super) route: &'a HttpRoute,
    pub(super) resolution_override:
        Option<&'a qpx_core::config::DestinationResolutionOverrideConfig>,
    pub(super) request_method: &'a Method,
    pub(super) request_version: http::Version,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: Option<crate::cache::RevalidationState>,
    pub(super) cache_collapse_guard: Option<crate::cache::RequestCollapseGuard>,
    pub(super) first_request: Option<Request<Body>>,
    pub(super) template: Option<ReverseRequestTemplate>,
    pub(super) mirror_upstreams: Vec<SelectedMirrorTarget>,
    pub(super) attempts: usize,
    pub(super) override_upstream: Option<&'a str>,
    pub(super) seed: u64,
    pub(super) sticky_seed: u64,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    pub(super) request_limit_ctx: &'a RateLimitContext,
    pub(super) audit_ctx: &'a DispatchAuditContext,
}

pub(super) struct ReverseIpcDispatchInput<'a> {
    pub(super) base: &'a BaseRequestFields,
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) route: &'a HttpRoute,
    pub(super) request_destination: &'a crate::destination::DestinationMetadata,
    pub(super) request_method: &'a Method,
    pub(super) request_version: http::Version,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: Option<crate::cache::RevalidationState>,
    pub(super) cache_collapse_guard: Option<crate::cache::RequestCollapseGuard>,
    pub(super) first_request: Option<Request<Body>>,
    pub(super) template: Option<ReverseRequestTemplate>,
    pub(super) mirror_upstreams: Vec<SelectedMirrorTarget>,
    pub(super) attempts: usize,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    pub(super) request_limit_ctx: &'a RateLimitContext,
    pub(super) audit_ctx: &'a DispatchAuditContext,
}

pub(super) struct ReversePostModuleInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) http_modules: crate::http::modules::HttpModuleExecution,
    pub(super) request_cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    pub(super) base: &'a BaseRequestFields,
    pub(super) runtime: &'a Runtime,
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) host: &'a str,
    pub(super) route: &'a HttpRoute,
    pub(super) resolution_override:
        Option<&'a qpx_core::config::DestinationResolutionOverrideConfig>,
    pub(super) request_destination: &'a crate::destination::DestinationMetadata,
    pub(super) request_method: &'a Method,
    pub(super) request_version: http::Version,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) override_upstream: Option<&'a str>,
    pub(super) ext_authz_mirror_upstreams: Vec<String>,
    pub(super) seed: u64,
    pub(super) sticky_seed: u64,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    pub(super) request_limit_ctx: &'a RateLimitContext,
    pub(super) audit_ctx: &'a DispatchAuditContext,
}

pub(super) enum ReverseAttemptOutcome {
    Response(Box<(ReverseInterimResponses, Response<Body>)>),
    Retry(anyhow::Error),
    Stop(anyhow::Error),
}

pub(super) type ReverseResponseRuleContinue = (
    Response<Body>,
    Option<Arc<CompiledHeaderControl>>,
    bool,
    Arc<[String]>,
    Option<bool>,
);

pub(super) struct ReverseResponseRuleInput<'a> {
    pub(super) response_rule: ResponseRuleDecision,
    pub(super) request_method: &'a Method,
    pub(super) request_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a DispatchAuditContext,
    pub(super) state: &'a runtime::RuntimeState,
    pub(super) route: &'a HttpRoute,
    pub(super) selected_upstream: Option<&'a Arc<UpstreamEndpoint>>,
    pub(super) attempt_idx: usize,
    pub(super) attempts: usize,
    pub(super) started: Instant,
}

pub(super) struct ReverseHttpSuccessInput<'a> {
    pub(super) base: &'a BaseRequestFields,
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) host: &'a str,
    pub(super) route: &'a HttpRoute,
    pub(super) resolution_override:
        Option<&'a qpx_core::config::DestinationResolutionOverrideConfig>,
    pub(super) request_method: &'a Method,
    pub(super) request_version: http::Version,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: &'a mut Option<crate::cache::RevalidationState>,
    pub(super) cache_collapse_guard: &'a mut Option<crate::cache::RequestCollapseGuard>,
    pub(super) template: Option<&'a ReverseRequestTemplate>,
    pub(super) mirror_upstreams: &'a mut Vec<SelectedMirrorTarget>,
    pub(super) attempts: usize,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a DispatchAuditContext,
    pub(super) attempt_idx: usize,
    pub(super) selected_upstream: Option<&'a Arc<UpstreamEndpoint>>,
    pub(super) started: Instant,
    pub(super) interim: ReverseInterimResponses,
    pub(super) response: Response<Body>,
    pub(super) upstream_cert: Option<crate::tls::cert_info::UpstreamCertificateInfo>,
    pub(super) export_session: Option<&'a crate::exporter::ExportSession>,
}

pub(super) struct ReverseIpcSuccessInput<'a> {
    pub(super) base: &'a BaseRequestFields,
    pub(super) state: &'a Arc<runtime::RuntimeState>,
    pub(super) conn: &'a ReverseConnInfo,
    pub(super) route: &'a HttpRoute,
    pub(super) request_destination: &'a crate::destination::DestinationMetadata,
    pub(super) request_method: &'a Method,
    pub(super) request_version: http::Version,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: &'a mut Option<crate::cache::RevalidationState>,
    pub(super) cache_collapse_guard: &'a mut Option<crate::cache::RequestCollapseGuard>,
    pub(super) template: Option<&'a ReverseRequestTemplate>,
    pub(super) mirror_upstreams: &'a mut Vec<SelectedMirrorTarget>,
    pub(super) attempts: usize,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a DispatchAuditContext,
    pub(super) attempt_idx: usize,
    pub(super) started: Instant,
    pub(super) response: Response<Body>,
    pub(super) export_session: Option<&'a crate::exporter::ExportSession>,
}
