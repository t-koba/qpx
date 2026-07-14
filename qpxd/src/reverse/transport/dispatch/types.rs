use crate::http::dispatch::DispatchAuditContext;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::policy_context::EffectivePolicyContext;
use crate::rate_limit::RateLimitContext;
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::{HttpRoute, SelectedMirrorTarget};
use crate::reverse::transport::request_template::{ReverseReplayRecorder, ReverseRequestTemplate};
use crate::reverse::transport::{InterimList, ReverseConnInfo};
use crate::runtime::{self, Runtime};
use hyper::{Method, Request, Response};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use qpxd_cache::CacheRequestKey;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

pub(super) struct InlineCache<T> {
    first: Option<(usize, T)>,
    additional: Vec<(usize, T)>,
}

impl<T> InlineCache<T> {
    pub(super) fn new() -> Self {
        Self {
            first: None,
            additional: Vec::new(),
        }
    }

    pub(super) fn contains(&self, key: usize) -> bool {
        self.get(key).is_some()
    }

    pub(super) fn get(&self, key: usize) -> Option<&T> {
        self.first
            .as_ref()
            .filter(|(existing, _)| *existing == key)
            .map(|(_, value)| value)
            .or_else(|| {
                self.additional
                    .iter()
                    .find(|(existing, _)| *existing == key)
                    .map(|(_, value)| value)
            })
    }

    pub(super) fn push(&mut self, key: usize, value: T) {
        if self.first.is_none() {
            self.first = Some((key, value));
        } else {
            self.additional.push((key, value));
        }
    }
}

impl<T> IntoIterator for InlineCache<T> {
    type Item = (usize, T);
    type IntoIter =
        std::iter::Chain<std::option::IntoIter<(usize, T)>, std::vec::IntoIter<(usize, T)>>;

    fn into_iter(self) -> Self::IntoIter {
        self.first.into_iter().chain(self.additional)
    }
}

pub(super) struct PreparedReverseRequest {
    pub(super) req: Request<Body>,
    pub(super) context: ReversePreparedContext,
    pub(super) route: ReversePreparedRoute,
    pub(super) observation: crate::http::pipeline::types::RequestObservation,
}

pub(super) struct ReversePreparedContext {
    pub(super) compiled: Arc<crate::reverse::CompiledReverse>,
    pub(super) state: Arc<runtime::RuntimeState>,
}

pub(super) struct ReversePreparedRoute {
    pub(super) route_idx: usize,
    pub(super) selected_policy: EffectivePolicyContext,
    pub(super) identity: crate::policy_context::ResolvedIdentity,
    pub(super) sanitized_headers: Option<http::HeaderMap>,
    // Keyed by `destination_override_key` (identity of the route's compiled
    // override); see `prepare.rs`.
    pub(super) request_destination_cache: InlineCache<crate::destination::DestinationMetadata>,
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

/// Shared shape for reverse dispatch stages that either short-circuit with a
/// finalized response or continue with stage-specific state.
pub(super) enum ReverseStageOutcome<T> {
    Response(Box<Response<Body>>),
    Continue(T),
}

pub(super) type ReverseAccessOutcome = ReverseStageOutcome<ReverseAccessControl>;

pub(super) struct ReverseAccessControl {
    pub(super) req: Request<Body>,
    pub(super) audit_ctx: DispatchAuditContext,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) override_upstream: Option<String>,
    pub(super) route_timeout: Duration,
    pub(super) cache_bypass: bool,
    pub(super) decision_service_mirror_upstreams: Vec<String>,
    pub(super) authorization_decision: Option<qpx_core::ipc::meta::AuthorizationDecisionContext>,
    pub(super) request_limit_ctx: RateLimitContext,
    pub(super) request_limits: crate::rate_limit::AppliedRateLimits,
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
    pub(super) sanitized_headers: Option<&'a http::HeaderMap>,
    pub(super) request_destination: &'a crate::destination::DestinationMetadata,
}

pub(super) type ReverseModuleOutcome = ReverseStageOutcome<ReverseModuleDispatch>;

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

pub(super) type ReverseCacheOutcome = ReverseStageOutcome<ReverseCacheState>;

pub(super) struct ReverseCacheState {
    pub(super) req: Request<Body>,
    pub(super) request_headers_snapshot: Option<http::HeaderMap>,
    pub(super) cache_lookup_key: Option<CacheRequestKey>,
    pub(super) cache_target_key: Option<CacheRequestKey>,
    pub(super) revalidation_state: Option<qpxd_cache::RevalidationState>,
    pub(super) cache_collapse_guard: Option<qpxd_cache::RequestCollapseGuard>,
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
    pub(super) replay_recorder: Option<ReverseReplayRecorder>,
    pub(super) mirror_upstreams: Vec<SelectedMirrorTarget>,
}

pub(super) struct ReverseRetryPrepareInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) route: &'a HttpRoute,
    pub(super) state: &'a runtime::RuntimeState,
    pub(super) request_method: &'a Method,
    pub(super) seed: u64,
    pub(super) sticky_seed: u64,
    pub(super) decision_service_mirror_upstreams: Vec<String>,
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
    pub(super) request_destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: Option<qpxd_cache::RevalidationState>,
    pub(super) cache_collapse_guard: Option<qpxd_cache::RequestCollapseGuard>,
    pub(super) first_request: Option<Request<Body>>,
    pub(super) template: Option<ReverseRequestTemplate>,
    pub(super) replay_recorder: Option<ReverseReplayRecorder>,
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
    pub(super) authorization_decision:
        Option<&'a qpx_core::ipc::meta::AuthorizationDecisionContext>,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: Option<qpxd_cache::RevalidationState>,
    pub(super) cache_collapse_guard: Option<qpxd_cache::RequestCollapseGuard>,
    pub(super) first_request: Option<Request<Body>>,
    pub(super) template: Option<ReverseRequestTemplate>,
    pub(super) replay_recorder: Option<ReverseReplayRecorder>,
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
    pub(super) authorization_decision:
        Option<&'a qpx_core::ipc::meta::AuthorizationDecisionContext>,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) override_upstream: Option<&'a str>,
    pub(super) decision_service_mirror_upstreams: Vec<String>,
    pub(super) seed: u64,
    pub(super) sticky_seed: u64,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    pub(super) request_limit_ctx: &'a RateLimitContext,
    pub(super) audit_ctx: &'a DispatchAuditContext,
}

pub(super) enum ReverseAttemptOutcome {
    Response((InterimList, Response<Body>)),
    Retry(anyhow::Error),
    Stop(anyhow::Error),
}

pub(super) type ReverseResponseRuleContinue = (
    Response<Body>,
    Option<Arc<CompiledHeaderControl>>,
    bool,
    Vec<String>,
    Option<bool>,
);

pub(super) struct ReverseResponseRuleInput<'a> {
    pub(super) response_rule: crate::http::dispatch::DispatchResponsePolicyOutcome,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) state: &'a runtime::RuntimeState,
    pub(super) route: &'a HttpRoute,
    pub(super) selected_upstream: Option<&'a Arc<UpstreamEndpoint>>,
    pub(super) attempt_idx: usize,
    pub(super) attempts: usize,
    pub(super) started: Option<Instant>,
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
    pub(super) request_destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) route_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) revalidation_state: &'a mut Option<qpxd_cache::RevalidationState>,
    pub(super) cache_collapse_guard: &'a mut Option<qpxd_cache::RequestCollapseGuard>,
    pub(super) template: Option<&'a ReverseRequestTemplate>,
    pub(super) replay_recorder: Option<ReverseReplayRecorder>,
    pub(super) mirror_upstreams: &'a mut Vec<SelectedMirrorTarget>,
    pub(super) attempts: usize,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a DispatchAuditContext,
    pub(super) attempt_idx: usize,
    pub(super) selected_upstream: Option<&'a Arc<UpstreamEndpoint>>,
    pub(super) started: Option<Instant>,
    pub(super) interim: InterimList,
    pub(super) response: Response<Body>,
    pub(super) upstream_cert: Option<qpx_core::tls::UpstreamCertificateInfo>,
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
    pub(super) revalidation_state: &'a mut Option<qpxd_cache::RevalidationState>,
    pub(super) cache_collapse_guard: &'a mut Option<qpxd_cache::RequestCollapseGuard>,
    pub(super) template: Option<&'a ReverseRequestTemplate>,
    pub(super) replay_recorder: Option<ReverseReplayRecorder>,
    pub(super) mirror_upstreams: &'a mut Vec<SelectedMirrorTarget>,
    pub(super) attempts: usize,
    pub(super) route_timeout: Duration,
    pub(super) proxy_name: &'a str,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit_ctx: &'a DispatchAuditContext,
    pub(super) attempt_idx: usize,
    pub(super) started: Option<Instant>,
    pub(super) response: Response<Body>,
    pub(super) export_session: Option<&'a crate::exporter::ExportSession>,
}
