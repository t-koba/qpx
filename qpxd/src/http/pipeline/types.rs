use crate::http::policy::response_policy::HttpResponseRuleEngine;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use crate::runtime::{CompiledListenerSettings, ExecutionPlan, Runtime, RuntimeState};
use hyper::Response;
use qpx_core::config::{ActionConfig, CachePolicyConfig};
use qpx_core::rules::{CandidateRequestObservationRequirements, CompiledHeaderControl};
use qpx_http::body::Body;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;

pub enum PrepareOutcome<P> {
    Response(Box<Response<Body>>),
    Prepared(Box<P>),
}

pub(crate) enum PolicyStage<D> {
    Decision(D),
    Observe(CandidateRequestObservationRequirements),
}

pub(crate) struct RequestContext {
    pub(crate) runtime: Option<Runtime>,
    pub(crate) state: Arc<RuntimeState>,
    pub(crate) proxy_name: String,
    pub(crate) listener_name: String,
    pub(crate) listener_cfg: CompiledListenerSettings,
    pub(crate) remote_addr: SocketAddr,
}

pub(crate) struct ResolvedPolicy {
    pub(crate) effective_policy: crate::policy_context::EffectivePolicyContext,
    pub(crate) destination: crate::destination::DestinationMetadata,
    pub(crate) identity: crate::policy_context::ResolvedIdentity,
    pub(crate) sanitized_headers: http::HeaderMap,
    pub(crate) response_engine: Option<Arc<HttpResponseRuleEngine>>,
    pub(crate) selected_plan: ExecutionPlan,
    pub(crate) action: ActionConfig,
    pub(crate) headers: Option<Arc<CompiledHeaderControl>>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) cache_policy: Option<CachePolicyConfig>,
}

pub(crate) struct RequestLimits {
    pub(crate) request_limits: AppliedRateLimits,
    pub(crate) request_limit_ctx: RateLimitContext,
    pub(crate) max_observed_request_body_bytes: usize,
    pub(crate) body_read_timeout: Duration,
}

pub(crate) struct RequestObservation {
    pub(crate) request_rpc: Option<crate::http::rpc::RpcMatchContext>,
    pub(crate) response_request_observation: CandidateRequestObservationRequirements,
    pub(crate) request_body_observed: bool,
    pub(crate) request_rpc_observed: bool,
}

pub(crate) struct PreparedRequestParts<P, M> {
    pub(crate) req: hyper::Request<Body>,
    pub(crate) base: BaseRequestFields,
    pub(crate) context: RequestContext,
    pub(crate) policy: P,
    pub(crate) limits: RequestLimits,
    pub(crate) observation: RequestObservation,
    pub(crate) mode: M,
}
