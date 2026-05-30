use super::super::ConnectTarget;
use crate::http::body::Body;
use crate::http::dispatch::DispatchAuditContext;
use crate::http::policy::EvaluatedAction;
use hyper::Request;
use std::sync::Arc;
use tokio::time::Duration;

pub(super) type TransparentPrepareOutcome =
    crate::http::pipeline::PrepareOutcome<TransparentPreparedRequest>;

pub(super) type TransparentPreparedRequest =
    crate::http::pipeline::PreparedRequestParts<TransparentPreparedPolicy, TransparentPreparedMode>;

pub(super) struct TransparentPreparedPolicy {
    pub(super) effective_policy: crate::policy_context::EffectivePolicyContext,
    pub(super) destination: crate::destination::DestinationMetadata,
    pub(super) identity: crate::policy_context::ResolvedIdentity,
    pub(super) sanitized_headers: http::HeaderMap,
    pub(super) response_engine:
        Option<Arc<crate::http::policy::response_policy::HttpResponseRuleEngine>>,
    pub(super) selected_plan: crate::runtime::ExecutionPlan,
    pub(super) policy: Option<Box<EvaluatedAction>>,
    pub(super) early_response: Option<Box<hyper::Response<Body>>>,
    pub(super) matched_rule: Option<String>,
}

pub(super) struct TransparentPreparedMode {
    pub(super) connect_target: ConnectTarget,
    pub(super) host_for_match: Option<String>,
}

pub(super) struct TransparentPolicyEvaluation {
    pub(super) policy: Option<Box<EvaluatedAction>>,
    pub(super) early_response: Option<Box<hyper::Response<Body>>>,
    pub(super) matched_rule: Option<String>,
    pub(super) request_rpc: Option<crate::http::rpc::RpcMatchContext>,
}

pub(super) enum TransparentPolicyStage {
    Decision(Box<TransparentPolicyEvaluation>),
    Observe(qpx_core::rules::CandidateRequestObservationRequirements),
}

pub(super) type TransparentAccessOutcome = crate::http::pipeline::AccessOutcome<TransparentAccess>;

pub(super) struct TransparentAccess {
    pub(super) policy: Box<EvaluatedAction>,
    pub(super) timeout_override: Option<Duration>,
    pub(super) audit: DispatchAuditContext,
}

pub(super) struct TransparentPolicyInput<'a> {
    pub(super) engine: &'a qpx_core::rules::RuleEngine,
    pub(super) req: &'a Request<Body>,
    pub(super) base: &'a crate::http::protocol::base_fields::BaseRequestFields,
    pub(super) sanitized_headers: &'a http::HeaderMap,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) request_rpc: Option<&'a crate::http::rpc::RpcMatchContext>,
    pub(super) proxy_name: &'a str,
    pub(super) forbidden_message: &'a str,
}
