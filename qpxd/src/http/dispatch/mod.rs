pub(crate) mod access;
pub(crate) mod audit;
pub(crate) mod audit_builder;
pub(crate) mod cache;
pub(crate) mod cache_decision;
pub(crate) mod connect_policy;
pub(crate) mod error;
pub(crate) mod ext_authz_access;
pub(crate) mod guard;
pub(crate) mod limit_response;
pub(crate) mod metrics;
pub(crate) mod outcome;
pub(crate) mod prepare;
pub(crate) mod response_policy;
pub(crate) mod websocket;

pub(crate) use access::{
    HttpAccessAllowed, HttpAccessDecision, HttpAccessInput, enforce_http_access,
};
pub(crate) use audit::{DispatchAuditContext, annotate_dispatch_response};
pub(crate) use audit_builder::{DispatchAuditInput, build_dispatch_audit_context};
pub(crate) use cache::{
    DispatchCacheCollapseOutcome, DispatchCacheLookupOutcome, DispatchCacheWriteInput,
    DispatchCachedResponseInput, dispatch_cache_collapse_continue,
    dispatch_cache_collapse_response, finalize_dispatch_cached_response,
    finalize_dispatch_stale_if_error_response, prepare_dispatch_cache_keys,
    write_dispatch_cache_result,
};
pub(crate) use cache_decision::{
    DispatchCacheDecisionInput, DispatchCollapsedCacheDecisionInput, cache_decision_is_hit,
    finalize_dispatch_cache_decision, finalize_dispatch_collapsed_cache_decision,
};
pub(crate) use connect_policy::{
    DispatchConnectRuleContextInput, build_dispatch_connect_rule_context,
};
pub(crate) use error::DispatchError;
pub(crate) use ext_authz_access::{
    ExtAuthzHttpAccessInput, ExtAuthzHttpAccessOutcome, apply_ext_authz_http_access,
};
pub(crate) use guard::{DispatchGuardInput, evaluate_http_guard};
pub(crate) use limit_response::{
    concurrency_limited_response_for_parts, rate_limit_response_for_parts,
};
pub(crate) use metrics::{
    record_cache_lookup_duration, record_cache_lookup_result, record_response_policy_action,
    record_upstream_request_duration,
};
pub(crate) use outcome::DispatchOutcome;
pub(crate) use prepare::response::{
    annotated_local_response, annotated_max_forwards_response, prepare_http_module_local_response,
    request_body_too_large_response,
};
pub(crate) use prepare::{
    DispatchRequestPrepareInput, PreparedDispatchRequest, prepare_dispatch_request,
};
pub(crate) use response_policy::{
    DispatchResponsePolicyInput, DispatchResponsePolicyOutcome, apply_dispatch_response_policy,
};
pub(crate) use websocket::{
    DispatchWebsocketProxyInput, emit_dispatch_websocket_response_preview,
    proxy_dispatch_websocket_http1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProxyKind {
    Forward,
    Reverse,
    Transparent,
    #[cfg(feature = "mitm")]
    Mitm,
}

impl ProxyKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Reverse => "reverse",
            Self::Transparent => "transparent",
            #[cfg(feature = "mitm")]
            Self::Mitm => "mitm",
        }
    }
}
