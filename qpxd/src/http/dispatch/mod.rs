pub(crate) mod access;
pub(crate) mod audit;
pub(crate) mod cache;
pub(crate) mod connect_policy;
pub(crate) mod error;
pub(crate) mod guard;
pub(crate) mod metrics;
pub(crate) mod outcome;
pub(crate) mod prepare;
pub(crate) mod rate_limit;
pub(crate) mod response_policy;
pub(crate) mod websocket;

pub(crate) use access::{ExtAuthzDenyResponseInput, ext_authz_deny_response};
pub(crate) use audit::{DispatchAuditContext, annotate_dispatch_response};
pub(crate) use cache::{
    DispatchCacheCollapseOutcome, DispatchCacheLookupOutcome, DispatchCacheWriteInput,
    DispatchCachedResponseInput, finalize_dispatch_cached_response,
    finalize_dispatch_stale_if_error_response, prepare_dispatch_cache_keys,
    write_dispatch_cache_result,
};
pub(crate) use connect_policy::{
    DispatchConnectRuleContextInput, build_dispatch_connect_rule_context,
};
pub(crate) use error::DispatchError;
pub(crate) use guard::{DispatchGuardInput, evaluate_http_guard};
pub(crate) use metrics::{
    record_cache_lookup_duration, record_cache_lookup_result, record_response_policy_action,
    record_upstream_request_duration,
};
pub(crate) use outcome::DispatchOutcome;
pub(crate) use prepare::{
    DispatchRequestPrepareInput, PreparedDispatchRequest, prepare_dispatch_request,
};
pub(crate) use rate_limit::{DispatchRateLimitInput, rate_limit_response};
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

impl std::fmt::Display for ProxyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
