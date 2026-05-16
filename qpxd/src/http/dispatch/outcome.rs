#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DispatchOutcome {
    Allow,
    Block,
    CacheCollapsedHit,
    CacheCollapsedStale,
    CacheHit,
    CacheOnlyIfCachedMiss,
    CacheStale,
    #[cfg(feature = "auth-basic")]
    Challenge,
    ConcurrencyLimited,
    EarlyResponse,
    Error,
    #[cfg(feature = "auth-basic")]
    Forbidden,
    GuardReject,
    HttpModuleLocalResponse,
    MaxForwards,
    RateLimited,
    Respond,
    ResponseLocalResponse,
    ResponseRuleLocalResponse,
    StaleIfError,
    ExtAuthzDeny,
    ExtAuthzLocalResponse,
}

impl DispatchOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::CacheCollapsedHit => "cache_collapsed_hit",
            Self::CacheCollapsedStale => "cache_collapsed_stale",
            Self::CacheHit => "cache_hit",
            Self::CacheOnlyIfCachedMiss => "cache_only_if_cached_miss",
            Self::CacheStale => "cache_stale",
            #[cfg(feature = "auth-basic")]
            Self::Challenge => "challenge",
            Self::ConcurrencyLimited => "concurrency_limited",
            Self::EarlyResponse => "early_response",
            Self::Error => "error",
            #[cfg(feature = "auth-basic")]
            Self::Forbidden => "forbidden",
            Self::GuardReject => "http_guard_reject",
            Self::HttpModuleLocalResponse => "http_module_local_response",
            Self::MaxForwards => "max_forwards",
            Self::RateLimited => "rate_limited",
            Self::Respond => "respond",
            Self::ResponseLocalResponse => "response_local_response",
            Self::ResponseRuleLocalResponse => "response_rule_local_response",
            Self::StaleIfError => "stale_if_error",
            Self::ExtAuthzDeny => "ext_authz_deny",
            Self::ExtAuthzLocalResponse => "ext_authz_local_response",
        }
    }

    pub(crate) fn audit_outcome(self) -> Self {
        self
    }
}

impl std::fmt::Display for DispatchOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
