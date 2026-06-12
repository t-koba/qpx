use super::{DispatchAuditContext, DispatchCachedResponseInput, DispatchOutcome};
use crate::http::capture::cache_flow::CacheLookupDecision;
use crate::http::dispatch::finalize_dispatch_cached_response;
use anyhow::Result;
use hyper::{Method, Response};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;

pub(crate) fn cache_decision_is_hit(decision: &CacheLookupDecision) -> bool {
    use CacheLookupDecision::{Hit, StaleWhileRevalidate};
    matches!(decision, Hit(_) | StaleWhileRevalidate(_, _))
}

pub(crate) struct DispatchCacheDecisionInput<'a> {
    pub(crate) decision: CacheLookupDecision,
    pub(crate) hit_outcome: DispatchOutcome,
    pub(crate) stale_outcome: DispatchOutcome,
    pub(crate) plan: &'a crate::runtime::ExecutionPlan,
    pub(crate) request_method: &'a Method,
    pub(crate) response_version: Option<http::Version>,
    pub(crate) proxy_name: &'a str,
    pub(crate) headers: Option<&'a CompiledHeaderControl>,
    pub(crate) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(crate) audit: &'a DispatchAuditContext,
}

pub(crate) struct DispatchCollapsedCacheDecisionInput<'a> {
    pub(crate) decision: CacheLookupDecision,
    pub(crate) plan: &'a crate::runtime::ExecutionPlan,
    pub(crate) request_method: &'a Method,
    pub(crate) response_version: Option<http::Version>,
    pub(crate) proxy_name: &'a str,
    pub(crate) headers: Option<&'a CompiledHeaderControl>,
    pub(crate) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(crate) audit: &'a DispatchAuditContext,
}

pub(crate) async fn finalize_dispatch_cache_decision(
    input: DispatchCacheDecisionInput<'_>,
) -> Result<Option<Response<Body>>> {
    let (response, outcome) = match input.decision {
        CacheLookupDecision::Hit(hit) => (hit, input.hit_outcome),
        CacheLookupDecision::StaleWhileRevalidate(hit, _) => (*hit, input.stale_outcome),
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            (response, DispatchOutcome::CacheOnlyIfCachedMiss)
        }
        CacheLookupDecision::Miss => return Ok(None),
    };
    Ok(Some(
        finalize_dispatch_cached_response(DispatchCachedResponseInput {
            response,
            outcome,
            plan: input.plan,
            request_method: input.request_method,
            response_version: input.response_version,
            proxy_name: input.proxy_name,
            headers: input.headers,
            http_modules: input.http_modules,
            audit: input.audit,
        })
        .await?,
    ))
}

pub(crate) async fn finalize_dispatch_collapsed_cache_decision(
    input: DispatchCollapsedCacheDecisionInput<'_>,
) -> Result<Option<Response<Body>>> {
    finalize_dispatch_cache_decision(DispatchCacheDecisionInput {
        decision: input.decision,
        hit_outcome: DispatchOutcome::CacheCollapsedHit,
        stale_outcome: DispatchOutcome::CacheCollapsedStale,
        plan: input.plan,
        request_method: input.request_method,
        response_version: input.response_version,
        proxy_name: input.proxy_name,
        headers: input.headers,
        http_modules: input.http_modules,
        audit: input.audit,
    })
    .await
}
