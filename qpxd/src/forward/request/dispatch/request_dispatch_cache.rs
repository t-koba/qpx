use crate::forward::request::resolve_upstream;
use crate::http::capture::cache_flow::{
    CacheLookupDecision, CacheWritebackContext, clone_request_head_for_revalidation,
    lookup_with_revalidation, process_upstream_response_for_cache,
};
use crate::http::dispatch::{
    DispatchAuditContext, DispatchCacheCollapseOutcome, DispatchCacheDecisionInput,
    DispatchCacheLookupOutcome, DispatchCollapsedCacheDecisionInput, DispatchOutcome,
    cache_decision_is_hit, dispatch_cache_collapse_continue, dispatch_cache_collapse_response,
    finalize_dispatch_cache_decision, finalize_dispatch_collapsed_cache_decision,
    prepare_dispatch_cache_keys, record_cache_lookup_duration, record_cache_lookup_result,
};
use crate::runtime::Runtime;
use crate::upstream::http1::proxy_http1_request;
use anyhow::Result;
use hyper::{Method, Request, Response};
use qpx_core::config::ActionKind;
use qpx_http::body::Body;
use qpxd_cache::CacheRequestKey;
use std::time::Duration;

pub(super) struct ForwardCacheLookupInput<'a> {
    pub(super) req: &'a mut Request<Body>,
    pub(super) runtime: &'a Runtime,
    pub(super) action: &'a qpx_core::config::ActionConfig,
    pub(super) listener_name: &'a str,
    pub(super) http_authority: &'a str,
    pub(super) upstream_timeout: Duration,
    pub(super) request_method: &'a Method,
    pub(super) client_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    pub(super) selected_plan: &'a crate::runtime::ExecutionPlan,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) audit: &'a DispatchAuditContext,
}

pub(super) async fn try_forward_cache_lookup(
    input: ForwardCacheLookupInput<'_>,
) -> Result<DispatchCacheLookupOutcome> {
    let Some(snapshot) = input.request_headers_snapshot else {
        return Ok(DispatchCacheLookupOutcome::Continue(None));
    };
    if input.cache_policy.is_none() {
        return Ok(DispatchCacheLookupOutcome::Continue(None));
    }
    let lookup_started = std::time::Instant::now();
    let lookup_result = lookup_with_revalidation(
        input.req,
        snapshot,
        input.cache_lookup_key,
        input.cache_policy,
        &input.state.cache.backends,
        &input.state.cache.background_revalidations,
        input.state.messages.cache_miss.as_str(),
    )
    .await;
    record_cache_lookup_duration(input.audit.kind, lookup_started.elapsed());
    let (lookup_decision, lookup_revalidation_state) = lookup_result?;
    input
        .http_modules
        .on_cache_lookup(cache_decision_is_hit(&lookup_decision))
        .await?;
    let response_version = matches!(lookup_decision, CacheLookupDecision::OnlyIfCachedMiss(_))
        .then_some(input.client_version);
    match &lookup_decision {
        CacheLookupDecision::Hit(_) | CacheLookupDecision::OnlyIfCachedMiss(_) => {}
        CacheLookupDecision::StaleWhileRevalidate(_, state) => {
            maybe_spawn_forward_background_revalidation(&input, state);
        }
        CacheLookupDecision::Miss => {
            record_cache_lookup_result(input.audit.kind, "miss");
            return Ok(DispatchCacheLookupOutcome::Continue(
                lookup_revalidation_state.map(Box::new),
            ));
        }
    }
    let response = finalize_dispatch_cache_decision(DispatchCacheDecisionInput {
        decision: lookup_decision,
        hit_outcome: DispatchOutcome::CacheHit,
        stale_outcome: DispatchOutcome::CacheStale,
        plan: input.selected_plan,
        request_method: input.request_method,
        response_version,
        proxy_name: input.proxy_name,
        headers: input.headers,
        http_modules: input.http_modules,
        audit: input.audit,
    })
    .await?;
    Ok(match response {
        Some(response) => DispatchCacheLookupOutcome::Response(Box::new(response)),
        None => DispatchCacheLookupOutcome::Continue(lookup_revalidation_state.map(Box::new)),
    })
}

fn maybe_spawn_forward_background_revalidation(
    input: &ForwardCacheLookupInput<'_>,
    state: &qpxd_cache::RevalidationState,
) {
    if *input.request_method != Method::GET {
        return;
    }
    let (Some(policy), Some(snapshot), Some(lookup_key), Some(target_key)) = (
        input.cache_policy,
        input.request_headers_snapshot,
        input.cache_lookup_key,
        input.cache_target_key,
    ) else {
        return;
    };
    let Some(guard) = state.begin_background_revalidation() else {
        return;
    };
    let runtime = input.runtime.clone();
    let action = input.action.clone();
    let listener_name = input.listener_name.to_string();
    let http_authority = input.http_authority.to_string();
    let policy = policy.clone();
    let snapshot = snapshot.clone();
    let lookup_key = lookup_key.clone();
    let target_key = target_key.clone();
    let bg_req = clone_request_head_for_revalidation(input.req);
    let upstream_timeout = input.upstream_timeout;
    let state = state.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let started = std::time::Instant::now();
        let runtime_state = runtime.state();
        let upstream = resolve_upstream(&action, &runtime_state, listener_name.as_str())
            .ok()
            .flatten();
        let Ok(resp) = proxy_http1_request(
            bg_req,
            upstream.as_ref(),
            http_authority.as_str(),
            upstream_timeout,
            &runtime_state.pools.upstream_proxy,
        )
        .await
        else {
            return;
        };
        let response_delay_secs = started.elapsed().as_secs();
        let backends = &runtime_state.cache.backends;
        let method = Method::GET;
        let _ = process_upstream_response_for_cache(
            resp,
            CacheWritebackContext {
                request_method: &method,
                response_delay_secs,
                cache_target_key: Some(&target_key),
                cache_lookup_key: Some(&lookup_key),
                cache_policy: Some(&policy),
                request_headers_snapshot: &snapshot,
                revalidation_state: Some(state),
                request_collapse_guard: None,
                body_read_timeout: std::time::Duration::from_millis(
                    runtime_state
                        .plan
                        .limits
                        .timeouts
                        .upstream_http_timeout_ms
                        .max(1),
                ),
                backends,
            },
        )
        .await;
    });
}

pub(super) struct ForwardCacheCollapseInput<'a> {
    pub(super) req: &'a mut Request<Body>,
    pub(super) request_method: &'a Method,
    pub(super) client_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    pub(super) selected_plan: &'a crate::runtime::ExecutionPlan,
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) upstream_timeout: Duration,
    pub(super) audit: &'a DispatchAuditContext,
    pub(super) revalidation_state: Option<qpxd_cache::RevalidationState>,
}

pub(super) async fn try_forward_cache_collapse(
    input: ForwardCacheCollapseInput<'_>,
) -> Result<DispatchCacheCollapseOutcome> {
    let mut revalidation_state = input.revalidation_state.clone();
    let mut guard = None;
    if input.request_method != Method::GET {
        return Ok(dispatch_cache_collapse_continue(revalidation_state, guard));
    }
    let (Some(snapshot), Some(policy), Some(lookup_key)) = (
        input.request_headers_snapshot,
        input.cache_policy,
        input.cache_lookup_key,
    ) else {
        return Ok(dispatch_cache_collapse_continue(revalidation_state, guard));
    };
    match input.state.cache.begin_request_collapse(lookup_key) {
        qpxd_cache::RequestCollapseJoin::Leader(leader) => guard = Some(leader),
        qpxd_cache::RequestCollapseJoin::Follower(waiter) => {
            if waiter.wait(input.upstream_timeout).await {
                let (lookup_decision, next_revalidation_state) = lookup_with_revalidation(
                    input.req,
                    snapshot,
                    input.cache_lookup_key,
                    Some(policy),
                    &input.state.cache.backends,
                    &input.state.cache.background_revalidations,
                    input.state.messages.cache_miss.as_str(),
                )
                .await?;
                revalidation_state = next_revalidation_state;
                input
                    .http_modules
                    .on_cache_lookup(cache_decision_is_hit(&lookup_decision))
                    .await?;
                if let Some(response) =
                    finalize_forward_collapsed_cache_decision(input, lookup_decision).await?
                {
                    return Ok(dispatch_cache_collapse_response(response));
                }
            }
        }
    }
    Ok(dispatch_cache_collapse_continue(revalidation_state, guard))
}

async fn finalize_forward_collapsed_cache_decision(
    input: ForwardCacheCollapseInput<'_>,
    lookup_decision: CacheLookupDecision,
) -> Result<Option<Response<Body>>> {
    let response_version = matches!(lookup_decision, CacheLookupDecision::OnlyIfCachedMiss(_))
        .then_some(input.client_version);
    finalize_dispatch_collapsed_cache_decision(DispatchCollapsedCacheDecisionInput {
        decision: lookup_decision,
        plan: input.selected_plan,
        request_method: input.request_method,
        response_version,
        proxy_name: input.proxy_name,
        headers: input.headers,
        http_modules: input.http_modules,
        audit: input.audit,
    })
    .await
}

pub(super) fn prepare_forward_cache_keys(
    req: &Request<Body>,
    action: &qpx_core::config::ActionConfig,
    cache_policy: Option<&qpx_core::config::CachePolicyConfig>,
) -> Result<(
    Option<http::HeaderMap>,
    Option<CacheRequestKey>,
    Option<CacheRequestKey>,
)> {
    let cache_applicable = cache_policy.is_some()
        && matches!(
            action.kind,
            ActionKind::Direct | ActionKind::Proxy | ActionKind::Tunnel | ActionKind::Inspect
        );
    if !cache_applicable {
        return Ok((None, None, None));
    }
    prepare_dispatch_cache_keys(req, cache_policy, req.uri().scheme_str().unwrap_or("http"))
}
