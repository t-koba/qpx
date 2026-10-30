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
    prepare_query_aware_cache_key_pair, record_cache_lookup_duration, record_cache_lookup_result,
};
use crate::runtime::Runtime;
use crate::upstream::http1::proxy_http1_request;
use anyhow::Result;
use hyper::Method;
use qpx_core::config::ActionKind;
use qpx_core::http_message::{Request, Response as OwnerResponse};
use qpx_http::body::Body;
use qpxd_cache::CacheRequestKey;
use std::time::Duration;

#[derive(Clone, Copy)]
pub(super) struct ForwardCacheContext<'a> {
    pub(super) request_method: &'a Method,
    pub(super) client_version: http::Version,
    pub(super) proxy_name: &'a str,
    pub(super) headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    pub(super) selected_plan: &'a crate::runtime::ExecutionPlan,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) request_headers_snapshot: Option<&'a Request<()>>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) upstream_timeout: Duration,
    pub(super) audit: &'a DispatchAuditContext,
}

pub(super) struct ForwardCacheLookupInput<'a> {
    pub(super) context: ForwardCacheContext<'a>,
    pub(super) req: &'a mut Request<Body>,
    pub(super) runtime: &'a Runtime,
    pub(super) action: &'a qpx_core::config::ActionConfig,
    pub(super) listener_name: &'a str,
    pub(super) http_authority: &'a str,
    pub(super) cache_target_key: Option<&'a CacheRequestKey>,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
}

pub(super) async fn try_forward_cache_lookup(
    input: ForwardCacheLookupInput<'_>,
) -> Result<DispatchCacheLookupOutcome> {
    let Some(snapshot) = input.context.request_headers_snapshot else {
        return Ok(DispatchCacheLookupOutcome::Continue(None));
    };
    if input.context.cache_policy.is_none() {
        return Ok(DispatchCacheLookupOutcome::Continue(None));
    }
    let lookup_started = std::time::Instant::now();
    let lookup_result = lookup_with_revalidation(
        input.req,
        snapshot,
        input.context.cache_lookup_key,
        input.context.cache_policy,
        &input.context.state.cache.backends,
        &input.context.state.cache.background_revalidations,
        input.context.state.messages.cache_miss.as_str(),
    )
    .await;
    record_cache_lookup_duration(input.context.audit.kind, lookup_started.elapsed());
    let (lookup_decision, lookup_revalidation_state) = lookup_result?;
    input
        .http_modules
        .on_cache_lookup(cache_decision_is_hit(&lookup_decision))
        .await?;
    let response_version = matches!(lookup_decision, CacheLookupDecision::OnlyIfCachedMiss(_))
        .then_some(input.context.client_version);
    match &lookup_decision {
        CacheLookupDecision::Hit(_) | CacheLookupDecision::OnlyIfCachedMiss(_) => {}
        CacheLookupDecision::StaleWhileRevalidate(_, state) => {
            maybe_spawn_forward_background_revalidation(&input, state);
        }
        CacheLookupDecision::Miss => {
            record_cache_lookup_result(input.context.audit.kind, "miss");
            return Ok(DispatchCacheLookupOutcome::Continue(
                lookup_revalidation_state.map(Box::new),
            ));
        }
    }
    let response = finalize_dispatch_cache_decision(DispatchCacheDecisionInput {
        decision: lookup_decision,
        hit_outcome: DispatchOutcome::CacheHit,
        stale_outcome: DispatchOutcome::CacheStale,
        plan: input.context.selected_plan,
        request_method: input.context.request_method,
        response_version,
        proxy_name: input.context.proxy_name,
        headers: input.context.headers,
        http_modules: input.http_modules,
        audit: input.context.audit,
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
    if *input.context.request_method != Method::GET {
        return;
    }
    let (Some(policy), Some(_snapshot), Some(lookup_key), Some(target_key)) = (
        input.context.cache_policy,
        input.context.request_headers_snapshot,
        input.context.cache_lookup_key,
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
    let lookup_key = lookup_key.clone();
    let target_key = target_key.clone();
    let bg_req = clone_request_head_for_revalidation(input.req);
    let snapshot = clone_request_head_for_revalidation(&bg_req);
    let upstream_timeout = input.context.upstream_timeout;
    let state = state.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let started = std::time::Instant::now();
        let runtime_state = runtime.state();
        let upstream = resolve_upstream(&action, &runtime_state, listener_name.as_str())
            .ok()
            .flatten();
        let bg_req = bg_req.map_body(|()| Body::empty());
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
        let _ = process_upstream_response_for_cache(
            OwnerResponse::from_http(resp),
            CacheWritebackContext {
                request_snapshot: &snapshot,
                response_delay_secs,
                cache_target_key: Some(&target_key),
                cache_lookup_key: Some(&lookup_key),
                cache_policy: Some(&policy),
                revalidation_state: Some(state),
                request_collapse_guard: None,
                body_read_timeout: runtime_state
                    .plan
                    .limits
                    .timeouts
                    .upstream_body_read_timeout(),
                writeback_admission: &runtime_state.cache.writeback_admission,
                backends,
            },
        )
        .await;
    });
}

pub(super) struct ForwardCacheCollapseInput<'a> {
    pub(super) context: ForwardCacheContext<'a>,
    pub(super) req: &'a mut Request<Body>,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) revalidation_state: Option<qpxd_cache::RevalidationState>,
}

pub(super) async fn try_forward_cache_collapse(
    input: ForwardCacheCollapseInput<'_>,
) -> Result<DispatchCacheCollapseOutcome<OwnerResponse<Body>>> {
    let mut revalidation_state = input.revalidation_state.clone();
    let mut guard = None;
    if input.context.request_method != Method::GET {
        return Ok(dispatch_cache_collapse_continue(revalidation_state, guard));
    }
    let (Some(snapshot), Some(policy), Some(lookup_key)) = (
        input.context.request_headers_snapshot,
        input.context.cache_policy,
        input.context.cache_lookup_key,
    ) else {
        return Ok(dispatch_cache_collapse_continue(revalidation_state, guard));
    };
    match input.context.state.cache.begin_request_collapse(lookup_key) {
        qpxd_cache::RequestCollapseJoin::Leader(leader) => guard = Some(leader),
        qpxd_cache::RequestCollapseJoin::Follower(waiter) => {
            if waiter.wait(input.context.upstream_timeout).await {
                let (lookup_decision, next_revalidation_state) = lookup_with_revalidation(
                    input.req,
                    snapshot,
                    input.context.cache_lookup_key,
                    Some(policy),
                    &input.context.state.cache.backends,
                    &input.context.state.cache.background_revalidations,
                    input.context.state.messages.cache_miss.as_str(),
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
) -> Result<Option<OwnerResponse<Body>>> {
    let response_version = matches!(lookup_decision, CacheLookupDecision::OnlyIfCachedMiss(_))
        .then_some(input.context.client_version);
    finalize_dispatch_collapsed_cache_decision(DispatchCollapsedCacheDecisionInput {
        decision: lookup_decision,
        plan: input.context.selected_plan,
        request_method: input.context.request_method,
        response_version,
        proxy_name: input.context.proxy_name,
        headers: input.context.headers,
        http_modules: input.http_modules,
        audit: input.context.audit,
    })
    .await
}

pub(super) async fn prepare_forward_cache_keys(
    req: Request<Body>,
    action: &qpx_core::config::ActionConfig,
    cache_policy: Option<&qpx_core::config::CachePolicyConfig>,
    max_request_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<(
    Request<Body>,
    Option<Request<()>>,
    Option<CacheRequestKey>,
    Option<CacheRequestKey>,
)> {
    let cache_applicable = cache_policy.is_some()
        && matches!(
            action.kind,
            ActionKind::Direct | ActionKind::Proxy | ActionKind::Tunnel | ActionKind::Inspect
        );
    if !cache_applicable {
        return Ok((req, None, None, None));
    }
    // RFC 10008 Sec 2.7: QUERY keys bind request content via the shared
    // helper; an over-limit body fails closed via the helper error.
    let scheme = req.uri().scheme_str().unwrap_or("http").to_string();
    let (req, lookup, target) = prepare_query_aware_cache_key_pair(
        req,
        cache_policy,
        scheme.as_str(),
        max_request_body_bytes,
        body_read_timeout,
    )
    .await?;
    let snapshot = lookup
        .as_ref()
        .map(|_| clone_request_head_for_revalidation(&req));
    Ok((req, snapshot, lookup, target))
}

#[cfg(test)]
mod forward_query_cache_tests {
    use super::*;
    use qpx_core::http_message::Request as OwnerRequest;

    async fn forward_keys(content_type: &str, body: &'static str) -> Option<CacheRequestKey> {
        let action = qpx_core::config::ActionConfig {
            kind: ActionKind::Direct,
            upstream: None,
            local_response: None,
        };
        let policy = qpx_core::config::CachePolicyConfig {
            enabled: true,
            backend: "test".to_string(),
            namespace: None,
            default_ttl_secs: None,
            max_object_bytes: 1024 * 1024,
            allow_set_cookie_store: false,
            allow_authorization_without_vary_store: false,
        };
        let req = OwnerRequest::from_http(
            http::Request::builder()
                .method(Method::QUERY)
                .uri("http://example.com/search")
                .header(http::header::CONTENT_TYPE, content_type)
                .body(Body::from(body))
                .unwrap(),
        );
        let (_, _, lookup, _) =
            prepare_forward_cache_keys(req, &action, Some(&policy), 1024, Duration::from_secs(1))
                .await
                .unwrap();
        lookup
    }

    #[tokio::test]
    async fn forward_query_keys_differ_by_body_and_content_type() {
        let first = forward_keys("application/sql", "select 1").await.unwrap();
        let other_body = forward_keys("application/sql", "select 2").await.unwrap();
        let other_type = forward_keys("text/plain", "select 1").await.unwrap();
        let same = forward_keys("application/sql", "select 1").await.unwrap();
        assert_ne!(first.content_digest, other_body.content_digest);
        assert_ne!(first.content_digest, other_type.content_digest);
        assert_eq!(first.content_digest, same.content_digest);
        // Same primary index (shared URI), distinct variants (content digest).
        assert_eq!(first.primary_hash(), other_body.primary_hash());
    }
}
