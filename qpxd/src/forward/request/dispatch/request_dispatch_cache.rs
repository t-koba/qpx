use crate::cache::CacheRequestKey;
use crate::forward::request::resolve_upstream;
use crate::http::body::Body;
use crate::http::capture::cache_flow::{
    CacheLookupDecision, CacheWritebackContext, clone_request_head_for_revalidation,
    lookup_with_revalidation, process_upstream_response_for_cache,
};
use crate::http::dispatch::{
    DispatchAuditContext, DispatchCacheCollapseOutcome, DispatchCacheLookupOutcome,
    DispatchCachedResponseInput, finalize_dispatch_cached_response, prepare_dispatch_cache_keys,
    record_cache_lookup_duration, record_cache_lookup_result,
};
use crate::runtime::Runtime;
use crate::upstream::http1::proxy_http1_request;
use anyhow::Result;
use hyper::{Method, Request, Response};
use qpx_core::config::ActionKind;
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
        input.state.messages.cache_miss.as_str(),
    )
    .await;
    record_cache_lookup_duration(input.audit.kind, lookup_started.elapsed());
    let (lookup_decision, lookup_revalidation_state) = lookup_result?;
    let cache_hit = matches!(
        lookup_decision,
        CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
    );
    input.http_modules.on_cache_lookup(cache_hit).await?;
    match lookup_decision {
        CacheLookupDecision::Hit(hit) => {
            let response = finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response: hit,
                outcome: crate::http::dispatch::DispatchOutcome::CacheHit,
                request_method: input.request_method,
                response_version: None,
                proxy_name: input.proxy_name,
                headers: input.headers,
                http_modules: input.http_modules,
                audit: input.audit,
            })
            .await?;
            Ok(DispatchCacheLookupOutcome::Response(response))
        }
        CacheLookupDecision::StaleWhileRevalidate(hit, state) => {
            maybe_spawn_forward_background_revalidation(&input, state.as_ref());
            let response = finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response: *hit,
                outcome: crate::http::dispatch::DispatchOutcome::CacheStale,
                request_method: input.request_method,
                response_version: None,
                proxy_name: input.proxy_name,
                headers: input.headers,
                http_modules: input.http_modules,
                audit: input.audit,
            })
            .await?;
            Ok(DispatchCacheLookupOutcome::Response(response))
        }
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            let response = finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response,
                outcome: crate::http::dispatch::DispatchOutcome::CacheOnlyIfCachedMiss,
                request_method: input.request_method,
                response_version: Some(input.client_version),
                proxy_name: input.proxy_name,
                headers: input.headers,
                http_modules: input.http_modules,
                audit: input.audit,
            })
            .await?;
            Ok(DispatchCacheLookupOutcome::Response(response))
        }
        CacheLookupDecision::Miss => {
            record_cache_lookup_result(input.audit.kind, "miss");
            Ok(DispatchCacheLookupOutcome::Continue(
                lookup_revalidation_state,
            ))
        }
    }
}

fn maybe_spawn_forward_background_revalidation(
    input: &ForwardCacheLookupInput<'_>,
    state: &crate::cache::RevalidationState,
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
    let Some(guard) = crate::cache::try_begin_background_revalidation(state) else {
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
        )
        .await
        else {
            return;
        };
        let response_delay_secs = started.elapsed().as_secs();
        let state_ref = runtime.state();
        let backends = &state_ref.cache.backends;
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
                    state_ref
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
    pub(super) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(super) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(super) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(super) upstream_timeout: Duration,
    pub(super) audit: &'a DispatchAuditContext,
    pub(super) revalidation_state: Option<crate::cache::RevalidationState>,
}

pub(super) async fn try_forward_cache_collapse(
    input: ForwardCacheCollapseInput<'_>,
) -> Result<DispatchCacheCollapseOutcome> {
    let mut revalidation_state = input.revalidation_state.clone();
    let mut guard = None;
    if input.request_method != Method::GET {
        return Ok(DispatchCacheCollapseOutcome::Continue {
            revalidation_state: revalidation_state.map(Box::new),
            guard,
        });
    }
    let (Some(snapshot), Some(policy), Some(lookup_key)) = (
        input.request_headers_snapshot,
        input.cache_policy,
        input.cache_lookup_key,
    ) else {
        return Ok(DispatchCacheCollapseOutcome::Continue {
            revalidation_state: revalidation_state.map(Box::new),
            guard,
        });
    };
    match crate::cache::begin_request_collapse(lookup_key) {
        crate::cache::RequestCollapseJoin::Leader(leader) => guard = Some(leader),
        crate::cache::RequestCollapseJoin::Follower(waiter) => {
            if waiter.wait(input.upstream_timeout).await {
                let (lookup_decision, next_revalidation_state) = lookup_with_revalidation(
                    input.req,
                    snapshot,
                    input.cache_lookup_key,
                    Some(policy),
                    &input.state.cache.backends,
                    input.state.messages.cache_miss.as_str(),
                )
                .await?;
                revalidation_state = next_revalidation_state;
                let cache_hit = matches!(
                    lookup_decision,
                    CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
                );
                input.http_modules.on_cache_lookup(cache_hit).await?;
                if let Some(response) =
                    finalize_forward_collapsed_cache_decision(input, lookup_decision).await?
                {
                    return Ok(DispatchCacheCollapseOutcome::Response(Box::new(response)));
                }
            }
        }
    }
    Ok(DispatchCacheCollapseOutcome::Continue {
        revalidation_state: revalidation_state.map(Box::new),
        guard,
    })
}

async fn finalize_forward_collapsed_cache_decision(
    input: ForwardCacheCollapseInput<'_>,
    lookup_decision: CacheLookupDecision,
) -> Result<Option<Response<Body>>> {
    match lookup_decision {
        CacheLookupDecision::Hit(hit) => Ok(Some(
            finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response: hit,
                outcome: crate::http::dispatch::DispatchOutcome::CacheCollapsedHit,
                request_method: input.request_method,
                response_version: None,
                proxy_name: input.proxy_name,
                headers: input.headers,
                http_modules: input.http_modules,
                audit: input.audit,
            })
            .await?,
        )),
        CacheLookupDecision::StaleWhileRevalidate(hit, _) => Ok(Some(
            finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response: *hit,
                outcome: crate::http::dispatch::DispatchOutcome::CacheCollapsedStale,
                request_method: input.request_method,
                response_version: None,
                proxy_name: input.proxy_name,
                headers: input.headers,
                http_modules: input.http_modules,
                audit: input.audit,
            })
            .await?,
        )),
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            let response = finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response,
                outcome: crate::http::dispatch::DispatchOutcome::CacheOnlyIfCachedMiss,
                request_method: input.request_method,
                response_version: Some(input.client_version),
                proxy_name: input.proxy_name,
                headers: input.headers,
                http_modules: input.http_modules,
                audit: input.audit,
            })
            .await?;
            Ok(Some(response))
        }
        CacheLookupDecision::Miss => Ok(None),
    }
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
