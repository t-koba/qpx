use super::*;

pub(super) async fn prepare_reverse_cache(
    input: ReverseCacheInput<'_>,
) -> Result<ReverseCacheOutcome> {
    let ReverseCacheInput {
        mut req,
        runtime,
        state,
        route,
        conn,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        request_cache_policy,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        http_modules,
        audit_ctx,
    } = input;
    let cache_default_scheme = if conn.tls_terminated { "https" } else { "http" };
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) =
        prepare_dispatch_cache_keys(&req, request_cache_policy, cache_default_scheme)?;
    let mut revalidation_state = None;
    if let (Some(snapshot), Some(policy)) =
        (request_headers_snapshot.as_ref(), request_cache_policy)
    {
        let outcome = reverse_cache_lookup(
            &mut req,
            ReverseCacheLookupInput {
                runtime,
                state,
                route,
                request_method,
                request_version,
                proxy_name,
                route_headers,
                policy,
                snapshot,
                cache_lookup_key: cache_lookup_key.as_ref(),
                cache_target_key: cache_target_key.as_ref(),
                override_upstream,
                seed,
                sticky_seed,
                route_timeout,
                http_modules,
                audit_ctx,
            },
        )
        .await?;
        match outcome {
            DispatchCacheLookupOutcome::Response(response) => {
                return Ok(ReverseCacheOutcome::Response(Box::new(response)));
            }
            DispatchCacheLookupOutcome::Continue(state) => revalidation_state = state,
        }
    }
    let collapse = reverse_cache_collapse(
        &mut req,
        ReverseCacheCollapseInput {
            runtime,
            state,
            request_method,
            request_version,
            proxy_name,
            route_headers,
            request_cache_policy,
            request_headers_snapshot: request_headers_snapshot.as_ref(),
            cache_lookup_key: cache_lookup_key.as_ref(),
            route_timeout,
            http_modules,
            audit_ctx,
            revalidation_state,
        },
    )
    .await?;
    let (revalidation_state, guard) = match collapse {
        DispatchCacheCollapseOutcome::Response(response) => {
            return Ok(ReverseCacheOutcome::Response(Box::new(response)));
        }
        DispatchCacheCollapseOutcome::Continue {
            revalidation_state,
            guard,
        } => (revalidation_state, guard),
    };
    Ok(ReverseCacheOutcome::Continue(Box::new(ReverseCacheState {
        req,
        request_headers_snapshot,
        cache_lookup_key,
        cache_target_key,
        revalidation_state,
        _cache_collapse_guard: guard,
    })))
}

struct ReverseCacheLookupInput<'a> {
    runtime: &'a Runtime,
    state: &'a Arc<runtime::RuntimeState>,
    route: &'a HttpRoute,
    request_method: &'a Method,
    request_version: http::Version,
    proxy_name: &'a str,
    route_headers: Option<&'a CompiledHeaderControl>,
    policy: &'a qpx_core::config::CachePolicyConfig,
    snapshot: &'a http::HeaderMap,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    cache_target_key: Option<&'a CacheRequestKey>,
    override_upstream: Option<&'a str>,
    seed: u64,
    sticky_seed: u64,
    route_timeout: Duration,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a DispatchAuditContext,
}

async fn reverse_cache_lookup(
    req: &mut Request<Body>,
    input: ReverseCacheLookupInput<'_>,
) -> Result<DispatchCacheLookupOutcome> {
    let ReverseCacheLookupInput {
        runtime,
        state,
        route,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        policy,
        snapshot,
        cache_lookup_key,
        cache_target_key,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        http_modules,
        audit_ctx,
    } = input;
    let lookup_started = Instant::now();
    let lookup_result = lookup_with_revalidation(
        req,
        snapshot,
        cache_lookup_key,
        Some(policy),
        &runtime.state().cache.backends,
        state.messages.cache_miss.as_str(),
    )
    .await;
    record_cache_lookup_duration(audit_ctx.kind, lookup_started.elapsed());
    let (lookup_decision, revalidation_state) = lookup_result?;
    let cache_hit = matches!(
        lookup_decision,
        CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
    );
    http_modules.on_cache_lookup(cache_hit).await?;
    match lookup_decision {
        CacheLookupDecision::Hit(hit) => Ok(DispatchCacheLookupOutcome::Response(
            finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response: hit,
                outcome: crate::http::dispatch::DispatchOutcome::CacheHit,
                request_method,
                response_version: Some(request_version),
                proxy_name,
                headers: route_headers,
                http_modules,
                audit: audit_ctx,
            })
            .await?,
        )),
        CacheLookupDecision::StaleWhileRevalidate(hit, state) => {
            maybe_spawn_reverse_revalidation(
                req,
                ReverseRevalidationInput {
                    runtime,
                    route,
                    request_method,
                    policy,
                    snapshot,
                    lookup_key: cache_lookup_key,
                    target_key: cache_target_key,
                    override_upstream,
                    seed,
                    sticky_seed,
                    route_timeout,
                    proxy_name,
                    state,
                },
            );
            Ok(DispatchCacheLookupOutcome::Response(
                finalize_dispatch_cached_response(DispatchCachedResponseInput {
                    response: hit,
                    outcome: crate::http::dispatch::DispatchOutcome::CacheStale,
                    request_method,
                    response_version: Some(request_version),
                    proxy_name,
                    headers: route_headers,
                    http_modules,
                    audit: audit_ctx,
                })
                .await?,
            ))
        }
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            Ok(DispatchCacheLookupOutcome::Response(
                finalize_dispatch_cached_response(DispatchCachedResponseInput {
                    response,
                    outcome: crate::http::dispatch::DispatchOutcome::CacheOnlyIfCachedMiss,
                    request_method,
                    response_version: Some(request_version),
                    proxy_name,
                    headers: route_headers,
                    http_modules,
                    audit: audit_ctx,
                })
                .await?,
            ))
        }
        CacheLookupDecision::Miss => {
            record_cache_lookup_result(audit_ctx.kind, "miss");
            Ok(DispatchCacheLookupOutcome::Continue(revalidation_state))
        }
    }
}

struct ReverseRevalidationInput<'a> {
    runtime: &'a Runtime,
    route: &'a HttpRoute,
    request_method: &'a Method,
    policy: &'a qpx_core::config::CachePolicyConfig,
    snapshot: &'a http::HeaderMap,
    lookup_key: Option<&'a CacheRequestKey>,
    target_key: Option<&'a CacheRequestKey>,
    override_upstream: Option<&'a str>,
    seed: u64,
    sticky_seed: u64,
    route_timeout: Duration,
    proxy_name: &'a str,
    state: crate::cache::RevalidationState,
}

fn maybe_spawn_reverse_revalidation(req: &Request<Body>, input: ReverseRevalidationInput<'_>) {
    let ReverseRevalidationInput {
        runtime,
        route,
        request_method,
        policy,
        snapshot,
        lookup_key,
        target_key,
        override_upstream,
        seed,
        sticky_seed,
        route_timeout,
        proxy_name,
        state,
    } = input;
    if *request_method != Method::GET || route.ipc.is_some() {
        return;
    }
    let Some(lookup_key) = lookup_key else {
        return;
    };
    let Some(target_key) = target_key else {
        return;
    };
    let Some(target) = override_upstream.map(OriginEndpoint::direct).or_else(|| {
        route
            .select_upstream(seed, sticky_seed)
            .map(|u| u.origin.clone())
    }) else {
        return;
    };
    if target.upstream.starts_with("ipc://") || target.upstream.starts_with("ipc+unix://") {
        return;
    }
    let Some(guard) = crate::cache::try_begin_background_revalidation(&state) else {
        return;
    };
    let runtime = runtime.clone();
    let proxy_name = proxy_name.to_string();
    let policy = policy.clone();
    let snapshot = snapshot.clone();
    let lookup_key = lookup_key.clone();
    let target_key = target_key.clone();
    let upstream_trust = route.upstream_trust.clone();
    let bg_req = clone_request_head_for_revalidation(req);
    tokio::spawn(async move {
        let _guard = guard;
        let started = Instant::now();
        let resp = timeout(
            route_timeout,
            proxy_http(
                bg_req,
                &target,
                proxy_name.as_str(),
                upstream_trust.as_deref(),
            ),
        )
        .await;
        let Ok(Ok(resp)) = resp else {
            return;
        };
        let response_delay_secs = started.elapsed().as_secs();
        let state_ref = runtime.state();
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
                body_read_timeout: Duration::from_millis(
                    state_ref.plan.limits.upstream_http_timeout_ms.max(1),
                ),
                backends: &state_ref.cache.backends,
            },
        )
        .await;
    });
}

struct ReverseCacheCollapseInput<'a> {
    runtime: &'a Runtime,
    state: &'a Arc<runtime::RuntimeState>,
    request_method: &'a Method,
    request_version: http::Version,
    proxy_name: &'a str,
    route_headers: Option<&'a CompiledHeaderControl>,
    request_cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    request_headers_snapshot: Option<&'a http::HeaderMap>,
    cache_lookup_key: Option<&'a CacheRequestKey>,
    route_timeout: Duration,
    http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &'a DispatchAuditContext,
    revalidation_state: Option<crate::cache::RevalidationState>,
}

async fn reverse_cache_collapse(
    req: &mut Request<Body>,
    input: ReverseCacheCollapseInput<'_>,
) -> Result<DispatchCacheCollapseOutcome> {
    let ReverseCacheCollapseInput {
        runtime,
        state,
        request_method,
        request_version,
        proxy_name,
        route_headers,
        request_cache_policy,
        request_headers_snapshot,
        cache_lookup_key,
        route_timeout,
        http_modules,
        audit_ctx,
        mut revalidation_state,
    } = input;
    if *request_method != Method::GET {
        return Ok(DispatchCacheCollapseOutcome::Continue {
            revalidation_state,
            guard: None,
        });
    }
    let (Some(snapshot), Some(policy), Some(lookup_key)) = (
        request_headers_snapshot,
        request_cache_policy,
        cache_lookup_key,
    ) else {
        return Ok(DispatchCacheCollapseOutcome::Continue {
            revalidation_state,
            guard: None,
        });
    };
    match crate::cache::begin_request_collapse(lookup_key) {
        crate::cache::RequestCollapseJoin::Leader(guard) => {
            Ok(DispatchCacheCollapseOutcome::Continue {
                revalidation_state,
                guard: Some(guard),
            })
        }
        crate::cache::RequestCollapseJoin::Follower(waiter) => {
            if !waiter.wait(route_timeout).await {
                return Ok(DispatchCacheCollapseOutcome::Continue {
                    revalidation_state,
                    guard: None,
                });
            }
            let (decision, state_update) = lookup_with_revalidation(
                req,
                snapshot,
                Some(lookup_key),
                Some(policy),
                &runtime.state().cache.backends,
                state.messages.cache_miss.as_str(),
            )
            .await?;
            revalidation_state = state_update;
            let cache_hit = matches!(
                decision,
                CacheLookupDecision::Hit(_) | CacheLookupDecision::StaleWhileRevalidate(_, _)
            );
            http_modules.on_cache_lookup(cache_hit).await?;
            match reverse_cache_collapse_response(
                decision,
                request_method,
                request_version,
                proxy_name,
                route_headers,
                http_modules,
                audit_ctx,
            )
            .await?
            {
                Some(response) => Ok(DispatchCacheCollapseOutcome::Response(response)),
                None => Ok(DispatchCacheCollapseOutcome::Continue {
                    revalidation_state,
                    guard: None,
                }),
            }
        }
    }
}

async fn reverse_cache_collapse_response(
    decision: CacheLookupDecision,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    route_headers: Option<&CompiledHeaderControl>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    audit_ctx: &DispatchAuditContext,
) -> Result<Option<Response<Body>>> {
    match decision {
        CacheLookupDecision::Hit(hit) => {
            let response = finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response: hit,
                outcome: crate::http::dispatch::DispatchOutcome::CacheCollapsedHit,
                request_method,
                response_version: Some(request_version),
                proxy_name,
                headers: route_headers,
                http_modules,
                audit: audit_ctx,
            })
            .await?;
            Ok(Some(response))
        }
        CacheLookupDecision::StaleWhileRevalidate(hit, _) => {
            let response = finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response: hit,
                outcome: crate::http::dispatch::DispatchOutcome::CacheCollapsedStale,
                request_method,
                response_version: Some(request_version),
                proxy_name,
                headers: route_headers,
                http_modules,
                audit: audit_ctx,
            })
            .await?;
            Ok(Some(response))
        }
        CacheLookupDecision::OnlyIfCachedMiss(response) => {
            let response = finalize_dispatch_cached_response(DispatchCachedResponseInput {
                response,
                outcome: crate::http::dispatch::DispatchOutcome::CacheOnlyIfCachedMiss,
                request_method,
                response_version: Some(request_version),
                proxy_name,
                headers: route_headers,
                http_modules,
                audit: audit_ctx,
            })
            .await?;
            Ok(Some(response))
        }
        CacheLookupDecision::Miss => Ok(None),
    }
}
