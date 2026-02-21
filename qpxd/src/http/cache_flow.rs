use crate::cache::{self, CacheBackend, CacheRequestKey, LookupOutcome, RevalidationState};
use anyhow::Result;
use hyper::{Body, Method, Request, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use std::collections::HashMap;
use std::sync::Arc;

pub fn clone_request_head_for_revalidation(req: &Request<Body>) -> Request<Body> {
    let mut out = Request::new(Body::empty());
    *out.method_mut() = req.method().clone();
    *out.uri_mut() = req.uri().clone();
    *out.version_mut() = req.version();
    *out.headers_mut() = req.headers().clone();
    out
}

pub enum CacheLookupDecision {
    Hit(Response<Body>),
    StaleWhileRevalidate(Response<Body>, RevalidationState),
    OnlyIfCachedMiss(Response<Body>),
    Miss,
}

pub struct CacheWritebackContext<'a> {
    pub request_method: &'a Method,
    pub response_delay_secs: u64,
    pub cache_target_key: Option<&'a CacheRequestKey>,
    pub cache_lookup_key: Option<&'a CacheRequestKey>,
    pub cache_policy: Option<&'a CachePolicyConfig>,
    pub request_headers_snapshot: &'a http::HeaderMap,
    pub revalidation_state: Option<RevalidationState>,
    pub backends: &'a HashMap<String, Arc<dyn CacheBackend>>,
}

pub async fn lookup_with_revalidation(
    req: &mut Request<Body>,
    request_headers_snapshot: &http::HeaderMap,
    cache_lookup_key: Option<&CacheRequestKey>,
    cache_policy: Option<&CachePolicyConfig>,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
    cache_miss_message: &str,
) -> Result<(CacheLookupDecision, Option<RevalidationState>)> {
    let Some(policy) = cache_policy else {
        return Ok((CacheLookupDecision::Miss, None));
    };
    let Some(key) = cache_lookup_key else {
        return Ok((CacheLookupDecision::Miss, None));
    };

    match cache::lookup(request_headers_snapshot, key, policy, backends).await? {
        LookupOutcome::Hit(hit) => Ok((CacheLookupDecision::Hit(hit), None)),
        LookupOutcome::StaleWhileRevalidate(hit, state) => {
            cache::attach_revalidation_headers(req.headers_mut(), &state);
            Ok((CacheLookupDecision::StaleWhileRevalidate(hit, state), None))
        }
        LookupOutcome::Revalidate(state) => {
            cache::attach_revalidation_headers(req.headers_mut(), &state);
            Ok((CacheLookupDecision::Miss, Some(state)))
        }
        LookupOutcome::OnlyIfCachedMiss => Ok((
            CacheLookupDecision::OnlyIfCachedMiss(cache::build_only_if_cached_miss_response(
                cache_miss_message,
            )),
            None,
        )),
        LookupOutcome::Miss => Ok((CacheLookupDecision::Miss, None)),
    }
}

pub async fn process_upstream_response_for_cache(
    mut response: Response<Body>,
    ctx: CacheWritebackContext<'_>,
) -> Result<Response<Body>> {
    let CacheWritebackContext {
        request_method,
        response_delay_secs,
        cache_target_key,
        cache_lookup_key,
        cache_policy,
        request_headers_snapshot,
        revalidation_state,
        backends,
    } = ctx;
    if let Some(policy) = cache_policy {
        cache::maybe_invalidate(
            request_method,
            response.status(),
            response.headers(),
            cache_target_key,
            policy,
            backends,
        )
        .await?;
    }

    if let (Some(policy), Some(_), Some(revalidation)) =
        (cache_policy, cache_lookup_key, revalidation_state)
    {
        if response.status() == StatusCode::NOT_MODIFIED {
            response = cache::revalidate_not_modified(
                request_headers_snapshot,
                policy,
                response,
                revalidation,
                response_delay_secs,
                backends,
            )
            .await?;
        }
    }

    if let (Some(policy), Some(key)) = (cache_policy, cache_lookup_key) {
        if response.status() != StatusCode::NOT_MODIFIED {
            response = cache::maybe_store(
                request_method,
                request_headers_snapshot,
                key,
                policy,
                response,
                response_delay_secs,
                backends,
            )
            .await?;
        }
    }

    Ok(response)
}
