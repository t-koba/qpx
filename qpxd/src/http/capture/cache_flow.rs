use anyhow::Result;
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::config::CachePolicyConfig;
use qpx_http::body::Body;
use qpxd_cache::{self as cache, CacheBackend, CacheRequestKey, LookupOutcome, RevalidationState};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn clone_request_head_for_revalidation(req: &Request<Body>) -> Request<Body> {
    let mut out = Request::new(Body::empty());
    *out.method_mut() = req.method().clone();
    *out.uri_mut() = req.uri().clone();
    *out.version_mut() = req.version();
    *out.headers_mut() = req.headers().clone();
    out
}

pub enum CacheLookupDecision {
    Hit(Response<Body>),
    StaleWhileRevalidate(Box<Response<Body>>, Box<RevalidationState>),
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
    pub request_collapse_guard: Option<cache::RequestCollapseGuard>,
    pub body_read_timeout: Duration,
    pub backends: &'a HashMap<String, Arc<dyn CacheBackend>>,
}

pub(crate) async fn lookup_with_revalidation(
    req: &mut Request<Body>,
    request_headers_snapshot: &http::HeaderMap,
    cache_lookup_key: Option<&CacheRequestKey>,
    cache_policy: Option<&CachePolicyConfig>,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
    background_revalidations: &Arc<cache::InFlightRevalidations>,
    cache_miss_message: &str,
) -> Result<(CacheLookupDecision, Option<RevalidationState>)> {
    let Some(policy) = cache_policy else {
        return Ok((CacheLookupDecision::Miss, None));
    };
    let Some(key) = cache_lookup_key else {
        return Ok((CacheLookupDecision::Miss, None));
    };

    match cache::lookup(
        req.method(),
        request_headers_snapshot,
        key,
        policy,
        backends,
        background_revalidations,
    )
    .await?
    {
        LookupOutcome::Hit(hit) => Ok((CacheLookupDecision::Hit(hit), None)),
        LookupOutcome::StaleWhileRevalidate(hit, state) => {
            cache::attach_revalidation_headers(req.headers_mut(), &state);
            Ok((
                CacheLookupDecision::StaleWhileRevalidate(hit, Box::new(state)),
                None,
            ))
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

pub(crate) async fn process_upstream_response_for_cache(
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
        mut request_collapse_guard,
        body_read_timeout,
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
        && response.status() == StatusCode::NOT_MODIFIED
    {
        response = cache::revalidate_not_modified(
            request_method,
            request_headers_snapshot,
            policy,
            response,
            revalidation,
            response_delay_secs,
            backends,
        )
        .await?;
    }

    if let (Some(policy), Some(key)) = (cache_policy, cache_lookup_key)
        && response.status() != StatusCode::NOT_MODIFIED
    {
        response = cache::maybe_store(
            request_method,
            request_headers_snapshot,
            key,
            policy,
            response,
            cache::CacheStoreTiming {
                response_delay_secs,
                body_read_timeout,
                request_collapse_guard: request_collapse_guard.take(),
            },
            backends,
        )
        .await?;
    }

    Ok(response)
}
