use anyhow::Result;
use hyper::StatusCode;
use qpx_core::config::CachePolicyConfig;
use qpx_core::http_message::Response;
use qpx_core::http_message::{OrdinaryHeaderName, Request as OwnerRequest};
use qpx_http::body::Body;
use qpxd_cache::{self as cache, CacheBackend, CacheRequestKey, LookupOutcome, RevalidationState};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Build a cache-owned revalidation request from a client request head.
///
/// Client preconditions and ranges are end-to-end for the client's own
/// response. A background refresh must not inherit them: an origin 304 for a
/// client condition would then be mistaken for a 304 to the cache's validators
/// and used to refresh a different cached representation.
pub(crate) fn prepare_background_revalidation_request(
    req: &mut OwnerRequest<()>,
    state: &cache::RevalidationState,
) {
    for name in [
        "if-match",
        "if-none-match",
        "if-modified-since",
        "if-unmodified-since",
        "if-range",
        "range",
    ] {
        let name = OrdinaryHeaderName::try_from(name).expect("ordinary revalidation condition");
        req.headers_mut().remove(&name);
    }
    let _cache_owned = cache::attach_revalidation_headers(req.headers_mut(), state);
}

pub(crate) fn clone_request_head_for_revalidation<B>(req: &OwnerRequest<B>) -> OwnerRequest<()> {
    let mut out = OwnerRequest::new(());
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

pub(crate) struct DeferredSnapshotCacheLookup {
    pub(crate) decision: CacheLookupDecision,
    pub(crate) revalidation_state: Option<RevalidationState>,
    pub(crate) request_head_snapshot: Option<OwnerRequest<()>>,
}

pub struct CacheWritebackContext<'a> {
    pub request_snapshot: &'a OwnerRequest<()>,
    pub response_delay_secs: u64,
    pub cache_target_key: Option<&'a CacheRequestKey>,
    pub cache_lookup_key: Option<&'a CacheRequestKey>,
    pub cache_policy: Option<&'a CachePolicyConfig>,
    pub revalidation_state: Option<RevalidationState>,
    pub request_collapse_guard: Option<cache::RequestCollapseGuard>,
    pub body_read_timeout: Duration,
    pub writeback_admission: &'a cache::CacheWritebackAdmission,
    pub backends: &'a HashMap<String, Arc<dyn CacheBackend>>,
}

pub(crate) async fn lookup_with_revalidation(
    req: &mut OwnerRequest<Body>,
    request_snapshot: &OwnerRequest<()>,
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
        request_snapshot,
        key,
        policy,
        backends,
        background_revalidations,
    )
    .await?
    {
        LookupOutcome::Hit(hit) => Ok((CacheLookupDecision::Hit(hit), None)),
        LookupOutcome::StaleWhileRevalidate(hit, state) => Ok((
            CacheLookupDecision::StaleWhileRevalidate(hit, Box::new(state)),
            None,
        )),
        LookupOutcome::Revalidate(state) => {
            let cache_owned = cache::attach_revalidation_headers(req.headers_mut(), &state);
            Ok((CacheLookupDecision::Miss, cache_owned.then_some(state)))
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

pub(crate) async fn lookup_with_deferred_snapshot(
    req: &mut OwnerRequest<Body>,
    cache_lookup_key: Option<&CacheRequestKey>,
    cache_policy: Option<&CachePolicyConfig>,
    backends: &HashMap<String, Arc<dyn CacheBackend>>,
    background_revalidations: &Arc<cache::InFlightRevalidations>,
    cache_miss_message: &str,
) -> Result<DeferredSnapshotCacheLookup> {
    let Some(policy) = cache_policy else {
        return Ok(DeferredSnapshotCacheLookup {
            decision: CacheLookupDecision::Miss,
            revalidation_state: None,
            request_head_snapshot: None,
        });
    };
    let Some(key) = cache_lookup_key else {
        return Ok(DeferredSnapshotCacheLookup {
            decision: CacheLookupDecision::Miss,
            revalidation_state: None,
            request_head_snapshot: None,
        });
    };

    // Send-safe snapshot: `Request<Body>` is not `Sync`, so the shared lookup
    // sees only the owned `()` head while the live body stays with `req`.
    let snapshot = clone_request_head_for_revalidation(req);
    let outcome = cache::lookup(&snapshot, key, policy, backends, background_revalidations).await?;
    Ok(match outcome {
        LookupOutcome::Hit(hit) => DeferredSnapshotCacheLookup {
            decision: CacheLookupDecision::Hit(hit),
            revalidation_state: None,
            request_head_snapshot: None,
        },
        LookupOutcome::StaleWhileRevalidate(hit, state) => {
            let request_head_snapshot = clone_request_head_for_revalidation(req);
            DeferredSnapshotCacheLookup {
                decision: CacheLookupDecision::StaleWhileRevalidate(hit, Box::new(state)),
                revalidation_state: None,
                request_head_snapshot: Some(request_head_snapshot),
            }
        }
        LookupOutcome::Revalidate(state) => {
            let request_head_snapshot = clone_request_head_for_revalidation(req);
            let cache_owned = cache::attach_revalidation_headers(req.headers_mut(), &state);
            DeferredSnapshotCacheLookup {
                decision: CacheLookupDecision::Miss,
                revalidation_state: cache_owned.then_some(state),
                request_head_snapshot: Some(request_head_snapshot),
            }
        }
        LookupOutcome::OnlyIfCachedMiss => DeferredSnapshotCacheLookup {
            decision: CacheLookupDecision::OnlyIfCachedMiss(
                cache::build_only_if_cached_miss_response(cache_miss_message),
            ),
            revalidation_state: None,
            request_head_snapshot: None,
        },
        LookupOutcome::Miss => DeferredSnapshotCacheLookup {
            decision: CacheLookupDecision::Miss,
            revalidation_state: None,
            request_head_snapshot: Some(clone_request_head_for_revalidation(req)),
        },
    })
}

pub(crate) async fn process_upstream_response_for_cache(
    mut response: Response<Body>,
    ctx: CacheWritebackContext<'_>,
) -> Result<Response<Body>> {
    let CacheWritebackContext {
        request_snapshot,
        response_delay_secs,
        cache_target_key,
        cache_lookup_key,
        cache_policy,
        revalidation_state,
        mut request_collapse_guard,
        body_read_timeout,
        writeback_admission,
        backends,
    } = ctx;
    if let Some(policy) = cache_policy {
        cache::maybe_invalidate(
            request_snapshot.method(),
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
            request_snapshot,
            policy,
            response,
            revalidation,
            response_delay_secs,
            body_read_timeout,
            backends,
        )
        .await?;
    }

    if let (Some(policy), Some(key)) = (cache_policy, cache_lookup_key)
        && response.status() != StatusCode::NOT_MODIFIED
    {
        response = cache::maybe_store(
            request_snapshot,
            key,
            policy,
            response,
            cache::CacheStoreContext {
                timing: cache::CacheStoreTiming {
                    response_delay_secs,
                    body_read_timeout,
                    request_collapse_guard: request_collapse_guard.take(),
                },
                writeback_admission,
                backends,
            },
        )
        .await?;
    }

    Ok(response)
}
