use super::{DispatchAuditContext, DispatchOutcome, annotate_dispatch_response};
use crate::http::capture::cache_flow::{
    CacheWritebackContext, process_upstream_response_for_cache,
};
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use anyhow::{Result, anyhow};
use http::header::{CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_TYPE};
use hyper::{Method, Request, Response};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use qpxd_cache::CacheRequestKey;
use sha2::{Digest, Sha256};

pub(crate) enum DispatchCacheLookupOutcome {
    // Both payloads are large (`Response<Body>` and a `RevalidationState` embedding a
    // `CachedResponseEnvelope`); box them so the variants stay balanced, matching
    // `DispatchCacheCollapseOutcome` below.
    Response(Box<Response<Body>>),
    Continue(Option<Box<qpxd_cache::RevalidationState>>),
}

pub(crate) enum DispatchCacheCollapseOutcome {
    Response(Box<Response<Body>>),
    Continue {
        revalidation_state: Option<Box<qpxd_cache::RevalidationState>>,
        guard: Option<qpxd_cache::RequestCollapseGuard>,
    },
}

pub(crate) fn dispatch_cache_collapse_continue(
    revalidation_state: Option<qpxd_cache::RevalidationState>,
    guard: Option<qpxd_cache::RequestCollapseGuard>,
) -> DispatchCacheCollapseOutcome {
    DispatchCacheCollapseOutcome::Continue {
        revalidation_state: revalidation_state.map(Box::new),
        guard,
    }
}

pub(crate) fn dispatch_cache_collapse_response(
    response: Response<Body>,
) -> DispatchCacheCollapseOutcome {
    DispatchCacheCollapseOutcome::Response(Box::new(response))
}

/// Buffers a QUERY request body and derives its RFC 10008 Sec 2.7 cache key
/// content digest over the body plus representation metadata. Shared by the
/// forward and reverse dispatch paths so both bind QUERY cache entries to
/// request content instead of the URI alone.
pub(crate) async fn buffer_query_for_cache_key(
    req: Request<Body>,
    max_body_bytes: usize,
) -> Result<(Request<Body>, String)> {
    let (parts, mut body) = req.into_parts();
    let mut content = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let next = content
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow!("QUERY request body length overflow"))?;
        if next > max_body_bytes {
            return Err(anyhow!(
                "QUERY request body exceeds route limit of {} bytes",
                max_body_bytes
            ));
        }
        content.extend_from_slice(&chunk);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"qpx-query-cache-key-v1\0");
    for name in [CONTENT_TYPE, CONTENT_ENCODING, CONTENT_LANGUAGE] {
        hasher.update(name.as_str().as_bytes());
        hasher.update([0]);
        for value in parts.headers.get_all(&name) {
            hasher.update((value.as_bytes().len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        hasher.update([0xff]);
    }
    hasher.update((content.len() as u64).to_be_bytes());
    hasher.update(&content);
    let digest = format!("sha-256:{:x}", hasher.finalize());
    Ok((Request::from_parts(parts, Body::from(content)), digest))
}

/// Derives cache keys for GET-like and QUERY requests. QUERY bodies are
/// buffered and bound to the RFC 10008 Sec 2.7 content digest; an over-limit
/// body fails closed via the helper error. Shared by forward and reverse
/// dispatch so both bind QUERY entries to request content, not the URI alone.
pub(crate) async fn prepare_query_aware_cache_key_pair(
    req: Request<Body>,
    cache_policy: Option<&qpx_core::config::CachePolicyConfig>,
    cache_default_scheme: &str,
    max_body_bytes: usize,
) -> Result<(
    Request<Body>,
    Option<CacheRequestKey>,
    Option<CacheRequestKey>,
)> {
    if cache_policy.is_none() {
        return Ok((req, None, None));
    }
    if *req.method() == Method::QUERY {
        let (req, digest) = buffer_query_for_cache_key(req, max_body_bytes).await?;
        let (lookup, target) =
            prepare_dispatch_cache_key_pair(&req, cache_policy, cache_default_scheme)?;
        let lookup = lookup.map(|key| key.with_content_digest(digest.clone()));
        let target = target.map(|key| key.with_content_digest(digest));
        return Ok((req, lookup, target));
    }
    let (lookup, target) =
        prepare_dispatch_cache_key_pair(&req, cache_policy, cache_default_scheme)?;
    Ok((req, lookup, target))
}

fn prepare_dispatch_cache_key_pair(
    req: &Request<Body>,
    cache_policy: Option<&qpx_core::config::CachePolicyConfig>,
    cache_default_scheme: &str,
) -> Result<(Option<CacheRequestKey>, Option<CacheRequestKey>)> {
    if cache_policy.is_none() {
        return Ok((None, None));
    }
    let key = CacheRequestKey::for_lookup(req, cache_default_scheme)?;
    Ok((key.clone(), key))
}

pub(crate) struct DispatchCacheWriteInput<'a> {
    pub(crate) response: Response<Body>,
    pub(crate) cache_policy: Option<&'a qpx_core::config::CachePolicyConfig>,
    pub(crate) response_cache_bypass: bool,
    pub(crate) request_headers_snapshot: Option<&'a http::HeaderMap>,
    pub(crate) cache_target_key: Option<&'a CacheRequestKey>,
    pub(crate) cache_lookup_key: Option<&'a CacheRequestKey>,
    pub(crate) revalidation_state: Option<qpxd_cache::RevalidationState>,
    pub(crate) request_collapse_guard: Option<qpxd_cache::RequestCollapseGuard>,
    pub(crate) request_method: &'a Method,
    pub(crate) response_delay_secs: u64,
    pub(crate) state: &'a crate::runtime::RuntimeState,
}

pub(crate) struct DispatchCachedResponseInput<'a> {
    pub(crate) response: Response<Body>,
    pub(crate) outcome: DispatchOutcome,
    pub(crate) plan: &'a crate::runtime::ExecutionPlan,
    pub(crate) request_method: &'a Method,
    pub(crate) response_version: Option<http::Version>,
    pub(crate) proxy_name: &'a str,
    pub(crate) headers: Option<&'a CompiledHeaderControl>,
    pub(crate) http_modules: &'a mut crate::http::modules::HttpModuleExecution,
    pub(crate) audit: &'a DispatchAuditContext,
}

pub(crate) async fn finalize_dispatch_cached_response(
    input: DispatchCachedResponseInput<'_>,
) -> Result<Response<Body>> {
    let DispatchCachedResponseInput {
        response,
        outcome,
        plan,
        request_method,
        response_version,
        proxy_name,
        headers,
        http_modules,
        audit,
    } = input;
    let modules_empty = http_modules.is_empty();
    let mut response = if modules_empty {
        response
    } else {
        http_modules.prepare_downstream_response(response).await?
    };
    let route_response_fields = headers.map_or(0, |control| {
        control
            .response_set()
            .len()
            .saturating_add(control.response_add().len())
    });
    let route_metadata_fields = plan
        .api_metadata
        .as_deref()
        .map_or(
            0,
            qpx_http::api_metadata::PreparedApiMetadata::field_line_count,
        )
        .saturating_add(usize::from(plan.hsts.is_some()));
    if route_response_fields != 0 || route_metadata_fields != 0 {
        response.headers_mut().reserve(
            route_response_fields
                .saturating_add(route_metadata_fields)
                .saturating_add(3),
        );
    }
    let version = response_version.unwrap_or_else(|| response.version());
    finalize_response_with_headers_in_place(
        request_method,
        version,
        proxy_name,
        &mut response,
        headers,
        false,
    );
    if !modules_empty {
        http_modules.on_logging(Some(response.status()), None).await;
    }
    annotate_dispatch_response(&mut response, audit, outcome, &[]);
    Ok(crate::http::capture::stream::limit_response_body_for_plan(
        response, plan,
    ))
}

pub(crate) async fn finalize_dispatch_stale_if_error_response(
    revalidation_state: Option<&qpxd_cache::RevalidationState>,
    plan: &crate::runtime::ExecutionPlan,
    request_method: &Method,
    proxy_name: &str,
    headers: Option<&CompiledHeaderControl>,
    http_modules: &mut crate::http::modules::HttpModuleExecution,
    audit: &DispatchAuditContext,
) -> Result<Option<Response<Body>>> {
    let Some(state) = revalidation_state else {
        return Ok(None);
    };
    let Some(stale) = qpxd_cache::maybe_build_stale_if_error_response(state).await else {
        return Ok(None);
    };
    Ok(Some(
        finalize_dispatch_cached_response(DispatchCachedResponseInput {
            response: stale,
            outcome: crate::http::dispatch::DispatchOutcome::StaleIfError,
            plan,
            request_method,
            response_version: None,
            proxy_name,
            headers,
            http_modules,
            audit,
        })
        .await?,
    ))
}

pub(crate) async fn write_dispatch_cache_result(
    input: DispatchCacheWriteInput<'_>,
) -> Result<Response<Body>> {
    let Some(policy) = input.cache_policy.filter(|_| !input.response_cache_bypass) else {
        return Ok(input.response);
    };

    if let Some(snapshot) = input.request_headers_snapshot {
        return process_upstream_response_for_cache(
            input.response,
            CacheWritebackContext {
                request_method: input.request_method,
                response_delay_secs: input.response_delay_secs,
                cache_target_key: input.cache_target_key,
                cache_lookup_key: input.cache_lookup_key,
                cache_policy: Some(policy),
                request_headers_snapshot: snapshot,
                revalidation_state: input.revalidation_state,
                request_collapse_guard: input.request_collapse_guard,
                body_read_timeout: std::time::Duration::from_millis(
                    input
                        .state
                        .plan
                        .limits
                        .timeouts
                        .upstream_http_timeout_ms
                        .max(1),
                ),
                writeback_admission: &input.state.cache.writeback_admission,
                backends: &input.state.cache.backends,
            },
        )
        .await;
    }

    qpxd_cache::maybe_invalidate(
        input.request_method,
        input.response.status(),
        input.response.headers(),
        input.cache_target_key,
        policy,
        &input.state.cache.backends,
    )
    .await?;
    Ok(input.response)
}
