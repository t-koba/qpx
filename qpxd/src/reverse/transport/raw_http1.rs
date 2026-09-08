use super::mirrors::{
    record_reverse_upstream_error, record_reverse_upstream_status, record_reverse_upstream_timeout,
};
use super::{InterimList, ReverseConnInfo};
use crate::http::codec::lazy_timeout::ReusablePendingTimeout;
use crate::reverse::{CompiledReverse, ReloadableReverse};
use crate::upstream::origin::{
    PreparedPlainHttp1Origin, PreparedPlainHttp1Session, prepare_plain_http1_origin,
    proxy_prepared_plain_http1_head_raw_response_with_interim,
};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use http::uri::{Authority, Uri};
use http::{HeaderMap, Method, Request, Response, StatusCode, Version};
use qpx_core::rules::RuleMatchContext;
use qpx_http::body::Body;
use std::sync::Arc;

pub(in crate::reverse) struct RawHttp1RequestView<'a> {
    pub(in crate::reverse) raw_head: &'a [u8],
    pub(in crate::reverse) method: &'a str,
    pub(in crate::reverse) target: &'a str,
    pub(in crate::reverse) version: u8,
    pub(in crate::reverse) headers: &'a [httparse::Header<'a>],
}

pub(in crate::reverse) struct PreparedRawHttp1Request {
    state: Arc<crate::runtime::RuntimeState>,
    compiled: Arc<CompiledReverse>,
    target: PreparedRawHttp1Target,
    raw_access_log_request: Option<Request<()>>,
    method: Method,
    keep_alive: bool,
    cache_hit: Option<CacheHitFastPath>,
}

/// Everything needed to serve an unconditional GET straight from the hot
/// response cache. Built only for routes whose plan carries exactly a
/// lookup+store cache policy (`supports_raw_cache_hit_dispatch`), so no other
/// request or response feature can be bypassed by taking this path.
struct CacheHitFastPath {
    namespace: Arc<str>,
    backend: Arc<dyn qpxd_cache::CacheBackend>,
    key: qpxd_cache::CacheRequestKey,
    headers: http::HeaderMap,
    miss: Option<RawCacheMissDispatch>,
}

/// Origin fetch state for serving cache misses without the generic dispatch
/// chain. Built alongside the hot-hit fast path only for routes whose plan is
/// exactly a lookup+store cache policy, so no other request or response
/// feature can be bypassed by taking this path.
struct RawCacheMissDispatch {
    request_head: Bytes,
    origin: PreparedPlainHttp1Origin,
    endpoint: Arc<crate::reverse::health::UpstreamEndpoint>,
    policy: super::super::router::RoutePolicy,
    max_response_body_bytes: usize,
    cache_policy: qpx_core::config::CachePolicyConfig,
}

enum PreparedRawHttp1Target {
    Origin {
        request_head: Bytes,
        origin: PreparedPlainHttp1Origin,
        endpoint: Arc<crate::reverse::health::UpstreamEndpoint>,
    },
    LocalResponse,
    Generic {
        uri: Uri,
        headers: HeaderMap,
    },
}

pub(in crate::reverse) enum PreparedRawHttp1Response {
    Direct(crate::upstream::raw_http1::RawHttp1ResponseRelay<tokio::net::TcpStream>),
    InMemory {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    },
    Generic(InterimList, Response<Body>),
}

impl PreparedRawHttp1Request {
    pub(in crate::reverse) fn method(&self) -> &Method {
        &self.method
    }

    pub(in crate::reverse) fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    pub(in crate::reverse) fn generic_request(&self) -> Option<Request<Body>> {
        let PreparedRawHttp1Target::Generic { uri, headers } = &self.target else {
            return None;
        };
        let mut request = Request::new(Body::empty());
        *request.method_mut() = self.method.clone();
        *request.uri_mut() = uri.clone();
        *request.version_mut() = Version::HTTP_11;
        *request.headers_mut() = headers.clone();
        Some(request)
    }

    pub(in crate::reverse) fn raw_access_log_request(&self) -> Option<&Request<()>> {
        if matches!(&self.target, PreparedRawHttp1Target::Generic { .. }) {
            return None;
        }
        self.raw_access_log_request.as_ref()
    }

    /// Direct combined access log built at prepare time, for fast-path
    /// responses whose target is generic (cache-hit routes).
    pub(in crate::reverse) fn direct_combined_log_request(&self) -> Option<&Request<()>> {
        self.raw_access_log_request.as_ref()
    }

    /// Serves the request from the cache-hit fast path when it can. Returns
    /// `None` for every request the fast path cannot serve exactly as the
    /// generic chain would, so the caller falls through without behavior
    /// change.
    pub(in crate::reverse) fn try_serving_cache_hit(&self) -> Option<PreparedRawHttp1Response> {
        let mut response = try_raw_cache_hit_response(self.cache_hit.as_ref()?)?;
        let body = take_in_memory_body(&[], &mut response)?;
        let (parts, _) = response.into_parts();
        Some(PreparedRawHttp1Response::InMemory {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }
}

#[derive(Default)]
pub(in crate::reverse) struct RawHttp1ConnectionCache {
    authority: Option<CachedAuthority>,
    target: Option<CachedOriginTarget>,
    serialized: Option<CachedSerializedRequest>,
}

struct CachedAuthority {
    raw: String,
    authority: Authority,
    normalized_host: String,
}

struct CachedOriginTarget {
    raw: String,
    query_offset: Option<usize>,
}

struct CachedSerializedRequest {
    downstream_head: Box<[u8]>,
    prepared: Box<PreparedRawHttp1Request>,
}

impl RawHttp1ConnectionCache {
    pub(in crate::reverse) fn cached_prefix_len(
        &self,
        reverse: &ReloadableReverse,
        bytes: &[u8],
    ) -> Option<usize> {
        let cached = self.serialized.as_ref()?;
        let consumed = cached.downstream_head.len();
        if bytes.len() < consumed || &bytes[..consumed] != cached.downstream_head.as_ref() {
            return None;
        }
        self.has_current_prepared(reverse).then_some(consumed)
    }

    fn has_current_prepared(&self, reverse: &ReloadableReverse) -> bool {
        let Some(cached) = self.serialized.as_ref() else {
            return false;
        };
        if qpx_observability::metrics_enabled() || qpx_observability::request_spans_enabled() {
            return false;
        }
        // Routing, tracing, and identity eligibility was validated before this
        // immutable state was cached. A reload changes the Arc identity below.
        reverse.runtime.is_current_state(&cached.prepared.state)
    }

    /// Return the cached request after the caller has validated its state.
    pub(in crate::reverse) fn prepared_request_ref_unchecked(
        &self,
    ) -> Option<&PreparedRawHttp1Request> {
        let cached = self.serialized.as_ref()?;
        Some(cached.prepared.as_ref())
    }

    fn routing_snapshot(
        &self,
        reverse: &ReloadableReverse,
    ) -> Option<(Arc<crate::runtime::RuntimeState>, Arc<CompiledReverse>)> {
        if let Some(cached) = self.serialized.as_ref()
            && reverse.runtime.is_current_state(&cached.prepared.state)
        {
            return Some((
                cached.prepared.state.clone(),
                cached.prepared.compiled.clone(),
            ));
        }
        let state = reverse.runtime.state();
        let compiled = reverse.compiled_if_current(&state)?;
        Some((state, compiled))
    }

    fn update_target(&mut self, raw: &str) -> Option<()> {
        if self.target.as_ref().is_some_and(|target| target.raw == raw) {
            return Some(());
        }
        let uri = raw.parse::<Uri>().ok()?;
        if !raw.starts_with('/') || uri.scheme().is_some() || uri.authority().is_some() {
            return None;
        }
        self.target = Some(CachedOriginTarget {
            raw: raw.to_owned(),
            query_offset: raw.find('?'),
        });
        Some(())
    }

    fn update_authority(&mut self, headers: &[httparse::Header<'_>]) -> Option<()> {
        let raw = request_authority_value(headers)?;
        if self
            .authority
            .as_ref()
            .is_some_and(|authority| authority.raw == raw)
        {
            return Some(());
        }
        let authority = raw.parse::<Authority>().ok()?;
        let normalized_host = authority.host().to_ascii_lowercase();
        self.authority = Some(CachedAuthority {
            raw: raw.to_owned(),
            authority,
            normalized_host,
        });
        Some(())
    }

    fn store_prepared_request(
        &mut self,
        downstream_head: &[u8],
        prepared: PreparedRawHttp1Request,
    ) -> Option<&PreparedRawHttp1Request> {
        let prepared = Box::new(prepared);
        self.serialized = Some(CachedSerializedRequest {
            downstream_head: downstream_head.into(),
            prepared,
        });
        self.serialized
            .as_ref()
            .map(|serialized| serialized.prepared.as_ref())
    }
}

impl CachedOriginTarget {
    fn path_and_query(&self) -> (&str, Option<&str>) {
        match self.query_offset {
            Some(offset) => (&self.raw[..offset], Some(&self.raw[offset + 1..])),
            None => (self.raw.as_str(), None),
        }
    }
}

pub(in crate::reverse) fn prepare_raw_http1_request<'a>(
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    request: RawHttp1RequestView<'_>,
    cache: &'a mut RawHttp1ConnectionCache,
) -> Option<&'a PreparedRawHttp1Request> {
    if request.version != 1 || !matches!(request.method, "GET" | "HEAD") {
        return None;
    }
    if qpx_observability::metrics_enabled() || qpx_observability::request_spans_enabled() {
        return None;
    }
    if cache
        .serialized
        .as_ref()
        .is_some_and(|cached| cached.downstream_head.as_ref() == request.raw_head)
        && cache.has_current_prepared(reverse)
    {
        let prepared = cache.prepared_request_ref_unchecked()?;
        return Some(prepared);
    }
    let (state, compiled) = cache.routing_snapshot(reverse)?;
    if state.destination_trace_enabled() || !state.security.identity_sources.sources.is_empty() {
        return None;
    }
    if request_has_body_or_expect(request.headers) || request_has_upgrade(request.headers) {
        return None;
    }
    cache.update_target(request.target)?;
    cache.update_authority(request.headers)?;
    let method = if request.method == "GET" {
        Method::GET
    } else {
        Method::HEAD
    };
    let route_match_context = {
        let target = cache.target.as_ref()?;
        let authority = cache.authority.as_ref()?;
        let (path, query) = target.path_and_query();
        RuleMatchContext {
            src_ip: Some(conn.remote_addr.ip()),
            dst_port: Some(conn.dst_port),
            host: Some(authority.normalized_host.as_str()),
            method: Some(request.method),
            path: Some(path),
            query,
            authority: Some(authority.authority.as_str()),
            scheme: Some("http"),
            http_version: Some("HTTP/1.1"),
            client_cert_present: Some(false),
            ..Default::default()
        }
    };

    let keep_alive = !has_connection_token(request.headers, b"close");
    let direct_combined_access_log =
        qpx_observability::access_log::direct_combined_access_log_enabled(
            &state.resources.access_log,
        );
    let direct_dispatch_allowed =
        !qpx_observability::access_log::access_log_service_required(&state.resources.access_log)
            || direct_combined_access_log;
    let raw_access_log_request = if direct_combined_access_log {
        let uri = request.target.parse::<Uri>().ok()?;
        let headers = crate::http::codec::h1_common::parse_header_map(request.headers).ok()?;
        let mut request = Request::new(());
        *request.method_mut() = method.clone();
        *request.uri_mut() = uri;
        *request.version_mut() = Version::HTTP_11;
        *request.headers_mut() = headers;
        Some(request)
    } else {
        None
    };
    let target = if let Some(route) = direct_dispatch_allowed
        .then(|| compiled.router.single_plain_http_route())
        .flatten()
        .filter(|route| route.supports_raw_http1_dispatch() && route.matches(&route_match_context))
    {
        let selected_upstream = route.single_plain_http_upstream_arc()?;
        if selected_upstream.has_time_dependent_admission_state() {
            return None;
        }
        let (connect_authority, host_authority) =
            selected_upstream.origin.direct_plain_http1_authorities()?;
        let origin = prepare_plain_http1_origin(&state.pools, connect_authority, host_authority);
        let request_head = serialize_upstream_request_head(
            request.method,
            request.target,
            request.headers,
            host_authority,
            state.plan.identity.proxy_name.as_ref(),
        )?;
        PreparedRawHttp1Target::Origin {
            request_head,
            origin,
            endpoint: selected_upstream,
        }
    } else if direct_dispatch_allowed
        && compiled
            .router
            .single_direct_local_response_route()
            .is_some_and(|route| {
                route.supports_raw_local_response_dispatch() && route.matches(&route_match_context)
            })
    {
        PreparedRawHttp1Target::LocalResponse
    } else {
        let uri = request.target.parse::<Uri>().ok()?;
        let headers = crate::http::codec::h1_common::parse_header_map(request.headers).ok()?;
        PreparedRawHttp1Target::Generic { uri, headers }
    };
    // The cache-hit fast path only applies to routes that fell through to the
    // generic target (cache routes never qualify for raw upstream dispatch)
    // and only when the request shape is one the fast path can serve exactly
    // like the generic chain would.
    let cache_hit = if matches!(target, PreparedRawHttp1Target::Generic { .. }) {
        build_raw_cache_hit_fast_path(
            &compiled,
            &state,
            &route_match_context,
            request.method,
            request.target,
            request.headers,
            &cache.authority,
            conn,
        )
    } else {
        None
    };
    cache.store_prepared_request(
        request.raw_head,
        PreparedRawHttp1Request {
            state,
            compiled,
            target,
            raw_access_log_request,
            method,
            keep_alive,
            cache_hit,
        },
    )
}

/// Conditional, negotiated, or directive-bearing requests must go through the
/// full lookup chain; the fast path only serves plain unconditional GETs.
fn raw_cache_hit_headers_eligible(headers: &[httparse::Header<'_>]) -> bool {
    headers.iter().all(|header| {
        !matches!(
            header.name,
            "if-match"
                | "If-Match"
                | "if-none-match"
                | "If-None-Match"
                | "if-modified-since"
                | "If-Modified-Since"
                | "if-unmodified-since"
                | "If-Unmodified-Since"
                | "if-range"
                | "If-Range"
                | "range"
                | "Range"
                | "cache-control"
                | "Cache-Control"
                | "pragma"
                | "Pragma"
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn build_raw_cache_hit_fast_path(
    compiled: &CompiledReverse,
    state: &crate::runtime::RuntimeState,
    route_match_context: &RuleMatchContext<'_>,
    method: &str,
    target: &str,
    headers: &[httparse::Header<'_>],
    authority: &Option<CachedAuthority>,
    conn: &ReverseConnInfo,
) -> Option<CacheHitFastPath> {
    if method != "GET" || !target.starts_with('/') {
        return None;
    }
    if !raw_cache_hit_headers_eligible(headers) {
        return None;
    }
    let route = compiled.router.single_cache_hit_route()?;
    if !route.matches(route_match_context) {
        return None;
    }
    let policy = route.plan.cache.as_ref()?;
    if !policy.enabled {
        return None;
    }
    let backend = state.cache.backends.get(policy.backend.as_str())?.clone();
    let scheme = if conn.tls_terminated { "https" } else { "http" };
    let host_header = authority.as_ref()?.raw.as_str();
    let normalized_authority = qpxd_cache::normalize_authority(host_header, scheme)?;
    let namespace = Arc::from(qpxd_cache::cache_namespace(policy, "default"));
    let parsed_headers = crate::http::codec::h1_common::parse_header_map(headers).ok()?;
    // Misses are served through the same raw origin machinery as plain
    // upstream dispatch; if the origin cannot be prepared, misses fall back
    // to the generic chain while hot hits keep working.
    let miss = build_raw_cache_miss_dispatch(route, state, method, target, headers);
    Some(CacheHitFastPath {
        namespace,
        backend,
        key: qpxd_cache::CacheRequestKey::from_normalized_parts(
            "GET",
            scheme,
            normalized_authority,
            target.to_string(),
        ),
        headers: parsed_headers,
        miss,
    })
}

/// Prepares the raw origin fetch for cache misses. Returns `None` when the
/// origin cannot be prepared; the caller then keeps the generic chain.
fn build_raw_cache_miss_dispatch(
    route: &crate::reverse::router::HttpRoute,
    state: &crate::runtime::RuntimeState,
    method: &str,
    target: &str,
    headers: &[httparse::Header<'_>],
) -> Option<RawCacheMissDispatch> {
    let selected_upstream = route.single_plain_http_upstream_arc()?;
    if selected_upstream.has_time_dependent_admission_state() {
        return None;
    }
    let (connect_authority, host_authority) =
        selected_upstream.origin.direct_plain_http1_authorities()?;
    let origin = prepare_plain_http1_origin(&state.pools, connect_authority, host_authority);
    let request_head = serialize_upstream_request_head(
        method,
        target,
        headers,
        host_authority,
        state.plan.identity.proxy_name.as_ref(),
    )?;
    Some(RawCacheMissDispatch {
        request_head,
        origin,
        endpoint: selected_upstream,
        policy: route.policy.clone(),
        max_response_body_bytes: route.plan.streaming.max_response_body_bytes,
        cache_policy: route.plan.cache.clone()?,
    })
}

/// Serves an unconditional GET from the hot response cache. Returns `None`
/// for every request the fast path cannot serve exactly as the generic chain
/// would (cold entry, stale beyond policy, vary negotiation, lookup errors),
/// which is indistinguishable from the fast path not existing.
fn try_raw_cache_hit_response(fast: &CacheHitFastPath) -> Option<Response<Body>> {
    let now = qpx_http::now_millis();
    let index_key = fast.key.primary_index_storage_key();
    let default_variant_key = fast.key.primary_default_variant_storage_key();
    match fast.backend.get_response_candidate(
        &fast.namespace,
        index_key.as_ref(),
        default_variant_key.as_ref(),
        now,
    ) {
        Ok(Some(candidate)) => {
            let outcome = qpxd_cache::build_hot_hit_response(candidate, now);
            match outcome {
                Ok(response) => response,
                Err(error) => {
                    tracing::warn!(
                        error = ?error,
                        "raw cache-hit fast path failed to build the response; falling back"
                    );
                    None
                }
            }
        }
        Ok(None) => None,
        Err(error) => {
            tracing::warn!(
                error = ?error,
                "raw cache-hit fast path lookup failed; falling back to generic dispatch"
            );
            None
        }
    }
}

pub(in crate::reverse) async fn dispatch_prepared_raw_http1_request(
    prepared: &PreparedRawHttp1Request,
    reverse: &ReloadableReverse,
    conn: &ReverseConnInfo,
    session: &mut PreparedPlainHttp1Session,
    pending_timeout: &mut ReusablePendingTimeout<'_>,
) -> Result<PreparedRawHttp1Response> {
    // Cache-hit fast paths are served by the caller before reaching this
    // dispatcher. When the hot probe missed, this raw cache dispatch serves
    // the request without the generic chain: a full cache lookup first (so
    // stale, revalidation, and vary cases still fall back), then a miss
    // fetches the origin and writes the response back through the same
    // store pipeline as the generic chain.
    if let Some(response) = dispatch_raw_cache_miss(prepared, session, pending_timeout).await? {
        return Ok(response);
    }
    if let Some(request) = prepared.generic_request() {
        session.release();
        let (interim, response) =
            super::handle_request_with_interim_ref(request, reverse, conn).await?;
        let mut response = response;
        if let Some(body) = take_in_memory_body(&interim, &mut response) {
            let (parts, _) = response.into_parts();
            return Ok(PreparedRawHttp1Response::InMemory {
                status: parts.status,
                headers: parts.headers,
                body,
            });
        }
        return Ok(PreparedRawHttp1Response::Generic(interim, response));
    }
    if matches!(&prepared.target, PreparedRawHttp1Target::LocalResponse) {
        session.release();
        let route = prepared
            .compiled
            .router
            .single_direct_local_response_route()
            .ok_or_else(|| anyhow!("raw HTTP/1 local-response route is no longer available"))?;
        let local = route
            .local_response
            .as_ref()
            .ok_or_else(|| anyhow!("raw HTTP/1 local-response route has no response"))?;
        let mut response = crate::http::local_response::finalized_compiled_local_response(
            &prepared.method,
            Version::HTTP_11,
            prepared.state.plan.identity.proxy_name.as_ref(),
            local,
            None,
        )?;
        super::dispatch::apply_reverse_route_metadata(route, false, &mut response)?;
        if let Some(body) = take_in_memory_body(&[], &mut response) {
            let (parts, _) = response.into_parts();
            return Ok(PreparedRawHttp1Response::InMemory {
                status: parts.status,
                headers: parts.headers,
                body,
            });
        }
        return Ok(PreparedRawHttp1Response::Generic(Vec::new(), response));
    }
    let route = prepared
        .compiled
        .router
        .single_plain_http_route()
        .ok_or_else(|| anyhow!("raw HTTP/1 route is no longer available"))?;
    let PreparedRawHttp1Target::Origin {
        request_head,
        origin,
        endpoint: selected_upstream,
    } = &prepared.target
    else {
        unreachable!();
    };
    if selected_upstream.has_time_dependent_admission_state() {
        return Err(anyhow!(
            "raw HTTP/1 route upstream is not currently available"
        ));
    }
    let started = route
        .policy
        .passive_health
        .as_ref()
        .is_some_and(|policy| policy.latency_threshold.is_some())
        .then(tokio::time::Instant::now);
    let response = pending_timeout
        .timeout_after_pending(
            route.policy.timeout,
            proxy_prepared_plain_http1_head_raw_response_with_interim(
                origin,
                session,
                &prepared.method,
                request_head.as_ref(),
                Version::HTTP_11,
                prepared.state.plan.identity.proxy_name.as_ref(),
            ),
        )
        .await;
    let mut proxied = match response {
        Ok(Ok(proxied)) => proxied,
        Ok(Err(error)) => {
            record_reverse_upstream_error(selected_upstream, &route.policy, &error);
            return Err(error);
        }
        Err(_) => {
            record_reverse_upstream_timeout(selected_upstream, &route.policy);
            return Err(anyhow!("upstream timeout"));
        }
    };
    record_reverse_upstream_status(selected_upstream, &route.policy, proxied.status(), started);
    if proxied.supports_direct_relay(route.plan.streaming.max_response_body_bytes) {
        proxied.finalize(
            Version::HTTP_11,
            prepared.state.plan.identity.proxy_name.as_ref(),
        );
        return Ok(PreparedRawHttp1Response::Direct(proxied));
    }
    session.recycle_response_globally(&mut proxied);
    let proxied = proxied.into_http_response()?;
    let mut response = proxied.response;
    crate::http::capture::stream::limit_response_body_for_plan_in_place(&mut response, &route.plan);
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        &prepared.method,
        Version::HTTP_11,
        prepared.state.plan.identity.proxy_name.as_ref(),
        &mut response,
        None,
        false,
    );
    if let Some(body) = take_in_memory_body(&proxied.interim, &mut response) {
        let (parts, _) = response.into_parts();
        return Ok(PreparedRawHttp1Response::InMemory {
            status: parts.status,
            headers: parts.headers,
            body,
        });
    }
    Ok(PreparedRawHttp1Response::Generic(proxied.interim, response))
}

/// Serves a cache-qualified request outside the generic chain when the cache
/// state allows it. Returns `Ok(None)` whenever the request must fall back to
/// the generic dispatch (revalidation, stale serving, request collapse, or an
/// unprepared origin); only plain hits and misses are handled here.
async fn dispatch_raw_cache_miss(
    prepared: &PreparedRawHttp1Request,
    session: &mut PreparedPlainHttp1Session,
    pending_timeout: &mut ReusablePendingTimeout<'_>,
) -> Result<Option<PreparedRawHttp1Response>> {
    let Some(fast) = prepared.cache_hit.as_ref() else {
        return Ok(None);
    };
    let Some(miss) = fast.miss.as_ref() else {
        return Ok(None);
    };
    if miss.endpoint.has_time_dependent_admission_state() {
        return Ok(None);
    }
    let outcome = qpxd_cache::lookup(
        &prepared.method,
        &fast.headers,
        &fast.key,
        &miss.cache_policy,
        &prepared.state.cache.backends,
        &prepared.state.cache.background_revalidations,
    )
    .await?;
    let response = match outcome {
        qpxd_cache::LookupOutcome::Hit(response) => response,
        qpxd_cache::LookupOutcome::Miss => {
            return serve_raw_cache_miss(fast, miss, prepared, session, pending_timeout).await;
        }
        // Revalidation, stale-while-revalidate, and only-if-cached responses
        // keep their full generic-chain semantics.
        _ => return Ok(None),
    };
    Ok(Some(PreparedRawHttp1Response::Generic(
        Vec::new(),
        response,
    )))
}

/// Fetches the origin for a cache miss and runs the response through the
/// same store pipeline the generic chain uses, then hands the response back
/// for the raw body relay.
async fn serve_raw_cache_miss(
    fast: &CacheHitFastPath,
    miss: &RawCacheMissDispatch,
    prepared: &PreparedRawHttp1Request,
    session: &mut PreparedPlainHttp1Session,
    pending_timeout: &mut ReusablePendingTimeout<'_>,
) -> Result<Option<PreparedRawHttp1Response>> {
    let started = miss
        .policy
        .passive_health
        .as_ref()
        .is_some_and(|policy| policy.latency_threshold.is_some())
        .then(tokio::time::Instant::now);
    let response = pending_timeout
        .timeout_after_pending(
            miss.policy.timeout,
            proxy_prepared_plain_http1_head_raw_response_with_interim(
                &miss.origin,
                session,
                &prepared.method,
                miss.request_head.as_ref(),
                Version::HTTP_11,
                prepared.state.plan.identity.proxy_name.as_ref(),
            ),
        )
        .await;
    let mut proxied = match response {
        Ok(Ok(proxied)) => proxied,
        Ok(Err(error)) => {
            record_reverse_upstream_error(&miss.endpoint, &miss.policy, &error);
            return Err(error);
        }
        Err(_) => {
            record_reverse_upstream_timeout(&miss.endpoint, &miss.policy);
            return Err(anyhow!("upstream timeout"));
        }
    };
    let response_delay_secs = started
        .map(|started| started.elapsed().as_secs())
        .unwrap_or(0);
    record_reverse_upstream_status(&miss.endpoint, &miss.policy, proxied.status(), started);
    session.recycle_response_globally(&mut proxied);
    let proxied = proxied.into_http_response()?;
    let mut response = proxied.response;
    limit_response_body_for_max_bytes(&mut response, miss.max_response_body_bytes);
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        &prepared.method,
        Version::HTTP_11,
        prepared.state.plan.identity.proxy_name.as_ref(),
        &mut response,
        None,
        false,
    );
    let mut response = qpxd_cache::maybe_store(
        &prepared.method,
        &fast.headers,
        &fast.key,
        &miss.cache_policy,
        response,
        qpxd_cache::CacheStoreContext {
            timing: qpxd_cache::CacheStoreTiming {
                response_delay_secs,
                body_read_timeout: std::time::Duration::from_millis(
                    prepared
                        .state
                        .plan
                        .limits
                        .timeouts
                        .upstream_http_timeout_ms
                        .max(1),
                ),
                request_collapse_guard: None,
            },
            writeback_admission: &prepared.state.cache.writeback_admission,
            backends: &prepared.state.cache.backends,
        },
    )
    .await?;
    if let Some(body) = take_in_memory_body(&proxied.interim, &mut response) {
        let (parts, _) = response.into_parts();
        return Ok(Some(PreparedRawHttp1Response::InMemory {
            status: parts.status,
            headers: parts.headers,
            body,
        }));
    }
    Ok(Some(PreparedRawHttp1Response::Generic(
        proxied.interim,
        response,
    )))
}

/// Mirrors `limit_response_body_for_plan_in_place` for the raw cache miss
/// path, which carries the streaming limit without a full execution plan.
fn limit_response_body_for_max_bytes(response: &mut Response<Body>, max_bytes: usize) {
    if http_body::Body::size_hint(response.body())
        .exact()
        .is_some_and(|len| len <= max_bytes as u64)
    {
        return;
    }
    if let Some(len) = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<usize>().ok())
        && len > max_bytes
    {
        response.headers_mut().remove(http::header::CONTENT_LENGTH);
    }
    let body = std::mem::replace(response.body_mut(), Body::empty());
    *response.body_mut() = body.limit_bytes(max_bytes);
}

fn take_in_memory_body(
    interim: &[crate::upstream::raw_http1::InterimResponseHead],
    response: &mut Response<Body>,
) -> Option<Bytes> {
    if !interim.is_empty() {
        return None;
    }
    if response.body().has_file_region() {
        return None;
    }
    response.body_mut().take_single_frame_without_trailers()
}

fn serialize_upstream_request_head(
    method: &str,
    target: &str,
    headers: &[httparse::Header<'_>],
    host_authority: &str,
    proxy_name: &str,
) -> Option<Bytes> {
    let capacity = headers
        .iter()
        .map(|header| header.name.len() + header.value.len() + 4)
        .sum::<usize>()
        .saturating_add(method.len() + target.len() + host_authority.len() + proxy_name.len() + 64);
    let mut out = BytesMut::with_capacity(capacity);
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for header in headers {
        let name = header.name.as_bytes();
        if name.eq_ignore_ascii_case(b"host")
            || is_hop_by_hop_header(name)
            || connection_lists_header(headers, name)
        {
            continue;
        }
        append_header_line(&mut out, name, header.value);
    }
    append_header_line(&mut out, b"Host", host_authority.as_bytes());
    let via = qpx_http::protocol::semantics::via_header_value(Version::HTTP_11, proxy_name)?;
    append_header_line(&mut out, b"Via", via.as_bytes());
    out.extend_from_slice(b"\r\n");
    Some(out.freeze())
}

fn request_authority_value<'a>(headers: &'a [httparse::Header<'a>]) -> Option<&'a str> {
    let mut hosts = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"));
    let raw = std::str::from_utf8(hosts.next()?.value).ok()?.trim();
    if raw.is_empty() || hosts.next().is_some() {
        return None;
    }
    Some(raw)
}

fn request_has_body_or_expect(headers: &[httparse::Header<'_>]) -> bool {
    if headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            || header.name.eq_ignore_ascii_case("expect")
    }) {
        return true;
    }
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
        .any(|header| {
            std::str::from_utf8(header.value).ok().is_none_or(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().parse::<u64>().ok() != Some(0))
            })
        })
}

fn request_has_upgrade(headers: &[httparse::Header<'_>]) -> bool {
    headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case("upgrade"))
        || has_connection_token(headers, b"upgrade")
}

fn has_connection_token(headers: &[httparse::Header<'_>], expected: &[u8]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && header
                .value
                .split(|byte| *byte == b',')
                .map(trim_ascii)
                .any(|token| token.eq_ignore_ascii_case(expected))
    })
}

fn connection_lists_header(headers: &[httparse::Header<'_>], name: &[u8]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && header
                .value
                .split(|byte| *byte == b',')
                .map(trim_ascii)
                .any(|token| token.eq_ignore_ascii_case(name))
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_hop_by_hop_header(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-authenticate")
        || name.eq_ignore_ascii_case(b"proxy-authentication-info")
        || name.eq_ignore_ascii_case(b"proxy-authorization")
        || name.eq_ignore_ascii_case(b"proxy-connection")
        || name.eq_ignore_ascii_case(b"te")
        || name.eq_ignore_ascii_case(b"trailer")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"upgrade")
}

fn append_header_line(out: &mut BytesMut, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_raw_request_rewrites_host_and_strips_connection_fields() {
        let headers = [
            httparse::Header {
                name: "Host",
                value: b"public.example",
            },
            httparse::Header {
                name: "Connection",
                value: b"x-private",
            },
            httparse::Header {
                name: "X-Private",
                value: b"secret",
            },
            httparse::Header {
                name: "X-End-To-End",
                value: b"kept",
            },
        ];
        let serialized =
            serialize_upstream_request_head("GET", "/path", &headers, "127.0.0.1:80", "qpx")
                .expect("serialized request");
        let text = std::str::from_utf8(serialized.as_ref()).expect("UTF-8 request");

        assert!(text.starts_with("GET /path HTTP/1.1\r\n"));
        assert!(text.contains("X-End-To-End: kept\r\n"));
        assert!(text.contains("Host: 127.0.0.1:80\r\n"));
        assert!(text.contains("Via: 1.1 qpx\r\n"));
        assert!(!text.contains("X-Private"));
        assert!(!text.contains("Connection"));
    }

    #[test]
    fn connection_cache_reuses_validated_target_and_authority() {
        let mut cache = RawHttp1ConnectionCache::default();
        let headers = [httparse::Header {
            name: "Host",
            value: b"Bench.Local:8080",
        }];

        cache.update_target("/bench?q=1").expect("target");
        cache.update_authority(&headers).expect("authority");
        cache.update_target("/bench?q=1").expect("cached target");
        cache.update_authority(&headers).expect("cached authority");

        let (path, query) = cache
            .target
            .as_ref()
            .expect("target cache")
            .path_and_query();
        assert_eq!(path, "/bench");
        assert_eq!(query, Some("q=1"));
        let authority = cache.authority.as_ref().expect("authority cache");
        assert_eq!(authority.authority.as_str(), "Bench.Local:8080");
        assert_eq!(authority.normalized_host, "bench.local");
    }

    #[test]
    fn connection_cache_rejects_non_origin_target_and_duplicate_host() {
        let mut cache = RawHttp1ConnectionCache::default();
        assert!(cache.update_target("http://example.test/path").is_none());
        let headers = [
            httparse::Header {
                name: "Host",
                value: b"one.example",
            },
            httparse::Header {
                name: "Host",
                value: b"two.example",
            },
        ];
        assert!(cache.update_authority(&headers).is_none());
    }

    #[test]
    fn in_memory_response_fast_path_takes_only_a_trailerless_frame() {
        let mut response = Response::new(Body::from(Bytes::from_static(b"body")));
        let body = take_in_memory_body(&[], &mut response).expect("single body frame");
        assert_eq!(body, Bytes::from_static(b"body"));
        assert!(take_in_memory_body(&[], &mut response).is_none());
    }

    #[test]
    fn raw_cache_hit_headers_eligibility_rejects_directives_and_ranges() {
        let eligible = [httparse::Header {
            name: "Host",
            value: b"bench.local",
        }];
        assert!(raw_cache_hit_headers_eligible(&eligible));
        for name in [
            "If-None-Match",
            "if-match",
            "Range",
            "Cache-Control",
            "pragma",
            "if-modified-since",
            "if-unmodified-since",
            "If-Range",
        ] {
            let headers = [
                httparse::Header {
                    name: "Host",
                    value: b"bench.local",
                },
                httparse::Header { name, value: b"1" },
            ];
            assert!(
                !raw_cache_hit_headers_eligible(&headers),
                "{name} must disqualify the fast path"
            );
        }
    }

    fn build_cache_hit_reverse_fixture(
        upstream_addr: std::net::SocketAddr,
        cache_dir: &std::path::Path,
    ) -> crate::reverse::ReloadableReverse {
        use qpx_core::config::{
            AccessLogConfig, AuditLogConfig, CacheBackendConfig, CachePolicyConfig, Config,
            IdentityConfig, MessagesConfig, ReverseEdgeConfig, ReverseRouteConfig,
            ReverseRouteTargetConfig, RuntimeConfig, SystemLogConfig, UpstreamConfig,
        };

        let route = ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: Default::default(),
            target: ReverseRouteTargetConfig::Upstream {
                upstreams: vec!["upstream".to_string()],
                lb: "round_robin".to_string(),
            },
            mirrors: Vec::new(),
            headers: None,
            timeout_ms: None,
            health_check: None,
            cache: Some(CachePolicyConfig {
                enabled: true,
                backend: "disk".to_string(),
                namespace: Some("ns".to_string()),
                default_ttl_secs: Some(600),
                max_object_bytes: 1024 * 1024,
                allow_set_cookie_store: false,
            }),
            capture: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            affinity: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: None,
        };
        let reverse_cfg = ReverseEdgeConfig {
            name: "test".to_string(),
            listen: "127.0.0.1:0".to_string(),
            tls: None,
            http3: None,
            xdp: None,
            enforce_sni_host_match: false,
            sni_host_exceptions: Vec::new(),
            policy_context: None,
            connection_filter: Vec::new(),
            destination_resolution: None,
            streaming: None,
            grpc: None,
            sse: None,
            routes: vec![route],
            tls_passthrough_routes: Vec::new(),
        };
        let upstream_cfg = UpstreamConfig {
            name: "upstream".to_string(),
            url: format!("http://{upstream_addr}"),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        };
        let config = Config {
            state_dir: None,
            identity: IdentityConfig::default(),
            messages: MessagesConfig::default(),
            runtime: RuntimeConfig::default(),
            telemetry: qpx_core::config::TelemetryConfig {
                system_log: SystemLogConfig::default(),
                access_log: AccessLogConfig::default(),
                audit_log: AuditLogConfig::default(),
                metrics: None,
                otel: None,
                exporter: None,
            },
            security: Default::default(),
            http: qpx_core::config::HttpGlobalConfig::default(),
            traffic: qpx_core::config::TrafficConfig::default(),
            acme: None,
            edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
            upstreams: vec![upstream_cfg],
            caches: vec![CacheBackendConfig {
                name: "disk".to_string(),
                kind: "disk".to_string(),
                endpoint: String::new(),
                path: Some(cache_dir.to_string_lossy().to_string()),
                max_bytes: Some(64 * 1024 * 1024),
                sweep_interval_secs: 60,
                timeout_ms: 1500,
                max_object_bytes: 1024 * 1024,
                auth_header_env: None,
            }],
        };
        let runtime = crate::runtime::Runtime::new(config).expect("runtime");
        crate::reverse::ReloadableReverse::new(
            reverse_cfg,
            runtime,
            Arc::<str>::from("reverse_upstreams_unhealthy"),
        )
        .expect("reloadable reverse")
    }

    fn prepared_raw_request<'a>(
        reverse: &'a crate::reverse::ReloadableReverse,
        conn: &'a ReverseConnInfo,
        connection_cache: &'a mut RawHttp1ConnectionCache,
    ) -> &'a PreparedRawHttp1Request {
        let headers = [httparse::Header {
            name: "Host",
            value: b"bench.local",
        }];
        let raw_head: &[u8] = b"GET /bench-1 HTTP/1.1\r\nHost: bench.local\r\n\r\n";
        let view = RawHttp1RequestView {
            raw_head,
            method: "GET",
            target: "/bench-1",
            version: 1,
            headers: &headers,
        };
        prepare_raw_http1_request(reverse, conn, view, connection_cache)
            .expect("prepared raw request")
    }

    async fn dispatch_prepared(
        prepared: &PreparedRawHttp1Request,
        reverse: &crate::reverse::ReloadableReverse,
        conn: &ReverseConnInfo,
        session: &mut crate::upstream::origin::PreparedPlainHttp1Session,
        pending_timeout: &mut ReusablePendingTimeout<'_>,
    ) -> PreparedRawHttp1Response {
        dispatch_prepared_raw_http1_request(prepared, reverse, conn, session, pending_timeout)
            .await
            .expect("dispatch")
    }

    /// Differential test: the fast path must serve exactly what the generic
    /// chain would serve for the same cached entry.
    #[tokio::test]
    async fn raw_cache_hit_fast_path_matches_generic_lookup_responses() {
        const BODY: &str = "fast-path-payload";
        let upstream_addr = crate::test_util::spawn_static_http_server(
            "200 OK",
            vec![
                ("ETag", "\"v1\"".to_string()),
                ("Cache-Control", "max-age=600".to_string()),
            ],
            BODY.to_string(),
            2,
        )
        .await;
        let cache_dir = tempfile::tempdir().expect("cache dir");
        // On macOS /var is a symlink to /private/var and the disk backend
        // refuses symlinked path components, so resolve the real path first.
        let cache_path = std::fs::canonicalize(cache_dir.path()).expect("canonicalize cache dir");
        let reverse = build_cache_hit_reverse_fixture(upstream_addr, &cache_path);

        let conn =
            ReverseConnInfo::plain(std::net::SocketAddr::from(([127, 0, 0, 1], 4242)), 18080);
        let mut connection_cache = RawHttp1ConnectionCache::default();
        let prepared = prepared_raw_request(&reverse, &conn, &mut connection_cache);
        assert!(
            prepared.cache_hit.is_some(),
            "a pure cache route with an unconditional GET must qualify for the fast path"
        );

        let pending_timer = tokio::time::sleep(std::time::Duration::ZERO);
        tokio::pin!(pending_timer);
        let mut pending_timeout = ReusablePendingTimeout::new(pending_timer.as_mut());
        let mut session = crate::upstream::origin::PreparedPlainHttp1Session::default();

        // First dispatch is a MISS served by the generic chain; it also stores
        // the response in the background. The miss response body streams
        // through the relay, so it arrives as a generic response.
        let miss = dispatch_prepared(
            prepared,
            &reverse,
            &conn,
            &mut session,
            &mut pending_timeout,
        )
        .await;
        let (miss_status, miss_body) = match miss {
            PreparedRawHttp1Response::InMemory { status, body, .. } => {
                (status, Bytes::copy_from_slice(body.as_ref()))
            }
            PreparedRawHttp1Response::Generic(_, response) => {
                let (parts, body) = response.into_parts();
                let body = qpx_http::body::to_bytes(body).await.expect("miss body");
                (parts.status, body)
            }
            PreparedRawHttp1Response::Direct(_) => {
                panic!("cache MISS must not take the direct relay path")
            }
        };
        assert_eq!(miss_status, StatusCode::OK);
        assert_eq!(miss_body.as_ref(), BODY.as_bytes());

        // Wait for the background writeback to publish the hot entry.
        let fast = prepared.cache_hit.as_ref().expect("fast path data");
        let mut hit_response = None;
        for _ in 0..300 {
            if let Some(response) = try_raw_cache_hit_response(fast) {
                hit_response = Some(response);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let hit_response =
            hit_response.expect("background writeback never published the hot entry");
        let (hit_status, hit_headers, hit_body) = {
            let (parts, body) = hit_response.into_parts();
            let body = qpx_http::body::to_bytes(body).await.expect("hit body");
            (parts.status, parts.headers, body)
        };

        // Reference: the generic lookup on the same key.
        let snapshot_headers = HeaderMap::from_iter([(
            http::header::HOST,
            http::HeaderValue::from_static("bench.local"),
        )]);
        let reference_policy = qpx_core::config::CachePolicyConfig {
            enabled: true,
            backend: "disk".to_string(),
            namespace: Some("ns".to_string()),
            default_ttl_secs: Some(600),
            max_object_bytes: 1024 * 1024,
            allow_set_cookie_store: false,
        };
        let reference = qpxd_cache::lookup(
            &Method::GET,
            &snapshot_headers,
            &fast.key,
            &reference_policy,
            &prepared.state.cache.backends,
            &prepared.state.cache.background_revalidations,
        )
        .await
        .expect("reference lookup");

        let (ref_status, ref_headers, ref_body) = match reference {
            qpxd_cache::LookupOutcome::Hit(response) => {
                let (parts, body) = response.into_parts();
                let body = qpx_http::body::to_bytes(body)
                    .await
                    .expect("reference body");
                (parts.status, parts.headers, body)
            }
            outcome => panic!("generic lookup did not HIT: {outcome:?}"),
        };

        assert_eq!(hit_status, ref_status);
        assert_eq!(hit_body.as_ref(), ref_body.as_ref());
        assert_eq!(
            hit_headers.get(http::header::ETAG),
            ref_headers.get(http::header::ETAG),
            "etag must match between fast path and generic lookup"
        );
        assert_eq!(
            hit_headers.get(http::header::CONTENT_LENGTH),
            ref_headers.get(http::header::CONTENT_LENGTH)
        );
        assert!(
            hit_headers
                .get(http::header::CACHE_STATUS)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("qpx; hit"))
        );
        assert!(hit_headers.contains_key(http::header::AGE));
        assert_eq!(hit_body.as_ref(), BODY.as_bytes());
    }

    /// Conditional and HEAD requests must keep using the generic chain.
    #[tokio::test]
    async fn raw_cache_hit_fast_path_skips_conditional_and_head_requests() {
        let upstream_addr = crate::test_util::spawn_static_http_server(
            "200 OK",
            vec![("Cache-Control", "max-age=600".to_string())],
            "payload".to_string(),
            1,
        )
        .await;
        let cache_dir = tempfile::tempdir().expect("cache dir");
        let cache_path = std::fs::canonicalize(cache_dir.path()).expect("canonicalize cache dir");
        let reverse = build_cache_hit_reverse_fixture(upstream_addr, &cache_path);
        let conn =
            ReverseConnInfo::plain(std::net::SocketAddr::from(([127, 0, 0, 1], 4242)), 18080);

        // A conditional GET disqualifies the fast path at prepare time.
        let conditional_head = [
            httparse::Header {
                name: "Host",
                value: b"bench.local",
            },
            httparse::Header {
                name: "If-None-Match",
                value: b"\"x\"",
            },
        ];
        let conditional_raw: &[u8] =
            b"GET /bench-1 HTTP/1.1\r\nHost: bench.local\r\nIf-None-Match: \"x\"\r\n\r\n";
        let conditional_view = RawHttp1RequestView {
            raw_head: conditional_raw,
            method: "GET",
            target: "/bench-1",
            version: 1,
            headers: &conditional_head,
        };
        let mut conditional_cache = RawHttp1ConnectionCache::default();
        let prepared =
            prepare_raw_http1_request(&reverse, &conn, conditional_view, &mut conditional_cache)
                .expect("prepared conditional request");
        assert!(
            prepared.cache_hit.is_none(),
            "conditional requests must not take the fast path"
        );

        // HEAD requests are also out of scope for the fast path.
        let head_view_headers = [httparse::Header {
            name: "Host",
            value: b"bench.local",
        }];
        let head_raw: &[u8] = b"HEAD /bench-1 HTTP/1.1\r\nHost: bench.local\r\n\r\n";
        let head_view = RawHttp1RequestView {
            raw_head: head_raw,
            method: "HEAD",
            target: "/bench-1",
            version: 1,
            headers: &head_view_headers,
        };
        let mut head_cache = RawHttp1ConnectionCache::default();
        let prepared = prepare_raw_http1_request(&reverse, &conn, head_view, &mut head_cache)
            .expect("prepared head request");
        assert!(
            prepared.cache_hit.is_none(),
            "HEAD requests must not take the fast path"
        );
    }
}
