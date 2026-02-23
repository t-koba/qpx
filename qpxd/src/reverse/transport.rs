use super::request_template::{request_is_retryable, ReverseRequestTemplate};
use super::router::{normalize_host_for_match, CompiledPathRewrite, ReverseRouter};
use crate::cache::CacheRequestKey;
use crate::http::cache_flow::{
    clone_request_head_for_revalidation, lookup_with_revalidation,
    process_upstream_response_for_cache, CacheLookupDecision, CacheWritebackContext,
};
use crate::http::common::bad_request_response as bad_request;
use crate::http::header_control::apply_request_headers;
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers,
    finalize_response_with_headers_in_place, handle_max_forwards_in_place,
};
use crate::http::local_response::build_local_response;
use crate::http::semantics::validate_incoming_request;
use crate::http::websocket::is_websocket_upgrade;
use crate::ipc_client::{proxy_ipc, proxy_ipc_upstream, ClientConnInfo};
use crate::runtime::Runtime;
use crate::upstream::origin::{proxy_http, proxy_websocket};
use anyhow::{anyhow, Result};
use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use hyper::{Body, Method, Request, Response, StatusCode};
use metrics::{counter, histogram};
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
use qpx_core::config::ReverseConfig;
use qpx_core::rules::RuleMatchContext;
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::time::{sleep, timeout, Duration, Instant};
use tracing::warn;
use url::Url;

#[derive(Debug, Clone)]
pub(crate) struct ReverseConnInfo {
    remote_addr: std::net::SocketAddr,
    dst_port: u16,
    tls_sni: Option<Arc<str>>,
    tls_terminated: bool,
}

impl ReverseConnInfo {
    pub(crate) fn plain(remote_addr: std::net::SocketAddr, dst_port: u16) -> Self {
        Self {
            remote_addr,
            dst_port,
            tls_sni: None,
            tls_terminated: false,
        }
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(crate) fn terminated(
        remote_addr: std::net::SocketAddr,
        dst_port: u16,
        tls_sni: Option<Arc<str>>,
    ) -> Self {
        Self {
            remote_addr,
            dst_port,
            tls_sni,
            tls_terminated: true,
        }
    }
}

pub(super) async fn handle_request(
    req: Request<Body>,
    reverse: super::ReloadableReverse,
    conn: ReverseConnInfo,
) -> Result<Response<Body>, Infallible> {
    let runtime = reverse.runtime.clone();
    let state = runtime.state();
    let request_method = req.method().clone();
    let request_version = req.version();
    let result = handle_request_inner(req, reverse, runtime, conn).await;
    Ok(result.unwrap_or_else(|err| {
        warn!(error = ?err, "reverse handling failed");
        finalize_response_for_request(
            &request_method,
            request_version,
            state.config.identity.proxy_name.as_str(),
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from(state.messages.reverse_error.clone()))
                .unwrap(),
            false,
        )
    }))
}

pub(crate) async fn handle_request_inner(
    mut req: Request<Body>,
    reverse: super::ReloadableReverse,
    runtime: Runtime,
    conn: ReverseConnInfo,
) -> Result<Response<Body>> {
    let compiled = reverse.compiled().await;
    let router: Arc<ReverseRouter> = compiled.router.clone();
    let security_policy = compiled.security_policy.as_ref();
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.clone();
    if let Err(err) = validate_incoming_request(&req) {
        return Ok(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name.as_str(),
            Response::builder()
                .status(err.http_status())
                .body(Body::from(err.to_string()))
                .unwrap_or_else(|_| bad_request(err.to_string())),
            false,
        ));
    }

    if req.method() == Method::TRACE && !state.config.runtime.trace_enabled {
        return Ok(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name.as_str(),
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from(state.messages.trace_disabled.clone()))?,
            false,
        ));
    }

    // Reverse proxies must not accept CONNECT; it is a forward-proxy-only method.
    if req.method() == Method::CONNECT {
        return Ok(finalize_response_for_request(
            &Method::CONNECT,
            req.version(),
            proxy_name.as_str(),
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from(state.messages.reverse_error.clone()))?,
            false,
        ));
    }
    if let Err(err) =
        security_policy.validate_request(&req, conn.tls_sni.as_deref(), conn.tls_terminated)
    {
        warn!(error = ?err, "reverse TLS host policy rejected request");
        let request_method = req.method().clone();
        return Ok(finalize_response_for_request(
            &request_method,
            req.version(),
            state.config.identity.proxy_name.as_str(),
            Response::builder()
                .status(StatusCode::MISDIRECTED_REQUEST)
                .body(Body::from("misdirected request"))?,
            false,
        ));
    }
    let host_header = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .unwrap_or("");
    let host = normalize_host_for_match(host_header);
    let method = req.method().as_str();

    let ctx = RuleMatchContext {
        src_ip: Some(conn.remote_addr.ip()),
        dst_port: Some(conn.dst_port),
        host: (!host.is_empty()).then_some(host.as_str()),
        sni: conn.tls_sni.as_deref(),
        method: Some(method),
        path: req.uri().path_and_query().map(|p| p.as_str()),
        headers: Some(req.headers()),
        user_groups: &[],
    };

    let route = router
        .select_route(&ctx)
        .ok_or_else(|| anyhow!("no route matched"))?;
    let seed = request_seed(&conn, host.as_str(), &req);
    let sticky_seed = sticky_seed(&conn, host.as_str());
    if let Some(local) = route.local_response.as_ref() {
        let request_method = req.method().clone();
        let response = finalize_response_with_headers(
            &request_method,
            req.version(),
            proxy_name.as_str(),
            build_local_response(local)?,
            route.headers.as_deref(),
            false,
        );
        counter!(state.metric_names.reverse_local_response_total.clone()).increment(1);
        return Ok(response);
    }

    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name.as_str(),
        state.config.runtime.trace_reflect_all_headers,
    ) {
        return Ok(response);
    }

    if let Some(rewrite) = route.path_rewrite.as_ref() {
        apply_path_rewrite(&mut req, rewrite);
    }

    apply_request_headers(req.headers_mut(), route.headers.as_deref());

    let request_method = req.method().clone();
    if is_websocket_upgrade(req.headers()) {
        let upgrade_wait_timeout =
            Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
        let tunnel_idle_timeout =
            Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
        let upstream = route
            .select_upstream(seed, sticky_seed)
            .ok_or_else(|| anyhow!("no healthy upstream"))?;
        upstream.inflight.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let response = timeout(
            route.policy.timeout,
            proxy_websocket(
                req,
                &upstream.target,
                proxy_name.as_str(),
                route.policy.timeout,
                upgrade_wait_timeout,
                tunnel_idle_timeout,
            ),
        )
        .await;
        upstream.inflight.fetch_sub(1, Ordering::Relaxed);
        match response {
            Ok(Ok(mut resp)) => {
                upstream.mark_success();
                histogram!(state.metric_names.reverse_upstream_latency_ms.clone())
                    .record(started.elapsed().as_secs_f64() * 1000.0);
                counter!(
                    state.metric_names.reverse_requests_total.clone(),
                    "result" => "ok"
                )
                .increment(1);
                let keep_upgrade = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
                let resp_version = resp.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    resp_version,
                    proxy_name.as_str(),
                    &mut resp,
                    route.headers.as_deref(),
                    keep_upgrade,
                );
                return Ok(resp);
            }
            Ok(Err(err)) => {
                upstream.mark_failure(&route.policy.health);
                counter!(
                    state.metric_names.reverse_requests_total.clone(),
                    "result" => "error"
                )
                .increment(1);
                return Err(err);
            }
            Err(_) => {
                upstream.mark_failure(&route.policy.health);
                counter!(
                    state.metric_names.reverse_requests_total.clone(),
                    "result" => "timeout"
                )
                .increment(1);
                return Err(anyhow!("upstream timeout"));
            }
        }
    }

    let cache_policy = route.cache_policy.as_ref().filter(|c| c.enabled);
    let cache_default_scheme = if conn.tls_terminated { "https" } else { "http" };
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) = if cache_policy.is_some() {
        let cache_lookup_key = CacheRequestKey::for_lookup(&req, cache_default_scheme)?;
        let cache_target_key = CacheRequestKey::for_target(&req, cache_default_scheme)?;
        let snapshot = cache_lookup_key.as_ref().map(|_| req.headers().clone());
        (snapshot, cache_lookup_key, cache_target_key)
    } else {
        (None, None, None)
    };
    let mut revalidation_state = None;
    if let (Some(snapshot), Some(_)) = (request_headers_snapshot.as_ref(), cache_policy) {
        let (lookup_decision, lookup_revalidation_state) = lookup_with_revalidation(
            &mut req,
            snapshot,
            cache_lookup_key.as_ref(),
            cache_policy,
            &runtime.state().cache_backends,
            state.messages.cache_miss.as_str(),
        )
        .await?;
        revalidation_state = lookup_revalidation_state;
        match lookup_decision {
            CacheLookupDecision::Hit(mut hit) => {
                let hit_version = hit.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    hit_version,
                    proxy_name.as_str(),
                    &mut hit,
                    route.headers.as_deref(),
                    false,
                );
                return Ok(hit);
            }
            CacheLookupDecision::StaleWhileRevalidate(mut hit, state) => {
                if request_method == Method::GET && route.ipc.is_none() {
                    if let (Some(policy), Some(snapshot), Some(lookup_key), Some(target_key)) = (
                        cache_policy,
                        request_headers_snapshot.as_ref(),
                        cache_lookup_key.as_ref(),
                        cache_target_key.as_ref(),
                    ) {
                        if let Some(upstream) = route.select_upstream(seed, sticky_seed) {
                            let target = upstream.target.clone();
                            if !target.starts_with("ipc://") && !target.starts_with("ipc+unix://") {
                                if let Some(guard) =
                                    crate::cache::try_begin_background_revalidation(&state)
                                {
                                    let runtime = runtime.clone();
                                    let proxy_name = proxy_name.clone();
                                    let timeout_dur = route.policy.timeout;
                                    let policy = (*policy).clone();
                                    let snapshot = (*snapshot).clone();
                                    let lookup_key = (*lookup_key).clone();
                                    let target_key = (*target_key).clone();
                                    let bg_req = clone_request_head_for_revalidation(&req);
                                    tokio::spawn(async move {
                                        let _guard = guard;
                                        let started = Instant::now();
                                        let resp = timeout(
                                            timeout_dur,
                                            proxy_http(
                                                bg_req,
                                                target.as_str(),
                                                proxy_name.as_str(),
                                            ),
                                        )
                                        .await;
                                        let Ok(Ok(resp)) = resp else {
                                            return;
                                        };
                                        let response_delay_secs = started.elapsed().as_secs();
                                        let state_ref = runtime.state();
                                        let backends = &state_ref.cache_backends;
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
                                                backends,
                                            },
                                        )
                                        .await;
                                    });
                                }
                            }
                        }
                    }
                }
                let hit_version = hit.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    hit_version,
                    proxy_name.as_str(),
                    &mut hit,
                    route.headers.as_deref(),
                    false,
                );
                return Ok(hit);
            }
            CacheLookupDecision::OnlyIfCachedMiss(response) => {
                return Ok(finalize_response_with_headers(
                    &request_method,
                    req.version(),
                    proxy_name.as_str(),
                    response,
                    route.headers.as_deref(),
                    false,
                ));
            }
            CacheLookupDecision::Miss => {}
        }
    }

    let can_retry = request_is_retryable(&req, &request_method);
    let attempts = if can_retry {
        route.policy.retry_attempts
    } else {
        1
    };
    let max_template_body_bytes = runtime
        .state()
        .config
        .runtime
        .max_reverse_retry_template_body_bytes;
    let mirror_upstreams = if request_is_templateable(&req, max_template_body_bytes) {
        route.select_mirror_upstreams(seed, sticky_seed)
    } else {
        Vec::new()
    };
    let need_template = attempts > 1 || !mirror_upstreams.is_empty();
    let (mut first_request, template) = if need_template {
        (
            None,
            Some(ReverseRequestTemplate::from_request(req, max_template_body_bytes).await?),
        )
    } else {
        (Some(req), None)
    };
    if let Some(template) = template.as_ref() {
        dispatch_mirrors(
            template,
            mirror_upstreams,
            route.policy.timeout,
            route.policy.health.clone(),
            proxy_name.as_str(),
        );
    }

    let ipc_conn = ClientConnInfo {
        remote_addr: Some(conn.remote_addr),
    };

    let mut last_err = None;

    if let Some(ipc) = route.ipc.as_ref() {
        let timeout_dur = std::cmp::min(route.policy.timeout, ipc.timeout());
        for attempt_idx in 0..attempts {
            let started = Instant::now();
            let req_for_upstream = if attempt_idx == 0 {
                match (&template, first_request.take()) {
                    (Some(template), _) => template.build()?,
                    (None, Some(req)) => req,
                    (None, None) => {
                        return Err(anyhow!("missing reverse request for first attempt"))
                    }
                }
            } else {
                template
                    .as_ref()
                    .ok_or_else(|| anyhow!("reverse retry template missing"))?
                    .build()?
            };

            let response = timeout(
                timeout_dur,
                proxy_ipc_upstream(
                    req_for_upstream,
                    ipc,
                    proxy_name.as_str(),
                    ipc_conn,
                    route.policy.timeout,
                ),
            )
            .await;

            match response {
                Ok(Ok(mut resp)) => {
                    if resp.status().is_server_error() {
                        if let Some(stale) = revalidation_state
                            .as_ref()
                            .and_then(crate::cache::maybe_build_stale_if_error_response)
                        {
                            let mut stale = stale;
                            let stale_version = stale.version();
                            finalize_response_with_headers_in_place(
                                &request_method,
                                stale_version,
                                proxy_name.as_str(),
                                &mut stale,
                                route.headers.as_deref(),
                                false,
                            );
                            return Ok(stale);
                        }
                    }
                    histogram!(state.metric_names.reverse_upstream_latency_ms.clone())
                        .record(started.elapsed().as_secs_f64() * 1000.0);
                    let response_delay_secs = started.elapsed().as_secs();
                    counter!(
                        state.metric_names.reverse_requests_total.clone(),
                        "result" => "ok"
                    )
                    .increment(1);
                    if let (Some(policy), Some(snapshot)) =
                        (cache_policy, request_headers_snapshot.as_ref())
                    {
                        resp = process_upstream_response_for_cache(
                            resp,
                            CacheWritebackContext {
                                request_method: &request_method,
                                response_delay_secs,
                                cache_target_key: cache_target_key.as_ref(),
                                cache_lookup_key: cache_lookup_key.as_ref(),
                                cache_policy: Some(policy),
                                request_headers_snapshot: snapshot,
                                revalidation_state: revalidation_state.take(),
                                backends: &runtime.state().cache_backends,
                            },
                        )
                        .await?;
                    } else if let Some(policy) = cache_policy {
                        crate::cache::maybe_invalidate(
                            &request_method,
                            resp.status(),
                            resp.headers(),
                            cache_target_key.as_ref(),
                            policy,
                            &runtime.state().cache_backends,
                        )
                        .await?;
                    }
                    let resp_version = resp.version();
                    finalize_response_with_headers_in_place(
                        &request_method,
                        resp_version,
                        proxy_name.as_str(),
                        &mut resp,
                        route.headers.as_deref(),
                        false,
                    );
                    return Ok(resp);
                }
                Ok(Err(err)) => {
                    counter!(
                        state.metric_names.reverse_requests_total.clone(),
                        "result" => "error"
                    )
                    .increment(1);
                    last_err = Some(err);
                }
                Err(_) => {
                    counter!(
                        state.metric_names.reverse_requests_total.clone(),
                        "result" => "timeout"
                    )
                    .increment(1);
                    last_err = Some(anyhow!("upstream timeout"));
                }
            }

            if attempt_idx + 1 < attempts && route.policy.retry_backoff > Duration::ZERO {
                sleep(route.policy.retry_backoff).await;
            }
        }

        if let Some(stale) = revalidation_state
            .as_ref()
            .and_then(crate::cache::maybe_build_stale_if_error_response)
        {
            let mut stale = stale;
            let stale_version = stale.version();
            finalize_response_with_headers_in_place(
                &request_method,
                stale_version,
                proxy_name.as_str(),
                &mut stale,
                route.headers.as_deref(),
                false,
            );
            return Ok(stale);
        }

        return Err(last_err.unwrap_or_else(|| anyhow!("upstream request failed")));
    }

    for attempt_idx in 0..attempts {
        let upstream = match route.select_upstream(seed, sticky_seed) {
            Some(u) => u,
            None => return Err(anyhow!("no upstream")),
        };
        upstream.inflight.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let req_for_upstream = if attempt_idx == 0 {
            match (&template, first_request.take()) {
                (Some(template), _) => template.build()?,
                (None, Some(req)) => req,
                (None, None) => return Err(anyhow!("missing reverse request for first attempt")),
            }
        } else {
            template
                .as_ref()
                .ok_or_else(|| anyhow!("reverse retry template missing"))?
                .build()?
        };
        let response = if upstream.target.starts_with("ipc://")
            || upstream.target.starts_with("ipc+unix://")
        {
            match Url::parse(&upstream.target) {
                Ok(url) => {
                    timeout(
                        route.policy.timeout,
                        proxy_ipc(req_for_upstream, &url, proxy_name.as_str()),
                    )
                    .await
                }
                Err(err) => Ok(Err(anyhow!("invalid ipc upstream url: {}", err))),
            }
        } else {
            timeout(
                route.policy.timeout,
                proxy_http(req_for_upstream, &upstream.target, proxy_name.as_str()),
            )
            .await
        };
        upstream.inflight.fetch_sub(1, Ordering::Relaxed);

        match response {
            Ok(Ok(mut resp)) => {
                if resp.status().is_server_error() {
                    if let Some(stale) = revalidation_state
                        .as_ref()
                        .and_then(crate::cache::maybe_build_stale_if_error_response)
                    {
                        upstream.mark_failure(&route.policy.health);
                        let mut stale = stale;
                        let stale_version = stale.version();
                        finalize_response_with_headers_in_place(
                            &request_method,
                            stale_version,
                            proxy_name.as_str(),
                            &mut stale,
                            route.headers.as_deref(),
                            false,
                        );
                        return Ok(stale);
                    }
                }
                upstream.mark_success();
                histogram!(state.metric_names.reverse_upstream_latency_ms.clone())
                    .record(started.elapsed().as_secs_f64() * 1000.0);
                let response_delay_secs = started.elapsed().as_secs();
                counter!(
                    state.metric_names.reverse_requests_total.clone(),
                    "result" => "ok"
                )
                .increment(1);
                if let (Some(policy), Some(snapshot)) =
                    (cache_policy, request_headers_snapshot.as_ref())
                {
                    resp = process_upstream_response_for_cache(
                        resp,
                        CacheWritebackContext {
                            request_method: &request_method,
                            response_delay_secs,
                            cache_target_key: cache_target_key.as_ref(),
                            cache_lookup_key: cache_lookup_key.as_ref(),
                            cache_policy: Some(policy),
                            request_headers_snapshot: snapshot,
                            revalidation_state: revalidation_state.take(),
                            backends: &runtime.state().cache_backends,
                        },
                    )
                    .await?;
                } else if let Some(policy) = cache_policy {
                    crate::cache::maybe_invalidate(
                        &request_method,
                        resp.status(),
                        resp.headers(),
                        cache_target_key.as_ref(),
                        policy,
                        &runtime.state().cache_backends,
                    )
                    .await?;
                }
                let resp_version = resp.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    resp_version,
                    proxy_name.as_str(),
                    &mut resp,
                    route.headers.as_deref(),
                    false,
                );
                return Ok(resp);
            }
            Ok(Err(err)) => {
                upstream.mark_failure(&route.policy.health);
                counter!(
                    state.metric_names.reverse_requests_total.clone(),
                    "result" => "error"
                )
                .increment(1);
                last_err = Some(err);
            }
            Err(_) => {
                upstream.mark_failure(&route.policy.health);
                counter!(
                    state.metric_names.reverse_requests_total.clone(),
                    "result" => "timeout"
                )
                .increment(1);
                last_err = Some(anyhow!("upstream timeout"));
            }
        }

        if attempt_idx + 1 < attempts && route.policy.retry_backoff > Duration::ZERO {
            sleep(route.policy.retry_backoff).await;
        }
    }

    if let Some(stale) = revalidation_state
        .as_ref()
        .and_then(crate::cache::maybe_build_stale_if_error_response)
    {
        let mut stale = stale;
        let stale_version = stale.version();
        finalize_response_with_headers_in_place(
            &request_method,
            stale_version,
            proxy_name.as_str(),
            &mut stale,
            route.headers.as_deref(),
            false,
        );
        return Ok(stale);
    }

    Err(last_err.unwrap_or_else(|| anyhow!("upstream request failed")))
}

fn apply_path_rewrite(req: &mut Request<Body>, rewrite: &CompiledPathRewrite) {
    let pq = req.uri().path_and_query();
    let path = pq.map(|pq| pq.path()).unwrap_or("/");
    let query = pq.and_then(|pq| pq.query());

    let mut new_path = path.to_string();
    if let Some(prefix) = &rewrite.strip_prefix {
        if let Some(rest) = new_path.strip_prefix(prefix.as_str()) {
            new_path = if rest.is_empty() || !rest.starts_with('/') {
                format!("/{rest}")
            } else {
                rest.to_string()
            };
        }
    }
    if let Some(prefix) = &rewrite.add_prefix {
        new_path = format!("{prefix}{new_path}");
    }
    if let Some(regex) = rewrite.regex.as_ref() {
        new_path = regex
            .pattern
            .replace(new_path.as_str(), regex.replace.as_str())
            .to_string();
        if new_path.is_empty() {
            new_path = "/".to_string();
        } else if !new_path.starts_with('/') {
            new_path = format!("/{new_path}");
        }
    }
    if let Some(q) = query {
        new_path = format!("{new_path}?{q}");
    }
    match new_path.parse::<http::Uri>() {
        Ok(new_uri) => {
            *req.uri_mut() = new_uri;
        }
        Err(err) => {
            counter!("qpx_reverse_path_rewrite_invalid_total").increment(1);
            warn!(
                error = ?err,
                "reverse path_rewrite produced invalid URI; keeping original"
            );
        }
    }
}

fn request_seed(conn: &ReverseConnInfo, host: &str, req: &Request<Body>) -> u64 {
    // Deterministic hashing for stable canary/mirror sampling.
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    fn feed(mut hash: u64, bytes: &[u8]) -> u64 {
        for b in bytes {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    let mut hash = FNV_OFFSET;
    match conn.remote_addr.ip() {
        std::net::IpAddr::V4(ip) => {
            hash = feed(hash, &ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            hash = feed(hash, &ip.octets());
        }
    }
    hash = feed(hash, host.as_bytes());
    hash = feed(hash, req.method().as_str().as_bytes());
    if let Some(pq) = req.uri().path_and_query() {
        hash = feed(hash, pq.as_str().as_bytes());
    } else {
        hash = feed(hash, b"/");
    }
    hash
}

fn sticky_seed(conn: &ReverseConnInfo, host: &str) -> u64 {
    // Stable per-client+host key for sticky load balancing.
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    fn feed(mut hash: u64, bytes: &[u8]) -> u64 {
        for b in bytes {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }
    let mut hash = FNV_OFFSET;
    match conn.remote_addr.ip() {
        std::net::IpAddr::V4(ip) => {
            hash = feed(hash, &ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            hash = feed(hash, &ip.octets());
        }
    }
    hash = feed(hash, host.as_bytes());
    hash
}

fn request_is_templateable(req: &Request<Body>, max_body_bytes: usize) -> bool {
    // We only attempt to clone/mirror requests that can be safely buffered.
    if req.headers().contains_key(TRANSFER_ENCODING) {
        return false;
    }
    let values = req.headers().get_all(CONTENT_LENGTH);
    let mut parsed = Vec::new();
    for value in values {
        let Ok(raw) = value.to_str() else {
            return false;
        };
        let Ok(len) = raw.trim().parse::<u64>() else {
            return false;
        };
        parsed.push(len);
    }
    if parsed.is_empty() {
        // HTTP/1.1 without Content-Length/Transfer-Encoding cannot have a body.
        return req.version() == http::Version::HTTP_11;
    }
    if parsed.iter().any(|l| *l != parsed[0]) {
        return false;
    }
    (parsed[0] as usize) <= max_body_bytes
}

fn dispatch_mirrors(
    template: &ReverseRequestTemplate,
    mirror_upstreams: Vec<Arc<super::health::UpstreamEndpoint>>,
    timeout_dur: Duration,
    health_policy: super::health::HealthCheckRuntime,
    proxy_name: &str,
) {
    if mirror_upstreams.is_empty() {
        return;
    }
    let proxy_name = proxy_name.to_string();
    for upstream in mirror_upstreams {
        let req = match template.build() {
            Ok(req) => req,
            Err(err) => {
                warn!(error = ?err, "reverse mirror build failed");
                continue;
            }
        };
        upstream.inflight.fetch_add(1, Ordering::Relaxed);
        let upstream_for_task = upstream.clone();
        let target = upstream.target.clone();
        let proxy_name = proxy_name.clone();
        let health_policy = health_policy.clone();
        tokio::spawn(async move {
            let response = timeout(
                timeout_dur,
                proxy_http(req, target.as_str(), proxy_name.as_str()),
            )
            .await;
            upstream_for_task.inflight.fetch_sub(1, Ordering::Relaxed);
            match response {
                Ok(Ok(_)) => upstream_for_task.mark_success(),
                Ok(Err(_)) | Err(_) => upstream_for_task.mark_failure(&health_policy),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::router::CompiledRegexPathRewrite;
    use super::*;
    use regex::Regex;

    fn make_req(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[test]
    fn path_rewrite_strip_prefix() {
        let mut req = make_req("/api/v1/users");
        apply_path_rewrite(
            &mut req,
            &CompiledPathRewrite {
                strip_prefix: Some("/api/v1".into()),
                add_prefix: None,
                regex: None,
            },
        );
        assert_eq!(req.uri().path(), "/users");
    }

    #[test]
    fn path_rewrite_add_prefix() {
        let mut req = make_req("/users");
        apply_path_rewrite(
            &mut req,
            &CompiledPathRewrite {
                strip_prefix: None,
                add_prefix: Some("/v2".into()),
                regex: None,
            },
        );
        assert_eq!(req.uri().path(), "/v2/users");
    }

    #[test]
    fn path_rewrite_strip_and_add() {
        let mut req = make_req("/api/v1/users");
        apply_path_rewrite(
            &mut req,
            &CompiledPathRewrite {
                strip_prefix: Some("/api/v1".into()),
                add_prefix: Some("/v2".into()),
                regex: None,
            },
        );
        assert_eq!(req.uri().path(), "/v2/users");
    }

    #[test]
    fn path_rewrite_preserves_query() {
        let mut req = make_req("/api/v1/users?q=foo&limit=10");
        apply_path_rewrite(
            &mut req,
            &CompiledPathRewrite {
                strip_prefix: Some("/api/v1".into()),
                add_prefix: None,
                regex: None,
            },
        );
        assert_eq!(
            req.uri().path_and_query().unwrap().as_str(),
            "/users?q=foo&limit=10"
        );
    }

    #[test]
    fn path_rewrite_root_only() {
        let mut req = make_req("/api/v1");
        apply_path_rewrite(
            &mut req,
            &CompiledPathRewrite {
                strip_prefix: Some("/api/v1".into()),
                add_prefix: None,
                regex: None,
            },
        );
        assert_eq!(req.uri().path(), "/");
    }

    #[test]
    fn path_rewrite_no_match_passthrough() {
        let mut req = make_req("/other/path");
        apply_path_rewrite(
            &mut req,
            &CompiledPathRewrite {
                strip_prefix: Some("/api/v1".into()),
                add_prefix: None,
                regex: None,
            },
        );
        assert_eq!(req.uri().path(), "/other/path");
    }

    #[test]
    fn path_rewrite_regex_replace() {
        let mut req = make_req("/api/v1/users");
        apply_path_rewrite(
            &mut req,
            &CompiledPathRewrite {
                strip_prefix: None,
                add_prefix: None,
                regex: Some(CompiledRegexPathRewrite {
                    pattern: Regex::new(r"^/api/v1/(.*)$").unwrap(),
                    replace: "/v2/$1".to_string(),
                }),
            },
        );
        assert_eq!(req.uri().path(), "/v2/users");
    }

    #[test]
    fn path_rewrite_regex_ensures_leading_slash() {
        let mut req = make_req("/api/v1/users");
        apply_path_rewrite(
            &mut req,
            &CompiledPathRewrite {
                strip_prefix: None,
                add_prefix: None,
                regex: Some(CompiledRegexPathRewrite {
                    pattern: Regex::new(r"^/api/v1/(.*)$").unwrap(),
                    replace: "$1".to_string(), // no leading slash
                }),
            },
        );
        assert_eq!(req.uri().path(), "/users");
    }
}

#[cfg(feature = "tls-rustls")]
pub(super) type ReverseTlsAcceptor = tokio_rustls::TlsAcceptor;

#[cfg(feature = "tls-rustls")]
pub(super) fn build_tls_acceptor(reverse: &ReverseConfig) -> Result<ReverseTlsAcceptor> {
    use qpx_core::tls::load_cert_chain;
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};
    use std::path::Path;

    let tls = reverse
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("tls config missing"))?;
    let resolver = Arc::new(SniResolver::new(tls)?);
    let mut config = if let Some(client_ca) = tls
        .client_ca
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let certs = load_cert_chain(Path::new(client_ca))?;
        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(anyhow!("no client CA certs loaded from {}", client_ca));
        }
        let verifier = WebPkiClientVerifier::builder(roots.into())
            .build()
            .map_err(|_| anyhow!("invalid reverse.tls.client_ca"))?;
        RustlsServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(resolver)
    } else {
        RustlsServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver)
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

#[cfg(feature = "tls-rustls")]
#[derive(Debug)]
struct SniResolver {
    certs: std::collections::HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    acme_snis: std::collections::HashSet<String>,
}

#[cfg(feature = "tls-rustls")]
impl SniResolver {
    fn new(tls: &qpx_core::config::ReverseTlsConfig) -> Result<Self> {
        use qpx_core::tls::{load_cert_chain, load_private_key};
        use rustls::crypto::ring::sign::any_supported_type;
        use rustls::sign::CertifiedKey;
        use std::collections::{HashMap, HashSet};
        use std::path::Path;

        let mut certs = HashMap::new();
        let mut acme_snis = HashSet::new();
        for cert in &tls.certificates {
            let cert_path = cert.cert.as_deref().unwrap_or("").trim();
            let key_path = cert.key.as_deref().unwrap_or("").trim();
            if cert_path.is_empty() && key_path.is_empty() {
                acme_snis.insert(cert.sni.to_ascii_lowercase());
            } else {
                if cert_path.is_empty() {
                    return Err(anyhow!("reverse.tls.certificates[].cert must not be empty"));
                }
                if key_path.is_empty() {
                    return Err(anyhow!("reverse.tls.certificates[].key must not be empty"));
                }
                let chain = load_cert_chain(Path::new(cert_path))?;
                let key = load_private_key(Path::new(key_path))?;
                let signing_key =
                    any_supported_type(&key).map_err(|_| anyhow!("unsupported key"))?;
                let certified = Arc::new(CertifiedKey::new(chain, signing_key));
                certs.insert(cert.sni.to_ascii_lowercase(), certified);
            }
        }
        Ok(Self { certs, acme_snis })
    }
}

#[cfg(feature = "tls-rustls")]
impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = client_hello.server_name()?.to_ascii_lowercase();
        if let Some(key) = self.certs.get(&name) {
            return Some(key.clone());
        }
        if self.acme_snis.contains(&name) {
            return crate::acme::cert_store().and_then(|store| store.get(&name));
        }
        None
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(super) type ReverseTlsAcceptor = NativeTlsAcceptor;

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
#[derive(Clone)]
pub(super) struct NativeTlsAcceptor {
    by_sni: std::collections::HashMap<String, tokio_native_tls::TlsAcceptor>,
    default: Option<tokio_native_tls::TlsAcceptor>,
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
impl NativeTlsAcceptor {
    pub(super) async fn accept<S>(
        &self,
        stream: S,
        sni: Option<&str>,
    ) -> Result<tokio_native_tls::TlsStream<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let key = sni.map(|v| v.to_ascii_lowercase());
        let acceptor = key
            .as_deref()
            .and_then(|k| self.by_sni.get(k))
            .or(self.default.as_ref())
            .ok_or_else(|| anyhow!("no TLS certificate for SNI {:?}", sni))?;
        Ok(acceptor.accept(stream).await?)
    }
}

#[cfg(all(not(feature = "tls-rustls"), feature = "tls-native"))]
pub(super) fn build_tls_acceptor(reverse: &ReverseConfig) -> Result<ReverseTlsAcceptor> {
    use anyhow::Context;
    use std::collections::HashMap;
    use std::fs;

    let tls = reverse
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("tls config missing"))?;

    let mut by_sni: HashMap<String, tokio_native_tls::TlsAcceptor> = HashMap::new();
    let mut default: Option<tokio_native_tls::TlsAcceptor> = None;

    for cert in &tls.certificates {
        let pkcs12_path = cert
            .pkcs12
            .as_deref()
            .ok_or_else(|| anyhow!("reverse.tls.certificates[].pkcs12 is required for tls-native"))?
            .trim();
        if pkcs12_path.is_empty() {
            return Err(anyhow!(
                "reverse.tls.certificates[].pkcs12 must not be empty"
            ));
        }
        let password = cert
            .pkcs12_password_env
            .as_deref()
            .map(|env| std::env::var(env).map_err(|_| anyhow!("{env} is set but missing")))
            .transpose()?
            .unwrap_or_default();

        let der = fs::read(pkcs12_path)
            .with_context(|| format!("failed to read pkcs12 {}", pkcs12_path))?;
        let identity = native_tls::Identity::from_pkcs12(&der, password.as_str())
            .map_err(|_| anyhow!("invalid pkcs12 identity: {}", pkcs12_path))?;
        let acceptor = tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::new(identity)?);

        let sni = cert.sni.trim();
        if sni.is_empty() {
            return Err(anyhow!("reverse.tls.certificates[].sni must not be empty"));
        }
        if sni == "*" {
            default = Some(acceptor);
        } else {
            by_sni.insert(sni.to_ascii_lowercase(), acceptor);
        }
    }

    Ok(NativeTlsAcceptor { by_sni, default })
}
