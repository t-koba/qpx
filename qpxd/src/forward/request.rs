use super::connect;
use super::policy::{evaluate_forward_policy, ForwardPolicyDecision};
use crate::cache::CacheRequestKey;
use crate::ftp;
use crate::http::address::{format_authority_host_port, parse_authority_host_port};
use crate::http::cache_flow::{
    clone_request_head_for_revalidation, lookup_with_revalidation,
    process_upstream_response_for_cache, CacheLookupDecision, CacheWritebackContext,
};
use crate::http::common::{
    bad_request_response as bad_request, blocked_response as blocked,
    forbidden_response as forbidden, resolve_named_upstream,
    too_many_requests_response as too_many_requests,
};
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers,
    finalize_response_with_headers_in_place, handle_max_forwards_in_place,
    prepare_request_with_headers_in_place,
};
use crate::http::local_response::build_local_response;
use crate::http::semantics::validate_incoming_request;
use crate::http::websocket::is_websocket_upgrade;
use crate::runtime::Runtime;
use crate::upstream::http1::{proxy_http1_request, proxy_websocket_http1, WebsocketProxyConfig};
use anyhow::{anyhow, Result};
use hyper::{Body, Method, Request, Response, StatusCode};
use qpx_core::config::ActionKind;
use qpx_core::rules::RuleMatchContext;
use std::sync::Arc;
use tokio::time::Duration;

pub(crate) async fn handle_request_inner(
    mut req: Request<Body>,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    if let Err(err) = validate_incoming_request(&req) {
        return Ok(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(err.http_status())
                .body(Body::from(err.to_string()))
                .unwrap_or_else(|_| bad_request(err.to_string())),
            false,
        ));
    }
    let listener_cfg = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    if let Some(limits) = state.rate_limiters.listener(listener_name) {
        if let Some(limiter) = limits.listener.requests.as_ref() {
            if let Some(retry_after) = limiter.try_acquire(remote_addr.ip(), 1) {
                return Ok(finalize_response_for_request(
                    req.method(),
                    req.version(),
                    proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                ));
            }
        }
    }
    let cache_policy = listener_cfg.cache.as_ref().filter(|c| c.enabled).cloned();
    let is_ftp_request = req
        .uri()
        .scheme_str()
        .map(|scheme| scheme.eq_ignore_ascii_case("ftp"))
        .unwrap_or(false);
    if is_ftp_request && !listener_cfg.ftp.enabled {
        return Ok(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::NOT_IMPLEMENTED)
                .body(Body::from(state.messages.ftp_disabled.clone()))
                .unwrap(),
            false,
        ));
    }

    if req.method() == Method::TRACE && !state.config.runtime.trace_enabled {
        return Ok(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from(state.messages.trace_disabled.clone()))
                .unwrap(),
            false,
        ));
    }

    if req.method() == Method::CONNECT {
        return connect::handle_connect(req, runtime, listener_name, remote_addr).await;
    }

    let host = match extract_host(&req) {
        Some(host) => host,
        None => {
            return Ok(finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("missing Host/authority"))
                    .unwrap_or_else(|_| bad_request("missing Host/authority")),
                false,
            ));
        }
    };
    let path = req.uri().path_and_query().map(|p| p.as_str());

    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: host.port,
        host: Some(host.host.as_str()),
        sni: None,
        method: Some(req.method().as_str()),
        path,
        headers: Some(req.headers()),
        user_groups: &[],
    };
    let policy = evaluate_forward_policy(
        &runtime,
        listener_name,
        ctx,
        req.headers(),
        req.method().as_str(),
        &req.uri().to_string(),
    )
    .await?;
    let (action, headers, matched_rule) = match policy {
        ForwardPolicyDecision::Allow(allowed) => {
            (allowed.action, allowed.headers, allowed.matched_rule)
        }
        ForwardPolicyDecision::Challenge(chal) => {
            let response = proxy_auth_required(chal, state.messages.proxy_auth_required.as_str());
            return Ok(finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                response,
                false,
            ));
        }
        ForwardPolicyDecision::Forbidden => {
            return Ok(finalize_response_for_request(
                req.method(),
                req.version(),
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            ));
        }
    };
    if let Some(rule) = matched_rule.as_deref() {
        if let Some(limits) = state.rate_limiters.listener(listener_name) {
            if let Some(rule_limits) = limits.rules.get(rule) {
                if let Some(limiter) = rule_limits.requests.as_ref() {
                    if let Some(retry_after) = limiter.try_acquire(remote_addr.ip(), 1) {
                        return Ok(finalize_response_for_request(
                            req.method(),
                            req.version(),
                            proxy_name,
                            too_many_requests(Some(retry_after)),
                            false,
                        ));
                    }
                }
            }
        }
    }

    if matches!(action.kind, ActionKind::Block) {
        return Ok(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            blocked(state.messages.blocked.as_str()),
            false,
        ));
    }
    if matches!(action.kind, ActionKind::Respond) {
        let local = action
            .local_response
            .as_ref()
            .ok_or_else(|| anyhow!("respond action requires local_response"))?;
        return Ok(finalize_response_with_headers(
            req.method(),
            req.version(),
            proxy_name,
            build_local_response(local)?,
            headers.as_deref(),
            false,
        ));
    }

    let client_version = req.version();
    let request_method = req.method().clone();
    if is_ftp_request {
        let mut response = ftp::handle_ftp(
            req,
            listener_cfg.ftp.clone(),
            Arc::<str>::from(state.messages.unsupported_ftp_method.as_str()),
            state.ftp_semaphore.clone(),
        )
        .await?;
        let response_version = response.version();
        finalize_response_with_headers_in_place(
            &request_method,
            response_version,
            proxy_name,
            &mut response,
            headers.as_deref(),
            false,
        );
        return Ok(response);
    }
    if let Some(response) = handle_max_forwards_in_place(
        &mut req,
        proxy_name,
        state.config.runtime.trace_reflect_all_headers,
    ) {
        return Ok(response);
    }
    let websocket = is_websocket_upgrade(req.headers());
    prepare_request_with_headers_in_place(&mut req, proxy_name, headers.as_deref(), websocket);
    if !req.headers().contains_key("host") {
        let default_port = match req.uri().scheme_str() {
            Some(s) if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("wss") => 443,
            Some(s) if s.eq_ignore_ascii_case("ftp") => 21,
            _ => 80,
        };
        let host_value = match host.port {
            Some(port) if port != default_port => {
                format_authority_host_port(host.host.as_str(), port)
            }
            _ => host.host.clone(),
        };
        req.headers_mut()
            .insert("host", http::HeaderValue::from_str(&host_value).unwrap());
    }
    let cache_applicable = cache_policy.is_some()
        && matches!(
            action.kind,
            ActionKind::Direct | ActionKind::Proxy | ActionKind::Tunnel | ActionKind::Inspect
        );
    let (request_headers_snapshot, cache_lookup_key, cache_target_key) = if cache_applicable {
        let cache_default_scheme = req.uri().scheme_str().unwrap_or("http");
        let cache_lookup_key = CacheRequestKey::for_lookup(&req, cache_default_scheme)?;
        let cache_target_key = CacheRequestKey::for_target(&req, cache_default_scheme)?;
        let snapshot = cache_lookup_key.as_ref().map(|_| req.headers().clone());
        (snapshot, cache_lookup_key, cache_target_key)
    } else {
        (None, None, None)
    };
    let mut revalidation_state = None;

    let upstream = resolve_upstream(&action, &state, listener_name)?;
    let upstream_timeout = Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);
    let upgrade_wait_timeout = Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout = Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
    let http_authority = match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => host.host.clone(),
    };
    let export_session = state.export_session(remote_addr, http_authority.as_str());
    let websocket_connect_authority = match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => format_authority_host_port(host.host.as_str(), 80),
    };
    let websocket_host_header = match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => host.host.clone(),
    };
    if websocket {
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_request_preview(&req);
            session.emit_plaintext(true, &preview);
        }
        let mut response = proxy_websocket_http1(
            req,
            WebsocketProxyConfig {
                upstream_proxy: upstream.as_deref(),
                direct_connect_authority: websocket_connect_authority.as_str(),
                direct_host_header: websocket_host_header.as_str(),
                timeout_dur: upstream_timeout,
                upgrade_wait_timeout,
                tunnel_idle_timeout,
                tunnel_label: "forward",
                upstream_context: "forward websocket upstream proxy",
                direct_context: "forward websocket direct",
            },
        )
        .await?;
        if let Some(session) = export_session.as_ref() {
            let preview = crate::exporter::serialize_response_preview(&response);
            session.emit_plaintext(false, &preview);
        }
        let keep_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
        let response_version = response.version();
        finalize_response_with_headers_in_place(
            &request_method,
            response_version,
            proxy_name,
            &mut response,
            headers.as_deref(),
            keep_upgrade,
        );
        return Ok(response);
    }

    if let (Some(snapshot), Some(_)) = (request_headers_snapshot.as_ref(), cache_policy.as_ref()) {
        let (lookup_decision, lookup_revalidation_state) = lookup_with_revalidation(
            &mut req,
            snapshot,
            cache_lookup_key.as_ref(),
            cache_policy.as_ref(),
            &state.cache_backends,
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
                    proxy_name,
                    &mut hit,
                    headers.as_deref(),
                    false,
                );
                return Ok(hit);
            }
            CacheLookupDecision::StaleWhileRevalidate(mut hit, state) => {
                if request_method == Method::GET {
                    if let (Some(policy), Some(snapshot), Some(lookup_key), Some(target_key)) = (
                        cache_policy.as_ref(),
                        request_headers_snapshot.as_ref(),
                        cache_lookup_key.as_ref(),
                        cache_target_key.as_ref(),
                    ) {
                        if let Some(guard) = crate::cache::try_begin_background_revalidation(&state)
                        {
                            let runtime = runtime.clone();
                            let upstream = upstream.clone();
                            let http_authority = http_authority.clone();
                            let policy = (*policy).clone();
                            let snapshot = (*snapshot).clone();
                            let lookup_key = (*lookup_key).clone();
                            let target_key = (*target_key).clone();
                            let bg_req = clone_request_head_for_revalidation(&req);
                            tokio::spawn(async move {
                                let _guard = guard;
                                let started = std::time::Instant::now();
                                let Ok(resp) = proxy_http1_request(
                                    bg_req,
                                    upstream.as_deref(),
                                    http_authority.as_str(),
                                    upstream_timeout,
                                )
                                .await
                                else {
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
                let hit_version = hit.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    hit_version,
                    proxy_name,
                    &mut hit,
                    headers.as_deref(),
                    false,
                );
                return Ok(hit);
            }
            CacheLookupDecision::OnlyIfCachedMiss(response) => {
                return Ok(finalize_response_with_headers(
                    &request_method,
                    client_version,
                    proxy_name,
                    response,
                    headers.as_deref(),
                    false,
                ));
            }
            CacheLookupDecision::Miss => {}
        }
    }

    let upstream_started = std::time::Instant::now();
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let mut response = match proxy_http1_request(
        req,
        upstream.as_deref(),
        http_authority.as_str(),
        upstream_timeout,
    )
    .await
    {
        Ok(resp) => resp,
        Err(err) => {
            if let Some(stale) = revalidation_state
                .as_ref()
                .and_then(crate::cache::maybe_build_stale_if_error_response)
            {
                let mut stale = stale;
                let stale_version = stale.version();
                finalize_response_with_headers_in_place(
                    &request_method,
                    stale_version,
                    proxy_name,
                    &mut stale,
                    headers.as_deref(),
                    false,
                );
                return Ok(stale);
            }
            return Err(err);
        }
    };
    let response_delay_secs = upstream_started.elapsed().as_secs();
    if response.status().is_server_error() {
        if let Some(stale) = revalidation_state
            .as_ref()
            .and_then(crate::cache::maybe_build_stale_if_error_response)
        {
            let mut stale = stale;
            let stale_version = stale.version();
            finalize_response_with_headers_in_place(
                &request_method,
                stale_version,
                proxy_name,
                &mut stale,
                headers.as_deref(),
                false,
            );
            return Ok(stale);
        }
    }
    if let Some(policy) = cache_policy.as_ref() {
        if let Some(snapshot) = request_headers_snapshot.as_ref() {
            response = process_upstream_response_for_cache(
                response,
                CacheWritebackContext {
                    request_method: &request_method,
                    response_delay_secs,
                    cache_target_key: cache_target_key.as_ref(),
                    cache_lookup_key: cache_lookup_key.as_ref(),
                    cache_policy: Some(policy),
                    request_headers_snapshot: snapshot,
                    revalidation_state,
                    backends: &state.cache_backends,
                },
            )
            .await?;
        } else {
            crate::cache::maybe_invalidate(
                &request_method,
                response.status(),
                response.headers(),
                cache_target_key.as_ref(),
                policy,
                &state.cache_backends,
            )
            .await?;
        }
    }
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        &request_method,
        response_version,
        proxy_name,
        &mut response,
        headers.as_deref(),
        false,
    );
    Ok(response)
}

pub(crate) fn proxy_auth_required(
    chal: qpx_core::auth::AuthChallenge,
    message: &str,
) -> Response<Body> {
    let mut builder = Response::builder().status(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    for header in chal.header_values {
        builder = builder.header("Proxy-Authenticate", header);
    }
    builder.body(Body::from(message.to_owned())).unwrap()
}

fn extract_host(req: &Request<Body>) -> Option<HostPort> {
    let default_port = match req.uri().scheme_str() {
        Some(s) if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("wss") => 443,
        Some(s) if s.eq_ignore_ascii_case("ftp") => 21,
        _ => 80,
    };
    if let Some(authority) = req.uri().authority() {
        return parse_authority_host_port(authority.as_str(), default_port).map(|(host, port)| {
            HostPort {
                host,
                port: Some(port),
            }
        });
    }
    if let Some(host) = req.headers().get("host").and_then(|v| v.to_str().ok()) {
        if let Some((h, p)) = parse_authority_host_port(host, default_port) {
            return Some(HostPort {
                host: h,
                port: Some(p),
            });
        }
        return Some(HostPort {
            host: host.to_string(),
            port: None,
        });
    }
    None
}

pub(crate) fn resolve_upstream(
    action: &qpx_core::config::ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_name: &str,
) -> Result<Option<String>> {
    let listener = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    resolve_named_upstream(action, state, listener.upstream_proxy.as_deref())
}

struct HostPort {
    host: String,
    port: Option<u16>,
}
