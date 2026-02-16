use super::connect;
use super::policy::{evaluate_forward_policy, ForwardPolicyDecision};
use crate::cache::CacheRequestKey;
use crate::ftp;
use crate::http::address::{format_authority_host_port, parse_authority_host_port};
use crate::http::cache_flow::{
    lookup_with_revalidation, process_upstream_response_for_cache, CacheLookupDecision,
    CacheWritebackContext,
};
use crate::http::common::{
    bad_request_response as bad_request, blocked_response as blocked,
    forbidden_response as forbidden, resolve_named_upstream,
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

    let host = extract_host(&req);
    let path = req.uri().path_and_query().map(|p| p.as_str());

    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: host.as_ref().and_then(|h| h.port),
        host: host.as_ref().map(|h| h.host.as_str()),
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
    let (action, headers) = match policy {
        ForwardPolicyDecision::Allow(allowed) => (allowed.action, allowed.headers),
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
    if let Some(response) = handle_max_forwards_in_place(&mut req, proxy_name) {
        return Ok(response);
    }
    let websocket = is_websocket_upgrade(req.headers());
    prepare_request_with_headers_in_place(&mut req, proxy_name, headers.as_deref(), websocket);
    if let Some(host) = host.as_ref() {
        if !req.headers().contains_key("host") {
            req.headers_mut()
                .insert("host", http::HeaderValue::from_str(&host.host).unwrap());
        }
    }
    let request_headers_snapshot = req.headers().clone();
    let cache_default_scheme = req.uri().scheme_str().unwrap_or("http");
    let cache_lookup_key = if matches!(
        action.kind,
        ActionKind::Direct | ActionKind::Proxy | ActionKind::Tunnel | ActionKind::Inspect
    ) {
        CacheRequestKey::for_lookup(&req, cache_default_scheme)?
    } else {
        None
    };
    let cache_target_key = if matches!(
        action.kind,
        ActionKind::Direct | ActionKind::Proxy | ActionKind::Tunnel | ActionKind::Inspect
    ) {
        CacheRequestKey::for_target(&req, cache_default_scheme)?
    } else {
        None
    };

    let upstream = resolve_upstream(&action, &state, listener_name)?;
    let upstream_timeout = Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);
    let upgrade_wait_timeout = Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
    let tunnel_idle_timeout = Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
    let target_host = host
        .as_ref()
        .ok_or_else(|| anyhow!("request host missing"))?;
    let http_authority = match target_host.port {
        Some(port) => format_authority_host_port(target_host.host.as_str(), port),
        None => target_host.host.clone(),
    };
    let export_session = state.export_session(remote_addr, http_authority.as_str());
    let websocket_connect_authority = match target_host.port {
        Some(port) => format_authority_host_port(target_host.host.as_str(), port),
        None => format_authority_host_port(target_host.host.as_str(), 80),
    };
    let websocket_host_header = match target_host.port {
        Some(port) => format_authority_host_port(target_host.host.as_str(), port),
        None => target_host.host.clone(),
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

    let (lookup_decision, revalidation_state) = lookup_with_revalidation(
        &mut req,
        &request_headers_snapshot,
        cache_lookup_key.as_ref(),
        cache_policy.as_ref(),
        &state.cache_backends,
        state.messages.cache_miss.as_str(),
    )
    .await?;
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

    let upstream_started = std::time::Instant::now();
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let mut response = proxy_http1_request(
        req,
        upstream.as_deref(),
        http_authority.as_str(),
        upstream_timeout,
    )
    .await?;
    let response_delay_secs = upstream_started.elapsed().as_secs();
    response = process_upstream_response_for_cache(
        response,
        CacheWritebackContext {
            request_method: &request_method,
            response_delay_secs,
            cache_target_key: cache_target_key.as_ref(),
            cache_lookup_key: cache_lookup_key.as_ref(),
            cache_policy: cache_policy.as_ref(),
            request_headers_snapshot: &request_headers_snapshot,
            revalidation_state,
            backends: &state.cache_backends,
        },
    )
    .await?;
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
