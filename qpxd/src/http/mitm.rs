use crate::http::address::format_authority_host_port;
use crate::http::common::{bad_request_response as bad_request, blocked_response as blocked};
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers_in_place,
    handle_max_forwards_in_place, prepare_request_with_headers_in_place,
};
use crate::http::policy::{evaluate_listener_policy, ListenerPolicyDecision};
use crate::http::semantics::validate_incoming_request;
use crate::http::websocket::{is_websocket_upgrade, spawn_upgrade_tunnel};
use crate::runtime::Runtime;
use anyhow::{anyhow, Result};
use hyper::client::conn::SendRequest;
use hyper::{Body, Request, Response};
use qpx_core::rules::RuleMatchContext;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

pub struct MitmRouteContext<'a> {
    pub listener_name: &'a str,
    pub src_addr: SocketAddr,
    pub dst_port: u16,
    pub host: &'a str,
    pub sni: &'a str,
}

pub async fn proxy_mitm_request(
    mut req: Request<Body>,
    runtime: Runtime,
    sender: Arc<Mutex<SendRequest<Body>>>,
    route: MitmRouteContext<'_>,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    let websocket = is_websocket_upgrade(req.headers());
    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut req));

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

    if req.method() == hyper::Method::TRACE && !state.config.runtime.trace_enabled {
        return Ok(finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            Response::builder()
                .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from(state.messages.trace_disabled.clone()))
                .unwrap_or_else(|_| bad_request("trace disabled")),
            false,
        ));
    }

    let engine = state
        .rules_by_listener
        .get(route.listener_name)
        .ok_or_else(|| anyhow!("rule engine not found"))?;

    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let ctx = RuleMatchContext {
        src_ip: Some(route.src_addr.ip()),
        dst_port: Some(route.dst_port),
        host: Some(route.host),
        sni: Some(route.sni),
        method: Some(req.method().as_str()),
        path: Some(path),
        headers: Some(req.headers()),
        user_groups: &[],
    };
    let decision = evaluate_listener_policy(
        engine,
        &ctx,
        req.method(),
        req.version(),
        proxy_name,
        blocked,
        state.messages.blocked.as_str(),
    )?;
    let policy = match decision {
        ListenerPolicyDecision::Proceed(policy) => policy,
        ListenerPolicyDecision::Early(response) => return Ok(response),
    };

    let req_method = req.method().clone();
    let export_server = format_authority_host_port(route.host, route.dst_port);
    let export_session = state.export_session(route.src_addr, export_server);
    if let Some(response) = handle_max_forwards_in_place(&mut req, proxy_name) {
        return Ok(response);
    }
    prepare_request_with_headers_in_place(
        &mut req,
        proxy_name,
        policy.headers.as_deref(),
        websocket,
    );
    *req.version_mut() = http::Version::HTTP_11;
    if !req.headers().contains_key(http::header::HOST) {
        let authority = format_authority_host_port(route.host, route.dst_port);
        req.headers_mut()
            .insert(http::header::HOST, http::HeaderValue::from_str(&authority)?);
    }
    let upstream_timeout = Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_request_preview(&req);
        session.emit_plaintext(true, &preview);
    }
    let mut guard = sender.lock().await;
    let mut response = timeout(upstream_timeout, guard.send_request(req)).await??;
    if let Some(session) = export_session.as_ref() {
        let preview = crate::exporter::serialize_response_preview(&response);
        session.emit_plaintext(false, &preview);
    }
    let keep_upgrade = websocket && response.status() == http::StatusCode::SWITCHING_PROTOCOLS;
    if keep_upgrade {
        let upgrade_wait_timeout =
            Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
        let tunnel_idle_timeout =
            Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
        if let Some(client_upgrade) = client_upgrade {
            spawn_upgrade_tunnel(
                &mut response,
                client_upgrade,
                "mitm",
                upgrade_wait_timeout,
                tunnel_idle_timeout,
            );
        }
    }
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        &req_method,
        response_version,
        proxy_name,
        &mut response,
        policy.headers.as_deref(),
        keep_upgrade,
    );
    Ok(response)
}
