use super::super::HostPort;
use crate::ftp;
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchWebsocketProxyInput, annotate_dispatch_response,
    emit_dispatch_websocket_response_preview, proxy_dispatch_websocket_http1,
};
use crate::http::local_response::build_local_response;
use crate::http::protocol::address::format_authority_host_port;
use crate::http::protocol::common::blocked_response as blocked;
use crate::http::protocol::l7::{
    finalize_response_for_request, finalize_response_with_headers,
    finalize_response_with_headers_in_place, handle_max_forwards_in_place,
};
use anyhow::{Result, anyhow};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::config::ActionKind;
use std::sync::Arc;
use tokio::time::Duration;

pub(super) struct ForwardWebsocketInput<'a> {
    pub(super) req: Request<Body>,
    pub(super) upstream: Option<&'a crate::upstream::pool::ResolvedUpstreamProxy>,
    pub(super) connect_authority: &'a str,
    pub(super) host_header: &'a str,
    pub(super) upstream_timeout: Duration,
    pub(super) upgrade_wait_timeout: Duration,
    pub(super) tunnel_idle_timeout: Duration,
    pub(super) export_session: Option<&'a crate::exporter::ExportSession>,
    pub(super) request_method: &'a Method,
    pub(super) proxy_name: &'a str,
    pub(super) headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    pub(super) audit: &'a DispatchAuditContext,
}

pub(super) fn handle_forward_local_action(
    req: &Request<Body>,
    state: &crate::runtime::RuntimeState,
    proxy_name: &str,
    action: &qpx_core::config::ActionConfig,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    audit: &DispatchAuditContext,
) -> Result<Option<Response<Body>>> {
    if matches!(action.kind, ActionKind::Block) {
        let mut response = finalize_response_for_request(
            req.method(),
            req.version(),
            proxy_name,
            blocked(state.messages.blocked.as_str()),
            false,
        );
        annotate_dispatch_response(
            &mut response,
            audit,
            crate::http::dispatch::DispatchOutcome::Block,
            &[],
        );
        return Ok(Some(response));
    }
    if matches!(action.kind, ActionKind::Respond) {
        let local = action
            .local_response
            .as_ref()
            .ok_or_else(|| anyhow!("respond action requires local_response"))?;
        let mut response = finalize_response_with_headers(
            req.method(),
            req.version(),
            proxy_name,
            build_local_response(local)?,
            headers,
            false,
        );
        annotate_dispatch_response(
            &mut response,
            audit,
            crate::http::dispatch::DispatchOutcome::Respond,
            &[],
        );
        return Ok(Some(response));
    }
    Ok(None)
}

pub(super) async fn handle_forward_ftp(
    req: Request<Body>,
    listener_cfg: &crate::runtime::CompiledListenerSettings,
    state: &crate::runtime::RuntimeState,
    request_method: &Method,
    proxy_name: &str,
    headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    audit: &DispatchAuditContext,
) -> Result<Response<Body>> {
    let mut response = ftp::handle_ftp(
        req,
        listener_cfg.ftp.clone(),
        Arc::<str>::from(state.messages.unsupported_ftp_method.as_str()),
        state.ftp_semaphore.clone(),
    )
    .await?;
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        request_method,
        response_version,
        proxy_name,
        &mut response,
        headers,
        false,
    );
    annotate_dispatch_response(
        &mut response,
        audit,
        crate::http::dispatch::DispatchOutcome::Allow,
        &[],
    );
    Ok(response)
}

pub(super) async fn handle_forward_max_forwards(
    req: &mut Request<Body>,
    state: &crate::runtime::RuntimeState,
    proxy_name: &str,
    audit: &DispatchAuditContext,
    body_read_timeout: Duration,
) -> Option<Response<Body>> {
    let mut response = handle_max_forwards_in_place(
        req,
        proxy_name,
        state.plan.limits.general.trace_reflect_all_headers,
        state.plan.limits.body.max_observed_request_body_bytes,
        body_read_timeout,
    )
    .await?;
    annotate_dispatch_response(
        &mut response,
        audit,
        crate::http::dispatch::DispatchOutcome::MaxForwards,
        &[],
    );
    Some(response)
}

pub(super) fn ensure_forward_host_header(req: &mut Request<Body>, host: &HostPort) -> Result<()> {
    if req.headers().contains_key("host") {
        return Ok(());
    }
    let default_port = match req.uri().scheme_str() {
        Some(s) if s.eq_ignore_ascii_case("https") || s.eq_ignore_ascii_case("wss") => 443,
        Some(s) if s.eq_ignore_ascii_case("ftp") => 21,
        _ => 80,
    };
    let host_value = match host.port {
        Some(port) if port != default_port => format_authority_host_port(host.host.as_str(), port),
        _ => host.host.clone(),
    };
    req.headers_mut()
        .insert("host", http::HeaderValue::from_str(&host_value)?);
    Ok(())
}

pub(super) fn forward_http_authority(host: &HostPort) -> String {
    match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => host.host.clone(),
    }
}

pub(super) fn forward_websocket_connect_authority(host: &HostPort) -> String {
    match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => format_authority_host_port(host.host.as_str(), 80),
    }
}

pub(super) fn forward_websocket_host_header(host: &HostPort) -> String {
    match host.port {
        Some(port) => format_authority_host_port(host.host.as_str(), port),
        None => host.host.clone(),
    }
}

pub(super) async fn proxy_forward_websocket(
    input: ForwardWebsocketInput<'_>,
) -> Result<Response<Body>> {
    let ForwardWebsocketInput {
        req,
        upstream,
        connect_authority,
        host_header,
        upstream_timeout,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        export_session,
        request_method,
        proxy_name,
        headers,
        audit,
    } = input;
    let mut response = proxy_dispatch_websocket_http1(DispatchWebsocketProxyInput {
        req,
        upstream_proxy: upstream,
        direct_connect_authority: connect_authority,
        direct_host_header: host_header,
        timeout_dur: upstream_timeout,
        upgrade_wait_timeout,
        tunnel_idle_timeout,
        tunnel_label: "forward",
        upstream_context: "forward websocket upstream proxy",
        direct_context: "forward websocket direct",
        export_session,
    })
    .await?;
    emit_dispatch_websocket_response_preview(export_session, &response).await;
    let keep_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    let response_version = response.version();
    finalize_response_with_headers_in_place(
        request_method,
        response_version,
        proxy_name,
        &mut response,
        headers,
        keep_upgrade,
    );
    annotate_dispatch_response(
        &mut response,
        audit,
        crate::http::dispatch::DispatchOutcome::Allow,
        &[],
    );
    Ok(response)
}
