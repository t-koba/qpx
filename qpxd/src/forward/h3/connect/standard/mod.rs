use crate::http::dispatch::DispatchOutcome;
use crate::http::protocol::common::connect_established_response as connect_established;
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::http3::codec::http_headers_to_h1;
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::{H3ServerRequestStream, send_h3_response};
use crate::policy_context::{AuditRecord, emit_audit_log};
use crate::rate_limit::RateLimitContext;
use anyhow::Result;
use hyper::Response;
use qpx_core::config::ActionConfig;
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use qpx_observability::access_log::RequestLogContext;
use std::sync::Arc;
use tokio::time::Duration;

mod established;
mod extended;
mod extended_handler;
mod handlers;
mod prepare;
mod target;
mod tunnel;
pub(in crate::forward::h3) mod udp;

pub(super) use self::extended::{
    normalize_h3_upstream_connect_headers, recv_upstream_h3_response_with_interim,
};
pub(in crate::forward::h3) use self::extended_handler::handle_h3_extended_connect;
pub(in crate::forward::h3) use self::handlers::handle_h3_connect;
pub(super) use self::prepare::prepare_h3_connect_request;

#[derive(Debug)]
pub(super) struct PreparedH3Connect {
    pub(super) authority: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) action: ActionConfig,
    pub(super) response_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) log_context: RequestLogContext,
    pub(super) matched_rule: Option<String>,
    pub(super) ext_authz_policy_id: Option<String>,
    pub(super) audit_path: Option<String>,
    pub(super) timeout_override: Option<Duration>,
    pub(super) rate_limit_profile: Option<String>,
    pub(super) rate_limit_context: RateLimitContext,
    pub(super) sanitized_headers: http::HeaderMap,
    pub(super) identity: crate::policy_context::ResolvedIdentity,
}

pub(super) struct H3PolicyResponseContext<'a> {
    pub(super) request_method: &'a http::Method,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) listener_name: &'a str,
    pub(super) conn: &'a H3ConnInfo,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) outcome: DispatchOutcome,
    pub(super) matched_rule: Option<&'a str>,
    pub(super) ext_authz_policy_id: Option<&'a str>,
    pub(super) log_context: &'a RequestLogContext,
}

pub(super) fn build_h3_connect_success_response(
    proxy_name: &str,
    request_method: &http::Method,
    capsule_protocol: bool,
    header_control: Option<&CompiledHeaderControl>,
) -> Result<::http::Response<()>> {
    let mut response = connect_established();
    if capsule_protocol {
        response.headers_mut().insert(
            http::header::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_static("?1"),
        );
    }
    let response = finalize_response_with_headers(
        request_method,
        http::Version::HTTP_3,
        proxy_name,
        response,
        header_control,
        false,
    );
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        response.status(),
        "HTTP/3 CONNECT response",
    )?;
    let mut out = ::http::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(response.headers())?;
    Ok(out)
}

pub(super) async fn send_h3_policy_response(
    req_stream: &mut H3ServerRequestStream,
    response: Response<Body>,
    ctx: H3PolicyResponseContext<'_>,
) -> Result<()> {
    let H3PolicyResponseContext {
        request_method,
        state,
        listener_name,
        conn,
        host,
        path,
        outcome,
        matched_rule,
        ext_authz_policy_id,
        log_context,
    } = ctx;
    emit_audit_log(
        state,
        AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Forward,
            name: listener_name,
            remote_ip: conn.remote_addr.ip(),
            host: Some(host),
            sni: Some(host),
            method: Some("CONNECT"),
            path,
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule,
            matched_route: None,
            ext_authz_policy_id,
        },
        log_context,
    );
    send_h3_response(
        response,
        request_method,
        req_stream,
        state.plan.limits.body.max_h3_response_body_bytes,
        Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
    )
    .await
}

#[cfg(test)]
mod tests;
