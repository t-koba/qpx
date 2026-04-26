use super::connect::{
    decide_connect_action_from_tls_metadata, listener_requires_upstream_cert_preview,
    listener_upstream_trust,
};
use super::h3::ForwardH3Handler;
use crate::destination::DestinationInputs;
use crate::forward::request::proxy_auth_required;
use crate::http::body::Body;
use crate::http::common::{
    blocked_response as blocked, connect_established_response as connect_established,
    forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::http::local_response::build_local_response;
use crate::http3::codec::{h1_headers_to_http, http_headers_to_h1};
use crate::http3::datagram::H3StreamDatagrams;
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::{send_h3_response, send_h3_static_response, H3ServerRequestStream};
use crate::policy_context::{
    apply_ext_authz_action_overrides, emit_audit_log, enforce_ext_authz, resolve_identity,
    sanitize_headers_for_policy, validate_ext_authz_allow_mode, AuditRecord,
    EffectivePolicyContext, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::RateLimitContext;
use crate::tls::client::preview_tls_certificate_with_options;
use crate::upstream::connect::connect_tunnel_target;
use crate::upstream::connect::TunnelIo;
use anyhow::{anyhow, Result};
use hyper::{Response, StatusCode};
use qpx_core::config::{ActionConfig, ActionKind, ConnectUdpConfig};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use qpx_observability::access_log::RequestLogContext;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::warn;

#[path = "h3_connect_extended.rs"]
mod h3_connect_extended;
#[path = "h3_connect_handlers.rs"]
mod h3_connect_handlers;
#[path = "h3_connect_parse.rs"]
mod h3_connect_parse;
#[path = "h3_connect_prepare.rs"]
mod h3_connect_prepare;
#[path = "h3_connect_tunnel.rs"]
mod h3_connect_tunnel;

use self::h3_connect_extended::{
    finalize_h3_connect_head_response, open_upstream_extended_connect_stream,
    relay_h3_extended_connect_stream, upstream_extended_connect_error_response,
    UpstreamExtendedConnectStream,
};
pub(super) use self::h3_connect_extended::{
    normalize_h3_upstream_connect_headers, recv_upstream_h3_response_with_interim,
};
pub(super) use self::h3_connect_handlers::{handle_h3_connect, handle_h3_extended_connect};
use self::h3_connect_parse::{default_port_for_scheme, format_authority, validate_h3_connect_head};
pub(super) use self::h3_connect_parse::{
    parse_connect_authority_required, parse_connect_udp_target,
};
pub(super) use self::h3_connect_prepare::prepare_h3_connect_request;
#[cfg(feature = "mitm")]
use self::h3_connect_tunnel::mitm_h3_connect_stream;
use self::h3_connect_tunnel::{prepare_h3_connect_stream, relay_h3_connect_stream};

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

pub(super) enum H3ConnectPreparation {
    Continue(Box<PreparedH3Connect>),
    Responded,
}

pub(super) struct H3PolicyResponseContext<'a> {
    pub(super) request_method: &'a http::Method,
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) listener_name: &'a str,
    pub(super) conn: &'a H3ConnInfo,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) outcome: &'static str,
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
    let status = ::http::StatusCode::from_u16(response.status().as_u16())?;
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
            kind: "forward",
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
        state.config.runtime.max_h3_response_body_bytes,
        Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
    )
    .await
}

#[cfg(test)]
#[path = "h3_connect_tests.rs"]
mod tests;
