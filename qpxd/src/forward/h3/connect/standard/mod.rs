use crate::http::protocol::common::connect_established_response as connect_established;
use crate::http::protocol::l7::finalize_response_with_headers_in_place;
use crate::http3::codec::http_headers_to_h1;
use crate::http3::server::{H3ServerRequestStream, send_h3_response};
use crate::rate_limit::RateLimitContext;
use anyhow::Result;
use qpx_core::config::ActionConfig;
use qpx_core::rules::CompiledHeaderControl;
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
    pub(super) decision_service_policy_id: Option<String>,
    pub(super) audit_path: Option<String>,
    pub(super) timeout_override: Option<Duration>,
    pub(super) rate_limit_profile: Option<String>,
    pub(super) rate_limit_context: RateLimitContext,
    pub(super) sanitized_headers: qpx_core::http_message::Headers,
    pub(super) identity: crate::policy_context::ResolvedIdentity,
}

pub(super) use super::H3ConnectAuditContext;

pub(super) fn build_h3_connect_success_response(
    proxy_name: &str,
    request_method: &http::Method,
    capsule_protocol: bool,
    header_control: Option<&CompiledHeaderControl>,
) -> Result<::http::Response<()>> {
    let mut response = connect_established();
    if capsule_protocol {
        response.headers_mut().insert(
            qpx_core::http_message::OrdinaryHeaderName::try_from("capsule-protocol")?,
            http::HeaderValue::from_static("?1"),
        );
    }
    finalize_response_with_headers_in_place(
        request_method,
        http::Version::HTTP_3,
        proxy_name,
        &mut response,
        header_control,
        false,
    );
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        response.status(),
        "HTTP/3 CONNECT response",
    )?;
    let response = response.into_http_for_codec()?;
    let mut out = ::http::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(response.headers())?;
    Ok(out)
}

pub(super) async fn send_h3_policy_response<R: crate::http::response_carrier::ResponseCarrier>(
    req_stream: &mut H3ServerRequestStream,
    response: R,
    ctx: H3ConnectAuditContext<'_>,
) -> Result<()> {
    super::emit_h3_connect_audit(&ctx, response.status().as_u16());
    send_h3_response(
        response.into_owner(),
        &http::Method::CONNECT,
        req_stream,
        ctx.state.plan.limits.body.max_h3_response_body_bytes,
        crate::forward::h3::h3_response_send_timeout(
            ctx.state.plan.limits.timeouts.h3_read_timeout_ms,
            None,
        ),
    )
    .await
}

#[cfg(test)]
mod tests;
