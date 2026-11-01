pub(super) mod parse;

use crate::http::dispatch::{DispatchConnectRuleContextInput, build_dispatch_connect_rule_context};
use qpx_core::rules::RuleMatchContext;

/// The parts of an HTTP/3 CONNECT request that its rule context carries.
pub(super) struct H3ConnectRuleContextInput<'a> {
    pub(super) remote_ip: std::net::IpAddr,
    pub(super) port: u16,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) authority: &'a str,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) headers: &'a qpx_core::http_message::Headers,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
}

/// The rule context for an HTTP/3 CONNECT request.
///
/// Both HTTP/3 backends judge a CONNECT request against the same context:
/// the same method, the same HTTP/3 version label and the same "h3" ALPN.
/// The parts that differ - where the request came from and what it carries -
/// are the caller's to pass in.
pub(super) fn build_h3_connect_rule_context<'a>(
    input: H3ConnectRuleContextInput<'a>,
) -> RuleMatchContext<'a> {
    let H3ConnectRuleContextInput {
        remote_ip,
        port,
        host,
        path,
        authority,
        destination,
        headers,
        identity,
    } = input;
    build_dispatch_connect_rule_context(DispatchConnectRuleContextInput {
        remote_ip,
        port,
        host,
        path,
        authority,
        http_version: http::Version::HTTP_3,
        alpn: Some("h3"),
        destination,
        headers,
        identity,
    })
}

/// Finalizes a local response for an HTTP/3 CONNECT request.
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(super) fn finalize_h3_connect_response(
    proxy_name: &str,
    response: http::Response<qpx_http::body::Body>,
    header_control: Option<&qpx_core::rules::CompiledHeaderControl>,
) -> http::Response<qpx_http::body::Body> {
    crate::http::protocol::l7::finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        response,
        header_control,
        false,
    )
}

/// Normalizes an upstream extended-CONNECT response head for downstream HTTP/3.
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(super) fn finalize_h3_connect_head_response(
    response: http::Response<()>,
    proxy_name: &str,
    header_control: Option<&qpx_core::rules::CompiledHeaderControl>,
    status_context: &str,
) -> anyhow::Result<http::Response<()>> {
    use qpx_http::{body::Body, protocol::semantics::validate_http_status_class};

    let (parts, _) = response.into_parts();
    let status = validate_http_status_class(parts.status, status_context)?;
    let mut downstream = http::Response::builder()
        .status(status)
        .body(Body::empty())?;
    *downstream.headers_mut() = crate::http3::codec::h1_headers_to_http(&parts.headers)?;
    let downstream = finalize_h3_connect_response(proxy_name, downstream, header_control);
    let status = validate_http_status_class(downstream.status(), status_context)?;
    let mut out = http::Response::builder().status(status).body(())?;
    *out.headers_mut() = crate::http3::codec::http_headers_to_h1(downstream.headers())?;
    Ok(out)
}

/// Finalizes a local auth-policy response without applying response-header controls.
#[cfg(all(
    feature = "auth-basic",
    any(feature = "http3-backend-h3", feature = "http3-backend-qpx")
))]
pub(super) fn finalize_h3_connect_auth_response(
    proxy_name: &str,
    response: http::Response<qpx_http::body::Body>,
) -> http::Response<qpx_http::body::Body> {
    crate::http::protocol::l7::finalize_response_for_request(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        response,
        false,
    )
}

/// Backend-neutral metadata shared by the HTTP/3 CONNECT policy-response senders.
pub(super) struct H3ConnectAuditContext<'a> {
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) listener_name: &'a str,
    pub(super) remote_ip: std::net::IpAddr,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) outcome: crate::http::dispatch::DispatchOutcome,
    pub(super) matched_rule: Option<&'a str>,
    pub(super) decision_service_policy_id: Option<&'a str>,
    pub(super) log_context: &'a qpx_observability::access_log::RequestLogContext,
}

pub(super) fn emit_h3_connect_audit(ctx: &H3ConnectAuditContext<'_>, status: u16) {
    crate::policy_context::emit_audit_log(
        ctx.state,
        crate::policy_context::AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Forward,
            name: ctx.listener_name,
            remote_ip: ctx.remote_ip,
            host: Some(ctx.host),
            sni: Some(ctx.host),
            method: Some("CONNECT"),
            path: ctx.path,
            outcome: ctx.outcome,
            status: Some(status),
            matched_rule: ctx.matched_rule,
            matched_route: None,
            decision_service_policy_id: ctx.decision_service_policy_id,
        },
        ctx.log_context,
    );
}

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
mod standard;

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(in crate::forward::h3) use standard::{handle_h3_connect, handle_h3_extended_connect};

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(in crate::forward::h3) mod udp {
    pub(in crate::forward::h3) use super::standard::udp::handle_h3_connect_udp;
}

/// Forwards valid UDP datagrams carried in complete CONNECT-UDP capsules.
#[cfg(feature = "http3")]
pub(super) async fn forward_udp_capsules(
    capsule_buf: &mut crate::http3::capsule::CapsuleBuffer,
    udp: &tokio::net::UdpSocket,
    rate_limit_ctx: &crate::rate_limit::RateLimitContext,
    request_limits: &crate::rate_limit::AppliedRateLimits,
) -> anyhow::Result<()> {
    while let Some((capsule_type, payload)) = capsule_buf.take_next()? {
        if capsule_type != 0 {
            continue;
        }
        let Some(datagram_payload) =
            crate::http3::capsule::decode_connect_udp_payload(payload.as_ref())
        else {
            continue;
        };
        apply_connect_udp_bandwidth_controls(
            rate_limit_ctx,
            request_limits,
            datagram_payload.len(),
        )
        .await?;
        udp.send(datagram_payload).await?;
    }
    Ok(())
}

#[cfg(feature = "http3")]
pub(super) async fn apply_connect_udp_bandwidth_controls(
    ctx: &crate::rate_limit::RateLimitContext,
    limits: &crate::rate_limit::AppliedRateLimits,
    bytes: usize,
) -> anyhow::Result<()> {
    let delay = limits
        .reserve_bytes(ctx, bytes as u64)
        .map_err(|_| anyhow::anyhow!("CONNECT-UDP bandwidth quota exceeded"))?;
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    Ok(())
}

#[cfg(feature = "http3")]
pub(super) fn h3_connect_rate_limited_response(
    proxy_name: &str,
    response_headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    request_limits: &crate::rate_limit::AppliedRateLimits,
    retry_after: Option<std::time::Duration>,
) -> http::Response<qpx_http::body::Body> {
    let mut response = finalize_h3_connect_response(
        proxy_name,
        crate::http::protocol::common::too_many_requests_response(retry_after),
        response_headers,
    );
    request_limits.apply_rate_limit_fields(response.headers_mut(), retry_after);
    response
}

#[cfg(all(test, feature = "http3"))]
mod h3_connect_rate_limited_response_tests {
    #[test]
    fn rate_limited_response_uses_429_retry_after_and_plain_text() {
        let request_limits = crate::rate_limit::AppliedRateLimits::default();
        let response =
            super::h3_connect_rate_limited_response("test-proxy", None, &request_limits, None);
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().get(http::header::RETRY_AFTER).is_none());
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8"),
        );
        let response = super::h3_connect_rate_limited_response(
            "test-proxy",
            None,
            &request_limits,
            Some(std::time::Duration::ZERO),
        );
        assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response
                .headers()
                .get(http::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            Some("1"),
        );
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8"),
        );
    }
}
