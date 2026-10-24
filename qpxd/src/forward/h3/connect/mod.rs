pub(super) mod parse;

use crate::http::dispatch::{DispatchConnectRuleContextInput, build_dispatch_connect_rule_context};
use crate::http::protocol::common::http_version_label;
use qpx_core::rules::RuleMatchContext;

/// The parts of an HTTP/3 CONNECT request that its rule context carries.
pub(super) struct H3ConnectRuleContextInput<'a> {
    pub(super) remote_ip: std::net::IpAddr,
    pub(super) port: u16,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) authority: &'a str,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) headers: &'a http::HeaderMap,
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
        http_version: http_version_label(http::Version::HTTP_3),
        alpn: Some("h3"),
        destination,
        headers,
        identity,
    })
}

/// Context for the shared successful forward-CONNECT audit event on either HTTP/3 backend.
#[cfg(feature = "http3")]
pub(super) struct H3ConnectAllowAuditContext<'a> {
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) listener_name: &'a str,
    pub(super) remote_ip: std::net::IpAddr,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) matched_rule: Option<&'a str>,
    pub(super) decision_service_policy_id: Option<&'a str>,
    pub(super) log_context: &'a qpx_observability::access_log::RequestLogContext,
}

/// Emits the common successful forward-CONNECT audit fields for H3 implementations.
#[cfg(feature = "http3")]
pub(super) fn emit_h3_connect_allow_audit(ctx: H3ConnectAllowAuditContext<'_>) {
    let H3ConnectAllowAuditContext {
        state,
        listener_name,
        remote_ip,
        host,
        path,
        matched_rule,
        decision_service_policy_id,
        log_context,
    } = ctx;
    crate::policy_context::emit_audit_log(
        state,
        crate::policy_context::AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Forward,
            name: listener_name,
            remote_ip,
            host: Some(host),
            sni: Some(host),
            method: Some("CONNECT"),
            path,
            outcome: crate::http::dispatch::DispatchOutcome::Allow,
            status: Some(http::StatusCode::OK.as_u16()),
            matched_rule,
            matched_route: None,
            decision_service_policy_id,
        },
        log_context,
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
    let mut response = crate::http::protocol::l7::finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        crate::http::protocol::common::too_many_requests_response(retry_after),
        response_headers,
        false,
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
