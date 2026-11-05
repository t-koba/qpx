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

/// Standard-response behavior oracle retained for parity tests.
#[cfg(test)]
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

/// Finalizes an owner-backed local response without exporting its head.
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(super) fn finalize_h3_connect_owner_response(
    proxy_name: &str,
    mut response: qpx_core::http_message::Response<qpx_http::body::Body>,
    header_control: Option<&qpx_core::rules::CompiledHeaderControl>,
) -> qpx_core::http_message::Response<qpx_http::body::Body> {
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        &mut response,
        header_control,
        false,
    );
    response
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
    let mut downstream = qpx_core::http_message::Response::from_http(downstream);
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        &mut downstream,
        header_control,
        false,
    );
    let status = validate_http_status_class(downstream.status(), status_context)?;
    let downstream = downstream.map_body(|_| ()).into_http_for_library();
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
    response: qpx_core::http_message::Response<qpx_http::body::Body>,
) -> http::Response<qpx_http::body::Body> {
    crate::http::protocol::l7::finalize_response_for_request(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        response,
        false,
    )
    .into_http_for_library()
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
) -> qpx_core::http_message::Response<qpx_http::body::Body> {
    let mut response = crate::http::protocol::common::too_many_requests_response(retry_after);
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        &mut response,
        response_headers,
        false,
    );
    request_limits.apply_rate_limit_fields(response.headers_mut(), retry_after);
    response
}

#[cfg(all(test, feature = "http3"))]
mod h3_connect_rate_limited_response_tests {
    #[tokio::test]
    async fn rate_limited_response_keeps_body_retry_and_fields_after_header_control() {
        use crate::rate_limit::{
            CompiledRateLimitPlan, RateLimitContext, RateLimitSet, TransportScope,
        };

        let config = serde_yaml::from_str(
            "enabled: true
experimental_rate_limit_fields: true
apply_to: [request]
key: global
requests: { quota: { interval_secs: 60, amount: 1 } }",
        )
        .unwrap();
        let plan = CompiledRateLimitPlan::from_sets(
            RateLimitSet::from_config(Some(&config)),
            RateLimitSet::default(),
        );
        let mut limits = plan.collect(TransportScope::Request);
        let context = RateLimitContext::default();
        assert!(limits.try_acquire_request(&context, 1).is_none());
        assert!(limits.try_acquire_request(&context, 1).is_some());
        let control = qpx_core::rules::CompiledHeaderControl::compile(
            &serde_yaml::from_str(
                "response_set: { connection: x-hop, x-hop: removed, rate-limit-policy: stale, ratelimit: stale }",
            )
            .unwrap(),
        )
        .unwrap();
        for retry in [None, Some(0), Some(3)] {
            let response = super::h3_connect_rate_limited_response(
                "test-proxy",
                Some(&control),
                &limits,
                retry.map(std::time::Duration::from_secs),
            )
            .into_http_for_codec()
            .unwrap();
            assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response.headers()[http::header::CONTENT_TYPE],
                "text/plain; charset=utf-8"
            );
            assert_eq!(
                response
                    .headers()
                    .get(http::header::RETRY_AFTER)
                    .map(|v| v.to_str().unwrap()),
                retry.map(|secs| secs.max(1).to_string()).as_deref(),
            );
            assert_eq!(response.headers()["via"], "3 test-proxy");
            assert!(!response.headers().contains_key("x-hop"));
            assert_eq!(
                response.headers()["rate-limit-policy"],
                "\"requests\";q=1;w=60;qu=\"requests\""
            );
            assert_eq!(
                response.headers()["ratelimit"],
                retry.map_or_else(
                    || "\"requests\";r=0".to_owned(),
                    |secs| format!("\"requests\";r=0;t={}", secs.max(1))
                ),
            );
            assert_eq!(
                qpx_http::body::to_bytes(response.into_body())
                    .await
                    .unwrap(),
                "too many requests",
            );
        }
    }
}
