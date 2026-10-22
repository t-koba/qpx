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
