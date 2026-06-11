use crate::destination::DestinationInputs;
use crate::policy_context::{EffectivePolicyContext, ResolvedIdentity, resolve_identity};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext, TransportScope};
use crate::runtime::{PlanFlags, RuntimeState};
use crate::transparent::destination::ConnectTarget;
use crate::transparent::quic::{
    extract_quic_client_hello_info_with_fingerprints, looks_like_quic_initial,
};
use anyhow::{Result, anyhow};
use qpx_core::rules::{RuleEngine, RuleMatchContext, RuleOutcomeRef};
use std::net::SocketAddr;

pub(super) struct UdpRuleEvaluation<'a> {
    pub(super) connect_target: ConnectTarget,
    pub(super) host_for_match_owned: Option<String>,
    pub(super) authority: String,
    pub(super) identity: ResolvedIdentity,
    pub(super) sni: Option<String>,
    pub(super) outcome: RuleOutcomeRef<'a>,
    pub(super) request_limit_ctx: RateLimitContext,
    pub(super) request_limits: AppliedRateLimits,
}

#[expect(
    clippy::too_many_arguments,
    reason = "UDP rule evaluation keeps packet, destination, and policy inputs explicit"
)]
pub(super) fn prepare_udp_rule_evaluation<'a>(
    state: &RuntimeState,
    engine: &'a RuleEngine,
    listener_name: &str,
    effective_policy: &EffectivePolicyContext,
    client_addr: SocketAddr,
    original_target: Option<SocketAddr>,
    packet: &[u8],
    destination_resolution: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
) -> Result<Option<UdpRuleEvaluation<'a>>> {
    let is_quic = looks_like_quic_initial(packet);
    let include_fingerprints = state
        .plan
        .transparent_edge(listener_name)
        .map(|edge| edge.flags.contains(PlanFlags::TLS_FINGERPRINT))
        .unwrap_or(false)
        || state
            .policy
            .connection_filters_by_listener
            .get(listener_name)
            .map(|engine| engine.any_rule_requires_tls_fingerprint())
            .unwrap_or(false);
    let client_hello = is_quic
        .then(|| extract_quic_client_hello_info_with_fingerprints(packet, include_fingerprints))
        .flatten();
    let sni = client_hello.as_ref().and_then(|hello| hello.sni.clone());
    let connect_target = match original_target {
        Some(target) => ConnectTarget::Socket(target),
        None => match sni.clone() {
            Some(host) => ConnectTarget::HostPort(host, 443),
            None => return Ok(None),
        },
    };
    let host_for_match_owned = match &connect_target {
        ConnectTarget::HostPort(host, _) => Some(host.clone()),
        ConnectTarget::Socket(addr) => Some(addr.ip().to_string()),
    };
    let authority = connect_target.authority();
    let scheme = if is_quic { "quic" } else { "udp" };
    let identity = resolve_identity(state, effective_policy, client_addr.ip(), None, None)?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: host_for_match_owned.as_deref(),
            ip: match &connect_target {
                ConnectTarget::Socket(addr) => Some(addr.ip()),
                ConnectTarget::HostPort(_, _) => host_for_match_owned
                    .as_deref()
                    .and_then(|value| value.parse().ok()),
            },
            sni: sni.as_deref(),
            scheme: Some(scheme),
            port: Some(connect_target.port()),
            alpn: client_hello
                .as_ref()
                .and_then(|hello| hello.alpn.as_deref()),
            ja3: client_hello.as_ref().and_then(|hello| hello.ja3.as_deref()),
            ja4: client_hello.as_ref().and_then(|hello| hello.ja4.as_deref()),
            ..Default::default()
        },
        destination_resolution,
    );
    let ctx = RuleMatchContext {
        src_ip: Some(client_addr.ip()),
        dst_port: Some(connect_target.port()),
        host: host_for_match_owned.as_deref(),
        sni: sni.as_deref(),
        authority: Some(authority.as_str()),
        scheme: Some(scheme),
        http_version: client_hello.as_ref().and_then(|hello| {
            hello.alpn.as_deref().and_then(|alpn| {
                if alpn.starts_with("h3") {
                    Some("HTTP/3")
                } else {
                    None
                }
            })
        }),
        alpn: client_hello
            .as_ref()
            .and_then(|hello| hello.alpn.as_deref()),
        tls_version: client_hello
            .as_ref()
            .and_then(|hello| hello.tls_version.as_deref()),
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        ja3: client_hello.as_ref().and_then(|hello| hello.ja3.as_deref()),
        ja4: client_hello.as_ref().and_then(|hello| hello.ja4.as_deref()),
        request_size: Some(packet.len() as u64),
        user: identity.user.as_deref(),
        user_groups: &identity.groups,
        device_id: identity.device_id.as_deref(),
        posture: &identity.posture,
        tenant: identity.tenant.as_deref(),
        auth_strength: identity.auth_strength.as_deref(),
        idp: identity.idp.as_deref(),
        ..Default::default()
    };
    let outcome = engine.evaluate_ref(&ctx);
    let request_limit_ctx =
        RateLimitContext::from_identity(client_addr.ip(), &identity, outcome.matched_rule, None);
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(listener_name, outcome.matched_rule)
        .ok_or_else(|| anyhow!("compiled transparent UDP execution plan not found"))?;
    let crate::rate_limit::RequestLimitAcquire {
        limits: request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        TransportScope::Udp,
        &request_limit_ctx,
        1,
    )?;
    if retry_after.is_some() {
        return Ok(None);
    }
    Ok(Some(UdpRuleEvaluation {
        connect_target,
        host_for_match_owned,
        authority,
        identity,
        sni,
        outcome,
        request_limit_ctx,
        request_limits,
    }))
}
