use crate::destination::{DestinationInputs, DestinationMetadata};
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::policy_context::sanitize_headers_for_policy;
use crate::reverse::ReloadableReverse;
use crate::runtime::ResolvedStreamingLimits;
use qpx_core::http_message::Request;
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::tls::extract_upstream_certificate_info;
use std::net::SocketAddr;

pub(super) struct ReverseH3RequestPeer<'a> {
    pub(super) remote_addr: SocketAddr,
    pub(super) dst_port: u16,
    pub(super) tls_sni: Option<&'a str>,
    pub(super) peer_certificates: Option<&'a [Vec<u8>]>,
}

pub(super) fn max_reverse_h3_request_body_bytes(
    reverse: &ReloadableReverse,
    fallback: ResolvedStreamingLimits,
) -> usize {
    let state = reverse.runtime.state();
    state
        .plan
        .reverse_edge(reverse.name.as_ref())
        .map(|edge| {
            edge.routes
                .iter()
                .fold(fallback.max_request_body_bytes, |max, route| {
                    max.max(route.plan.streaming.max_request_body_bytes)
                })
        })
        .unwrap_or(fallback.max_request_body_bytes)
}

pub(super) fn request_streaming_limits_for_head(
    reverse: &ReloadableReverse,
    req_head: &Request<()>,
    peer: ReverseH3RequestPeer<'_>,
    fallback: ResolvedStreamingLimits,
) -> ResolvedStreamingLimits {
    let state = reverse.runtime.state();
    let Some(edge) = state.plan.reverse_edge(reverse.name.as_ref()) else {
        return fallback;
    };
    let compiled = reverse.compiled.load_full();
    let router = compiled.router.as_ref();
    let base = extract_base_request_fields(
        req_head,
        BaseRequestContext {
            peer_ip: Some(peer.remote_addr.ip()),
            dst_port: Some(peer.dst_port),
            sni: peer.tls_sni,
            scheme: Some(http::uri::Scheme::HTTPS),
            ..Default::default()
        },
    );
    let host = base.host().unwrap_or_default();
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: Some(peer.dst_port),
        src_ip: Some(peer.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host),
        sni: peer.tls_sni,
        path: base.path(),
    };
    let mut deferred_limits: Option<ResolvedStreamingLimits> = None;
    let client_cert = peer
        .peer_certificates
        .and_then(|certs| certs.first())
        .map(|cert| extract_upstream_certificate_info(Some(cert.as_slice())));
    let mut fallback_to_edge = false;
    let mut selected_limits = None;
    let _ = router.try_for_each_candidate_route(prefilter_ctx, |_, route| {
        let resolution_override = route.plan.destination_resolution.as_ref();
        let effective_policy = route.plan.policy_context.clone();
        let mut sanitized_headers = req_head.headers().clone();
        if sanitize_headers_for_policy(
            &state,
            &effective_policy,
            peer.remote_addr.ip(),
            &mut sanitized_headers,
        )
        .is_err()
        {
            fallback_to_edge = true;
            return Ok::<bool, ()>(true);
        }
        let identity = match crate::policy_context::resolve_identity_local(
            &state,
            &effective_policy,
            peer.remote_addr.ip(),
            Some(&sanitized_headers),
            peer.peer_certificates,
        ) {
            Ok(identity) => identity,
            Err(_) => {
                fallback_to_edge = true;
                return Ok(true);
            }
        };
        let destination = classify_reverse_h3_destination(&state, &peer, host, resolution_override);
        let ctx = crate::http::policy::rule_context::build_request_rule_match_context(
            crate::http::policy::rule_context::RequestRuleContextInput {
                base: &base,
                headers: &sanitized_headers,
                destination: &destination,
                identity: &identity,
                request_size: None,
                rpc: None,
                client_cert: client_cert.as_ref(),
                upstream_cert: None,
            },
        );
        if route.requires_request_size()
            || route.requires_request_body_observation()
            || route.requires_request_rpc_context()
        {
            if route.matches_without_request_body_observation(&ctx) {
                let current = deferred_limits.unwrap_or(edge.streaming);
                deferred_limits = Some(current.request_side_fail_closed(route.plan.streaming));
            }
            return Ok(false);
        }
        if route.matches(&ctx) {
            selected_limits = Some(
                deferred_limits
                    .map(|limits| limits.request_side_fail_closed(route.plan.streaming))
                    .unwrap_or(route.plan.streaming),
            );
            return Ok(true);
        }
        Ok(false)
    });
    if fallback_to_edge {
        return edge.streaming;
    }
    selected_limits.unwrap_or_else(|| deferred_limits.unwrap_or(edge.streaming))
}

fn classify_reverse_h3_destination(
    state: &crate::runtime::RuntimeState,
    peer: &ReverseH3RequestPeer<'_>,
    host: &str,
    resolution_override: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
) -> DestinationMetadata {
    state.classify_destination(
        &DestinationInputs {
            host: (!host.is_empty()).then_some(host),
            ip: host.parse().ok(),
            sni: peer.tls_sni,
            scheme: Some("https"),
            port: Some(peer.dst_port),
            alpn: Some("h3"),
            ja3: None,
            ja4: None,
            cert_subject: None,
            cert_issuer: None,
            cert_san_dns: &[],
            cert_san_uri: &[],
            cert_fingerprint_sha256: None,
        },
        resolution_override,
    )
}
