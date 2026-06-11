use crate::destination::{DestinationInputs, DestinationMetadata};
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::policy_context::{resolve_identity, sanitize_headers_for_policy};
use crate::reverse::ReloadableReverse;
use crate::reverse::router::normalize_host_for_match;
use crate::runtime::ResolvedStreamingLimits;
use http::Request;
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::tls::extract_upstream_certificate_info;
use std::net::SocketAddr;

pub(super) struct ReverseH3RequestPeer<'a> {
    pub(super) remote_addr: SocketAddr,
    pub(super) dst_port: u16,
    pub(super) tls_sni: Option<&'a str>,
    pub(super) peer_certificates: Option<&'a [Vec<u8>]>,
}

fn request_side_fail_closed(
    left: ResolvedStreamingLimits,
    right: ResolvedStreamingLimits,
) -> ResolvedStreamingLimits {
    ResolvedStreamingLimits {
        body_channel_capacity: left
            .body_channel_capacity
            .min(right.body_channel_capacity)
            .max(1),
        body_read_timeout_ms: left
            .body_read_timeout_ms
            .min(right.body_read_timeout_ms)
            .max(1),
        body_send_timeout_ms: left
            .body_send_timeout_ms
            .min(right.body_send_timeout_ms)
            .max(1),
        max_request_body_bytes: left
            .max_request_body_bytes
            .min(right.max_request_body_bytes),
        max_response_body_bytes: left
            .max_response_body_bytes
            .min(right.max_response_body_bytes),
        max_grpc_message_bytes: left
            .max_grpc_message_bytes
            .min(right.max_grpc_message_bytes),
        max_grpc_web_trailer_bytes: left
            .max_grpc_web_trailer_bytes
            .min(right.max_grpc_web_trailer_bytes),
        max_grpc_stream_duration_ms: left
            .max_grpc_stream_duration_ms
            .min(right.max_grpc_stream_duration_ms),
        observe_grpc_messages: left.observe_grpc_messages || right.observe_grpc_messages,
        sse: fail_closed_sse(left.sse, right.sse),
    }
}

fn fail_closed_sse(
    left: qpx_core::config::SseStreamingPolicy,
    right: qpx_core::config::SseStreamingPolicy,
) -> qpx_core::config::SseStreamingPolicy {
    qpx_core::config::SseStreamingPolicy {
        disable_compression: left.disable_compression || right.disable_compression,
        flush_policy: left.flush_policy,
        idle_timeout_ms: left.idle_timeout_ms.min(right.idle_timeout_ms).max(1),
        max_stream_duration_ms: left
            .max_stream_duration_ms
            .min(right.max_stream_duration_ms)
            .max(1),
        max_line_bytes: left.max_line_bytes.min(right.max_line_bytes).max(1),
        max_event_id_bytes: left.max_event_id_bytes.min(right.max_event_id_bytes).max(1),
    }
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
    let authority_owned = req_head
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            req_head
                .headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        });
    let host = normalize_host_for_match(authority_owned.as_deref().unwrap_or_default());
    let base = extract_base_request_fields(
        req_head,
        BaseRequestContext {
            peer_ip: Some(peer.remote_addr.ip()),
            dst_port: Some(peer.dst_port),
            host: (!host.is_empty()).then_some(host.as_str()),
            sni: peer.tls_sni,
            authority: authority_owned.as_deref(),
            scheme: Some("https"),
        },
    );
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: Some(peer.dst_port),
        src_ip: Some(peer.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host.as_str()),
        sni: peer.tls_sni,
        path: base.path.as_deref(),
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
        let identity = match resolve_identity(
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
        let destination =
            classify_reverse_h3_destination(&state, &peer, host.as_str(), resolution_override);
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
                deferred_limits = Some(request_side_fail_closed(current, route.plan.streaming));
            }
            return Ok(false);
        }
        if route.matches(&ctx) {
            selected_limits = Some(
                deferred_limits
                    .map(|limits| request_side_fail_closed(limits, route.plan.streaming))
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
