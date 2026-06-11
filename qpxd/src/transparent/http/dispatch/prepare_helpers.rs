use super::super::ConnectTarget;
use crate::destination::DestinationInputs;
use crate::http::body::size::observed_request_size;
use crate::http::dispatch::{
    DispatchAuditInput, DispatchGuardInput, ProxyKind, build_dispatch_audit_context,
};
use crate::http::policy::response_policy::{ResponseRuleCandidates, response_request_obs};
use crate::http::policy::rule_context::{
    RequestRuleContextInput, build_request_rule_match_context,
};
use crate::http::protocol::preflight::{PreflightOptions, PreflightOutcome, preflight_validate};
use crate::runtime::CompiledTransparentEdge;
use hyper::{Request, StatusCode};
use qpx_http::body::Body;
use std::net::SocketAddr;
use std::time::Duration;

#[expect(
    clippy::too_many_arguments,
    reason = "transparent response observation passes already-derived request facts explicitly"
)]
pub(super) fn response_request_observation(
    req: &Request<Body>,
    base: &crate::http::protocol::base_fields::BaseRequestFields,
    sanitized_headers: &http::HeaderMap,
    destination: &crate::destination::DestinationMetadata,
    identity: &crate::policy_context::ResolvedIdentity,
    request_rpc: Option<&crate::http::rpc::RpcMatchContext>,
    response_engine: Option<&crate::http::policy::response_policy::HttpResponseRuleEngine>,
    candidates: &ResponseRuleCandidates,
) -> qpx_core::rules::CandidateRequestObservationRequirements {
    let ctx = build_request_rule_match_context(RequestRuleContextInput {
        base,
        headers: sanitized_headers,
        destination,
        identity,
        request_size: observed_request_size(req),
        rpc: request_rpc,
        client_cert: None,
        upstream_cert: None,
    });
    response_request_obs(response_engine, candidates, &ctx)
}

#[expect(
    clippy::too_many_arguments,
    reason = "guard input construction keeps transparent mode facts explicit before shared dispatch"
)]
pub(super) fn guard_input<'a>(
    profile: Option<&'a crate::http::policy::guard::CompiledHttpGuardProfile>,
    req: &'a Request<Body>,
    destination: &'a crate::destination::DestinationMetadata,
    state: &std::sync::Arc<crate::runtime::RuntimeState>,
    proxy_name: &'a str,
    listener_name: &'a str,
    remote_addr: SocketAddr,
    path: Option<&str>,
    identity: &crate::policy_context::ResolvedIdentity,
    host: Option<String>,
) -> DispatchGuardInput<'a> {
    DispatchGuardInput {
        profile,
        req,
        destination,
        proxy_name,
        audit: build_dispatch_audit_context(DispatchAuditInput {
            state: state.clone(),
            kind: ProxyKind::Transparent,
            scope_name: listener_name,
            remote_addr,
            host,
            sni: None,
            request_method: req.method().clone(),
            path: path.map(str::to_string),
            matched_rule: None,
            matched_route: None,
            identity,
            destination,
            ext_authz: None,
        }),
    }
}

pub(super) fn preflight_rejection(
    req: &Request<Body>,
    proxy_name: &str,
    trace_enabled: bool,
    trace_disabled_message: &str,
) -> Option<Box<hyper::Response<Body>>> {
    match preflight_validate(
        req,
        proxy_name,
        PreflightOptions::reject_connect(
            trace_enabled,
            trace_disabled_message,
            StatusCode::METHOD_NOT_ALLOWED,
            "transparent HTTP forward_edges do not support CONNECT",
        ),
    ) {
        PreflightOutcome::Reject(response) => Some(response),
        PreflightOutcome::Continue => None,
    }
}

pub(super) fn request_observation_limit(
    edge: &CompiledTransparentEdge,
    guard: Option<&crate::http::policy::guard::CompiledHttpGuardProfile>,
    state: &crate::runtime::RuntimeState,
) -> usize {
    let default_limit = guard
        .and_then(|profile| profile.request_body_observation_cap())
        .map(|cap| cap.min(state.plan.limits.body.max_observed_request_body_bytes))
        .unwrap_or(state.plan.limits.body.max_observed_request_body_bytes);
    edge.request_body_observation_limit(default_limit)
}

pub(super) fn body_read_timeout(edge: &CompiledTransparentEdge) -> Duration {
    Duration::from_millis(edge.default_plan.streaming.body_read_timeout_ms)
}

pub(super) fn destination(
    state: &crate::runtime::RuntimeState,
    host_for_match: &Option<String>,
    base: &crate::http::protocol::base_fields::BaseRequestFields,
    connect_target: &ConnectTarget,
    resolution: Option<&qpx_core::config::DestinationResolutionOverrideConfig>,
) -> crate::destination::DestinationMetadata {
    state.classify_destination(
        &DestinationInputs {
            host: host_for_match.as_deref(),
            ip: host_for_match
                .as_deref()
                .and_then(|value| value.parse().ok()),
            scheme: base.scheme.as_deref(),
            port: Some(connect_target.port()),
            ..Default::default()
        },
        resolution,
    )
}
