use crate::destination::DestinationInputs;
use crate::forward::{evaluate_forward_policy, proxy_auth_required, ForwardPolicyDecision};
use crate::http::address::format_authority_host_port;
use crate::http::base_fields::{
    extract_base_request_fields, BaseRequestContext, BaseRequestFields,
};
use crate::http::body::Body;
use crate::http::body_size::observed_request_size;
use crate::http::common::{
    blocked_response as blocked, forbidden_response as forbidden,
    too_many_requests_response as too_many_requests,
};
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers_in_place,
    handle_max_forwards_in_place, prepare_request_with_headers_in_place,
};
use crate::http::local_response::build_local_response;
use crate::http::preflight::{preflight_validate, PreflightOptions, PreflightOutcome};
use crate::http::response_policy::{
    apply_listener_response_policy, ListenerResponsePolicyDecision, ResponseBodyObservationLimits,
};
use crate::http::websocket::{is_websocket_upgrade, spawn_upgrade_tunnel};
use crate::policy_context::{
    attach_log_context, emit_audit_log, enforce_ext_authz, merge_header_controls,
    merge_policy_tags, resolve_identity, sanitize_headers_for_policy,
    strip_untrusted_identity_headers, validate_ext_authz_allow_mode, AuditRecord,
    EffectivePolicyContext, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use crate::tls::UpstreamCertificateInfo;
use anyhow::{anyhow, Result};
use hyper::client::conn::http1::SendRequest;
use hyper::{Request, Response};
use qpx_core::config::ActionKind;
use qpx_core::prefilter::MatchPrefilterContext;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

#[path = "mitm_dispatch.rs"]
mod mitm_dispatch;

use self::mitm_dispatch::dispatch_mitm_request;

pub struct MitmRouteContext<'a> {
    pub listener_name: &'a str,
    pub src_addr: SocketAddr,
    pub dst_port: u16,
    pub host: &'a str,
    pub sni: &'a str,
    pub upstream_cert: Option<Arc<UpstreamCertificateInfo>>,
}

pub async fn proxy_mitm_request(
    req: Request<Body>,
    runtime: Runtime,
    sender: Arc<Mutex<SendRequest<Body>>>,
    route: MitmRouteContext<'_>,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    if let PreflightOutcome::Reject(response) = preflight_validate(
        &req,
        proxy_name,
        PreflightOptions::allow_connect(
            state.config.runtime.trace_enabled,
            state.messages.trace_disabled.as_str(),
        ),
    ) {
        return Ok(*response);
    }
    let base = extract_base_request_fields(
        &req,
        BaseRequestContext {
            peer_ip: Some(route.src_addr.ip()),
            dst_port: Some(route.dst_port),
            host: Some(route.host),
            sni: Some(route.sni),
            scheme: Some("https"),
            ..Default::default()
        },
    );
    let response = dispatch_mitm_request(req, base, runtime, sender, route).await?;
    Ok(response)
}
