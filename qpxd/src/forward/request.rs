use super::connect;
use super::policy::{evaluate_forward_policy, ForwardPolicyDecision};
use crate::cache::CacheRequestKey;
use crate::destination::DestinationInputs;
use crate::ftp;
use crate::http::address::format_authority_host_port;
use crate::http::base_fields::{
    extract_base_request_fields, BaseRequestContext, BaseRequestFields,
};
use crate::http::body::Body;
use crate::http::body_size::observed_request_size;
use crate::http::cache_flow::{
    clone_request_head_for_revalidation, lookup_with_revalidation,
    process_upstream_response_for_cache, CacheLookupDecision, CacheWritebackContext,
};
use crate::http::common::{
    bad_request_response as bad_request, blocked_response as blocked,
    forbidden_response as forbidden, resolve_named_upstream,
    too_many_requests_response as too_many_requests,
};
use crate::http::dispatcher::attach_interim_response_heads;
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers,
    finalize_response_with_headers_in_place, handle_max_forwards_in_place,
    prepare_request_with_headers_in_place,
};
use crate::http::local_response::build_local_response;
use crate::http::preflight::{preflight_validate, PreflightOptions, PreflightOutcome};
use crate::http::response_policy::{
    apply_listener_response_policy, ListenerResponsePolicyDecision, ResponseBodyObservationLimits,
};
use crate::http::websocket::is_websocket_upgrade;
use crate::policy_context::{
    apply_ext_authz_action_overrides, attach_log_context, emit_audit_log, enforce_ext_authz,
    merge_header_controls, merge_policy_tags, resolve_identity, sanitize_headers_for_policy,
    strip_untrusted_identity_headers, validate_ext_authz_allow_mode, AuditRecord,
    EffectivePolicyContext, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use crate::upstream::http1::{
    proxy_http1_request, proxy_http1_request_with_interim, proxy_websocket_http1,
    WebsocketProxyConfig,
};
use anyhow::{anyhow, Result};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::config::ActionKind;
use qpx_core::prefilter::MatchPrefilterContext;
use std::sync::Arc;
use tokio::time::Duration;

#[path = "request_dispatch.rs"]
mod request_dispatch;

use self::request_dispatch::dispatch_forward_request;

pub(crate) async fn handle_request_inner(
    req: Request<Body>,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
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
    if req.method() == Method::CONNECT {
        return connect::handle_connect(req, runtime, listener_name, remote_addr).await;
    }

    let base = extract_base_request_fields(
        &req,
        BaseRequestContext {
            peer_ip: Some(remote_addr.ip()),
            ..Default::default()
        },
    );
    let interim = Vec::new();
    let mut response =
        dispatch_forward_request(req, base, runtime, listener_name, remote_addr).await?;
    attach_interim_response_heads(&mut response, interim);
    Ok(response)
}

pub(crate) fn proxy_auth_required(chal: qpx_auth::AuthChallenge, message: &str) -> Response<Body> {
    let mut builder = Response::builder().status(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    for header in chal.header_values {
        builder = builder.header("Proxy-Authenticate", header);
    }
    builder.body(Body::from(message.to_owned())).unwrap()
}

pub(crate) fn resolve_upstream(
    action: &qpx_core::config::ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_name: &str,
) -> Result<Option<crate::upstream::pool::ResolvedUpstreamProxy>> {
    let listener = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    resolve_named_upstream(action, state, listener.upstream_proxy.as_deref())
}

pub(crate) fn resolve_upstream_url(
    action: &qpx_core::config::ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_name: &str,
) -> Result<Option<String>> {
    let listener = state
        .listener_config(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    if matches!(action.kind, qpx_core::config::ActionKind::Direct) {
        return Ok(None);
    }
    if let Some(upstream_name) = action
        .upstream
        .as_deref()
        .or(listener.upstream_proxy.as_deref())
    {
        if upstream_name.contains("://") {
            return Ok(Some(upstream_name.to_string()));
        }
        if (upstream_name.contains(':') || upstream_name.starts_with('['))
            && upstream_name.parse::<http::uri::Authority>().is_ok()
        {
            if upstream_name.contains('@') {
                return Ok(Some(format!("http://{}", upstream_name)));
            }
            return Ok(Some(upstream_name.to_string()));
        }
        if let Some(url) = state.upstreams.get(upstream_name) {
            return Ok(Some(url.clone()));
        }
        return Err(anyhow!(
            "unknown upstream reference: {} (define it in top-level upstreams[])",
            upstream_name
        ));
    }
    match action.kind {
        qpx_core::config::ActionKind::Proxy | qpx_core::config::ActionKind::Tunnel => Err(anyhow!(
            "{:?} action requires an upstream reference (set action.upstream or listeners[].upstream_proxy)",
            action.kind
        )),
        qpx_core::config::ActionKind::Inspect => Ok(None),
        qpx_core::config::ActionKind::Direct
        | qpx_core::config::ActionKind::Block
        | qpx_core::config::ActionKind::Respond => Ok(None),
    }
}

struct HostPort {
    host: String,
    port: Option<u16>,
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
