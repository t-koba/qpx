use super::connect;
use crate::http::body::Body;
use crate::http::dispatcher::attach_interim_response_heads;
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::http::protocol::common::resolve_named_upstream;
use crate::http::protocol::preflight::{PreflightOptions, PreflightOutcome, preflight_validate};
use crate::runtime::Runtime;
use anyhow::{Result, anyhow};
#[cfg(feature = "auth-basic")]
use hyper::StatusCode;
use hyper::{Method, Request, Response};
use std::sync::Arc;

mod dispatch;

use self::dispatch::dispatch_forward_request;

pub(crate) async fn handle_request_inner(
    req: Request<Body>,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: std::net::SocketAddr,
) -> Result<Response<Body>> {
    let dispatch_view = runtime.dispatch_view();
    let proxy_name = dispatch_view.plan.identity.proxy_name.as_ref();
    if let PreflightOutcome::Reject(response) = preflight_validate(
        &req,
        proxy_name,
        PreflightOptions::allow_connect(
            dispatch_view.plan.limits.general.trace_enabled,
            dispatch_view.messages.trace_disabled.as_str(),
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
        match dispatch_forward_request(req, base, runtime, listener_name, remote_addr).await {
            Ok(response) => response,
            Err(err) => err.into_response_result()?,
        };
    attach_interim_response_heads(&mut response, interim);
    Ok(response)
}

#[cfg(feature = "auth-basic")]
pub(crate) fn proxy_auth_required(
    chal: crate::runtime::auth::AuthChallenge,
    message: &str,
) -> Response<Body> {
    let mut builder = Response::builder().status(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    for header in chal.header_values {
        builder = builder.header("Proxy-Authenticate", header);
    }
    builder
        .body(Body::from(message.to_owned()))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

pub(crate) fn resolve_upstream(
    action: &qpx_core::config::ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_name: &str,
) -> Result<Option<crate::upstream::pool::ResolvedUpstreamProxy>> {
    let listener = state
        .ingress_edge_settings(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    resolve_named_upstream(action, state, listener.upstream_proxy.as_deref())
}

pub(crate) fn resolve_upstream_url(
    action: &qpx_core::config::ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_name: &str,
) -> Result<Option<String>> {
    let listener = state
        .ingress_edge_settings(listener_name)
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
            "{:?} action requires an upstream reference (set action.upstream or forward_edges[].upstream_proxy)",
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
mod tests;
