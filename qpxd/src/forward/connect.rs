use super::policy::{evaluate_forward_policy, ForwardPolicyDecision};
use crate::forward::request::{proxy_auth_required, resolve_upstream};
use crate::http::address::parse_authority_host_port;
use crate::http::common::{
    blocked_response as blocked, connect_established_response as connect_established,
    forbidden_response as forbidden,
};
use crate::http::l7::finalize_response_for_request;
use crate::http::local_response::build_local_response;
#[cfg(feature = "mitm")]
use crate::http::server::serve_http1_with_upgrades;
use crate::io_copy::copy_bidirectional_with_export_and_idle;
use crate::runtime::Runtime;
#[cfg(feature = "mitm")]
use crate::upstream::connect::TunnelIo;
use crate::upstream::connect::{connect_tunnel_target, ConnectedTunnel};
#[cfg(feature = "mitm")]
use anyhow::Context;
use anyhow::{anyhow, Result};
#[cfg(feature = "mitm")]
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response};
use qpx_core::config::ActionKind;
use qpx_core::rules::RuleMatchContext;
use std::net::SocketAddr;
use tokio::task;
use tokio::time::{timeout, Duration};
use tracing::warn;

#[cfg(feature = "mitm")]
use crate::http::mitm::{proxy_mitm_request, MitmRouteContext};
#[cfg(feature = "mitm")]
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream};
#[cfg(feature = "mitm")]
use qpx_core::tls::MitmConfig;

pub(super) async fn handle_connect(
    req: Request<Body>,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: SocketAddr,
) -> Result<Response<Body>> {
    let state = runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    let req_version = req.version();

    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| anyhow!("missing authority"))?
        .as_str()
        .to_string();
    let (host, port) = parse_authority_host_port(&authority, 443)
        .ok_or_else(|| anyhow!("invalid connect authority"))?;

    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: Some(port),
        host: Some(host.as_str()),
        sni: Some(host.as_str()),
        method: Some("CONNECT"),
        path: None,
        headers: Some(req.headers()),
        user_groups: &[],
    };

    let action = match evaluate_forward_policy(
        &runtime,
        listener_name,
        ctx,
        req.headers(),
        "CONNECT",
        &authority,
    )
    .await?
    {
        ForwardPolicyDecision::Allow(allowed) => allowed.action,
        ForwardPolicyDecision::Challenge(chal) => {
            let response = proxy_auth_required(chal, state.messages.proxy_auth_required.as_str());
            return Ok(finalize_response_for_request(
                &Method::CONNECT,
                req_version,
                proxy_name,
                response,
                false,
            ));
        }
        ForwardPolicyDecision::Forbidden => {
            return Ok(finalize_response_for_request(
                &Method::CONNECT,
                req_version,
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            ));
        }
    };
    let upstream_timeout = Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);

    match action.kind {
        ActionKind::Block => Ok(finalize_response_for_request(
            &Method::CONNECT,
            req_version,
            proxy_name,
            blocked(state.messages.blocked.as_str()),
            false,
        )),
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            Ok(finalize_response_for_request(
                &Method::CONNECT,
                req_version,
                proxy_name,
                build_local_response(local)?,
                false,
            ))
        }
        ActionKind::Inspect => {
            #[cfg(not(feature = "mitm"))]
            {
                Ok(finalize_response_for_request(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    blocked(state.messages.blocked.as_str()),
                    false,
                ))
            }

            #[cfg(feature = "mitm")]
            {
                let tls_inspection = state
                    .listener_config(listener_name)
                    .and_then(|l| l.tls_inspection.as_ref());
                if !tls_inspection.map(|t| t.enabled).unwrap_or(false) {
                    return Ok(finalize_response_for_request(
                        &Method::CONNECT,
                        req_version,
                        proxy_name,
                        blocked(state.messages.blocked.as_str()),
                        false,
                    ));
                }
                let verify = tls_inspection
                    .map(|t| {
                        t.verify_upstream
                            && !state.tls_verify_exception_matches(listener_name, &host)
                    })
                    .unwrap_or(true);
                let mitm = state
                    .mitm
                    .clone()
                    .ok_or_else(|| anyhow!("mitm not available"))?;
                let upstream = resolve_upstream(&action, &state, listener_name)?;
                let upstream_connected =
                    match connect_tunnel_target(&host, port, upstream.as_deref(), upstream_timeout)
                        .await
                    {
                        Ok(stream) => stream,
                        Err(_) => {
                            return Ok(finalize_response_for_request(
                                &Method::CONNECT,
                                req_version,
                                proxy_name,
                                Response::builder()
                                    .status(hyper::StatusCode::BAD_GATEWAY)
                                    .body(Body::from(state.messages.proxy_error.clone()))
                                    .unwrap(),
                                false,
                            ))
                        }
                    };
                let runtime_for_mitm = runtime.clone();
                let listener_name_owned = listener_name.to_string();
                let mitm_context = ForwardMitmContext {
                    host,
                    port,
                    upstream_tcp: upstream_connected.io,
                    mitm,
                    verify_upstream: verify,
                    runtime: runtime_for_mitm,
                    listener_name: listener_name_owned,
                    remote_addr,
                };
                task::spawn(async move {
                    if let Err(err) = mitm_connect(req, mitm_context).await {
                        warn!(error = ?err, "mitm tunnel failed");
                    }
                });
                Ok(finalize_response_for_request(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    connect_established(),
                    false,
                ))
            }
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {
            let upstream = resolve_upstream(&action, &state, listener_name)?;
            let connected =
                match connect_tunnel_target(&host, port, upstream.as_deref(), upstream_timeout)
                    .await
                {
                    Ok(stream) => stream,
                    Err(_) => {
                        return Ok(finalize_response_for_request(
                            &Method::CONNECT,
                            req_version,
                            proxy_name,
                            Response::builder()
                                .status(hyper::StatusCode::BAD_GATEWAY)
                                .body(Body::from(state.messages.proxy_error.clone()))
                                .unwrap(),
                            false,
                        ))
                    }
                };
            let runtime_for_tunnel = runtime.clone();
            task::spawn(async move {
                if let Err(err) =
                    tunnel_connect(req, connected, runtime_for_tunnel, remote_addr).await
                {
                    warn!(error = ?err, "tunnel failed");
                }
            });
            Ok(finalize_response_for_request(
                &Method::CONNECT,
                req_version,
                proxy_name,
                connect_established(),
                false,
            ))
        }
    }
}

async fn tunnel_connect(
    req: Request<Body>,
    server: ConnectedTunnel,
    runtime: Runtime,
    remote_addr: SocketAddr,
) -> Result<()> {
    let upgrade_wait =
        Duration::from_millis(runtime.state().config.runtime.upgrade_wait_timeout_ms);
    let upgraded = timeout(upgrade_wait, hyper::upgrade::on(req)).await??;
    let export = server
        .peer_addr
        .and_then(|server_addr| runtime.state().export_session(remote_addr, server_addr));
    let idle_timeout = Duration::from_millis(runtime.state().config.runtime.tunnel_idle_timeout_ms);
    copy_bidirectional_with_export_and_idle(upgraded, server.io, export, Some(idle_timeout))
        .await?;
    Ok(())
}

#[cfg(feature = "mitm")]
struct ForwardMitmContext {
    host: String,
    port: u16,
    upstream_tcp: TunnelIo,
    mitm: MitmConfig,
    verify_upstream: bool,
    runtime: Runtime,
    listener_name: String,
    remote_addr: SocketAddr,
}

#[cfg(feature = "mitm")]
async fn mitm_connect(req: Request<Body>, ctx: ForwardMitmContext) -> Result<()> {
    let ForwardMitmContext {
        host,
        port,
        upstream_tcp,
        mitm,
        verify_upstream,
        runtime,
        listener_name,
        remote_addr,
    } = ctx;
    let upstream_timeout =
        Duration::from_millis(runtime.state().config.runtime.upstream_http_timeout_ms);

    let upgrade_wait =
        Duration::from_millis(runtime.state().config.runtime.upgrade_wait_timeout_ms);
    let upgraded = timeout(upgrade_wait, hyper::upgrade::on(req)).await??;
    let client_tls = accept_mitm_client(upgraded, &mitm, upstream_timeout).await?;
    let sender = connect_mitm_upstream(
        upstream_tcp,
        host.as_str(),
        &mitm,
        verify_upstream,
        upstream_timeout,
        "forward MITM upstream conn",
    )
    .await?;
    let connect_host = host.clone();
    let header_read_timeout =
        Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
    let service = service_fn(move |inner_req: Request<Body>| {
        let sender = sender.clone();
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let connect_host = connect_host.clone();
        async move {
            let route = MitmRouteContext {
                listener_name: listener_name.as_str(),
                src_addr: remote_addr,
                dst_port: port,
                host: connect_host.as_str(),
                sni: connect_host.as_str(),
            };
            let response = proxy_mitm_request(inner_req, runtime, sender, route).await?;
            Ok::<_, anyhow::Error>(response)
        }
    });

    serve_http1_with_upgrades(client_tls, service, header_read_timeout, false)
        .await
        .context("serve_connection failed")?;
    Ok(())
}
