use super::super::super::super::connect::{
    ConnectPolicyInput, decide_connect_action_from_tls_metadata, forward_connect_verify_upstream,
    listener_requires_upstream_cert_preview, listener_upstream_trust,
};
use super::super::super::backend_h3::ForwardH3Handler;
use super::build_h3_connect_success_response;
use super::tunnel::{H3ConnectPolicyContext, prepare_h3_connect_stream, relay_h3_connect_stream};
#[cfg(feature = "mitm")]
use super::tunnel::{MitmH3ConnectInput, mitm_h3_connect_stream};
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::H3ServerRequestStream;
use crate::policy_context::ResolvedIdentity;
#[cfg(feature = "mitm")]
use crate::tls::TlsClientHelloInfo;
use crate::tls::preview::preview_client_certificate_with_timeout;
use crate::upstream::connect::TunnelIo;
use anyhow::{Result, anyhow};
use qpx_core::config::{ActionConfig, ActionKind};
use qpx_core::rules::CompiledHeaderControl;
#[cfg(feature = "mitm")]
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_observability::access_log::RequestLogContext;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::warn;

pub(super) struct EstablishedH3Connect {
    pub(super) req_stream: H3ServerRequestStream,
    pub(super) handler: ForwardH3Handler,
    pub(super) conn: H3ConnInfo,
    pub(super) proxy_name: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) authority: String,
    pub(super) action: ActionConfig,
    pub(super) response_headers: Option<Arc<CompiledHeaderControl>>,
    pub(super) log_context: RequestLogContext,
    pub(super) matched_rule: Option<String>,
    pub(super) decision_service_policy_id: Option<String>,
    pub(super) audit_path: Option<String>,
    pub(super) upstream_timeout: Duration,
    pub(super) tunnel_idle_timeout: Duration,
    pub(super) sanitized_headers: http::HeaderMap,
    pub(super) identity: ResolvedIdentity,
    pub(super) server: TunnelIo,
}

pub(super) async fn finish_h3_connect(input: EstablishedH3Connect) -> Result<()> {
    let EstablishedH3Connect {
        mut req_stream,
        handler,
        conn,
        proxy_name,
        host,
        port,
        authority,
        action,
        response_headers,
        log_context,
        matched_rule,
        decision_service_policy_id,
        audit_path,
        upstream_timeout,
        tunnel_idle_timeout,
        sanitized_headers,
        identity,
        server,
    } = input;
    let state = handler.runtime.state();
    let established = build_h3_connect_success_response(
        proxy_name.as_str(),
        &http::Method::CONNECT,
        false,
        response_headers.as_deref(),
    )?;
    tokio::time::timeout(tunnel_idle_timeout, req_stream.send_response(established))
        .await
        .map_err(|_| anyhow!("forward HTTP/3 CONNECT response send timeout"))??;
    let initial_post_connect_action = action.clone();
    let (mut req_stream, client_prefetch, client_hello, mut action) = prepare_h3_connect_stream(
        req_stream,
        &handler.runtime,
        H3ConnectPolicyContext {
            listener_name: handler.listener_name.as_ref(),
            remote_addr: conn.remote_addr,
            host: host.as_str(),
            port,
            authority: authority.as_str(),
            sanitized_headers: sanitized_headers.clone(),
            identity: &identity,
            initial_action: action,
        },
    )
    .await?;
    let listener_cfg = state
        .ingress_edge_settings(handler.listener_name.as_ref())
        .ok_or_else(|| anyhow!("listener not found"))?;
    let listener_trust = listener_upstream_trust(listener_cfg)?;
    let mut server = Some(server);
    if let Some(client_hello) = client_hello.as_ref()
        && listener_requires_upstream_cert_preview(listener_cfg)
        && matches!(
            action.kind,
            ActionKind::Inspect | ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
        )
    {
        let preview_verify = forward_connect_verify_upstream(
            &state,
            Some(listener_cfg),
            handler.listener_name.as_ref(),
            host.as_str(),
        );
        let preview_server = server
            .take()
            .ok_or_else(|| anyhow!("HTTP/3 CONNECT upstream tunnel missing before cert preview"))?;
        match preview_client_certificate_with_timeout(
            host.as_str(),
            preview_server,
            preview_verify,
            listener_trust.as_deref(),
            upstream_timeout,
        )
        .await
        {
            Ok(upstream_cert) => {
                action = decide_connect_action_from_tls_metadata(ConnectPolicyInput {
                    runtime: &handler.runtime,
                    listener_name: handler.listener_name.as_ref(),
                    remote_addr: conn.remote_addr,
                    host: host.as_str(),
                    port,
                    authority: authority.as_str(),
                    sanitized_headers: &sanitized_headers,
                    identity: &identity,
                    client_hello,
                    upstream_cert: Some(&upstream_cert),
                })
                .await?;
            }
            Err(err) => {
                if listener_trust.is_some() {
                    return Err(err);
                }
                warn!(
                    error = ?err,
                    "forward HTTP/3 CONNECT upstream certificate preview failed"
                );
            }
        }
    }
    if (server.is_none() || action != initial_post_connect_action)
        && matches!(
            action.kind,
            ActionKind::Inspect | ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
        )
    {
        let upstream = crate::forward::request::resolve_upstream(
            &action,
            &state,
            handler.listener_name.as_ref(),
        )?;
        server = Some(
            crate::upstream::connect::connect_tunnel_target(
                host.as_str(),
                port,
                upstream.as_ref(),
                proxy_name.as_str(),
                upstream_timeout,
            )
            .await?
            .io,
        );
    }
    super::super::emit_h3_connect_allow_audit(super::super::H3ConnectAllowAuditContext {
        state: &state,
        listener_name: handler.listener_name.as_ref(),
        remote_ip: conn.remote_addr.ip(),
        host: host.as_str(),
        path: audit_path.as_deref(),
        matched_rule: matched_rule.as_deref(),
        decision_service_policy_id: decision_service_policy_id.as_deref(),
        log_context: &log_context,
    });
    match action.kind {
        ActionKind::Block | ActionKind::Respond => {
            let _ = req_stream.finish().await;
            Ok(())
        }
        ActionKind::Inspect => {
            #[cfg(not(feature = "mitm"))]
            {
                Ok(())
            }
            #[cfg(feature = "mitm")]
            {
                finish_h3_connect_mitm(H3ConnectMitmFinish {
                    req_stream,
                    client_prefetch,
                    server,
                    handler,
                    conn,
                    host,
                    port,
                    client_hello,
                    upstream_timeout,
                    tunnel_idle_timeout,
                    listener_trust,
                })
                .await
            }
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {
            if let Err(err) = relay_h3_connect_stream(
                req_stream,
                client_prefetch,
                server.ok_or_else(|| anyhow!("HTTP/3 CONNECT tunnel upstream missing"))?,
                tunnel_idle_timeout,
            )
            .await
            {
                warn!(error = ?err, "forward HTTP/3 CONNECT relay failed");
            }
            Ok(())
        }
    }
}

#[cfg(feature = "mitm")]
struct H3ConnectMitmFinish {
    req_stream: H3ServerRequestStream,
    client_prefetch: bytes::Bytes,
    server: Option<TunnelIo>,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
    host: String,
    port: u16,
    client_hello: Option<TlsClientHelloInfo>,
    upstream_timeout: Duration,
    tunnel_idle_timeout: Duration,
    listener_trust: Option<Arc<CompiledUpstreamTlsTrust>>,
}

#[cfg(feature = "mitm")]
async fn finish_h3_connect_mitm(input: H3ConnectMitmFinish) -> Result<()> {
    let H3ConnectMitmFinish {
        req_stream,
        client_prefetch,
        server,
        handler,
        conn,
        host,
        port,
        client_hello,
        upstream_timeout,
        tunnel_idle_timeout,
        listener_trust,
    } = input;
    let state = handler.runtime.state();
    let listener_cfg = state.ingress_edge_settings(handler.listener_name.as_ref());
    let tls_inspection = listener_cfg.and_then(|l| l.tls_inspection.as_ref());
    if !tls_inspection.map(|t| t.enabled).unwrap_or(false) {
        return Ok(());
    }
    let verify_upstream = forward_connect_verify_upstream(
        &state,
        listener_cfg,
        handler.listener_name.as_ref(),
        host.as_str(),
    );
    let Some(mitm) = state.security.destination.tls.mitm.clone() else {
        return Ok(());
    };
    let upstream_tcp = server.ok_or_else(|| anyhow!("HTTP/3 CONNECT MITM upstream missing"))?;
    if let Err(err) = mitm_h3_connect_stream(MitmH3ConnectInput {
        req_stream,
        client_prefetch,
        upstream_tcp,
        runtime: handler.runtime.clone(),
        listener_name: handler.listener_name.clone(),
        remote_addr: conn.remote_addr,
        host,
        port,
        mitm_server_name: client_hello
            .as_ref()
            .and_then(|hello| hello.sni.as_deref())
            .unwrap_or("unknown")
            .to_string(),
        mitm,
        verify_upstream,
        trust: listener_trust,
        header_read_timeout: state.plan.limits.timeouts.http_header_read_timeout(),
        upstream_timeout,
        tunnel_idle_timeout,
    })
    .await
    {
        warn!(error = ?err, "forward HTTP/3 CONNECT MITM failed");
    }
    Ok(())
}
