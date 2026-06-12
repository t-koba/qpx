use super::super::super::backend_h3::ForwardH3Handler;
use super::established::{EstablishedH3Connect, finish_h3_connect};
use super::{
    H3PolicyResponseContext, PreparedH3Connect, prepare_h3_connect_request, send_h3_policy_response,
};
use crate::http::dispatch::DispatchOutcome;
use crate::http::protocol::common::{
    blocked_response as blocked, too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::H3ServerRequestStream;
use crate::upstream::connect::connect_tunnel_target;
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::ActionKind;
use qpx_http::body::Body;
use tokio::time::Duration;
use tracing::warn;

pub(crate) async fn handle_h3_connect(
    req_head: ::http::Request<()>,
    mut req_stream: H3ServerRequestStream,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
) -> Result<()> {
    let prepared = match prepare_h3_connect_request(
        &req_head,
        &mut req_stream,
        &handler,
        &conn,
        None,
    )
    .await?
    {
        Some(prepared) => *prepared,
        None => return Ok(()),
    };

    let state = handler.runtime.state();
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms.max(1));
    let proxy_name = state.plan.identity.proxy_name.to_string();
    let PreparedH3Connect {
        authority,
        host,
        port,
        action,
        response_headers,
        log_context,
        matched_rule,
        ext_authz_policy_id,
        audit_path,
        timeout_override,
        rate_limit_profile,
        mut rate_limit_context,
        sanitized_headers,
        identity,
    } = prepared;
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled HTTP/3 CONNECT execution plan not found"))?;
    let request_limits = state.policy.rate_limiters.collect_plan_with_profile(
        &selected_plan.rate_limits,
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Connect,
    )?;
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    macro_rules! send_policy {
        ($response:expr, $outcome:expr) => {
            send_h3_policy_response(
                &mut req_stream,
                $response,
                H3PolicyResponseContext {
                    request_method: &http::Method::CONNECT,
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn: &conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: $outcome,
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
        };
    }
    macro_rules! send_finalized {
        ($base:expr, $outcome:expr) => {
            send_policy!(
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    $base,
                    response_headers.as_deref(),
                    false,
                ),
                $outcome
            )
        };
    }
    macro_rules! send_blocked {
        () => {
            send_finalized!(
                blocked(state.messages.blocked.as_str()),
                DispatchOutcome::Block
            )
        };
    }
    match action.kind {
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy | ActionKind::Inspect => {}
        _ => {
            send_blocked!().await?;
            return Ok(());
        }
    }
    if matches!(action.kind, ActionKind::Inspect) {
        #[cfg(not(feature = "mitm"))]
        {
            send_blocked!().await?;
            return Ok(());
        }

        #[cfg(feature = "mitm")]
        {
            let tls_inspection = state
                .ingress_edge_settings(handler.listener_name.as_ref())
                .and_then(|l| l.tls_inspection.as_ref());
            if !tls_inspection.map(|t| t.enabled).unwrap_or(false) {
                send_blocked!().await?;
                return Ok(());
            }
            if state.security.destination.tls.mitm.is_none() {
                send_blocked!().await?;
                return Ok(());
            }
        }
    }

    let upstream = match crate::forward::request::resolve_upstream(
        &action,
        &state,
        handler.listener_name.as_ref(),
    ) {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT upstream resolution failed");
            send_finalized!(
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(state.messages.proxy_error.clone()))?,
                DispatchOutcome::Error
            )
            .await?;
            return Ok(());
        }
    };
    rate_limit_context.upstream = upstream.as_ref().map(|upstream| upstream.key().to_string());
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_context) {
        Some(permits) => permits,
        None => {
            send_finalized!(too_many_requests(None), DispatchOutcome::ConcurrencyLimited).await?;
            return Ok(());
        }
    };
    let server = match connect_tunnel_target(
        &host,
        port,
        upstream.as_ref(),
        proxy_name.as_str(),
        upstream_timeout,
    )
    .await
    {
        Ok(stream) => stream.io,
        Err(err) => {
            warn!(
                error = ?err,
                upstream = upstream.as_ref().map(|u| u.endpoint().cache_key()),
                "forward HTTP/3 CONNECT tunnel establish failed"
            );
            send_finalized!(
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(state.messages.proxy_error.clone()))?,
                DispatchOutcome::Error
            )
            .await?;
            return Ok(());
        }
    };

    finish_h3_connect(EstablishedH3Connect {
        req_stream,
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
        ext_authz_policy_id,
        audit_path,
        upstream_timeout,
        tunnel_idle_timeout,
        sanitized_headers,
        identity,
        server,
    })
    .await
}
