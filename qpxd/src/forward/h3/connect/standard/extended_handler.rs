use super::super::super::backend_h3::ForwardH3Handler;
use super::extended::{
    OpenUpstreamExtendedConnectInput, UpstreamExtendedConnectStream,
    finalize_h3_connect_head_response, open_upstream_extended_connect_stream,
    relay_h3_extended_connect_stream, upstream_extended_connect_error_response,
};
use super::{
    H3ConnectPreparation, H3PolicyResponseContext, PreparedH3Connect, prepare_h3_connect_request,
    send_h3_policy_response,
};
use crate::forward::connect::listener_upstream_trust;
use crate::http::body::Body;
use crate::http::protocol::common::{
    blocked_response as blocked, too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::http3::datagram::H3StreamDatagrams;
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::{H3ServerRequestStream, send_h3_response, send_h3_static_response};
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::ActionKind;
use tokio::time::Duration;
use tracing::warn;

pub(crate) async fn handle_h3_extended_connect(
    req_head: ::http::Request<()>,
    mut req_stream: H3ServerRequestStream,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
    protocol: ::h3::ext::Protocol,
    datagrams: Option<H3StreamDatagrams>,
) -> Result<()> {
    if protocol == ::h3::ext::Protocol::WEB_TRANSPORT {
        send_h3_static_response(
            &mut req_stream,
            ::http::StatusCode::NOT_IMPLEMENTED,
            b"WEBTRANSPORT relay requires the http3-backend-qpx build",
            &http::Method::CONNECT,
            handler.runtime.state().plan.identity.proxy_name.as_ref(),
            handler
                .runtime
                .state()
                .plan
                .limits
                .body
                .max_h3_response_body_bytes,
        )
        .await?;
        return Ok(());
    }
    let prepared = match prepare_h3_connect_request(
        &req_head,
        &mut req_stream,
        &handler,
        &conn,
        None,
    )
    .await?
    {
        H3ConnectPreparation::Continue(prepared) => *prepared,
        H3ConnectPreparation::Responded => return Ok(()),
    };

    let state = handler.runtime.state();
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms.max(1));
    let proxy_name = state.plan.identity.proxy_name.to_string();
    let PreparedH3Connect {
        host,
        port: _,
        action,
        response_headers,
        log_context,
        matched_rule,
        ext_authz_policy_id,
        audit_path,
        timeout_override,
        rate_limit_profile,
        rate_limit_context,
        sanitized_headers,
        ..
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
        ($req_stream:expr, $response:expr, $outcome:expr) => {
            send_h3_policy_response(
                $req_stream,
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

    if !matches!(
        action.kind,
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
    ) {
        let response = finalize_response_with_headers(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            proxy_name.as_str(),
            blocked(state.messages.blocked.as_str()),
            response_headers.as_deref(),
            false,
        );
        send_policy!(
            &mut req_stream,
            response,
            crate::http::dispatch::DispatchOutcome::Block
        )
        .await?;
        return Ok(());
    }

    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_context) {
        Some(permits) => permits,
        None => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                too_many_requests(None),
                response_headers.as_deref(),
                false,
            );
            send_policy!(
                &mut req_stream,
                response,
                crate::http::dispatch::DispatchOutcome::ConcurrencyLimited
            )
            .await?;
            return Ok(());
        }
    };

    let verify_upstream = state
        .ingress_edge_settings(handler.listener_name.as_ref())
        .and_then(|listener| listener.tls_inspection.as_ref())
        .map(|cfg| {
            cfg.verify_upstream
                && !state
                    .tls_verify_exception_matches(handler.listener_name.as_ref(), host.as_str())
        })
        .unwrap_or(true);
    let listener_trust = state
        .ingress_edge_settings(handler.listener_name.as_ref())
        .map(listener_upstream_trust)
        .transpose()?
        .flatten();

    let upstream = match open_upstream_extended_connect_stream(OpenUpstreamExtendedConnectInput {
        req_head: &req_head,
        sanitized_headers: &sanitized_headers,
        proxy_name: proxy_name.as_str(),
        upstream: action.upstream.as_deref(),
        verify_upstream,
        trust: listener_trust.as_deref(),
        protocol,
        enable_datagram: datagrams.is_some(),
        datagram_channel_capacity: state.plan.limits.h3.datagram_channel_capacity,
        timeout_dur: upstream_timeout,
    })
    .await
    {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(error = ?err, protocol = ?protocol, "forward HTTP/3 extended CONNECT establish failed");
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(state.messages.proxy_error.clone()))?,
                response_headers.as_deref(),
                false,
            );
            send_policy!(
                &mut req_stream,
                response,
                crate::http::dispatch::DispatchOutcome::Error
            )
            .await?;
            return Ok(());
        }
    };

    let UpstreamExtendedConnectStream {
        interim,
        response,
        req_stream: upstream_stream,
        datagrams: upstream_datagrams,
        _endpoint,
        driver,
        datagram_task,
        ..
    } = upstream;
    for interim in interim {
        let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
        tokio::time::timeout(tunnel_idle_timeout, req_stream.send_response(interim))
            .await
            .map_err(|_| anyhow!("HTTP/3 extended CONNECT interim response send timed out"))??;
    }
    if !response.status().is_success() {
        let response = upstream_extended_connect_error_response(
            response,
            upstream_stream,
            proxy_name.as_str(),
            response_headers.as_deref(),
            Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
        )?;
        send_h3_response(
            response,
            &http::Method::CONNECT,
            &mut req_stream,
            state.plan.limits.body.max_h3_response_body_bytes,
            Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
        )
        .await?;
        if let Some(task) = datagram_task {
            task.abort();
            let _ = task.await;
        }
        let _ = driver.await;
        return Ok(());
    }

    let established = finalize_h3_connect_head_response(
        response,
        proxy_name.as_str(),
        response_headers.as_deref(),
    )?;
    tokio::time::timeout(tunnel_idle_timeout, req_stream.send_response(established))
        .await
        .map_err(|_| anyhow!("forward HTTP/3 extended CONNECT response send timeout"))??;
    if let Err(err) = relay_h3_extended_connect_stream(
        req_stream,
        datagrams,
        upstream_stream,
        upstream_datagrams,
        tunnel_idle_timeout,
    )
    .await
    {
        warn!(error = ?err, protocol = ?protocol, "forward HTTP/3 extended CONNECT relay failed");
    }
    if let Some(task) = datagram_task {
        task.abort();
        let _ = task.await;
    }
    let _ = driver.await;
    Ok(())
}
