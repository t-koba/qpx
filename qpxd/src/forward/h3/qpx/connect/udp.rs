use super::super::ForwardQpxHandler;
use super::super::connect_upstream::{
    build_qpx_connect_success_head, open_upstream_qpx_connect_udp_stream,
};
use super::super::relay::{relay_qpx_connect_udp_stream, relay_qpx_connect_udp_stream_chained};
use super::super::response::{QpxPolicyResponseContext, send_qpx_policy_response};
use super::prepare::PreparedQpxConnect;
use crate::forward::request::resolve_upstream_url;
use crate::http::body::Body;
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::policy_context::{AuditRecord, emit_audit_log};
use crate::rate_limit::RateLimitContext;
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::ActionConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(super) async fn handle_qpx_connect_udp_stream(
    handler: &ForwardQpxHandler,
    prepared: PreparedQpxConnect,
    req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
    datagrams: Option<qpx_h3::StreamDatagrams>,
) -> Result<()> {
    run_connect_udp_relay(handler, prepared, req_stream, conn, datagrams).await
}

async fn run_connect_udp_relay(
    handler: &ForwardQpxHandler,
    prepared: PreparedQpxConnect,
    mut req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
    datagrams: Option<qpx_h3::StreamDatagrams>,
) -> Result<()> {
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.to_string();
    let connect_udp_cfg = handler.connect_udp.clone();
    let PreparedQpxConnect {
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
        ..
    } = prepared;
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled qpx-h3 CONNECT-UDP execution plan not found"))?;
    let request_limits = state.policy.rate_limiters.collect_plan_with_profile(
        &selected_plan.rate_limits,
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Http3Datagram,
    )?;
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    macro_rules! send_policy {
        ($req_stream:expr, $response:expr, $outcome:expr) => {
            send_qpx_policy_response(
                $req_stream,
                $response,
                QpxPolicyResponseContext {
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
    let upstream = match establish_connect_udp_upstream(
        &action,
        &state,
        handler.listener_name.as_ref(),
        host.as_str(),
        port,
        &mut rate_limit_context,
    ) {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(
                error = ?err,
                "forward HTTP/3 qpx-h3 CONNECT-UDP upstream resolution failed"
            );
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
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_context) {
        Some(permits) => permits,
        None => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Body::from("too many requests"))?,
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

    if let Some(upstream) = upstream {
        let listener_cfg = state
            .ingress_edge_settings(handler.listener_name.as_ref())
            .ok_or_else(|| anyhow!("listener not found"))?;
        let listener_trust = crate::forward::connect::listener_upstream_trust(listener_cfg)?;
        let verify_upstream = listener_cfg
            .tls_inspection
            .as_ref()
            .map(|cfg| {
                cfg.verify_upstream
                    && !state
                        .tls_verify_exception_matches(handler.listener_name.as_ref(), host.as_str())
            })
            .unwrap_or(true);
        let upstream_chain = match open_upstream_qpx_connect_udp_stream(
            &upstream,
            host.as_str(),
            port,
            proxy_name.as_str(),
            verify_upstream,
            listener_trust.as_deref(),
            upstream_timeout,
        )
        .await
        {
            Ok(chain) => chain,
            Err(err) => {
                let response = finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(
                            state.messages.upstream_connect_udp_failed.clone(),
                        ))?,
                    response_headers.as_deref(),
                    false,
                );
                warn!(
                    error = ?err,
                    upstream = %upstream,
                    "failed to establish qpx-h3 CONNECT-UDP upstream chain"
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

        for interim in &upstream_chain.interim {
            let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim.clone())?;
            timeout(
                Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
                req_stream.send_response_head(&interim),
            )
            .await
            .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP interim response send timed out"))??;
        }
        let response =
            build_qpx_connect_success_head(proxy_name.as_str(), true, response_headers.as_deref())?;
        emit_audit_log(
            &state,
            AuditRecord {
                kind: crate::http::dispatch::ProxyKind::Forward,
                name: handler.listener_name.as_ref(),
                remote_ip: conn.remote_addr.ip(),
                host: Some(host.as_str()),
                sni: Some(host.as_str()),
                method: Some("CONNECT"),
                path: audit_path.as_deref(),
                outcome: crate::http::dispatch::DispatchOutcome::Allow,
                status: Some(StatusCode::OK.as_u16()),
                matched_rule: matched_rule.as_deref(),
                matched_route: None,
                ext_authz_policy_id: ext_authz_policy_id.as_deref(),
            },
            &log_context,
        );
        let response_send_timeout = Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1));
        timeout(
            response_send_timeout,
            req_stream.send_response_head(&response),
        )
        .await
        .map_err(|_| anyhow!("forward qpx-h3 CONNECT-UDP response send timeout"))??;
        let relay_result = relay_qpx_connect_udp_stream_chained(
            req_stream,
            datagrams,
            upstream_chain.request_stream,
            upstream_chain.datagrams,
            connect_udp_cfg,
            rate_limit_context.clone(),
            request_limits.clone(),
        )
        .await;
        if let Err(err) = relay_result {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP chained relay failed");
        }
        if let Some(task) = upstream_chain.datagram_task {
            task.abort();
            let _ = task.await;
        }
        let _ = upstream_chain.driver.await;
        return Ok(());
    }

    let target = match timeout(upstream_timeout, lookup_host((host.as_str(), port))).await {
        Ok(Ok(mut addrs)) => match addrs.next() {
            Some(addr) => addr,
            None => {
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
        },
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP DNS resolution failed");
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
        Err(_) => {
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

    let bind_addr: SocketAddr = if target.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let udp = match UdpSocket::bind(bind_addr).await {
        Ok(udp) => udp,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP bind failed");
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
    match timeout(upstream_timeout, udp.connect(target)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP connect failed");
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
        Err(_) => {
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
    }

    let response =
        build_qpx_connect_success_head(proxy_name.as_str(), true, response_headers.as_deref())?;
    emit_audit_log(
        &state,
        AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Forward,
            name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            outcome: crate::http::dispatch::DispatchOutcome::Allow,
            status: Some(StatusCode::OK.as_u16()),
            matched_rule: matched_rule.as_deref(),
            matched_route: None,
            ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        },
        &log_context,
    );
    let response_send_timeout = Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1));
    timeout(
        response_send_timeout,
        req_stream.send_response_head(&response),
    )
    .await
    .map_err(|_| anyhow!("forward qpx-h3 CONNECT-UDP response send timeout"))??;
    if let Err(err) = relay_qpx_connect_udp_stream(
        req_stream,
        udp,
        connect_udp_cfg,
        datagrams,
        rate_limit_context,
        request_limits,
    )
    .await
    {
        warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP relay failed");
    }
    Ok(())
}

fn establish_connect_udp_upstream(
    action: &ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener_name: &str,
    host: &str,
    port: u16,
    rate_limit_context: &mut RateLimitContext,
) -> Result<Option<String>> {
    let upstream = resolve_upstream_url(action, state, listener_name)?;
    rate_limit_context.upstream = upstream.clone().or_else(|| Some(format!("{host}:{port}")));
    Ok(upstream)
}
