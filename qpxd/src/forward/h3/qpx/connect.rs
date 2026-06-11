use super::ForwardQpxHandler;
use super::connect_upstream::{
    OpenUpstreamQpxExtendedConnectInput, build_qpx_connect_success_head,
    open_upstream_qpx_extended_connect_stream,
};
use super::relay::relay_qpx_extended_connect_stream;
use super::response::{
    QpxPolicyResponseContext, finalize_qpx_connect_head_response, send_qpx_policy_response,
    send_qpx_response_stream, send_qpx_static_response,
    upstream_qpx_extended_connect_error_response,
};
use crate::forward::request::resolve_upstream;
use crate::http::dispatch::{DispatchOutcome, ProxyKind};
use crate::http::protocol::common::{
    blocked_response as blocked, too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::policy_context::{AuditRecord, emit_audit_log};
use crate::rate_limit::TransportScope;
use crate::upstream::connect::connect_tunnel_target;
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::ActionKind;
use qpx_http::body::Body;
use tokio::time::{Duration, timeout};
use tracing::warn;

mod prepare;
mod udp;

use self::prepare::{PrepareQpxConnectInput, PreparedQpxConnect, prepare_qpx_connect_request};
pub(super) async fn handle_qpx_connect_stream(
    handler: &ForwardQpxHandler,
    req_head: http::Request<()>,
    mut req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
    protocol: qpx_h3::Protocol,
    datagrams: Option<qpx_h3::StreamDatagrams>,
) -> Result<()> {
    let prepared = match prepare_qpx_connect_request(PrepareQpxConnectInput {
        req_head: &req_head,
        req_stream: &mut req_stream,
        handler,
        conn: &conn,
        protocol: Some(&protocol),
        connect_udp_cfg: Some(&handler.connect_udp),
    })
    .await?
    {
        Some(prepared) => *prepared,
        None => return Ok(()),
    };

    match protocol {
        qpx_h3::Protocol::ConnectUdp => {
            udp::run_connect_udp_relay(handler, prepared, req_stream, conn, datagrams).await
        }
        qpx_h3::Protocol::Other(protocol_name) => {
            handle_qpx_extended_connect_stream(
                handler,
                prepared,
                req_head,
                req_stream,
                conn,
                protocol_name,
                datagrams,
            )
            .await
        }
        qpx_h3::Protocol::WebTransport => {
            send_qpx_static_response(
                &mut req_stream,
                StatusCode::NOT_IMPLEMENTED,
                b"WEBTRANSPORT is handled by the dedicated relay path",
                &http::Method::CONNECT,
                handler.runtime.state().plan.identity.proxy_name.as_ref(),
            )
            .await
        }
    }
}

pub(super) async fn handle_qpx_traditional_connect_stream(
    handler: &ForwardQpxHandler,
    req_head: http::Request<()>,
    mut req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
) -> Result<()> {
    let prepared = match prepare_qpx_connect_request(PrepareQpxConnectInput {
        req_head: &req_head,
        req_stream: &mut req_stream,
        handler,
        conn: &conn,
        protocol: None,
        connect_udp_cfg: None,
    })
    .await?
    {
        Some(prepared) => *prepared,
        None => return Ok(()),
    };
    run_qpx_traditional_connect_tunnel(handler, prepared, req_stream, conn).await
}

async fn run_qpx_traditional_connect_tunnel(
    handler: &ForwardQpxHandler,
    prepared: PreparedQpxConnect,
    mut req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
) -> Result<()> {
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.to_string();
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
        rate_limit_context,
        ..
    } = prepared;
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled qpx-h3 CONNECT execution plan not found"))?;
    let matched_rule_name = matched_rule.as_deref();
    let request_limits = state.policy.rate_limiters.collect_plan_with_profile(
        &selected_plan.rate_limits,
        rate_limit_profile.as_deref(),
        TransportScope::Connect,
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
                    matched_rule: matched_rule_name,
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
        };
    }

    if !matches!(
        action.kind,
        ActionKind::Inspect | ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
    ) {
        let response = finalize_response_with_headers(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            proxy_name.as_str(),
            blocked(state.messages.blocked.as_str()),
            response_headers.as_deref(),
            false,
        );
        send_policy!(&mut req_stream, response, DispatchOutcome::Block).await?;
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
                DispatchOutcome::ConcurrencyLimited
            )
            .await?;
            return Ok(());
        }
    };

    let upstream = match resolve_upstream(&action, &state, handler.listener_name.as_ref()) {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT upstream resolution failed");
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
            send_policy!(&mut req_stream, response, DispatchOutcome::Error).await?;
            return Ok(());
        }
    };
    let server = match connect_tunnel_target(
        host.as_str(),
        port,
        upstream.as_ref(),
        proxy_name.as_str(),
        upstream_timeout,
    )
    .await
    {
        Ok(server) => server,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT establish failed");
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
            send_policy!(&mut req_stream, response, DispatchOutcome::Error).await?;
            return Ok(());
        }
    };

    let response =
        build_qpx_connect_success_head(proxy_name.as_str(), false, response_headers.as_deref())?;
    timeout(
        Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
        req_stream.send_response_head(&response),
    )
    .await
    .map_err(|_| anyhow!("qpx-h3 CONNECT response head send timed out"))??;
    emit_audit_log(
        &state,
        AuditRecord {
            kind: ProxyKind::Forward,
            name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            outcome: DispatchOutcome::Allow,
            status: Some(StatusCode::OK.as_u16()),
            matched_rule: matched_rule_name,
            matched_route: None,
            ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        },
        &log_context,
    );

    let (client_write, client_read) = req_stream.split();
    let (server_read, server_write) = tokio::io::split(server.io);
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms.max(1));
    if let Err(err) = crate::tunnel::relay_tunnel(
        client_read,
        client_write,
        server_read,
        server_write,
        crate::tunnel::TunnelPolicy::h3(
            Some(tunnel_idle_timeout),
            "qpx_h3_connect",
            handler.listener_name.clone(),
        ),
    )
    .await
    {
        warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT relay failed");
    }
    Ok(())
}

async fn handle_qpx_extended_connect_stream(
    handler: &ForwardQpxHandler,
    prepared: PreparedQpxConnect,
    req_head: http::Request<()>,
    mut req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
    protocol_name: String,
    datagrams: Option<qpx_h3::StreamDatagrams>,
) -> Result<()> {
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.to_string();
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms.max(1));
    let PreparedQpxConnect {
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
    } = prepared;
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled qpx-h3 CONNECT execution plan not found"))?;
    let matched_rule_name = matched_rule.as_deref();
    let request_limits = state.policy.rate_limiters.collect_plan_with_profile(
        &selected_plan.rate_limits,
        rate_limit_profile.as_deref(),
        TransportScope::Connect,
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
                    matched_rule: matched_rule_name,
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
        send_policy!(&mut req_stream, response, DispatchOutcome::Block).await?;
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
                DispatchOutcome::ConcurrencyLimited
            )
            .await?;
            return Ok(());
        }
    };

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
    let upstream = match open_upstream_qpx_extended_connect_stream(
        &state.pools,
        OpenUpstreamQpxExtendedConnectInput {
            req_head: &req_head,
            sanitized_headers: &sanitized_headers,
            proxy_name: proxy_name.as_str(),
            upstream: action.upstream.as_deref(),
            verify_upstream,
            trust: listener_trust.as_deref(),
            protocol: qpx_h3::Protocol::Other(protocol_name),
            enable_datagram: datagrams.is_some(),
            timeout_dur: upstream_timeout,
        },
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 extended CONNECT establish failed");
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
            send_policy!(&mut req_stream, response, DispatchOutcome::Error).await?;
            return Ok(());
        }
    };

    finish_qpx_extended_connect_stream(FinishQpxExtendedConnectInput {
        state: &state,
        handler,
        req_stream,
        conn: &conn,
        datagrams,
        upstream,
        proxy_name: proxy_name.as_str(),
        host: host.as_str(),
        response_headers: response_headers.as_deref(),
        audit_path: audit_path.as_deref(),
        matched_rule: matched_rule_name,
        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        log_context: &log_context,
        tunnel_idle_timeout,
    })
    .await
}

struct FinishQpxExtendedConnectInput<'a> {
    state: &'a crate::runtime::RuntimeState,
    handler: &'a ForwardQpxHandler,
    req_stream: qpx_h3::RequestStream,
    conn: &'a qpx_h3::ConnectionInfo,
    datagrams: Option<qpx_h3::StreamDatagrams>,
    upstream: qpx_h3::ExtendedConnectStream,
    proxy_name: &'a str,
    host: &'a str,
    response_headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    audit_path: Option<&'a str>,
    matched_rule: Option<&'a str>,
    ext_authz_policy_id: Option<&'a str>,
    log_context: &'a qpx_observability::access_log::RequestLogContext,
    tunnel_idle_timeout: Duration,
}

async fn finish_qpx_extended_connect_stream(
    input: FinishQpxExtendedConnectInput<'_>,
) -> Result<()> {
    let FinishQpxExtendedConnectInput {
        state,
        handler,
        mut req_stream,
        conn,
        datagrams,
        upstream,
        proxy_name,
        host,
        response_headers,
        audit_path,
        matched_rule,
        ext_authz_policy_id,
        log_context,
        tunnel_idle_timeout,
    } = input;
    let qpx_h3::ExtendedConnectStream {
        interim,
        response,
        request_stream: upstream_stream,
        datagrams: upstream_datagrams,
        driver,
        datagram_task,
        ..
    } = upstream;
    let h3_timeout = Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1));
    for interim in interim {
        let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
        timeout(h3_timeout, req_stream.send_response_head(&interim))
            .await
            .map_err(|_| anyhow!("qpx-h3 interim response send timed out"))??;
    }
    if !response.status().is_success() {
        let response = upstream_qpx_extended_connect_error_response(
            response,
            upstream_stream,
            proxy_name,
            response_headers,
            h3_timeout,
        )?;
        send_qpx_response_stream(
            &mut req_stream,
            response,
            &http::Method::CONNECT,
            state.plan.limits.body.max_h3_response_body_bytes,
            h3_timeout,
        )
        .await?;
        abort_qpx_extended_driver(datagram_task, driver).await;
        return Ok(());
    }

    let established = finalize_qpx_connect_head_response(response, proxy_name, response_headers)?;
    timeout(h3_timeout, req_stream.send_response_head(&established))
        .await
        .map_err(|_| anyhow!("qpx-h3 CONNECT response head send timed out"))??;
    emit_audit_log(
        state,
        AuditRecord {
            kind: ProxyKind::Forward,
            name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            host: Some(host),
            sni: Some(host),
            method: Some("CONNECT"),
            path: audit_path,
            outcome: DispatchOutcome::Allow,
            status: Some(StatusCode::OK.as_u16()),
            matched_rule,
            matched_route: None,
            ext_authz_policy_id,
        },
        log_context,
    );
    if let Err(err) = relay_qpx_extended_connect_stream(
        req_stream,
        datagrams,
        upstream_stream,
        upstream_datagrams,
        tunnel_idle_timeout,
    )
    .await
    {
        warn!(error = ?err, "forward HTTP/3 qpx-h3 extended CONNECT relay failed");
    }
    abort_qpx_extended_driver(datagram_task, driver).await;
    Ok(())
}

async fn abort_qpx_extended_driver(
    datagram_task: Option<tokio::task::JoinHandle<()>>,
    driver: tokio::task::JoinHandle<()>,
) {
    if let Some(task) = datagram_task {
        task.abort();
        let _ = task.await;
    }
    let _ = driver.await;
}
