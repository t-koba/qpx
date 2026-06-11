use super::super::ForwardQpxHandler;
use super::super::connect_upstream::{
    build_qpx_connect_success_head, open_upstream_qpx_connect_udp_stream,
};
use super::super::relay::{relay_qpx_connect_udp_stream, relay_qpx_connect_udp_stream_chained};
use super::super::response::{QpxPolicyResponseContext, send_qpx_policy_response};
use super::prepare::PreparedQpxConnect;
use crate::forward::request::resolve_upstream_url;
use crate::http::dispatch::{DispatchOutcome, ProxyKind};
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::policy_context::{AuditRecord, emit_audit_log};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext, TransportScope};
use anyhow::{Result, anyhow};
use hyper::{Response, StatusCode};
use qpx_core::config::ConnectUdpConfig;
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(super) async fn run_connect_udp_relay(
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
    let matched_rule_name = matched_rule.as_deref();
    let request_limits = state.policy.rate_limiters.collect_plan_with_profile(
        &selected_plan.rate_limits,
        rate_limit_profile.as_deref(),
        TransportScope::Http3Datagram,
    )?;
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    let success_context = ConnectUdpSuccessContext {
        state: &state,
        handler,
        conn: &conn,
        response_headers: response_headers.as_deref(),
        host: host.as_str(),
        audit_path: audit_path.as_deref(),
        matched_rule: matched_rule_name,
        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        log_context: &log_context,
        send_timeouts: (
            Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
            Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1)),
        ),
    };
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
    macro_rules! send_bad_gateway {
        ($body:expr) => {{
            let response = connect_udp_bad_gateway_response(
                proxy_name.as_str(),
                $body,
                response_headers.as_deref(),
            )?;
            send_policy!(&mut req_stream, response, DispatchOutcome::Error).await?;
            return Ok(());
        }};
    }
    let upstream = match resolve_upstream_url(&action, &state, handler.listener_name.as_ref()) {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(
                error = ?err,
                "forward HTTP/3 qpx-h3 CONNECT-UDP upstream resolution failed"
            );
            send_bad_gateway!(state.messages.proxy_error.clone());
        }
    };
    rate_limit_context.upstream = upstream.clone().or_else(|| Some(format!("{host}:{port}")));
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
                DispatchOutcome::ConcurrencyLimited
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
            &state.pools,
            &upstream,
            (host.as_str(), port),
            proxy_name.as_str(),
            verify_upstream,
            listener_trust.as_deref(),
            upstream_timeout,
        )
        .await
        {
            Ok(chain) => chain,
            Err(err) => {
                warn!(
                    error = ?err,
                    upstream = %upstream,
                    "failed to establish qpx-h3 CONNECT-UDP upstream chain"
                );
                send_bad_gateway!(state.messages.upstream_connect_udp_failed.clone());
            }
        };

        return relay_opened_chained_connect_udp(
            success_context,
            req_stream,
            datagrams,
            upstream_chain,
            connect_udp_cfg,
            rate_limit_context,
            request_limits,
        )
        .await;
    }

    let udp = match open_direct_connect_udp_socket(host.as_str(), port, upstream_timeout).await {
        Ok(udp) => udp,
        Err(_) => {
            send_bad_gateway!(state.messages.proxy_error.clone());
        }
    };

    send_connect_udp_success_head(success_context, &mut req_stream).await?;
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

struct ConnectUdpSuccessContext<'a> {
    state: &'a Arc<crate::runtime::RuntimeState>,
    handler: &'a ForwardQpxHandler,
    conn: &'a qpx_h3::ConnectionInfo,
    response_headers: Option<&'a CompiledHeaderControl>,
    host: &'a str,
    audit_path: Option<&'a str>,
    matched_rule: Option<&'a str>,
    ext_authz_policy_id: Option<&'a str>,
    log_context: &'a qpx_observability::access_log::RequestLogContext,
    send_timeouts: (Duration, Duration),
}

async fn relay_opened_chained_connect_udp(
    success_context: ConnectUdpSuccessContext<'_>,
    mut req_stream: qpx_h3::RequestStream,
    datagrams: Option<qpx_h3::StreamDatagrams>,
    upstream_chain: qpx_h3::ExtendedConnectStream,
    connect_udp_cfg: ConnectUdpConfig,
    rate_limit_context: RateLimitContext,
    request_limits: AppliedRateLimits,
) -> Result<()> {
    for interim in &upstream_chain.interim {
        let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim.clone())?;
        timeout(
            success_context.send_timeouts.0,
            req_stream.send_response_head(&interim),
        )
        .await
        .map_err(|_| anyhow!("qpx-h3 CONNECT-UDP interim response send timed out"))??;
    }
    send_connect_udp_success_head(success_context, &mut req_stream).await?;
    if let Err(err) = relay_qpx_connect_udp_stream_chained(
        req_stream,
        datagrams,
        upstream_chain.request_stream,
        upstream_chain.datagrams,
        connect_udp_cfg,
        rate_limit_context,
        request_limits,
    )
    .await
    {
        warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP chained relay failed");
    }
    if let Some(task) = upstream_chain.datagram_task {
        task.abort();
        let _ = task.await;
    }
    let _ = upstream_chain.driver.await;
    Ok(())
}

async fn open_direct_connect_udp_socket(
    host: &str,
    port: u16,
    upstream_timeout: Duration,
) -> Result<UdpSocket> {
    let target = match timeout(upstream_timeout, lookup_host((host, port))).await {
        Ok(Ok(mut addrs)) => addrs
            .next()
            .ok_or_else(|| anyhow!("CONNECT-UDP target resolution returned no addresses"))?,
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP DNS resolution failed");
            return Err(err.into());
        }
        Err(_) => return Err(anyhow!("forward HTTP/3 qpx-h3 CONNECT-UDP DNS timed out")),
    };
    let bind_addr: SocketAddr = if target.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let udp = UdpSocket::bind(bind_addr).await.map_err(|err| {
        warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP bind failed");
        err
    })?;
    match timeout(upstream_timeout, udp.connect(target)).await {
        Ok(Ok(())) => Ok(udp),
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT-UDP connect failed");
            Err(err.into())
        }
        Err(_) => Err(anyhow!(
            "forward HTTP/3 qpx-h3 CONNECT-UDP connect timed out"
        )),
    }
}

async fn send_connect_udp_success_head(
    ctx: ConnectUdpSuccessContext<'_>,
    req_stream: &mut qpx_h3::RequestStream,
) -> Result<()> {
    let proxy_name = ctx.state.plan.identity.proxy_name.as_ref();
    let response = build_qpx_connect_success_head(proxy_name, true, ctx.response_headers)?;
    emit_audit_log(
        ctx.state,
        AuditRecord {
            kind: ProxyKind::Forward,
            name: ctx.handler.listener_name.as_ref(),
            remote_ip: ctx.conn.remote_addr.ip(),
            host: Some(ctx.host),
            sni: Some(ctx.host),
            method: Some("CONNECT"),
            path: ctx.audit_path,
            outcome: DispatchOutcome::Allow,
            status: Some(StatusCode::OK.as_u16()),
            matched_rule: ctx.matched_rule,
            matched_route: None,
            ext_authz_policy_id: ctx.ext_authz_policy_id,
        },
        ctx.log_context,
    );
    timeout(
        ctx.send_timeouts.1,
        req_stream.send_response_head(&response),
    )
    .await
    .map_err(|_| anyhow!("forward qpx-h3 CONNECT-UDP response send timeout"))??;
    Ok(())
}

fn connect_udp_bad_gateway_response(
    proxy_name: &str,
    body: String,
    response_headers: Option<&CompiledHeaderControl>,
) -> Result<Response<Body>> {
    Ok(finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(body))?,
        response_headers,
        false,
    ))
}
