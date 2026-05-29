use super::super::h3_body_read_timeout;
use super::super::response::{
    finalize_qpx_connect_head_response, send_qpx_response_stream,
    upstream_qpx_extended_connect_error_response,
};
use super::super::webtransport::{
    QpxWebTransportRelayContext, WebTransportFlowLimits, relay_qpx_webtransport_session,
};
use super::ForwardQpxHandler;
use crate::http3::codec::sanitize_interim_response_for_h3;
use crate::policy_context::{AuditRecord, emit_audit_log};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext, TransportScope};
use crate::runtime::RuntimeState;
use anyhow::{Result, anyhow};
use hyper::StatusCode;
use qpx_core::rules::CompiledHeaderControl;
use qpx_observability::access_log::RequestLogContext;
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(super) struct QpxWebTransportEstablishedContext<'a> {
    pub(super) handler: &'a ForwardQpxHandler,
    pub(super) state: &'a RuntimeState,
    pub(super) req_stream: qpx_h3::RequestStream,
    pub(super) conn: &'a qpx_h3::ConnectionInfo,
    pub(super) session: qpx_h3::WebTransportSession,
    pub(super) upstream: qpx_h3::ExtendedConnectStream,
    pub(super) host: &'a str,
    pub(super) audit_path: Option<&'a str>,
    pub(super) matched_rule: Option<&'a str>,
    pub(super) ext_authz_policy_id: Option<&'a str>,
    pub(super) log_context: &'a RequestLogContext,
    pub(super) response_headers: Option<&'a CompiledHeaderControl>,
    pub(super) request_limit_ctx: RateLimitContext,
    pub(super) request_limits: AppliedRateLimits,
    pub(super) rate_limit_profile: Option<&'a str>,
    pub(super) proxy_name: &'a str,
    pub(super) max_h3_response_body_bytes: usize,
    pub(super) tunnel_idle_timeout: Duration,
}

pub(super) async fn relay_established_webtransport(
    ctx: QpxWebTransportEstablishedContext<'_>,
) -> Result<()> {
    let QpxWebTransportEstablishedContext {
        handler,
        state,
        mut req_stream,
        conn,
        session,
        upstream,
        host,
        audit_path,
        matched_rule,
        ext_authz_policy_id,
        log_context,
        response_headers,
        request_limit_ctx,
        request_limits,
        rate_limit_profile,
        proxy_name,
        max_h3_response_body_bytes,
        tunnel_idle_timeout,
    } = ctx;
    let qpx_h3::WebTransportSession {
        session_id,
        opener: downstream_opener,
        datagrams: downstream_datagrams,
        bidi_streams: downstream_bidi_streams,
        uni_streams: downstream_uni_streams,
    } = session;
    let qpx_h3::ExtendedConnectStream {
        interim,
        response,
        request_stream: upstream_request,
        datagrams: upstream_datagrams,
        opener: upstream_opener,
        associated_bidi,
        associated_uni,
        _critical_streams,
        _endpoint,
        driver,
        datagram_task,
        _connection_use,
        _session,
        ..
    } = upstream;

    for interim in interim {
        let interim = sanitize_interim_response_for_h3(interim)?;
        timeout(
            h3_body_read_timeout(&handler.runtime),
            req_stream.send_response_head(&interim),
        )
        .await
        .map_err(|_| anyhow!("qpx-h3 interim response send timed out"))??;
    }
    if !response.status().is_success() {
        let response = upstream_qpx_extended_connect_error_response(
            response,
            upstream_request,
            proxy_name,
            response_headers,
            h3_body_read_timeout(&handler.runtime),
        )?;
        send_qpx_response_stream(
            &mut req_stream,
            response,
            &http::Method::CONNECT,
            max_h3_response_body_bytes,
            h3_body_read_timeout(&handler.runtime),
        )
        .await?;
        abort_webtransport_driver(datagram_task, driver).await;
        return Ok(());
    }

    let established = finalize_qpx_connect_head_response(response, proxy_name, response_headers)?;
    timeout(
        tunnel_idle_timeout,
        req_stream.send_response_head(&established),
    )
    .await
    .map_err(|_| anyhow!("forward qpx-h3 extended CONNECT response send timeout"))??;
    emit_allow_audit(
        state,
        handler,
        conn,
        AllowAuditContext {
            host,
            audit_path,
            matched_rule,
            ext_authz_policy_id,
            log_context,
        },
    );

    let flow_limits =
        collect_webtransport_flow_limits(state, handler, matched_rule, rate_limit_profile)?;
    let relay_result = relay_qpx_webtransport_session(QpxWebTransportRelayContext {
        downstream_request: req_stream,
        downstream_datagrams,
        downstream_opener,
        downstream_bidi_streams,
        downstream_uni_streams,
        upstream_request,
        upstream_datagrams,
        upstream_opener: upstream_opener
            .ok_or_else(|| anyhow!("missing upstream WebTransport opener"))?,
        upstream_bidi_streams: associated_bidi
            .ok_or_else(|| anyhow!("missing upstream WebTransport bidi channel"))?,
        upstream_uni_streams: associated_uni
            .ok_or_else(|| anyhow!("missing upstream WebTransport uni channel"))?,
        session_id,
        idle_timeout: tunnel_idle_timeout,
        rate_limit_ctx: request_limit_ctx,
        request_limits,
        flow_limits,
    })
    .await;
    if let Err(err) = relay_result {
        warn!(error = ?err, "forward HTTP/3 WebTransport relay failed");
    }
    abort_webtransport_driver(datagram_task, driver).await;
    Ok(())
}

fn collect_webtransport_flow_limits(
    state: &RuntimeState,
    handler: &ForwardQpxHandler,
    matched_rule: Option<&str>,
    rate_limit_profile: Option<&str>,
) -> Result<WebTransportFlowLimits> {
    let rate_limiters = &state.policy.rate_limiters;
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule)
        .ok_or_else(|| anyhow!("compiled WebTransport execution plan not found"))?;
    Ok(WebTransportFlowLimits {
        bidi: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportBidi,
        )?,
        bidi_downstream: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportBidiDownstream,
        )?,
        bidi_upstream: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportBidiUpstream,
        )?,
        uni: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportUni,
        )?,
        uni_downstream: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportUniDownstream,
        )?,
        uni_upstream: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportUniUpstream,
        )?,
        datagram: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportDatagram,
        )?,
        datagram_downstream: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportDatagramDownstream,
        )?,
        datagram_upstream: rate_limiters.collect_plan_with_profile(
            &selected_plan.rate_limits,
            rate_limit_profile,
            TransportScope::WebtransportDatagramUpstream,
        )?,
    })
}

struct AllowAuditContext<'a> {
    host: &'a str,
    audit_path: Option<&'a str>,
    matched_rule: Option<&'a str>,
    ext_authz_policy_id: Option<&'a str>,
    log_context: &'a RequestLogContext,
}

fn emit_allow_audit(
    state: &RuntimeState,
    handler: &ForwardQpxHandler,
    conn: &qpx_h3::ConnectionInfo,
    ctx: AllowAuditContext<'_>,
) {
    emit_audit_log(
        state,
        AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Forward,
            name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            host: Some(ctx.host),
            sni: Some(ctx.host),
            method: Some("CONNECT"),
            path: ctx.audit_path,
            outcome: crate::http::dispatch::DispatchOutcome::Allow,
            status: Some(StatusCode::OK.as_u16()),
            matched_rule: ctx.matched_rule,
            matched_route: None,
            ext_authz_policy_id: ctx.ext_authz_policy_id,
        },
        ctx.log_context,
    );
}

async fn abort_webtransport_driver(
    datagram_task: Option<tokio::task::JoinHandle<()>>,
    driver: tokio::task::JoinHandle<()>,
) {
    if let Some(task) = datagram_task {
        task.abort();
        let _ = task.await;
    }
    let _ = driver.await;
}
