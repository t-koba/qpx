use super::super::super::backend_h3::ForwardH3Handler;
use super::{
    H3ConnectPreparation, H3PolicyResponseContext, build_h3_connect_success_response,
    normalize_h3_upstream_connect_headers, prepare_h3_connect_request,
    recv_upstream_h3_response_with_interim, send_h3_policy_response,
};
mod chained;
mod upstream;

use self::chained::{apply_connect_udp_bandwidth_controls, relay_h3_connect_udp_stream_chained};
use self::upstream::{UpstreamConnectUdpParams, open_upstream_connect_udp_stream};
use crate::http::body::Body;
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::http3::capsule::{
    CapsuleBuffer, decode_quic_varint, encode_datagram_capsule_context_header,
};
use crate::http3::datagram::H3StreamDatagrams;
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::H3ServerRequestStream;
use crate::policy_context::{AuditRecord, emit_audit_log};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use hyper::{Response, StatusCode};
use qpx_core::config::ConnectUdpConfig;
use std::net::SocketAddr;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::{Duration, timeout};
use tracing::warn;

pub(in crate::forward::h3) async fn handle_h3_connect_udp(
    req_head: ::http::Request<()>,
    mut req_stream: H3ServerRequestStream,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
    datagrams: Option<H3StreamDatagrams>,
) -> Result<()> {
    let connect_udp_cfg = handler.connect_udp.clone();
    let prepared = match prepare_h3_connect_request(
        &req_head,
        &mut req_stream,
        &handler,
        &conn,
        Some(&connect_udp_cfg),
    )
    .await?
    {
        H3ConnectPreparation::Continue(prepared) => *prepared,
        H3ConnectPreparation::Responded => return Ok(()),
    };

    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.to_string();
    let super::PreparedH3Connect {
        authority: _authority,
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
        .ok_or_else(|| anyhow!("compiled HTTP/3 CONNECT-UDP execution plan not found"))?;
    let request_limits = state.policy.rate_limiters.collect_plan_with_profile(
        &selected_plan.rate_limits,
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Http3Datagram,
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
    let upstream = match crate::forward::request::resolve_upstream_url(
        &action,
        &state,
        handler.listener_name.as_ref(),
    ) {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(
                error = ?err,
                "forward HTTP/3 CONNECT-UDP upstream resolution failed"
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
            send_policy!(response, crate::http::dispatch::DispatchOutcome::Error).await?;
            return Ok(());
        }
    };
    rate_limit_context.upstream = upstream
        .clone()
        .or_else(|| Some(format!("{}:{}", host, port)));
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
                response,
                crate::http::dispatch::DispatchOutcome::ConcurrencyLimited
            )
            .await?;
            return Ok(());
        }
    };

    if let Some(upstream) = upstream {
        let listener_trust = state
            .ingress_edge_settings(handler.listener_name.as_ref())
            .map(crate::forward::connect::listener_upstream_trust)
            .transpose()?
            .flatten();
        let upstream_params = UpstreamConnectUdpParams {
            upstream: &upstream,
            target_host: host.as_str(),
            target_port: port,
            proxy_name: proxy_name.as_str(),
            verify_upstream: state
                .ingress_edge_settings(handler.listener_name.as_ref())
                .and_then(|listener| listener.tls_inspection.as_ref())
                .map(|cfg| {
                    cfg.verify_upstream
                        && !state.tls_verify_exception_matches(
                            handler.listener_name.as_ref(),
                            host.as_str(),
                        )
                })
                .unwrap_or(true),
            trust: listener_trust.as_deref(),
            timeout_dur: upstream_timeout,
            datagram_channel_capacity: state.plan.limits.h3.datagram_channel_capacity,
        };
        let mut upstream_chain = match open_upstream_connect_udp_stream(upstream_params).await {
            Ok(chain) => chain,
            Err(err) => {
                let upstream_target =
                    crate::forward::connect::udp_upstream::parse_connect_udp_upstream(&upstream)
                        .ok()
                        .map(|(host, port)| format!("{}:{}", host, port))
                        .unwrap_or_else(|| "<invalid>".to_string());
                warn!(
                    error = ?err,
                    upstream = %upstream_target,
                    "failed to establish CONNECT-UDP upstream chain"
                );
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
                send_policy!(response, crate::http::dispatch::DispatchOutcome::Error).await?;
                return Ok(());
            }
        };

        for interim in upstream_chain.interim.drain(..) {
            let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
            timeout(
                Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
                req_stream.send_response(interim),
            )
            .await
            .map_err(|_| anyhow!("CONNECT-UDP interim response send timed out"))??;
        }

        let response = build_h3_connect_success_response(
            proxy_name.as_str(),
            &http::Method::CONNECT,
            true,
            response_headers.as_deref(),
        )?;
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
        timeout(response_send_timeout, req_stream.send_response(response))
            .await
            .map_err(|_| anyhow!("forward HTTP/3 CONNECT-UDP response send timeout"))??;

        let relay_result = relay_h3_connect_udp_stream_chained(
            req_stream,
            datagrams,
            upstream_chain.req_stream,
            upstream_chain.datagrams,
            connect_udp_cfg,
            rate_limit_context.clone(),
            request_limits.clone(),
        )
        .await;

        upstream_chain.driver.abort();
        let _ = upstream_chain.driver.await;
        upstream_chain.datagram_task.abort();
        let _ = upstream_chain.datagram_task.await;
        return relay_result;
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
                send_policy!(response, crate::http::dispatch::DispatchOutcome::Error).await?;
                return Ok(());
            }
        },
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT-UDP DNS resolution failed");
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
            send_policy!(response, crate::http::dispatch::DispatchOutcome::Error).await?;
            return Ok(());
        }
        Err(_) => {
            warn!("forward HTTP/3 CONNECT-UDP DNS resolution timed out");
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
            send_policy!(response, crate::http::dispatch::DispatchOutcome::Error).await?;
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
            warn!(error = ?err, "forward HTTP/3 CONNECT-UDP bind failed");
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
            send_policy!(response, crate::http::dispatch::DispatchOutcome::Error).await?;
            return Ok(());
        }
    };
    match timeout(upstream_timeout, udp.connect(target)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT-UDP connect failed");
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
            send_policy!(response, crate::http::dispatch::DispatchOutcome::Error).await?;
            return Ok(());
        }
        Err(_) => {
            warn!("forward HTTP/3 CONNECT-UDP connect timed out");
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
            send_policy!(response, crate::http::dispatch::DispatchOutcome::Error).await?;
            return Ok(());
        }
    }

    let response = build_h3_connect_success_response(
        proxy_name.as_str(),
        &http::Method::CONNECT,
        true,
        response_headers.as_deref(),
    )?;
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
    timeout(response_send_timeout, req_stream.send_response(response))
        .await
        .map_err(|_| anyhow!("forward HTTP/3 CONNECT-UDP response send timeout"))??;

    if let Err(err) = relay_h3_connect_udp_stream(
        req_stream,
        udp,
        connect_udp_cfg,
        datagrams,
        rate_limit_context,
        request_limits,
    )
    .await
    {
        warn!(error = ?err, "forward HTTP/3 CONNECT-UDP relay failed");
    }
    Ok(())
}

async fn relay_h3_connect_udp_stream(
    req_stream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    udp: UdpSocket,
    connect_udp_cfg: ConnectUdpConfig,
    mut datagrams: Option<H3StreamDatagrams>,
    rate_limit_ctx: RateLimitContext,
    request_limits: AppliedRateLimits,
) -> Result<()> {
    let (mut req_send, mut req_recv) = req_stream.split();
    let idle_timeout = Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1));
    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let mut capsule_buf = CapsuleBuffer::new();
    let mut udp_buf = BytesMut::with_capacity(65_536);
    udp_buf.extend_from_slice(&[0]); // CONNECT-UDP context id = 0

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = req_recv.recv_data() => {
                match recv? {
                    Some(mut bytes) => {
                        let remaining = bytes.remaining();
                        let bytes = bytes.copy_to_bytes(remaining);
                        capsule_buf.push(bytes, connect_udp_cfg.max_capsule_buffer_bytes)?;
                        while let Some((capsule_type, payload)) = capsule_buf.take_next()? {
                            if capsule_type != 0 {
                                continue;
                            }
                            let (context_id, offset) = match decode_quic_varint(payload.as_ref()) {
                                Some(v) => v,
                                None => continue,
                            };
                            if context_id != 0 || offset > payload.len() {
                                continue;
                            }
                            apply_connect_udp_bandwidth_controls(
                                &rate_limit_ctx,
                                &request_limits,
                                payload.len().saturating_sub(offset),
                            )
                            .await?;
                            udp.send(&payload[offset..]).await?;
                        }
                        idle_deadline
                            .as_mut()
                            .reset(crate::runtime::tokio_deadline_after(idle_timeout));
                    }
                    None => break,
                }
            }
            payload = async {
                if let Some(datagrams) = datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = payload else {
                    break;
                };
                let (context_id, offset) = match decode_quic_varint(payload.as_ref()) {
                    Some(v) => v,
                    None => continue,
                };
                if context_id != 0 || offset > payload.len() {
                    continue;
                }
                apply_connect_udp_bandwidth_controls(
                    &rate_limit_ctx,
                    &request_limits,
                    payload.len().saturating_sub(offset),
                )
                .await?;
                udp.send(&payload[offset..]).await?;
                idle_deadline
                    .as_mut()
                    .reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            recv = udp.recv_buf(&mut udp_buf) => {
                let read_len = recv?;
                if read_len == 0 {
                    udp_buf.truncate(1);
                    continue;
                }
                let datagram_payload = udp_buf.split_to(read_len + 1).freeze();
                let payload_len = datagram_payload.len().saturating_sub(1);
                let stream_payload = datagram_payload.slice(1..);
                if udp_buf.capacity() < 65_536 {
                    udp_buf.reserve(65_536 - udp_buf.capacity());
                }
                udp_buf.extend_from_slice(&[0]);
                apply_connect_udp_bandwidth_controls(&rate_limit_ctx, &request_limits, payload_len).await?;
                let mut sent = false;
                if let Some(datagrams) = datagrams.as_mut()
                    && datagrams.sender.send_datagram(datagram_payload).is_ok()
                {
                    sent = true;
                }
                if !sent {
                    let header = encode_datagram_capsule_context_header(payload_len)?;
                    timeout(idle_timeout, req_send.send_data(header))
                        .await
                        .map_err(|_| anyhow!("CONNECT-UDP capsule send timed out"))??;
                    timeout(
                        idle_timeout,
                        req_send.send_data(stream_payload),
                    )
                    .await
                    .map_err(|_| anyhow!("CONNECT-UDP capsule payload send timed out"))??;
                }
                idle_deadline
                    .as_mut()
                    .reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
        }
    }

    timeout(idle_timeout, req_send.finish())
        .await
        .map_err(|_| anyhow!("CONNECT-UDP stream finish timed out"))??;
    Ok(())
}
