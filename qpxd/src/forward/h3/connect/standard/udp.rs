use super::super::super::backend_h3::ForwardH3Handler;
use super::{
    H3PolicyResponseContext, build_h3_connect_success_response,
    normalize_h3_upstream_connect_headers, prepare_h3_connect_request,
    recv_upstream_h3_response_with_interim, send_h3_policy_response,
};
mod chained;
mod upstream;

use self::chained::relay_h3_connect_udp_stream_chained;
use self::upstream::{UpstreamConnectUdpParams, open_upstream_connect_udp_stream};
use super::super::apply_connect_udp_bandwidth_controls;
use crate::http::dispatch::{DispatchOutcome, ProxyKind};
use crate::http::protocol::common::too_many_requests_response as too_many_requests;
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::http3::capsule::{
    CapsuleBuffer, decode_connect_udp_payload, encode_datagram_capsule_context_header,
};
use crate::http3::datagram::H3StreamDatagrams;
use crate::http3::h3_buf_to_bytes;
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::H3ServerRequestStream;
use crate::policy_context::{AuditRecord, emit_audit_log};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext, TransportScope};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use hyper::{Response, StatusCode};
use qpx_core::config::ConnectUdpConfig;
use qpx_http::body::Body;
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
        Some(prepared) => *prepared,
        None => return Ok(()),
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
        decision_service_policy_id,
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
    let matched_rule_name = matched_rule.as_deref();
    let mut request_limits = state.policy.rate_limiters.collect_plan_with_profile(
        &selected_plan.rate_limits,
        rate_limit_profile.as_deref(),
        TransportScope::Http3Datagram,
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
                    matched_rule: matched_rule_name,
                    decision_service_policy_id: decision_service_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
        };
    }
    macro_rules! send_proxy_error {
        () => {
            send_policy!(
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name.as_str(),
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(state.messages.proxy_error.clone()))?,
                    response_headers.as_deref(),
                    false,
                ),
                DispatchOutcome::Error
            )
        };
    }
    macro_rules! send_upstream_connect_udp_failed {
        () => {
            send_policy!(
                finalize_response_with_headers(
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
                ),
                DispatchOutcome::Error
            )
        };
    }
    macro_rules! send_concurrency_limited {
        ($retry_after:expr) => {{
            let retry_after = $retry_after;
            let mut response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name.as_str(),
                too_many_requests(retry_after),
                response_headers.as_deref(),
                false,
            );
            request_limits.apply_rate_limit_fields(response.headers_mut(), retry_after);
            send_policy!(response, DispatchOutcome::ConcurrencyLimited)
        }};
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
            send_proxy_error!().await?;
            return Ok(());
        }
    };
    rate_limit_context.upstream = upstream
        .clone()
        .or_else(|| Some(format!("{}:{}", host, port)));
    let concurrency = request_limits.acquire_concurrency_with_retry(&rate_limit_context);
    let _concurrency_permits = match concurrency.permits {
        Some(permits) => permits,
        None => {
            send_concurrency_limited!(concurrency.retry_after).await?;
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
                send_upstream_connect_udp_failed!().await?;
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
                decision_service_policy_id: decision_service_policy_id.as_deref(),
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
                send_proxy_error!().await?;
                return Ok(());
            }
        },
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT-UDP DNS resolution failed");
            send_proxy_error!().await?;
            return Ok(());
        }
        Err(_) => {
            warn!("forward HTTP/3 CONNECT-UDP DNS resolution timed out");
            send_proxy_error!().await?;
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
            send_proxy_error!().await?;
            return Ok(());
        }
    };
    match timeout(upstream_timeout, udp.connect(target)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            warn!(error = ?err, "forward HTTP/3 CONNECT-UDP connect failed");
            send_proxy_error!().await?;
            return Ok(());
        }
        Err(_) => {
            warn!("forward HTTP/3 CONNECT-UDP connect timed out");
            send_proxy_error!().await?;
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
            decision_service_policy_id: decision_service_policy_id.as_deref(),
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
                    Some(chunk) => {
                        let bytes = h3_buf_to_bytes(chunk);
                        capsule_buf.push(bytes, connect_udp_cfg.max_capsule_buffer_bytes)?;
                        while let Some((capsule_type, payload)) = capsule_buf.take_next()? {
                            if capsule_type != 0 {
                                continue;
                            }
                            let Some(datagram_payload) = decode_connect_udp_payload(payload.as_ref()) else {
                                continue;
                            };
                            apply_connect_udp_bandwidth_controls(
                                &rate_limit_ctx,
                                &request_limits,
                                datagram_payload.len(),
                            )
                            .await?;
                            udp.send(datagram_payload).await?;
                        }
                        idle_deadline
                            .as_mut()
                            .reset(crate::runtime::tokio_deadline_after(idle_timeout));
                    }
                    None => {
                        if let Err(err) = capsule_buf.ensure_complete() {
                            req_send.stop_stream(::h3::error::Code::H3_MESSAGE_ERROR);
                            req_recv.stop_sending(::h3::error::Code::H3_MESSAGE_ERROR);
                            return Err(err);
                        }
                        break;
                    }
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
                let Some(datagram_payload) = decode_connect_udp_payload(payload.as_ref()) else {
                    continue;
                };
                apply_connect_udp_bandwidth_controls(
                    &rate_limit_ctx,
                    &request_limits,
                    datagram_payload.len(),
                )
                .await?;
                udp.send(datagram_payload).await?;
                idle_deadline
                    .as_mut()
                    .reset(crate::runtime::tokio_deadline_after(idle_timeout));
            }
            recv = recv_connect_udp_response(&udp, &mut udp_buf) => {
                let (datagram_payload, stream_payload) = recv?;
                let payload_len = stream_payload.len();
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

// A zero-byte UDP receive still carries a response: preserve its context ID
// and restore the receive buffer exactly as for a nonempty datagram.
async fn recv_connect_udp_response(
    udp: &UdpSocket,
    udp_buf: &mut BytesMut,
) -> std::io::Result<(Bytes, Bytes)> {
    let read_len = udp.recv_buf(udp_buf).await?;
    let datagram_payload = udp_buf.split_to(read_len + 1).freeze();
    let stream_payload = datagram_payload.slice(1..);
    if udp_buf.capacity() < 65_536 {
        udp_buf.reserve(65_536 - udp_buf.capacity());
    }
    udp_buf.extend_from_slice(&[0]);
    Ok((datagram_payload, stream_payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_udp_empty_response_then_nonempty() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(upstream.local_addr().unwrap()).await.unwrap();
        upstream.connect(udp.local_addr().unwrap()).await.unwrap();

        let mut udp_buf = BytesMut::with_capacity(65_536);
        udp_buf.extend_from_slice(&[0]);
        let mut responses = Vec::new();
        let mut capsules = CapsuleBuffer::new();
        for payload in [b"".as_slice(), b"next response"] {
            upstream.send(payload).await.unwrap();
            let response = timeout(
                Duration::from_secs(2),
                recv_connect_udp_response(&udp, &mut udp_buf),
            )
            .await
            .expect("UDP response should not be skipped")
            .unwrap();
            assert_eq!(udp_buf.as_ref(), &[0]);
            let header = encode_datagram_capsule_context_header(response.1.len()).unwrap();
            capsules.push(header, 65_536).unwrap();
            capsules.push(response.1.clone(), 65_536).unwrap();
            responses.push(response);
        }

        for ((datagram, stream_payload), expected) in
            responses.iter().zip([b"".as_slice(), b"next response"])
        {
            let mut expected_datagram = vec![0];
            expected_datagram.extend_from_slice(expected);
            assert_eq!(datagram.as_ref(), expected_datagram);
            assert_eq!(stream_payload.as_ref(), expected);
            let (capsule_type, capsule_payload) = capsules.take_next().unwrap().unwrap();
            assert_eq!(capsule_type, 0);
            assert_eq!(capsule_payload, *datagram);
        }
        assert!(capsules.take_next().unwrap().is_none());
        capsules.ensure_complete().unwrap();
    }
}
