use super::h3::ForwardH3Handler;
use super::h3_connect::{
    build_h3_connect_success_response, normalize_h3_upstream_connect_headers,
    prepare_h3_connect_request, recv_upstream_h3_response_with_interim, send_h3_policy_response,
    H3ConnectPreparation, H3PolicyResponseContext,
};
use crate::http::body::Body;
use crate::http::l7::finalize_response_with_headers;
use crate::http3::capsule::{
    append_capsule_chunk, decode_quic_varint, encode_datagram_capsule,
    encode_datagram_capsule_value, take_next_capsule,
};
use crate::http3::datagram::{H3DatagramDispatch, H3StreamDatagrams};
use crate::http3::listener::H3ConnInfo;
use crate::http3::quic::build_h3_client_config;
use crate::http3::server::H3ServerRequestStream;
use crate::policy_context::{emit_audit_log, AuditRecord};
use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use hyper::{Response, StatusCode};
use qpx_core::config::ConnectUdpConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::{sleep, timeout, Duration, Instant};
use tracing::warn;

pub(super) async fn handle_h3_connect_udp(
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
    let proxy_name = state.config.identity.proxy_name.clone();
    let super::h3_connect::PreparedH3Connect {
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
    let mut request_limits = state.policy.rate_limiters.collect(
        handler.listener_name.as_ref(),
        matched_rule.as_deref(),
        None,
        crate::rate_limit::TransportScope::Http3Datagram,
    );
    request_limits.extend_from(&state.policy.rate_limiters.collect_profile(
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Http3Datagram,
    )?);
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
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
            send_policy!(response, "error").await?;
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
            send_policy!(response, "concurrency_limited").await?;
            return Ok(());
        }
    };

    if let Some(upstream) = upstream {
        let mut upstream_chain = match open_upstream_connect_udp_stream(
            &upstream,
            host.as_str(),
            port,
            proxy_name.as_str(),
            state
                .listener_config(handler.listener_name.as_ref())
                .and_then(|listener| listener.tls_inspection.as_ref())
                .map(|cfg| {
                    cfg.verify_upstream
                        && !state.tls_verify_exception_matches(
                            handler.listener_name.as_ref(),
                            host.as_str(),
                        )
                })
                .unwrap_or(true),
            upstream_timeout,
        )
        .await
        {
            Ok(chain) => chain,
            Err(err) => {
                let upstream_target =
                    crate::forward::connect_udp_upstream::parse_connect_udp_upstream(&upstream)
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
                send_policy!(response, "error").await?;
                return Ok(());
            }
        };

        for interim in upstream_chain.interim.drain(..) {
            let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
            timeout(
                Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
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
                kind: "forward",
                name: handler.listener_name.as_ref(),
                remote_ip: conn.remote_addr.ip(),
                host: Some(host.as_str()),
                sni: Some(host.as_str()),
                method: Some("CONNECT"),
                path: audit_path.as_deref(),
                outcome: "allow",
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
                send_policy!(response, "error").await?;
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
            send_policy!(response, "error").await?;
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
            send_policy!(response, "error").await?;
            return Ok(());
        }
    };

    let bind_addr: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
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
            send_policy!(response, "error").await?;
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
            send_policy!(response, "error").await?;
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
            send_policy!(response, "error").await?;
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
            kind: "forward",
            name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            outcome: "allow",
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

struct UpstreamConnectUdpStream {
    interim: Vec<::http::Response<()>>,
    _endpoint: quinn::Endpoint,
    driver: tokio::task::JoinHandle<()>,
    datagram_task: tokio::task::JoinHandle<()>,
    datagrams: Option<H3StreamDatagrams>,
    req_stream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
}

async fn open_upstream_connect_udp_stream(
    upstream: &str,
    target_host: &str,
    target_port: u16,
    proxy_name: &str,
    verify_upstream: bool,
    timeout_dur: Duration,
) -> Result<UpstreamConnectUdpStream> {
    let (upstream_host, upstream_port, uri) =
        crate::forward::connect_udp_upstream::build_upstream_connect_udp_uri(
            upstream,
            target_host,
            target_port,
        )?;
    let upstream_addr = timeout(
        timeout_dur,
        lookup_host((upstream_host.as_str(), upstream_port)),
    )
    .await??
    .next()
    .ok_or_else(|| anyhow!("failed to resolve CONNECT-UDP upstream proxy"))?;

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(build_h3_client_config(verify_upstream)?);

    let connection = timeout(
        timeout_dur,
        endpoint.connect(upstream_addr, &upstream_host)?,
    )
    .await??;
    let mut builder = ::h3::client::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let h3_build = builder.build::<_, _, Bytes>(h3_quinn::Connection::new(connection));
    let (mut h3_conn, mut sender) = timeout(timeout_dur, h3_build).await??;
    use h3_datagram::datagram_handler::HandleDatagramsExt as _;
    let datagram_dispatch = Arc::new(H3DatagramDispatch::new(64));
    let reader = h3_conn.get_datagram_reader();
    let datagram_task = {
        let dispatch = datagram_dispatch.clone();
        tokio::spawn(async move {
            dispatch.run(reader).await;
        })
    };

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::HeaderName::from_static("capsule-protocol"),
        http::header::HeaderValue::from_static("?1"),
    );
    let normalized_headers = normalize_h3_upstream_connect_headers(&uri, &headers, proxy_name)?;
    let mut request = ::http::Request::builder()
        .method(::http::Method::CONNECT)
        .uri(uri)
        .body(())?;
    request
        .extensions_mut()
        .insert(::h3::ext::Protocol::CONNECT_UDP);
    *request.headers_mut() = normalized_headers;

    let mut req_stream = match timeout(timeout_dur, sender.send_request(request)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(err.into());
        }
        Err(_) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(anyhow!("upstream CONNECT-UDP request timed out"));
        }
    };
    let (interim, response) = match recv_upstream_h3_response_with_interim(
        &mut req_stream,
        timeout_dur,
        "upstream CONNECT-UDP response",
    )
    .await
    {
        Ok(parts) => parts,
        Err(err) => {
            datagram_task.abort();
            let _ = datagram_task.await;
            return Err(err);
        }
    };
    if !response.status().is_success() {
        datagram_task.abort();
        let _ = datagram_task.await;
        return Err(anyhow!(
            "upstream CONNECT-UDP failed with status {}",
            response.status()
        ));
    }
    let capsule = response
        .headers()
        .get(::http::header::HeaderName::from_static("capsule-protocol"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if capsule != Some("?1") {
        datagram_task.abort();
        let _ = datagram_task.await;
        return Err(anyhow!(
            "upstream CONNECT-UDP missing required response header: Capsule-Protocol: ?1"
        ));
    }

    let stream_id = req_stream.id();
    let upstream_datagrams = Some(
        datagram_dispatch
            .register_stream(stream_id, h3_conn.get_datagram_sender(stream_id))
            .await,
    );

    let driver = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| h3_conn.poll_close(cx)).await;
    });

    Ok(UpstreamConnectUdpStream {
        interim,
        _endpoint: endpoint,
        driver,
        datagram_task,
        datagrams: upstream_datagrams,
        req_stream,
    })
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

    let mut capsule_buf = BytesMut::new();
    let mut udp_buf = [0u8; 65535];

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = req_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        append_capsule_chunk(
                            &mut capsule_buf,
                            &bytes,
                            connect_udp_cfg.max_capsule_buffer_bytes,
                        )?;
                        while let Some((capsule_type, payload)) = take_next_capsule(&mut capsule_buf)? {
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
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
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
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
            recv = udp.recv(&mut udp_buf) => {
                let n = recv?;
                if n == 0 {
                    continue;
                }
                apply_connect_udp_bandwidth_controls(&rate_limit_ctx, &request_limits, n).await?;
                let mut sent = false;
                if let Some(datagrams) = datagrams.as_mut() {
                    let mut value = Vec::with_capacity(1 + n);
                    value.push(0); // context id = 0
                    value.extend_from_slice(&udp_buf[..n]);
                    if datagrams.sender.send_datagram(Bytes::from(value)).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule(&udp_buf[..n])?;
                    timeout(idle_timeout, req_send.send_data(capsule))
                        .await
                        .map_err(|_| anyhow!("CONNECT-UDP capsule send timed out"))??;
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
        }
    }

    timeout(idle_timeout, req_send.finish())
        .await
        .map_err(|_| anyhow!("CONNECT-UDP stream finish timed out"))??;
    Ok(())
}

async fn relay_h3_connect_udp_stream_chained(
    downstream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut downstream_datagrams: Option<H3StreamDatagrams>,
    upstream: ::h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    mut upstream_datagrams: Option<H3StreamDatagrams>,
    connect_udp_cfg: ConnectUdpConfig,
    rate_limit_ctx: RateLimitContext,
    request_limits: AppliedRateLimits,
) -> Result<()> {
    let (mut downstream_send, mut downstream_recv) = downstream.split();
    let (mut upstream_send, mut upstream_recv) = upstream.split();

    let idle_timeout = Duration::from_secs(connect_udp_cfg.idle_timeout_secs.max(1));
    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                break;
            }
            recv = downstream_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        apply_connect_udp_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            bytes.len(),
                        )
                        .await?;
                        timeout(idle_timeout, upstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("CONNECT-UDP upstream DATA send timed out"))??;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => break,
                }
            }
            recv = upstream_recv.recv_data() => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        apply_connect_udp_bandwidth_controls(
                            &rate_limit_ctx,
                            &request_limits,
                            bytes.len(),
                        )
                        .await?;
                        timeout(idle_timeout, downstream_send.send_data(bytes))
                            .await
                            .map_err(|_| anyhow!("CONNECT-UDP downstream DATA send timed out"))??;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => break,
                }
            }
            down_payload = async {
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = down_payload else {
                    break;
                };
                let fallback = payload.clone();
                apply_connect_udp_bandwidth_controls(
                    &rate_limit_ctx,
                    &request_limits,
                    fallback.len(),
                )
                .await?;
                let mut sent = false;
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    if datagrams.sender.send_datagram(payload).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule_value(fallback.as_ref())?;
                    timeout(idle_timeout, upstream_send.send_data(capsule))
                        .await
                        .map_err(|_| anyhow!("CONNECT-UDP upstream capsule send timed out"))??;
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
            up_payload = async {
                if let Some(datagrams) = upstream_datagrams.as_mut() {
                    datagrams.receiver.recv().await
                } else {
                    std::future::pending::<Option<Bytes>>().await
                }
            } => {
                let Some(payload) = up_payload else {
                    break;
                };
                let fallback = payload.clone();
                apply_connect_udp_bandwidth_controls(
                    &rate_limit_ctx,
                    &request_limits,
                    fallback.len(),
                )
                .await?;
                let mut sent = false;
                if let Some(datagrams) = downstream_datagrams.as_mut() {
                    if datagrams.sender.send_datagram(payload).is_ok() {
                        sent = true;
                    }
                }
                if !sent {
                    let capsule = encode_datagram_capsule_value(fallback.as_ref())?;
                    timeout(idle_timeout, downstream_send.send_data(capsule))
                        .await
                        .map_err(|_| anyhow!("CONNECT-UDP downstream capsule send timed out"))??;
                }
                idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
            }
        }
    }

    let _ = timeout(idle_timeout, upstream_send.finish()).await;
    let _ = timeout(idle_timeout, downstream_send.finish()).await;
    Ok(())
}

async fn apply_connect_udp_bandwidth_controls(
    ctx: &RateLimitContext,
    limits: &AppliedRateLimits,
    bytes: usize,
) -> Result<()> {
    let delay = limits
        .reserve_bytes(ctx, bytes as u64)
        .map_err(|_| anyhow!("CONNECT-UDP bandwidth quota exceeded"))?;
    if !delay.is_zero() {
        sleep(delay).await;
    }
    Ok(())
}
