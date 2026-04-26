use super::h3_qpx_relay::{
    relay_qpx_connect_udp_stream, relay_qpx_connect_udp_stream_chained,
    relay_qpx_extended_connect_stream,
};
use super::*;
use crate::destination::DestinationInputs;
use crate::forward::request::resolve_upstream_url;
use crate::http::body::Body;
use crate::http::common::{
    blocked_response as blocked, connect_established_response as connect_established,
    forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::policy_context::{
    apply_ext_authz_action_overrides, emit_audit_log, enforce_ext_authz, resolve_identity,
    sanitize_headers_for_policy, validate_ext_authz_allow_mode, AuditRecord,
    EffectivePolicyContext, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
};
use crate::rate_limit::RateLimitContext;
use anyhow::{anyhow, Result};
use hyper::{Response, StatusCode};
use qpx_core::config::{ActionConfig, ActionKind, ConnectUdpConfig};
use qpx_core::rules::{CompiledHeaderControl, RuleMatchContext};
use qpx_observability::access_log::RequestLogContext;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{lookup_host, UdpSocket};
use tokio::time::{timeout, Duration};
use tracing::warn;

#[derive(Debug)]
struct PreparedQpxConnect {
    host: String,
    port: u16,
    action: ActionConfig,
    response_headers: Option<Arc<CompiledHeaderControl>>,
    log_context: RequestLogContext,
    matched_rule: Option<String>,
    ext_authz_policy_id: Option<String>,
    audit_path: Option<String>,
    timeout_override: Option<Duration>,
    rate_limit_profile: Option<String>,
    rate_limit_context: RateLimitContext,
    sanitized_headers: http::HeaderMap,
}

enum QpxConnectPreparation {
    Continue(Box<PreparedQpxConnect>),
    Responded,
}

struct PrepareQpxConnectInput<'a> {
    req_head: &'a http::Request<()>,
    req_stream: &'a mut qpx_h3::RequestStream,
    handler: &'a ForwardQpxHandler,
    conn: &'a qpx_h3::ConnectionInfo,
    protocol: Option<&'a qpx_h3::Protocol>,
    connect_udp_cfg: Option<&'a ConnectUdpConfig>,
}

struct OpenUpstreamQpxExtendedConnectInput<'a> {
    req_head: &'a http::Request<()>,
    sanitized_headers: &'a http::HeaderMap,
    proxy_name: &'a str,
    upstream: Option<&'a str>,
    verify_upstream: bool,
    protocol: qpx_h3::Protocol,
    enable_datagram: bool,
    timeout_dur: Duration,
}

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
        QpxConnectPreparation::Continue(prepared) => *prepared,
        QpxConnectPreparation::Responded => return Ok(()),
    };

    match protocol {
        qpx_h3::Protocol::ConnectUdp => {
            handle_qpx_connect_udp_stream(handler, prepared, req_stream, conn, datagrams).await
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
            )
            .await
        }
    }
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
    let proxy_name = state.config.identity.proxy_name.clone();
    let tunnel_idle_timeout =
        Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms.max(1));
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
    let mut request_limits = state.policy.rate_limiters.collect(
        handler.listener_name.as_ref(),
        matched_rule.as_deref(),
        None,
        crate::rate_limit::TransportScope::Connect,
    );
    request_limits.extend_from(&state.policy.rate_limiters.collect_profile(
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Connect,
    )?);
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
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
        send_policy!(&mut req_stream, response, "block").await?;
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
            send_policy!(&mut req_stream, response, "concurrency_limited").await?;
            return Ok(());
        }
    };

    let upstream =
        match open_upstream_qpx_extended_connect_stream(OpenUpstreamQpxExtendedConnectInput {
            req_head: &req_head,
            sanitized_headers: &sanitized_headers,
            proxy_name: proxy_name.as_str(),
            upstream: action.upstream.as_deref(),
            verify_upstream: state
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
            protocol: qpx_h3::Protocol::Other(protocol_name),
            enable_datagram: datagrams.is_some(),
            timeout_dur: upstream_timeout,
        })
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
                send_policy!(&mut req_stream, response, "error").await?;
                return Ok(());
            }
        };

    let qpx_h3::ExtendedConnectStream {
        interim,
        response,
        request_stream: upstream_stream,
        datagrams: upstream_datagrams,
        opener: _,
        associated_bidi: _,
        associated_uni: _,
        _critical_streams,
        _endpoint,
        driver,
        datagram_task,
        _connection_use,
    } = upstream;
    for interim in interim {
        let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
        timeout(
            Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
            req_stream.send_response_head(&interim),
        )
        .await
        .map_err(|_| anyhow!("qpx-h3 interim response send timed out"))??;
    }
    if !response.status().is_success() {
        let response = upstream_qpx_extended_connect_error_response(
            response,
            upstream_stream,
            proxy_name.as_str(),
            response_headers.as_deref(),
            Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
        )?;
        send_qpx_response_stream(
            &mut req_stream,
            response,
            &http::Method::CONNECT,
            state.config.runtime.max_h3_response_body_bytes,
            Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
        )
        .await?;
        if let Some(task) = datagram_task {
            task.abort();
            let _ = task.await;
        }
        let _ = driver.await;
        return Ok(());
    }

    let established = finalize_qpx_connect_head_response(
        response,
        proxy_name.as_str(),
        response_headers.as_deref(),
    )?;
    timeout(
        Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
        req_stream.send_response_head(&established),
    )
    .await
    .map_err(|_| anyhow!("qpx-h3 CONNECT response head send timed out"))??;
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
    if let Some(task) = datagram_task {
        task.abort();
        let _ = task.await;
    }
    let _ = driver.await;
    Ok(())
}

async fn handle_qpx_connect_udp_stream(
    handler: &ForwardQpxHandler,
    prepared: PreparedQpxConnect,
    mut req_stream: qpx_h3::RequestStream,
    conn: qpx_h3::ConnectionInfo,
    datagrams: Option<qpx_h3::StreamDatagrams>,
) -> Result<()> {
    let state = handler.runtime.state();
    let proxy_name = state.config.identity.proxy_name.clone();
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
    let mut request_limits = state.policy.rate_limiters.collect(
        handler.listener_name.as_ref(),
        matched_rule.as_deref(),
        None,
        crate::rate_limit::TransportScope::Connect,
    );
    request_limits.extend_from(&state.policy.rate_limiters.collect_profile(
        rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Connect,
    )?);
    let upstream_timeout = timeout_override
        .unwrap_or_else(|| Duration::from_millis(state.config.runtime.upstream_http_timeout_ms));
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
    let upstream = match resolve_upstream_url(&action, &state, handler.listener_name.as_ref()) {
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
            send_policy!(&mut req_stream, response, "error").await?;
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
            send_policy!(&mut req_stream, response, "concurrency_limited").await?;
            return Ok(());
        }
    };

    if let Some(upstream) = upstream {
        let upstream_chain = match open_upstream_qpx_connect_udp_stream(
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
                send_policy!(&mut req_stream, response, "error").await?;
                return Ok(());
            }
        };

        for interim in &upstream_chain.interim {
            let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim.clone())?;
            timeout(
                Duration::from_millis(state.config.runtime.h3_read_timeout_ms.max(1)),
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
                send_policy!(&mut req_stream, response, "error").await?;
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
            send_policy!(&mut req_stream, response, "error").await?;
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
            send_policy!(&mut req_stream, response, "error").await?;
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
            send_policy!(&mut req_stream, response, "error").await?;
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
            send_policy!(&mut req_stream, response, "error").await?;
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
            send_policy!(&mut req_stream, response, "error").await?;
            return Ok(());
        }
    }

    let response =
        build_qpx_connect_success_head(proxy_name.as_str(), true, response_headers.as_deref())?;
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

async fn prepare_qpx_connect_request(
    input: PrepareQpxConnectInput<'_>,
) -> Result<QpxConnectPreparation> {
    let PrepareQpxConnectInput {
        req_head,
        req_stream,
        handler,
        conn,
        protocol,
        connect_udp_cfg,
    } = input;
    let state = handler.runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    let is_connect_udp = protocol == Some(&qpx_h3::Protocol::ConnectUdp);
    let is_extended_connect = protocol.is_some();

    if is_connect_udp {
        let Some(cfg) = connect_udp_cfg else {
            send_qpx_static_response(
                req_stream,
                StatusCode::NOT_IMPLEMENTED,
                state.messages.connect_udp_disabled.as_bytes(),
            )
            .await?;
            return Ok(QpxConnectPreparation::Responded);
        };
        if !cfg.enabled {
            send_qpx_static_response(
                req_stream,
                StatusCode::NOT_IMPLEMENTED,
                state.messages.connect_udp_disabled.as_bytes(),
            )
            .await?;
            return Ok(QpxConnectPreparation::Responded);
        }
    }

    let req_authority = match req_head.uri().authority().map(|a| a.as_str().to_string()) {
        Some(authority) => authority,
        None => {
            let message = if is_connect_udp {
                b"missing CONNECT-UDP authority".as_slice()
            } else {
                b"missing CONNECT authority".as_slice()
            };
            send_qpx_static_response(req_stream, StatusCode::BAD_REQUEST, message).await?;
            return Ok(QpxConnectPreparation::Responded);
        }
    };

    let (host, port, authority_host_for_validation, authority_port_for_validation, auth_uri) =
        if is_connect_udp {
            let uri_template = connect_udp_cfg.and_then(|cfg| cfg.uri_template.as_deref());
            let (host, port) = match parse_connect_udp_target(req_head.uri(), uri_template) {
                Ok(parsed) => parsed,
                Err(_) => {
                    send_qpx_static_response(
                        req_stream,
                        StatusCode::BAD_REQUEST,
                        b"invalid CONNECT-UDP target",
                    )
                    .await?;
                    return Ok(QpxConnectPreparation::Responded);
                }
            };
            let scheme = match req_head.uri().scheme_str() {
                Some(scheme) => scheme,
                None => {
                    send_qpx_static_response(
                        req_stream,
                        StatusCode::BAD_REQUEST,
                        b"missing CONNECT-UDP :scheme",
                    )
                    .await?;
                    return Ok(QpxConnectPreparation::Responded);
                }
            };
            let default_port = match scheme {
                "http" => 80,
                "https" | "h3" => 443,
                _ => 443,
            };
            let authority = req_head.uri().authority().expect("checked above");
            let authority_host = authority.host().to_string();
            let authority_port = authority.port_u16().unwrap_or(default_port);
            let path = match req_head.uri().path_and_query().map(|pq| pq.as_str()) {
                Some(path) => path,
                None => {
                    send_qpx_static_response(
                        req_stream,
                        StatusCode::BAD_REQUEST,
                        b"missing CONNECT-UDP :path",
                    )
                    .await?;
                    return Ok(QpxConnectPreparation::Responded);
                }
            };
            let auth_uri = format!("{scheme}://{req_authority}{path}");
            (host, port, authority_host, authority_port, auth_uri)
        } else {
            let (host, port) = match parse_connect_authority_required(&req_authority) {
                Ok(parsed) => parsed,
                Err(_) => {
                    send_qpx_static_response(
                        req_stream,
                        StatusCode::BAD_REQUEST,
                        b"invalid CONNECT authority",
                    )
                    .await?;
                    return Ok(QpxConnectPreparation::Responded);
                }
            };
            let auth_uri = if is_extended_connect {
                let scheme = req_head.uri().scheme_str().unwrap_or("https");
                let path = req_head
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                format!("{scheme}://{req_authority}{path}")
            } else {
                req_authority.clone()
            };
            (host.clone(), port, host, port, auth_uri)
        };

    let headers = match h1_headers_to_http(req_head.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            let message = if is_connect_udp {
                b"invalid CONNECT-UDP headers".as_slice()
            } else {
                b"invalid CONNECT headers".as_slice()
            };
            send_qpx_static_response(req_stream, StatusCode::BAD_REQUEST, message).await?;
            return Ok(QpxConnectPreparation::Responded);
        }
    };

    if let Err(err) = validate_qpx_connect_head(
        req_head,
        &headers,
        authority_host_for_validation.as_str(),
        authority_port_for_validation,
        protocol,
    ) {
        let message = if is_connect_udp {
            b"bad CONNECT-UDP request".as_slice()
        } else {
            b"bad CONNECT request".as_slice()
        };
        warn!(error = ?err, "invalid forward HTTP/3 qpx-h3 CONNECT request");
        send_qpx_static_response(req_stream, StatusCode::BAD_REQUEST, message).await?;
        return Ok(QpxConnectPreparation::Responded);
    }

    let listener_cfg = state
        .listener_config(handler.listener_name.as_ref())
        .ok_or_else(|| anyhow!("listener not found"))?;
    let effective_policy =
        EffectivePolicyContext::from_single(listener_cfg.policy_context.as_ref());
    let sanitized_headers =
        sanitize_headers_for_policy(&state, &effective_policy, conn.remote_addr.ip(), &headers)?;
    let mut identity = resolve_identity(
        &state,
        &effective_policy,
        conn.remote_addr.ip(),
        Some(&sanitized_headers),
        conn.peer_certificates
            .as_deref()
            .map(|certs| certs.as_slice()),
    )?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: if is_connect_udp {
                req_head.uri().scheme_str()
            } else {
                Some("https")
            },
            port: Some(port),
            alpn: Some("h3"),
            ..Default::default()
        },
        listener_cfg.destination_resolution.as_ref(),
    );
    let audit_path = req_head
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string());
    let ctx = RuleMatchContext {
        src_ip: Some(conn.remote_addr.ip()),
        dst_port: Some(port),
        host: Some(host.as_str()),
        sni: Some(host.as_str()),
        method: Some("CONNECT"),
        path: audit_path.as_deref(),
        authority: Some(req_authority.as_str()),
        http_version: Some(http_version_label(http::Version::HTTP_3)),
        alpn: Some("h3"),
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        headers: Some(&sanitized_headers),
        user: identity.user.as_deref(),
        user_groups: &identity.groups,
        device_id: identity.device_id.as_deref(),
        posture: &identity.posture,
        tenant: identity.tenant.as_deref(),
        auth_strength: identity.auth_strength.as_deref(),
        idp: identity.idp.as_deref(),
        ..Default::default()
    };

    let (mut action, matched_rule) = match evaluate_forward_policy(
        &handler.runtime,
        handler.listener_name.as_ref(),
        ctx,
        &sanitized_headers,
        "CONNECT",
        auth_uri.as_str(),
    )
    .await
    {
        Ok(ForwardPolicyDecision::Allow(allowed)) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (
                allowed.action,
                allowed.matched_rule.map(|rule: Arc<str>| rule.to_string()),
            )
        }
        Ok(ForwardPolicyDecision::Challenge(challenge)) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                proxy_auth_required(challenge, state.messages.proxy_auth_required.as_str()),
                false,
            );
            send_qpx_policy_response(
                req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: "challenge",
                    matched_rule: None,
                    ext_authz_policy_id: None,
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(QpxConnectPreparation::Responded);
        }
        Ok(ForwardPolicyDecision::Forbidden) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            );
            send_qpx_policy_response(
                req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: "forbidden",
                    matched_rule: None,
                    ext_authz_policy_id: None,
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(QpxConnectPreparation::Responded);
        }
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT policy evaluation failed");
            send_qpx_static_response(
                req_stream,
                StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
            )
            .await?;
            return Ok(QpxConnectPreparation::Responded);
        }
    };

    let request_limit_ctx = RateLimitContext::from_identity(
        conn.remote_addr.ip(),
        &identity,
        matched_rule.as_deref(),
        None,
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_request(
        crate::rate_limit::RequestLimitCollectInput {
            listener: Some(handler.listener_name.as_ref()),
            rule: matched_rule.as_deref(),
            profile: None,
            scope: crate::rate_limit::TransportScope::Http3Datagram,
            extra: None,
            ctx: &request_limit_ctx,
            cost: 1,
        },
    )?;
    if let Some(retry_after) = retry_after {
        let log_context = identity.to_log_context(matched_rule.as_deref(), None, None);
        let response = finalize_response_for_request(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            proxy_name,
            too_many_requests(Some(retry_after)),
            false,
        );
        send_qpx_policy_response(
            req_stream,
            response,
            QpxPolicyResponseContext {
                state: &state,
                listener_name: handler.listener_name.as_ref(),
                conn,
                host: host.as_str(),
                path: audit_path.as_deref(),
                outcome: "rate_limited",
                matched_rule: matched_rule.as_deref(),
                ext_authz_policy_id: None,
                log_context: &log_context,
            },
        )
        .await?;
        return Ok(QpxConnectPreparation::Responded);
    }

    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: "forward",
            proxy_name,
            scope_name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            dst_port: Some(port),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            uri: Some(auth_uri.as_str()),
            matched_rule: matched_rule.as_deref(),
            matched_route: None,
            action: Some(&action),
            headers: Some(&sanitized_headers),
            identity: &identity,
        },
    )
    .await?;
    let ext_authz_policy_id = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    };
    let ext_authz_policy_tags = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
    };
    let mut log_context = identity.to_log_context(
        matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    log_context.policy_tags = ext_authz_policy_tags;
    let (response_headers, timeout_override, rate_limit_profile) = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardConnect)?;
            let rate_limit_profile = allow.rate_limit_profile.clone();
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                &state.policy.rate_limiters,
                rate_limit_profile.as_deref(),
                crate::rate_limit::TransportScope::Http3Datagram,
                &request_limit_ctx,
                1,
            )? {
                let response = finalize_response_for_request(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                );
                send_qpx_policy_response(
                    req_stream,
                    response,
                    QpxPolicyResponseContext {
                        state: &state,
                        listener_name: handler.listener_name.as_ref(),
                        conn,
                        host: host.as_str(),
                        path: audit_path.as_deref(),
                        outcome: "rate_limited",
                        matched_rule: matched_rule.as_deref(),
                        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                        log_context: &log_context,
                    },
                )
                .await?;
                return Ok(QpxConnectPreparation::Responded);
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            (allow.headers, allow.timeout_override, rate_limit_profile)
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let response = if let Some(local) = deny.local_response.as_ref() {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    build_local_response(local)?,
                    deny.headers.as_deref(),
                    false,
                )
            } else {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    forbidden(state.messages.forbidden.as_str()),
                    deny.headers.as_deref(),
                    false,
                )
            };
            send_qpx_policy_response(
                req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: if deny.local_response.is_some() {
                        "ext_authz_local_response"
                    } else {
                        "ext_authz_deny"
                    },
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(QpxConnectPreparation::Responded);
        }
    };

    match action.kind {
        ActionKind::Block => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            send_qpx_policy_response(
                req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: "block",
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(QpxConnectPreparation::Responded);
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                build_local_response(local)?,
                response_headers.as_deref(),
                false,
            );
            send_qpx_policy_response(
                req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: "respond",
                    matched_rule: matched_rule.as_deref(),
                    ext_authz_policy_id: ext_authz_policy_id.as_deref(),
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(QpxConnectPreparation::Responded);
        }
        ActionKind::Inspect => {}
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }

    Ok(QpxConnectPreparation::Continue(Box::new(
        PreparedQpxConnect {
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
            rate_limit_context: request_limit_ctx,
            sanitized_headers,
        },
    )))
}

fn validate_qpx_connect_head(
    req_head: &http::Request<()>,
    headers: &http::HeaderMap,
    authority_host: &str,
    authority_port: u16,
    protocol: Option<&qpx_h3::Protocol>,
) -> Result<()> {
    crate::http::semantics::validate_h2_h3_request_headers(http::Version::HTTP_3, headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    crate::http::semantics::validate_expect_header(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    if req_head.method() != http::Method::CONNECT {
        return Err(anyhow!("CONNECT method required"));
    }
    match protocol {
        Some(qpx_h3::Protocol::ConnectUdp) => {
            let scheme = req_head
                .uri()
                .scheme_str()
                .ok_or_else(|| anyhow!("CONNECT-UDP requires :scheme"))?;
            if scheme.trim().is_empty() {
                return Err(anyhow!("CONNECT-UDP :scheme must not be empty"));
            }
            let path = req_head
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .ok_or_else(|| anyhow!("CONNECT-UDP requires :path"))?;
            if path.trim().is_empty() {
                return Err(anyhow!("CONNECT-UDP :path must not be empty"));
            }
            let capsule_protocol = headers
                .get("capsule-protocol")
                .and_then(|v| v.to_str().ok())
                .map(str::trim);
            if capsule_protocol != Some("?1") {
                return Err(anyhow!("CONNECT-UDP requires Capsule-Protocol: ?1"));
            }
        }
        Some(_) => {
            let scheme = req_head
                .uri()
                .scheme_str()
                .ok_or_else(|| anyhow!("extended CONNECT requires :scheme"))?;
            if scheme.trim().is_empty() {
                return Err(anyhow!("extended CONNECT :scheme must not be empty"));
            }
            let path = req_head
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .ok_or_else(|| anyhow!("extended CONNECT requires :path"))?;
            if path.trim().is_empty() {
                return Err(anyhow!("extended CONNECT :path must not be empty"));
            }
        }
        None => {
            if req_head.uri().scheme_str().is_some() || req_head.uri().path_and_query().is_some() {
                return Err(anyhow!(
                    "CONNECT request target must be authority-form without scheme/path"
                ));
            }
        }
    }

    let host_values: Vec<_> = headers.get_all(http::header::HOST).iter().collect();
    if host_values.len() > 1 {
        return Err(anyhow!("multiple Host headers are not allowed"));
    }
    if let Some(value) = host_values.first() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid Host header"))?
            .trim();
        if raw.is_empty() {
            return Err(anyhow!("Host header must not be empty"));
        }
        let (host_name, host_port) =
            crate::http::address::parse_authority_host_port(raw, authority_port)
                .ok_or_else(|| anyhow!("invalid Host header"))?;
        if host_port != authority_port || !host_name.eq_ignore_ascii_case(authority_host) {
            return Err(anyhow!("Host header does not match CONNECT authority"));
        }
    }
    Ok(())
}

fn build_qpx_connect_success_head(
    proxy_name: &str,
    capsule_protocol: bool,
    header_control: Option<&CompiledHeaderControl>,
) -> Result<http::Response<()>> {
    let mut response = connect_established();
    if capsule_protocol {
        response.headers_mut().insert(
            http::header::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_static("?1"),
        );
    }
    let response = finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        response,
        header_control,
        false,
    );
    let status = http::StatusCode::from_u16(response.status().as_u16())?;
    let mut out = http::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(response.headers())?;
    Ok(out)
}

async fn open_upstream_qpx_extended_connect_stream(
    input: OpenUpstreamQpxExtendedConnectInput<'_>,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let OpenUpstreamQpxExtendedConnectInput {
        req_head,
        sanitized_headers,
        proxy_name,
        upstream,
        verify_upstream,
        protocol,
        enable_datagram,
        timeout_dur,
    } = input;
    let (connect_host, connect_port) =
        parse_qpx_extended_connect_upstream(req_head.uri(), upstream).await?;
    let upstream_addr = match timeout(
        timeout_dur,
        lookup_host((connect_host.as_str(), connect_port)),
    )
    .await
    {
        Ok(Ok(mut addrs)) => addrs
            .next()
            .ok_or_else(|| anyhow!("failed to resolve extended CONNECT upstream"))?,
        Ok(Err(err)) => return Err(anyhow!(err)),
        Err(_) => return Err(anyhow!("extended CONNECT upstream resolution timed out")),
    };

    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint
        .set_default_client_config(crate::http3::quic::build_h3_client_config(verify_upstream)?);
    let connection =
        match timeout(timeout_dur, endpoint.connect(upstream_addr, &connect_host)?).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(err)) => return Err(anyhow!(err)),
            Err(_) => return Err(anyhow!("extended CONNECT upstream connect timed out")),
        };
    let normalized_headers =
        normalize_qpx_upstream_connect_headers(req_head.uri(), sanitized_headers, proxy_name)?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(req_head.uri().clone())
        .body(())?;
    *request.headers_mut() = normalized_headers;
    qpx_h3::open_extended_connect_stream(
        endpoint,
        connection,
        request,
        Some(protocol.clone()),
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram,
            enable_webtransport: protocol == qpx_h3::Protocol::WebTransport,
            max_webtransport_sessions: if protocol == qpx_h3::Protocol::WebTransport {
                1
            } else {
                0
            },
            max_request_body_bytes: 16 * 1024 * 1024,
            max_concurrent_streams_per_connection: 64,
            read_timeout: timeout_dur,
            ..Default::default()
        },
        timeout_dur,
    )
    .await
}

async fn open_upstream_qpx_connect_udp_stream(
    upstream: &str,
    target_host: &str,
    target_port: u16,
    proxy_name: &str,
    verify_upstream: bool,
    timeout_dur: Duration,
) -> Result<qpx_h3::ExtendedConnectStream> {
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
    endpoint
        .set_default_client_config(crate::http3::quic::build_h3_client_config(verify_upstream)?);

    let connection = timeout(
        timeout_dur,
        endpoint.connect(upstream_addr, &upstream_host)?,
    )
    .await??;

    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::HeaderName::from_static("capsule-protocol"),
        http::header::HeaderValue::from_static("?1"),
    );
    let normalized_headers = normalize_qpx_upstream_connect_headers(&uri, &headers, proxy_name)?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(uri)
        .body(())?;
    *request.headers_mut() = normalized_headers;

    let stream = qpx_h3::open_extended_connect_stream(
        endpoint,
        connection,
        request,
        Some(qpx_h3::Protocol::ConnectUdp),
        qpx_h3::Settings {
            enable_extended_connect: true,
            enable_datagram: true,
            enable_webtransport: false,
            max_webtransport_sessions: 0,
            max_request_body_bytes: 16 * 1024 * 1024,
            max_concurrent_streams_per_connection: 64,
            read_timeout: timeout_dur,
            ..Default::default()
        },
        timeout_dur,
    )
    .await?;

    if !stream.response.status().is_success() {
        return Err(anyhow!(
            "upstream CONNECT-UDP failed with status {}",
            stream.response.status()
        ));
    }
    let capsule = stream
        .response
        .headers()
        .get(http::header::HeaderName::from_static("capsule-protocol"))
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if capsule != Some("?1") {
        return Err(anyhow!(
            "upstream CONNECT-UDP missing required response header: Capsule-Protocol: ?1"
        ));
    }
    Ok(stream)
}
