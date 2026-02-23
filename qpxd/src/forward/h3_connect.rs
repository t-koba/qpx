use super::h3::ForwardH3Handler;
use crate::http::l7::finalize_response_for_request;
use crate::http::local_response::build_local_response;
#[cfg(feature = "mitm")]
use crate::http::mitm::{proxy_mitm_request, MitmRouteContext};
#[cfg(feature = "mitm")]
use crate::http::server::serve_http1_with_upgrades;
use crate::http3::codec::{h1_headers_to_http, http_headers_to_h1};
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::{send_h3_response, send_h3_static_response, H3ServerRequestStream};
#[cfg(feature = "mitm")]
use crate::tls::mitm::{accept_mitm_client, connect_mitm_upstream};
use crate::upstream::connect::connect_tunnel_target;
use crate::upstream::connect::TunnelIo;
use crate::upstream::http1::parse_upstream_proxy_endpoint;
use anyhow::{anyhow, Result};
use bytes::Buf;
use bytes::Bytes;
#[cfg(feature = "mitm")]
use hyper::service::service_fn;
#[cfg(feature = "mitm")]
use hyper::Request;
use hyper::{Body, Response, StatusCode};
use percent_encoding::percent_decode_str;
use qpx_core::config::{ActionConfig, ActionKind, ConnectUdpConfig};
#[cfg(feature = "mitm")]
use qpx_core::middleware::access_log::{AccessLogContext, AccessLogService};
use qpx_core::rules::RuleMatchContext;
use std::net::SocketAddr;
#[cfg(feature = "mitm")]
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant};
use tracing::warn;

#[derive(Debug)]
enum ConnectPolicy {
    Allow(ActionConfig),
    RateLimited,
    Challenge(qpx_core::auth::AuthChallenge),
    Forbidden,
}

#[derive(Debug)]
pub(super) struct PreparedH3Connect {
    pub(super) authority: String,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) action: ActionConfig,
}

pub(super) enum H3ConnectPreparation {
    Continue(Box<PreparedH3Connect>),
    Responded,
}

pub(super) async fn prepare_h3_connect_request(
    req_head: &http1::Request<()>,
    req_stream: &mut H3ServerRequestStream,
    handler: &ForwardH3Handler,
    conn: &H3ConnInfo,
    connect_udp_cfg: Option<&ConnectUdpConfig>,
) -> Result<H3ConnectPreparation> {
    let state = handler.runtime.state();
    let proxy_name = state.config.identity.proxy_name.as_str();
    let max_h3_response_body_bytes = state.config.runtime.max_h3_response_body_bytes;
    let is_connect_udp = connect_udp_cfg.is_some();

    if let Some(limits) = state.rate_limiters.listener(handler.listener_name.as_ref()) {
        if let Some(limiter) = limits.listener.requests.as_ref() {
            if limiter.try_acquire(conn.remote_addr.ip(), 1).is_some() {
                send_h3_static_response(
                    req_stream,
                    http1::StatusCode::TOO_MANY_REQUESTS,
                    b"too many requests",
                    &http::Method::CONNECT,
                    proxy_name,
                    max_h3_response_body_bytes,
                )
                .await?;
                return Ok(H3ConnectPreparation::Responded);
            }
        }
    }

    if let Some(cfg) = connect_udp_cfg {
        if !cfg.enabled {
            send_h3_static_response(
                req_stream,
                http1::StatusCode::NOT_IMPLEMENTED,
                state.messages.connect_udp_disabled.as_bytes(),
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
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
            send_h3_static_response(
                req_stream,
                http1::StatusCode::BAD_REQUEST,
                message,
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
    };

    let (host, port, authority_host_for_validation, authority_port_for_validation, auth_uri) =
        if is_connect_udp {
            let uri_template = connect_udp_cfg.and_then(|cfg| cfg.uri_template.as_deref());
            let (host, port) = match parse_connect_udp_target(req_head.uri(), uri_template) {
                Ok(parsed) => parsed,
                Err(_) => {
                    send_h3_static_response(
                        req_stream,
                        http1::StatusCode::BAD_REQUEST,
                        b"invalid CONNECT-UDP target",
                        &http::Method::CONNECT,
                        proxy_name,
                        max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(H3ConnectPreparation::Responded);
                }
            };
            let scheme = match req_head.uri().scheme_str() {
                Some(scheme) => scheme,
                None => {
                    send_h3_static_response(
                        req_stream,
                        http1::StatusCode::BAD_REQUEST,
                        b"missing CONNECT-UDP :scheme",
                        &http::Method::CONNECT,
                        proxy_name,
                        max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(H3ConnectPreparation::Responded);
                }
            };
            let default_port = default_port_for_scheme(scheme);
            let authority = req_head.uri().authority().expect("checked above");
            let authority_host = authority.host().to_string();
            let authority_port = authority.port_u16().unwrap_or(default_port);
            let path = match req_head.uri().path_and_query().map(|pq| pq.as_str()) {
                Some(path) => path,
                None => {
                    send_h3_static_response(
                        req_stream,
                        http1::StatusCode::BAD_REQUEST,
                        b"missing CONNECT-UDP :path",
                        &http::Method::CONNECT,
                        proxy_name,
                        max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(H3ConnectPreparation::Responded);
                }
            };
            let auth_uri = format!("{scheme}://{req_authority}{path}");
            (host, port, authority_host, authority_port, auth_uri)
        } else {
            let (host, port) = match parse_connect_authority_required(&req_authority) {
                Ok(parsed) => parsed,
                Err(_) => {
                    send_h3_static_response(
                        req_stream,
                        http1::StatusCode::BAD_REQUEST,
                        b"invalid CONNECT authority",
                        &http::Method::CONNECT,
                        proxy_name,
                        max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(H3ConnectPreparation::Responded);
                }
            };
            (host.clone(), port, host, port, req_authority.clone())
        };

    let headers = match h1_headers_to_http(req_head.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            let message = if is_connect_udp {
                b"invalid CONNECT-UDP headers".as_slice()
            } else {
                b"invalid CONNECT headers".as_slice()
            };
            send_h3_static_response(
                req_stream,
                http1::StatusCode::BAD_REQUEST,
                message,
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
    };

    if let Err(err) = validate_h3_connect_head(
        req_head,
        &headers,
        authority_host_for_validation.as_str(),
        authority_port_for_validation,
        is_connect_udp,
    ) {
        if is_connect_udp {
            warn!(error = ?err, "invalid forward HTTP/3 CONNECT-UDP request");
        } else {
            warn!(error = ?err, "invalid forward HTTP/3 CONNECT request");
        }
        let message = if is_connect_udp {
            b"bad CONNECT-UDP request".as_slice()
        } else {
            b"bad CONNECT request".as_slice()
        };
        send_h3_static_response(
            req_stream,
            http1::StatusCode::BAD_REQUEST,
            message,
            &http::Method::CONNECT,
            proxy_name,
            max_h3_response_body_bytes,
        )
        .await?;
        return Ok(H3ConnectPreparation::Responded);
    }

    let decision = match evaluate_connect_policy(
        handler,
        conn.remote_addr,
        &host,
        port,
        &headers,
        auth_uri.as_str(),
    )
    .await
    {
        Ok(decision) => decision,
        Err(err) => {
            if is_connect_udp {
                warn!(
                    error = ?err,
                    "forward HTTP/3 CONNECT-UDP policy evaluation failed"
                );
            } else {
                warn!(error = ?err, "forward HTTP/3 CONNECT policy evaluation failed");
            }
            send_h3_static_response(
                req_stream,
                http1::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
    };

    let action = match decision {
        ConnectPolicy::RateLimited => {
            send_h3_static_response(
                req_stream,
                http1::StatusCode::TOO_MANY_REQUESTS,
                b"too many requests",
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        ConnectPolicy::Challenge(challenge) => {
            let response = crate::forward::request::proxy_auth_required(
                challenge,
                state.messages.proxy_auth_required.as_str(),
            );
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                response,
                false,
            );
            send_h3_response(
                response,
                &http::Method::CONNECT,
                req_stream,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        ConnectPolicy::Forbidden => {
            send_h3_static_response(
                req_stream,
                http1::StatusCode::FORBIDDEN,
                state.messages.forbidden.as_bytes(),
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        ConnectPolicy::Allow(action) => action,
    };

    match action.kind {
        ActionKind::Block => {
            send_h3_static_response(
                req_stream,
                http1::StatusCode::FORBIDDEN,
                state.messages.blocked.as_bytes(),
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            send_h3_local_response(
                req_stream,
                local,
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(H3ConnectPreparation::Responded);
        }
        ActionKind::Inspect => {
            if is_connect_udp {
                // CONNECT-UDP inspection is unsupported; fail closed.
                send_h3_static_response(
                    req_stream,
                    http1::StatusCode::FORBIDDEN,
                    state.messages.blocked.as_bytes(),
                    &http::Method::CONNECT,
                    proxy_name,
                    max_h3_response_body_bytes,
                )
                .await?;
                return Ok(H3ConnectPreparation::Responded);
            }
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }

    Ok(H3ConnectPreparation::Continue(Box::new(
        PreparedH3Connect {
            authority: format_authority(&host, port),
            host,
            port,
            action,
        },
    )))
}

pub(super) async fn handle_h3_connect(
    req_head: http1::Request<()>,
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
        H3ConnectPreparation::Continue(prepared) => *prepared,
        H3ConnectPreparation::Responded => return Ok(()),
    };

    let state = handler.runtime.state();
    let upstream_timeout = Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);
    let tunnel_idle_timeout =
        Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms.max(1));
    let proxy_name = state.config.identity.proxy_name.clone();
    let PreparedH3Connect {
        authority: _authority,
        host,
        port,
        action,
    } = prepared;
    match action.kind {
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy | ActionKind::Inspect => {}
        _ => {
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::FORBIDDEN,
                state.messages.blocked.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }
    }
    if matches!(action.kind, ActionKind::Inspect) {
        #[cfg(not(feature = "mitm"))]
        {
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::FORBIDDEN,
                state.messages.blocked.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }

        #[cfg(feature = "mitm")]
        {
            let tls_inspection = state
                .listener_config(handler.listener_name.as_ref())
                .and_then(|l| l.tls_inspection.as_ref());
            if !tls_inspection.map(|t| t.enabled).unwrap_or(false) {
                send_h3_static_response(
                    &mut req_stream,
                    http1::StatusCode::FORBIDDEN,
                    state.messages.blocked.as_bytes(),
                    &http::Method::CONNECT,
                    proxy_name.as_str(),
                    state.config.runtime.max_h3_response_body_bytes,
                )
                .await?;
                return Ok(());
            }
            let verify_upstream = tls_inspection
                .map(|t| {
                    t.verify_upstream
                        && !state
                            .tls_verify_exception_matches(handler.listener_name.as_ref(), &host)
                })
                .unwrap_or(true);
            let mitm = match state.mitm.clone() {
                Some(mitm) => mitm,
                None => {
                    send_h3_static_response(
                        &mut req_stream,
                        http1::StatusCode::FORBIDDEN,
                        state.messages.blocked.as_bytes(),
                        &http::Method::CONNECT,
                        proxy_name.as_str(),
                        state.config.runtime.max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(());
                }
            };

            let upstream = match crate::forward::request::resolve_upstream(
                &action,
                &state,
                handler.listener_name.as_ref(),
            ) {
                Ok(upstream) => upstream,
                Err(err) => {
                    warn!(error = ?err, "forward HTTP/3 CONNECT upstream resolution failed");
                    send_h3_static_response(
                        &mut req_stream,
                        http1::StatusCode::BAD_GATEWAY,
                        state.messages.proxy_error.as_bytes(),
                        &http::Method::CONNECT,
                        proxy_name.as_str(),
                        state.config.runtime.max_h3_response_body_bytes,
                    )
                    .await?;
                    return Ok(());
                }
            };
            let upstream_connected =
                match connect_tunnel_target(&host, port, upstream.as_deref(), upstream_timeout)
                    .await
                {
                    Ok(stream) => stream.io,
                    Err(err) => {
                        warn!(
                            error = ?err,
                            upstream = upstream
                                .as_deref()
                                .and_then(|u| parse_upstream_proxy_endpoint(u).ok())
                                .map(|e| e.cache_key()),
                            "forward HTTP/3 CONNECT tunnel establish failed"
                        );
                        send_h3_static_response(
                            &mut req_stream,
                            http1::StatusCode::BAD_GATEWAY,
                            state.messages.proxy_error.as_bytes(),
                            &http::Method::CONNECT,
                            proxy_name.as_str(),
                            state.config.runtime.max_h3_response_body_bytes,
                        )
                        .await?;
                        return Ok(());
                    }
                };
            let established = build_h3_connect_success_response(
                proxy_name.as_str(),
                &http::Method::CONNECT,
                false,
            )?;
            req_stream.send_response(established).await?;
            if let Err(err) = mitm_h3_connect_stream(
                req_stream,
                upstream_connected,
                handler.runtime.clone(),
                handler.listener_name.clone(),
                conn.remote_addr,
                host,
                port,
                mitm,
                verify_upstream,
                Duration::from_millis(state.config.runtime.http_header_read_timeout_ms),
                upstream_timeout,
                tunnel_idle_timeout,
            )
            .await
            {
                warn!(error = ?err, "forward HTTP/3 CONNECT MITM failed");
            }
            return Ok(());
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
            send_h3_static_response(
                &mut req_stream,
                http1::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name.as_str(),
                state.config.runtime.max_h3_response_body_bytes,
            )
            .await?;
            return Ok(());
        }
    };
    let server: TunnelIo =
        match connect_tunnel_target(&host, port, upstream.as_deref(), upstream_timeout).await {
            Ok(stream) => stream.io,
            Err(err) => {
                warn!(
                    error = ?err,
                    upstream = upstream
                        .as_deref()
                        .and_then(|u| parse_upstream_proxy_endpoint(u).ok())
                        .map(|e| e.cache_key()),
                    "forward HTTP/3 CONNECT tunnel establish failed"
                );
                send_h3_static_response(
                    &mut req_stream,
                    http1::StatusCode::BAD_GATEWAY,
                    state.messages.proxy_error.as_bytes(),
                    &http::Method::CONNECT,
                    proxy_name.as_str(),
                    state.config.runtime.max_h3_response_body_bytes,
                )
                .await?;
                return Ok(());
            }
        };

    let established =
        build_h3_connect_success_response(proxy_name.as_str(), &http::Method::CONNECT, false)?;
    req_stream.send_response(established).await?;
    if let Err(err) = relay_h3_connect_stream(req_stream, server, tunnel_idle_timeout).await {
        warn!(error = ?err, "forward HTTP/3 CONNECT relay failed");
    }
    Ok(())
}

pub(super) fn build_h3_connect_success_response(
    proxy_name: &str,
    request_method: &http::Method,
    capsule_protocol: bool,
) -> Result<http1::Response<()>> {
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())?;
    if capsule_protocol {
        response.headers_mut().insert(
            http::header::HeaderName::from_static("capsule-protocol"),
            http::HeaderValue::from_static("?1"),
        );
    }
    let response = finalize_response_for_request(
        request_method,
        http::Version::HTTP_3,
        proxy_name,
        response,
        false,
    );
    let status = http1::StatusCode::from_u16(response.status().as_u16())?;
    let mut out = http1::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(response.headers())?;
    Ok(out)
}

async fn evaluate_connect_policy(
    handler: &ForwardH3Handler,
    remote_addr: SocketAddr,
    host: &str,
    port: u16,
    headers: &http::HeaderMap,
    authority: &str,
) -> Result<ConnectPolicy> {
    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: Some(port),
        host: Some(host),
        sni: Some(host),
        method: Some("CONNECT"),
        path: None,
        headers: Some(headers),
        user_groups: &[],
    };
    match crate::forward::evaluate_forward_policy(
        &handler.runtime,
        handler.listener_name.as_ref(),
        ctx,
        headers,
        "CONNECT",
        authority,
    )
    .await?
    {
        crate::forward::ForwardPolicyDecision::Allow(allowed) => {
            if let Some(rule) = allowed.matched_rule.as_deref() {
                let state = handler.runtime.state();
                if let Some(limits) = state.rate_limiters.listener(handler.listener_name.as_ref()) {
                    if let Some(rule_limits) = limits.rules.get(rule) {
                        if let Some(limiter) = rule_limits.requests.as_ref() {
                            if limiter.try_acquire(remote_addr.ip(), 1).is_some() {
                                return Ok(ConnectPolicy::RateLimited);
                            }
                        }
                    }
                }
            }
            Ok(ConnectPolicy::Allow(allowed.action))
        }
        crate::forward::ForwardPolicyDecision::Challenge(challenge) => {
            Ok(ConnectPolicy::Challenge(challenge))
        }
        crate::forward::ForwardPolicyDecision::Forbidden => Ok(ConnectPolicy::Forbidden),
    }
}

async fn relay_h3_connect_stream(
    req_stream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    server: TunnelIo,
    idle_timeout: Duration,
) -> Result<()> {
    let (mut req_send, mut req_recv) = req_stream.split();
    let (mut server_read, mut server_write) = tokio::io::split(server);

    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let mut client_eof = false;
    let mut server_eof = false;
    let mut buf = [0u8; 16 * 1024];

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                return Err(anyhow!("forward HTTP/3 CONNECT tunnel idle timeout"));
            }
            recv = req_recv.recv_data(), if !client_eof => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        server_write.write_all(&bytes).await?;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => {
                        client_eof = true;
                        // Half-close upstream; the other direction may still drain.
                        let _ = server_write.shutdown().await;
                        if server_eof {
                            break;
                        }
                    }
                }
            }
            n = server_read.read(&mut buf), if !server_eof => {
                let n = n?;
                if n == 0 {
                    server_eof = true;
                    let _ = req_send.finish().await;
                    if client_eof {
                        break;
                    }
                } else {
                    req_send.send_data(Bytes::copy_from_slice(&buf[..n])).await?;
                    idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "mitm")]
#[allow(clippy::too_many_arguments)]
async fn mitm_h3_connect_stream(
    req_stream: H3ServerRequestStream,
    upstream_tcp: TunnelIo,
    runtime: crate::runtime::Runtime,
    listener_name: Arc<str>,
    remote_addr: SocketAddr,
    host: String,
    port: u16,
    mitm: qpx_core::tls::MitmConfig,
    verify_upstream: bool,
    header_read_timeout: Duration,
    upstream_timeout: Duration,
    tunnel_idle_timeout: Duration,
) -> Result<()> {
    let (client_io, bridge_io) = tokio::io::duplex(64 * 1024);

    let bridge = relay_h3_connect_stream_to_io(req_stream, bridge_io, tunnel_idle_timeout);
    let mitm_fut = async move {
        let client_tls = accept_mitm_client(client_io, &mitm, upstream_timeout).await?;
        let sender = connect_mitm_upstream(
            upstream_tcp,
            host.as_str(),
            &mitm,
            verify_upstream,
            upstream_timeout,
            "forward HTTP/3 MITM upstream conn",
        )
        .await?;
        let connect_host = host.clone();
        let runtime_for_service = runtime.clone();
        let listener_name_for_service = listener_name.clone();
        let service = service_fn(move |inner_req: Request<Body>| {
            let sender = sender.clone();
            let runtime = runtime_for_service.clone();
            let listener_name = listener_name_for_service.clone();
            let connect_host = connect_host.clone();
            async move {
                let route = MitmRouteContext {
                    listener_name: listener_name.as_ref(),
                    src_addr: remote_addr,
                    dst_port: port,
                    host: connect_host.as_str(),
                    sni: connect_host.as_str(),
                };
                let response = proxy_mitm_request(inner_req, runtime, sender, route).await?;
                Ok::<_, anyhow::Error>(response)
            }
        });
        let access_cfg = runtime.state().config.access_log.clone();
        let service = AccessLogService::new(
            service,
            remote_addr,
            AccessLogContext {
                kind: "forward",
                name: listener_name,
            },
            &access_cfg,
        );

        serve_http1_with_upgrades(client_tls, service, header_read_timeout, false).await?;
        Ok::<(), anyhow::Error>(())
    };

    let _ = tokio::try_join!(mitm_fut, bridge)?;
    Ok(())
}

#[cfg(feature = "mitm")]
async fn relay_h3_connect_stream_to_io(
    req_stream: ::h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    io: tokio::io::DuplexStream,
    idle_timeout: Duration,
) -> Result<()> {
    let (mut req_send, mut req_recv) = req_stream.split();
    let (mut io_read, mut io_write) = tokio::io::split(io);

    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let mut client_eof = false;
    let mut io_eof = false;
    let mut buf = [0u8; 16 * 1024];

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                return Err(anyhow!("forward HTTP/3 CONNECT tunnel idle timeout"));
            }
            recv = req_recv.recv_data(), if !client_eof => {
                match recv? {
                    Some(chunk) => {
                        let mut chunk = chunk;
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        io_write.write_all(&bytes).await?;
                        idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                    }
                    None => {
                        client_eof = true;
                        let _ = io_write.shutdown().await;
                        if io_eof {
                            break;
                        }
                    }
                }
            }
            n = io_read.read(&mut buf), if !io_eof => {
                let n = n?;
                if n == 0 {
                    io_eof = true;
                    let _ = req_send.finish().await;
                    if client_eof {
                        break;
                    }
                } else {
                    req_send.send_data(Bytes::copy_from_slice(&buf[..n])).await?;
                    idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                }
            }
        }
    }
    Ok(())
}

fn validate_h3_connect_head(
    req_head: &http1::Request<()>,
    headers: &http::HeaderMap,
    authority_host: &str,
    authority_port: u16,
    allow_extended_connect: bool,
) -> Result<()> {
    crate::http::semantics::validate_h2_h3_connect_headers(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    crate::http::semantics::validate_expect_header(headers)
        .map_err(|err| anyhow!("invalid CONNECT request headers: {}", err))?;
    if req_head.method() != http1::Method::CONNECT {
        return Err(anyhow!("CONNECT method required"));
    }
    if allow_extended_connect {
        let is_connect_udp = req_head
            .extensions()
            .get::<::h3::ext::Protocol>()
            .map(|p| *p == ::h3::ext::Protocol::CONNECT_UDP)
            .unwrap_or(false);
        if !is_connect_udp {
            return Err(anyhow!("CONNECT-UDP protocol required"));
        }
        // RFC 9298 section 3.4: :scheme and :path are derived from the expanded URI template and
        // MUST be present (non-empty). Unlike CONNECT, :authority is the proxy authority.
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
            .map(|v| v.trim());
        if capsule_protocol != Some("?1") {
            return Err(anyhow!("CONNECT-UDP requires Capsule-Protocol: ?1"));
        }
    } else if req_head.uri().scheme_str().is_some() || req_head.uri().path_and_query().is_some() {
        return Err(anyhow!(
            "CONNECT request target must be authority-form without scheme/path"
        ));
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

async fn send_h3_local_response(
    req_stream: &mut H3ServerRequestStream,
    local: &qpx_core::config::LocalResponseConfig,
    request_method: &http::Method,
    request_version: http::Version,
    proxy_name: &str,
    max_h3_response_body_bytes: usize,
) -> Result<()> {
    let response = finalize_response_for_request(
        request_method,
        request_version,
        proxy_name,
        build_local_response(local)?,
        false,
    );
    send_h3_response(
        response,
        request_method,
        req_stream,
        max_h3_response_body_bytes,
    )
    .await
}

fn parse_connect_authority_required(authority: &str) -> Result<(String, u16)> {
    let uri = http1::Uri::builder()
        .scheme("http")
        .authority(authority)
        .path_and_query("/")
        .build()
        .map_err(|_| anyhow!("invalid CONNECT authority"))?;
    let parsed = uri
        .authority()
        .ok_or_else(|| anyhow!("invalid CONNECT authority"))?;
    let port = parsed
        .port_u16()
        .ok_or_else(|| anyhow!("CONNECT authority must include explicit port"))?;
    Ok((parsed.host().to_string(), port))
}

fn parse_connect_udp_target(uri: &http1::Uri, uri_template: Option<&str>) -> Result<(String, u16)> {
    if let Some(template) = uri_template {
        // Strict mode: when a template is configured, only that template is accepted.
        return parse_connect_udp_target_from_template(uri, template);
    }

    let path_and_query = uri
        .path_and_query()
        .ok_or_else(|| anyhow!("CONNECT-UDP requires :path"))?;

    // RFC 9298 default template: /.well-known/masque/udp/{target_host}/{target_port}/
    let path = path_and_query.path();
    let segments = path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if segments.len() >= 5
        && segments[0] == ".well-known"
        && segments[1] == "masque"
        && segments[2] == "udp"
    {
        let host = percent_decode_str(segments[3])
            .decode_utf8()
            .map_err(|_| anyhow!("invalid CONNECT-UDP target_host encoding"))?;
        let host = host.trim();
        if host.is_empty() {
            return Err(anyhow!("CONNECT-UDP target_host must not be empty"));
        }
        let port: u16 = segments[4]
            .parse()
            .map_err(|_| anyhow!("invalid CONNECT-UDP target_port"))?;
        if port == 0 {
            return Err(anyhow!(
                "CONNECT-UDP target_port must be in range 1..=65535"
            ));
        }
        return Ok((host.to_string(), port));
    }

    // Query-based templates:
    // - ...?target_host=...&target_port=...
    // - ...?h=...&p=...
    if let Some(query) = path_and_query.query() {
        let mut target_host: Option<String> = None;
        let mut target_port: Option<u16> = None;
        if let Some(host) = query_get_single(query, "target_host")? {
            target_host = Some(decode_connect_udp_host(host)?);
        } else if let Some(host) = query_get_single(query, "h")? {
            target_host = Some(decode_connect_udp_host(host)?);
        }
        if let Some(port) = query_get_single(query, "target_port")? {
            target_port = Some(parse_connect_udp_port(port)?);
        } else if let Some(port) = query_get_single(query, "p")? {
            target_port = Some(parse_connect_udp_port(port)?);
        }
        if let (Some(h), Some(p)) = (target_host, target_port) {
            return Ok((h, p));
        }
    }

    Err(anyhow!("unsupported CONNECT-UDP request target"))
}

fn parse_connect_udp_target_from_template(
    uri: &http1::Uri,
    template: &str,
) -> Result<(String, u16)> {
    let path_and_query = uri
        .path_and_query()
        .ok_or_else(|| anyhow!("CONNECT-UDP requires :path"))?;
    let req_segments = path_and_query
        .path()
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let template_path_and_query = if template.starts_with('/') {
        template
    } else {
        let (_, rest) = template
            .split_once("://")
            .ok_or_else(|| anyhow!("invalid CONNECT-UDP uri_template"))?;
        let idx = rest
            .find('/')
            .ok_or_else(|| anyhow!("CONNECT-UDP uri_template must include a path"))?;
        &rest[idx..]
    };
    let (template_path, template_query) = match template_path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (template_path_and_query, None),
    };

    let template_segments = template_path
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if template_segments.len() != req_segments.len() {
        return Err(anyhow!("CONNECT-UDP uri_template path mismatch"));
    }

    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    for (tpl, actual) in template_segments.iter().zip(req_segments.iter()) {
        match *tpl {
            "{target_host}" => host = Some(decode_connect_udp_host(actual)?),
            "{target_port}" => port = Some(parse_connect_udp_port(actual)?),
            _ if tpl.starts_with('{') && tpl.ends_with('}') => {
                // Other template variables are treated as wildcard segments.
            }
            _ if tpl == actual => {}
            _ => return Err(anyhow!("CONNECT-UDP uri_template path mismatch")),
        }
    }

    if let (Some(host), Some(port)) = (host.take(), port.take()) {
        return Ok((host, port));
    }

    if let (Some(query), Some(template_query)) = (path_and_query.query(), template_query) {
        let (host_key, port_key) = connect_udp_query_keys_from_template(template_query);
        if host.is_none() {
            if let Some(key) = host_key.as_deref() {
                if let Some(value) = query_get_single(query, key)? {
                    host = Some(decode_connect_udp_host(value)?);
                }
            }
        }
        if port.is_none() {
            if let Some(key) = port_key.as_deref() {
                if let Some(value) = query_get_single(query, key)? {
                    port = Some(parse_connect_udp_port(value)?);
                }
            }
        }
    }

    match (host, port) {
        (Some(h), Some(p)) => Ok((h, p)),
        _ => Err(anyhow!("unsupported CONNECT-UDP request target")),
    }
}

fn connect_udp_query_keys_from_template(query_template: &str) -> (Option<String>, Option<String>) {
    let mut host_key: Option<String> = None;
    let mut port_key: Option<String> = None;

    // Query expansion: {?target_host,target_port} / {&target_host,target_port}
    let mut rest = query_template;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            break;
        };
        let inside = &after[..close];
        let mut chars = inside.chars();
        let op = chars.next();
        if matches!(op, Some('?') | Some('&')) {
            for var in inside[1..].split(',').map(|v| v.trim()) {
                match var {
                    "target_host" => host_key = Some("target_host".to_string()),
                    "target_port" => port_key = Some("target_port".to_string()),
                    _ => {}
                }
            }
        }
        rest = &after[close + 1..];
    }

    // Literal key=value pairs: h={target_host}&p={target_port}
    let mut depth = 0u32;
    let mut start = 0usize;
    for (idx, ch) in query_template.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            '&' if depth == 0 => {
                connect_udp_parse_query_kv_template(
                    &query_template[start..idx],
                    &mut host_key,
                    &mut port_key,
                );
                start = idx + 1;
            }
            _ => {}
        }
    }
    connect_udp_parse_query_kv_template(&query_template[start..], &mut host_key, &mut port_key);

    (host_key, port_key)
}

fn connect_udp_parse_query_kv_template(
    part: &str,
    host_key: &mut Option<String>,
    port_key: &mut Option<String>,
) {
    let Some((k, v)) = part.split_once('=') else {
        return;
    };
    match v.trim() {
        "{target_host}" => *host_key = Some(k.trim().to_string()),
        "{target_port}" => *port_key = Some(k.trim().to_string()),
        _ => {}
    }
}

fn query_get_single<'a>(query: &'a str, key: &str) -> Result<Option<&'a str>> {
    let mut found = None::<&'a str>;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            if found.is_some() {
                return Err(anyhow!("duplicate query parameter: {}", key));
            }
            found = Some(v);
        }
    }
    Ok(found)
}

fn decode_connect_udp_host(raw: &str) -> Result<String> {
    let host = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| anyhow!("invalid CONNECT-UDP target_host encoding"))?;
    let host = host.trim();
    if host.is_empty() {
        return Err(anyhow!("CONNECT-UDP target_host must not be empty"));
    }
    Ok(host.to_string())
}

fn parse_connect_udp_port(raw: &str) -> Result<u16> {
    let port: u16 = raw
        .parse()
        .map_err(|_| anyhow!("invalid CONNECT-UDP target_port"))?;
    if port == 0 {
        return Err(anyhow!(
            "CONNECT-UDP target_port must be in range 1..=65535"
        ));
    }
    Ok(port)
}

fn default_port_for_scheme(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("http") {
        80
    } else {
        443
    }
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_authority_requires_explicit_port() {
        assert!(parse_connect_authority_required("example.com").is_err());
        let (host, port) = parse_connect_authority_required("example.com:8443").expect("valid");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn connect_udp_target_from_well_known_path() {
        let uri = http1::Uri::builder()
            .scheme("https")
            .authority("proxy.example")
            .path_and_query("/.well-known/masque/udp/192.0.2.6/443/")
            .build()
            .unwrap();
        let (host, port) = parse_connect_udp_target(&uri, None).expect("valid");
        assert_eq!(host, "192.0.2.6");
        assert_eq!(port, 443);

        let uri = http1::Uri::builder()
            .scheme("https")
            .authority("proxy.example")
            .path_and_query("/.well-known/masque/udp/2001%3Adb8%3A%3A42/8443/")
            .build()
            .unwrap();
        let (host, port) = parse_connect_udp_target(&uri, None).expect("valid");
        assert_eq!(host, "2001:db8::42");
        assert_eq!(port, 8443);
    }

    #[test]
    fn connect_udp_target_from_query() {
        let uri = http1::Uri::builder()
            .scheme("https")
            .authority("proxy.example")
            .path_and_query("/masque?h=example.com&p=8443")
            .build()
            .unwrap();
        let (host, port) = parse_connect_udp_target(&uri, None).expect("valid");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn connect_udp_target_from_custom_template_path() {
        let uri = http1::Uri::builder()
            .scheme("https")
            .authority("proxy.example")
            .path_and_query("/masque/udp/example.com/8443")
            .build()
            .unwrap();
        let template = "https://proxy.example/masque/udp/{target_host}/{target_port}";
        let (host, port) = parse_connect_udp_target(&uri, Some(template)).expect("valid");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }
}
