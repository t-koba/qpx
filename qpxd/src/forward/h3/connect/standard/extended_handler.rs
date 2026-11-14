use super::super::super::backend_h3::ForwardH3Handler;
use super::super::{finalize_h3_connect_head_response, finalize_h3_connect_owner_response};
use super::extended::{
    OpenUpstreamExtendedConnectInput, UpstreamExtendedConnectStream,
    open_upstream_extended_connect_stream, relay_h3_extended_connect_stream,
    upstream_extended_connect_error_response,
};
use super::{
    H3ConnectAuditContext, PreparedH3Connect, prepare_h3_connect_request, send_h3_policy_response,
};
use crate::http::dispatch::DispatchOutcome;
use crate::http::protocol::common::blocked_response as blocked;
use crate::http3::datagram::H3StreamDatagrams;
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::{
    H3ServerRequestStream, send_h3_response_with_timeouts, send_h3_static_response,
};
use crate::rate_limit::TransportScope;
use anyhow::{Result, anyhow};
use qpx_core::config::ActionKind;
use tokio::time::Duration;
use tracing::warn;

pub(crate) async fn handle_h3_extended_connect(
    req_head: qpx_core::http_message::Request<()>,
    mut req_stream: H3ServerRequestStream,
    handler: ForwardH3Handler,
    conn: H3ConnInfo,
    protocol: ::h3::ext::Protocol,
    datagrams: Option<H3StreamDatagrams>,
) -> Result<()> {
    let state = handler.runtime.state();
    if protocol == ::h3::ext::Protocol::WEB_TRANSPORT {
        send_h3_static_response(
            &mut req_stream,
            ::http::StatusCode::NOT_IMPLEMENTED,
            b"WEBTRANSPORT relay requires the http3-backend-qpx build",
            &http::Method::CONNECT,
            state.plan.identity.proxy_name.as_ref(),
            state.plan.limits.body.max_h3_response_body_bytes,
            crate::http3::server::h3_static_response_send_timeout(
                Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms),
                None,
            ),
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
        Some(prepared) => *prepared,
        None => return Ok(()),
    };

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
        decision_service_policy_id,
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
    let matched_rule_name = matched_rule.as_deref();
    let mut request_limits = state.policy.rate_limiters.collect_plan_with_profile(
        &selected_plan.rate_limits,
        rate_limit_profile.as_deref(),
        TransportScope::Connect,
    )?;
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    macro_rules! send_policy {
        ($req_stream:expr, $response:expr, $outcome:expr) => {
            send_h3_policy_response(
                $req_stream,
                $response,
                H3ConnectAuditContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    remote_ip: conn.remote_addr.ip(),
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

    if !matches!(
        action.kind,
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy
    ) {
        let mut response = blocked(state.messages.blocked.as_str());
        crate::http::protocol::l7::finalize_response_with_headers_in_place(
            &http::Method::CONNECT,
            http::Version::HTTP_3,
            proxy_name.as_str(),
            &mut response,
            response_headers.as_deref(),
            false,
        );
        send_policy!(&mut req_stream, response, DispatchOutcome::Block).await?;
        return Ok(());
    }

    let concurrency = request_limits.acquire_concurrency_with_retry(&rate_limit_context);
    let _concurrency_permits = match concurrency.permits {
        Some(permits) => permits,
        None => {
            let response = super::super::h3_connect_rate_limited_response(
                proxy_name.as_str(),
                response_headers.as_deref(),
                &request_limits,
                concurrency.retry_after,
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

    let listener_cfg = state.ingress_edge_settings(handler.listener_name.as_ref());
    let verify_upstream =
        state.tls_verify_upstream(listener_cfg, handler.listener_name.as_ref(), host.as_str());
    let listener_trust = listener_cfg.and_then(|cfg| cfg.upstream_tls_trust());

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
            let response = finalize_h3_connect_owner_response(
                proxy_name.as_str(),
                super::super::super::h3_bad_gateway_base_response(
                    state.messages.proxy_error.clone(),
                ),
                response_headers.as_deref(),
            );
            send_policy!(&mut req_stream, response, DispatchOutcome::Error).await?;
            return Ok(());
        }
    };

    finish_h3_extended_connect_stream(
        &state,
        req_stream,
        protocol,
        datagrams,
        upstream,
        proxy_name.as_str(),
        response_headers.as_deref(),
        tunnel_idle_timeout,
        selected_plan,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "extended CONNECT finish keeps stream, upstream, datagram, policy, and timeout facts explicit"
)]
async fn finish_h3_extended_connect_stream(
    state: &crate::runtime::RuntimeState,
    mut req_stream: H3ServerRequestStream,
    protocol: ::h3::ext::Protocol,
    datagrams: Option<H3StreamDatagrams>,
    upstream: UpstreamExtendedConnectStream,
    proxy_name: &str,
    response_headers: Option<&qpx_core::rules::CompiledHeaderControl>,
    tunnel_idle_timeout: Duration,
    selected_plan: &crate::runtime::ExecutionPlan,
) -> Result<()> {
    let UpstreamExtendedConnectStream {
        interim,
        response,
        req_stream: upstream_stream,
        datagrams: upstream_datagrams,
        _endpoint,
        driver,
        datagram_task,
    } = upstream;
    for interim in interim {
        let interim = crate::http3::codec::sanitize_interim_response_for_h3(interim)?;
        tokio::time::timeout(tunnel_idle_timeout, req_stream.send_response(interim))
            .await
            .map_err(|_| anyhow!("HTTP/3 extended CONNECT interim response send timed out"))??;
    }
    if !response.status().is_success() {
        let body_read_timeout =
            Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1));
        let response = upstream_extended_connect_error_response(
            response,
            upstream_stream,
            proxy_name,
            response_headers,
            body_read_timeout,
        )?;
        send_h3_extended_connect_error_response(response, &mut req_stream, state, selected_plan)
            .await?;
        abort_h3_extended_driver(datagram_task, driver).await;
        return Ok(());
    }

    let established = finalize_h3_connect_head_response(
        response,
        proxy_name,
        response_headers,
        "HTTP/3 extended CONNECT response",
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
    abort_h3_extended_driver(datagram_task, driver).await;
    Ok(())
}

async fn send_h3_extended_connect_error_response(
    response: qpx_core::http_message::Response<qpx_http::body::Body>,
    req_stream: &mut H3ServerRequestStream,
    state: &crate::runtime::RuntimeState,
    selected_plan: &crate::runtime::ExecutionPlan,
) -> Result<()> {
    let h3_read_timeout_ms = state.plan.limits.timeouts.h3_read_timeout_ms;
    let body_read_timeout = Duration::from_millis(h3_read_timeout_ms.max(1));
    let body_send_timeout = crate::forward::h3::h3_response_send_timeout(
        h3_read_timeout_ms,
        Some(selected_plan.streaming.body_send_timeout_ms),
    );
    send_h3_response_with_timeouts(
        response,
        &http::Method::CONNECT,
        req_stream,
        state.plan.limits.body.max_h3_response_body_bytes,
        body_read_timeout,
        body_send_timeout,
    )
    .await
}

async fn abort_h3_extended_driver(
    datagram_task: Option<tokio::task::JoinHandle<()>>,
    driver: tokio::task::JoinHandle<()>,
) {
    if let Some(task) = datagram_task {
        task.abort();
        let _ = task.await;
    }
    let _ = driver.await;
}

#[cfg(test)]
mod tests {
    use super::send_h3_extended_connect_error_response;
    use bytes::Bytes;
    use qpx_core::http_message::Response as OwnerResponse;
    use qpx_http::body::Body;
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use quinn::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::time::{Duration, Instant};

    #[tokio::test]
    async fn selected_plan_send_budget_stops_extended_connect_error_on_peer_flow_control()
    -> anyhow::Result<()> {
        let config: qpx_core::config::Config = serde_yaml::from_str(
            r#"runtime:
  h3_read_timeout_ms: 2000
edges:
- kind: forward
  name: forward
  listen: 127.0.0.1:0
  default_action: { type: direct }
  http3: { enabled: true }
  streaming:
    body_read_timeout_ms: 2000
    body_send_timeout_ms: 40
  rules:
  - name: selected
    match:
      host: [selected.example]
    action: { type: direct }
"#,
        )?;
        let runtime = crate::runtime::Runtime::new(config)?;
        let state = runtime.state();
        let selected_plan = state
            .plan
            .ingress_edge_execution_plan("forward", Some("selected"))
            .expect("matched execution plan");
        assert_eq!(selected_plan.streaming.body_read_timeout_ms, 2000);
        assert_eq!(selected_plan.streaming.body_send_timeout_ms, 40);
        assert_eq!(state.plan.limits.timeouts.h3_read_timeout_ms, 2000);

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let der = cert.cert.der().clone();
        let provider = quinn::rustls::crypto::ring::default_provider();
        let mut server_tls =
            quinn::rustls::ServerConfig::builder_with_provider(provider.clone().into())
                .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(
                    vec![der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        cert.signing_key.serialize_der(),
                    )),
                )?;
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?)),
            "127.0.0.1:0".parse()?,
        )?;
        let addr = endpoint.local_addr()?;
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let mut builder = ::h3::server::builder();
            builder.enable_extended_connect(true);
            let mut connection = builder
                .build::<_, Bytes>(h3_quinn::Connection::new(conn))
                .await
                .unwrap();
            let resolver = connection.accept().await.unwrap().unwrap();
            let (_, mut request_stream) = resolver.resolve_request().await.unwrap();
            let selected_plan = server_state
                .plan
                .ingress_edge_execution_plan("forward", Some("selected"))
                .unwrap();
            let response = OwnerResponse::from_http(
                http::Response::builder()
                    .status(http::StatusCode::FORBIDDEN)
                    .body(Body::from(Bytes::from(vec![b'x'; 1024 * 1024])))
                    .unwrap(),
            );
            let started = Instant::now();
            let result = tokio::time::timeout(
                Duration::from_millis(500),
                send_h3_extended_connect_error_response(
                    response,
                    &mut request_stream,
                    &server_state,
                    selected_plan,
                ),
            )
            .await;
            let elapsed = started.elapsed();
            let error = match result {
                Ok(Err(err)) => err.to_string(),
                Ok(Ok(())) => "response unexpectedly completed".to_owned(),
                Err(_) => "send exceeded outer test deadline".to_owned(),
            };
            let _ = result_tx.send((error, elapsed));
            let _ = connection.accept().await;
        });

        let mut roots = quinn::rustls::RootCertStore::empty();
        roots.add(der)?;
        let mut client_tls = quinn::rustls::ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&quinn::rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls)?));
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(quinn::VarInt::from_u32(1024));
        transport.receive_window(quinn::VarInt::from_u32(4096));
        client_config.transport_config(Arc::new(transport));
        client.set_default_client_config(client_config);
        let conn = client.connect(addr, "localhost")?.await?;
        let mut builder = ::h3::client::builder();
        builder.enable_extended_connect(true);
        let (mut connection, mut sender) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
            .await?;
        let driver =
            tokio::spawn(async move { std::future::poll_fn(|cx| connection.poll_close(cx)).await });
        let uri = http::Uri::builder()
            .scheme("https")
            .authority("localhost")
            .path_and_query("/")
            .build()?;
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(uri)
            .body(())?;
        request
            .extensions_mut()
            .insert(::h3::ext::Protocol::CONNECT_UDP);
        let mut request_stream = sender.send_request(request).await?;
        request_stream.finish().await?;
        let response = request_stream.recv_response().await?;
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);

        let (error, elapsed) = tokio::time::timeout(Duration::from_secs(3), result_rx).await??;
        assert!(
            error.contains("HTTP/3 response DATA send timed out"),
            "unexpected response send result: {error}"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "send took {elapsed:?}"
        );

        driver.abort();
        server.abort();
        Ok(())
    }
}
