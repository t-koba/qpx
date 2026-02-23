use super::destination::{resolve_http_target, resolve_upstream, ConnectTarget};
use crate::http::common::{
    bad_request_response as bad_request, forbidden_response as forbidden,
    too_many_requests_response as too_many_requests,
};
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers_in_place,
    handle_max_forwards_in_place, prepare_request_with_headers_in_place,
};
use crate::http::policy::{evaluate_listener_policy, ListenerPolicyDecision};
use crate::http::semantics::validate_incoming_request;
use crate::http::server::serve_http1_with_upgrades;
use crate::http::websocket::is_websocket_upgrade;
use crate::runtime::Runtime;
use crate::upstream::http1::{proxy_http1_request, proxy_websocket_http1, WebsocketProxyConfig};
use anyhow::{anyhow, Context, Result};
use hyper::service::service_fn;
use hyper::{Body, Request, StatusCode};
use qpx_core::middleware::access_log::{AccessLogContext, AccessLogService};
use qpx_core::rules::RuleMatchContext;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::error;

pub(super) async fn handle_http_connection<I>(
    stream: I,
    remote_addr: SocketAddr,
    original_target: Option<ConnectTarget>,
    listener_name: &str,
    runtime: Runtime,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let listener_name = listener_name.to_string();
    let header_read_timeout =
        Duration::from_millis(runtime.state().config.runtime.http_header_read_timeout_ms);
    let access_cfg = runtime.state().config.access_log.clone();
    let access_name = Arc::<str>::from(listener_name.as_str());

    let service = service_fn(move |mut req: Request<Body>| {
        let runtime = runtime.clone();
        let listener_name = listener_name.clone();
        let original_target = original_target.clone();

        async move {
            let error_state = runtime.state();
            let request_method = req.method().clone();
            let request_version = req.version();

            let result: Result<hyper::Response<Body>> = (|| async move {
                let state = runtime.state();
                let proxy_name = state.config.identity.proxy_name.as_str();
                if let Err(err) = validate_incoming_request(&req) {
                    return Ok::<_, anyhow::Error>(finalize_response_for_request(
                        req.method(),
                        req.version(),
                        proxy_name,
                        hyper::Response::builder()
                            .status(err.http_status())
                            .body(Body::from(err.to_string()))
                            .unwrap_or_else(|_| bad_request(err.to_string())),
                        false,
                    ));
                }

                if req.method() == hyper::Method::TRACE && !state.config.runtime.trace_enabled {
                    return Ok::<_, anyhow::Error>(finalize_response_for_request(
                        req.method(),
                        req.version(),
                        proxy_name,
                        hyper::Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(Body::from(state.messages.trace_disabled.clone()))
                            .unwrap_or_else(|_| bad_request("trace disabled")),
                        false,
                    ));
                }
                if let Some(limits) = state.rate_limiters.listener(listener_name.as_str()) {
                    if let Some(limiter) = limits.listener.requests.as_ref() {
                        if let Some(retry_after) = limiter.try_acquire(remote_addr.ip(), 1) {
                            return Ok::<_, anyhow::Error>(finalize_response_for_request(
                                req.method(),
                                req.version(),
                                proxy_name,
                                too_many_requests(Some(retry_after)),
                                false,
                            ));
                        }
                    }
                }

                let engine = state
                    .rules_by_listener
                    .get(&listener_name)
                    .ok_or_else(|| anyhow!("rule engine not found"))?;
                let listener_cfg = state
                    .listener_config(&listener_name)
                    .ok_or_else(|| anyhow!("listener not found"))?;

                let (connect_target, host_for_match) =
                    resolve_http_target(&req, original_target.as_ref())?;
                let path = req.uri().path_and_query().map(|pq| pq.as_str());

                let ctx = RuleMatchContext {
                    src_ip: Some(remote_addr.ip()),
                    dst_port: Some(connect_target.port()),
                    host: host_for_match.as_deref(),
                    sni: None,
                    method: Some(req.method().as_str()),
                    path,
                    headers: Some(req.headers()),
                    user_groups: &[],
                };
                let decision = evaluate_listener_policy(
                    engine,
                    &ctx,
                    req.method(),
                    req.version(),
                    proxy_name,
                    forbidden,
                    state.messages.forbidden.as_str(),
                )?;
                let (policy, early_response, matched_rule) = match decision {
                    ListenerPolicyDecision::Proceed(mut policy) => {
                        let matched_rule = policy.matched_rule.take();
                        (Some(policy), None, matched_rule)
                    }
                    ListenerPolicyDecision::Early(response, matched_rule) => {
                        (None, Some(response), matched_rule)
                    }
                };
                if let Some(rule) = matched_rule.as_deref() {
                    if let Some(limits) = state.rate_limiters.listener(listener_name.as_str()) {
                        if let Some(rule_limits) = limits.rules.get(rule) {
                            if let Some(limiter) = rule_limits.requests.as_ref() {
                                if let Some(retry_after) = limiter.try_acquire(remote_addr.ip(), 1)
                                {
                                    return Ok::<_, anyhow::Error>(finalize_response_for_request(
                                        req.method(),
                                        req.version(),
                                        proxy_name,
                                        too_many_requests(Some(retry_after)),
                                        false,
                                    ));
                                }
                            }
                        }
                    }
                }
                if let Some(response) = early_response {
                    return Ok::<_, anyhow::Error>(response);
                }
                let policy = policy.expect("policy");

                let req_method = req.method().clone();
                if let Some(response) = handle_max_forwards_in_place(
                    &mut req,
                    proxy_name,
                    state.config.runtime.trace_reflect_all_headers,
                ) {
                    return Ok::<_, anyhow::Error>(response);
                }
                let websocket = is_websocket_upgrade(req.headers());
                prepare_request_with_headers_in_place(
                    &mut req,
                    proxy_name,
                    policy.headers.as_deref(),
                    websocket,
                );

                let upstream = resolve_upstream(&policy.action, &state, listener_cfg)?;
                let upstream_timeout =
                    Duration::from_millis(state.config.runtime.upstream_http_timeout_ms);
                let upgrade_wait_timeout =
                    Duration::from_millis(state.config.runtime.upgrade_wait_timeout_ms);
                let tunnel_idle_timeout =
                    Duration::from_millis(state.config.runtime.tunnel_idle_timeout_ms);
                let authority = connect_target.authority();
                let export_session = state.export_session(remote_addr, authority.as_str());
                if websocket {
                    if let Some(session) = export_session.as_ref() {
                        let preview = crate::exporter::serialize_request_preview(&req);
                        session.emit_plaintext(true, &preview);
                    }
                    let mut response = proxy_websocket_http1(
                        req,
                        WebsocketProxyConfig {
                            upstream_proxy: upstream.as_deref(),
                            direct_connect_authority: authority.as_str(),
                            direct_host_header: authority.as_str(),
                            timeout_dur: upstream_timeout,
                            upgrade_wait_timeout,
                            tunnel_idle_timeout,
                            tunnel_label: "transparent",
                            upstream_context: "transparent websocket upstream proxy",
                            direct_context: "transparent websocket direct",
                        },
                    )
                    .await?;
                    if let Some(session) = export_session.as_ref() {
                        let preview = crate::exporter::serialize_response_preview(&response);
                        session.emit_plaintext(false, &preview);
                    }
                    let keep_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
                    let response_version = response.version();
                    finalize_response_with_headers_in_place(
                        &req_method,
                        response_version,
                        proxy_name,
                        &mut response,
                        policy.headers.as_deref(),
                        keep_upgrade,
                    );
                    return Ok::<_, anyhow::Error>(response);
                }

                if let Some(session) = export_session.as_ref() {
                    let preview = crate::exporter::serialize_request_preview(&req);
                    session.emit_plaintext(true, &preview);
                }
                let mut response = proxy_http1_request(
                    req,
                    upstream.as_deref(),
                    authority.as_str(),
                    upstream_timeout,
                )
                .await?;
                if let Some(session) = export_session.as_ref() {
                    let preview = crate::exporter::serialize_response_preview(&response);
                    session.emit_plaintext(false, &preview);
                }
                let response_version = response.version();
                finalize_response_with_headers_in_place(
                    &req_method,
                    response_version,
                    proxy_name,
                    &mut response,
                    policy.headers.as_deref(),
                    false,
                );
                Ok::<_, anyhow::Error>(response)
            })()
            .await;

            match result {
                Ok(response) => Ok::<_, Infallible>(response),
                Err(err) => {
                    error!(error = ?err, "transparent request handling failed");
                    Ok(finalize_response_for_request(
                        &request_method,
                        request_version,
                        error_state.config.identity.proxy_name.as_str(),
                        hyper::Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from(error_state.messages.proxy_error.clone()))
                            .unwrap_or_else(|_| bad_request("proxy error")),
                        false,
                    ))
                }
            }
        }
    });
    let service = AccessLogService::new(
        service,
        remote_addr,
        AccessLogContext {
            kind: "transparent",
            name: access_name,
        },
        &access_cfg,
    );

    serve_http1_with_upgrades(stream, service, header_read_timeout, false)
        .await
        .context("transparent HTTP serve_connection failed")?;

    Ok(())
}
