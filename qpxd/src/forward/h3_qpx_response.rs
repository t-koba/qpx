use crate::http::body::Body;
use crate::http::dispatch::DispatchOutcome;
use crate::http::l7::finalize_response_with_headers;
use crate::http3::codec::{h1_headers_to_http, http_headers_to_h1};
use crate::policy_context::{AuditRecord, emit_audit_log};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::{Response, StatusCode};
use qpx_core::rules::CompiledHeaderControl;
use qpx_observability::access_log::RequestLogContext;
use std::time::Duration;
use tokio::time::timeout;
use tracing::warn;

pub(super) async fn collect_forward_response(
    mut response: Response<crate::http::body::Body>,
    request_method: &http::Method,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<qpx_h3::Response> {
    let interim = crate::http::interim::take_interim_response_heads(&mut response)
        .into_iter()
        .filter_map(|head| {
            let mut response = http::Response::builder()
                .status(head.status)
                .body(())
                .ok()?;
            *response.headers_mut() = head.headers;
            Some(response)
        })
        .collect();
    let (head, body, trailers): (http::Response<()>, bytes::Bytes, Option<http::HeaderMap>) =
        crate::http3::codec::hyper_response_to_h3(
            response,
            request_method,
            max_body_bytes,
            body_read_timeout,
        )
        .await?;
    Ok(qpx_h3::Response {
        interim,
        response: head.map(|_| body),
        trailers,
    })
}

pub(super) async fn send_qpx_static_response(
    req_stream: &mut qpx_h3::RequestStream,
    status: StatusCode,
    body: &[u8],
) -> Result<()> {
    const STATIC_RESPONSE_SEND_TIMEOUT: Duration = Duration::from_secs(30);

    let response = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(())?;
    tokio::time::timeout(
        STATIC_RESPONSE_SEND_TIMEOUT,
        req_stream.send_response_head(&response),
    )
    .await
    .map_err(|_| anyhow!("forward qpx-h3 response send timeout"))??;
    if !body.is_empty() {
        tokio::time::timeout(
            STATIC_RESPONSE_SEND_TIMEOUT,
            req_stream.send_data(Bytes::copy_from_slice(body)),
        )
        .await
        .map_err(|_| anyhow!("forward qpx-h3 response body send timeout"))??;
    }
    tokio::time::timeout(STATIC_RESPONSE_SEND_TIMEOUT, req_stream.finish())
        .await
        .map_err(|_| anyhow!("forward qpx-h3 response finish timeout"))?
}

pub(super) async fn send_qpx_response_stream(
    req_stream: &mut qpx_h3::RequestStream,
    response: Response<Body>,
    request_method: &http::Method,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<()> {
    let (head, body, trailers): (http::Response<()>, Bytes, Option<http::HeaderMap>) =
        crate::http3::codec::hyper_response_to_h3(
            response,
            request_method,
            max_body_bytes,
            body_read_timeout,
        )
        .await?;
    tokio::time::timeout(body_read_timeout, req_stream.send_response_head(&head))
        .await
        .map_err(|_| anyhow!("forward qpx-h3 response send timeout"))??;
    if !body.is_empty() {
        tokio::time::timeout(body_read_timeout, req_stream.send_data(body))
            .await
            .map_err(|_| anyhow!("forward qpx-h3 response body send timeout"))??;
    }
    if let Some(trailers) = trailers.as_ref() {
        tokio::time::timeout(body_read_timeout, req_stream.send_trailers(trailers))
            .await
            .map_err(|_| anyhow!("forward qpx-h3 response trailer send timeout"))??;
    }
    tokio::time::timeout(body_read_timeout, req_stream.finish())
        .await
        .map_err(|_| anyhow!("forward qpx-h3 response finish timeout"))?
}

pub(super) async fn send_qpx_policy_response(
    req_stream: &mut qpx_h3::RequestStream,
    response: Response<Body>,
    ctx: QpxPolicyResponseContext<'_>,
) -> Result<()> {
    let QpxPolicyResponseContext {
        state,
        listener_name,
        conn,
        host,
        path,
        outcome,
        matched_rule,
        ext_authz_policy_id,
        log_context,
    } = ctx;
    emit_audit_log(
        state,
        AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Forward,
            name: listener_name,
            remote_ip: conn.remote_addr.ip(),
            host: Some(host),
            sni: Some(host),
            method: Some("CONNECT"),
            path,
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule,
            matched_route: None,
            ext_authz_policy_id,
        },
        log_context,
    );
    send_qpx_response_stream(
        req_stream,
        response,
        &http::Method::CONNECT,
        state.plan.limits.max_h3_response_body_bytes,
        Duration::from_millis(state.plan.limits.h3_read_timeout_ms.max(1)),
    )
    .await
}

pub(super) struct QpxPolicyResponseContext<'a> {
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) listener_name: &'a str,
    pub(super) conn: &'a qpx_h3::ConnectionInfo,
    pub(super) host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) outcome: DispatchOutcome,
    pub(super) matched_rule: Option<&'a str>,
    pub(super) ext_authz_policy_id: Option<&'a str>,
    pub(super) log_context: &'a RequestLogContext,
}

pub(super) fn finalize_qpx_connect_head_response(
    response: http::Response<()>,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
) -> Result<http::Response<()>> {
    let (parts, _) = response.into_parts();
    let mut downstream = Response::builder()
        .status(StatusCode::from_u16(parts.status.as_u16())?)
        .body(Body::empty())?;
    *downstream.headers_mut() = h1_headers_to_http(&parts.headers)?;
    let downstream = finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        downstream,
        header_control,
        false,
    );
    let status = http::StatusCode::from_u16(downstream.status().as_u16())?;
    let mut out = http::Response::builder().status(status).body(())?;
    *out.headers_mut() = http_headers_to_h1(downstream.headers())?;
    Ok(out)
}

pub(super) fn upstream_qpx_extended_connect_error_response(
    response: http::Response<()>,
    upstream: qpx_h3::RequestStream,
    proxy_name: &str,
    header_control: Option<&CompiledHeaderControl>,
    body_read_timeout: Duration,
) -> Result<Response<Body>> {
    let (parts, _) = response.into_parts();
    let mut downstream = Response::builder()
        .status(StatusCode::from_u16(parts.status.as_u16())?)
        .body(body_from_upstream_qpx_stream(upstream, body_read_timeout))?;
    *downstream.headers_mut() = h1_headers_to_http(&parts.headers)?;
    Ok(finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        downstream,
        header_control,
        false,
    ))
}

fn body_from_upstream_qpx_stream(
    mut upstream: qpx_h3::RequestStream,
    body_read_timeout: Duration,
) -> Body {
    let (mut sender, body) = Body::channel();
    tokio::spawn(async move {
        loop {
            let next = tokio::select! {
                _ = sender.closed() => return,
                recv = timeout(body_read_timeout, upstream.recv_data()) => recv,
            };
            match next {
                Err(_) => {
                    warn!("extended CONNECT upstream error body timed out");
                    sender.abort();
                    return;
                }
                Ok(Ok(Some(chunk))) => {
                    if sender.send_data(chunk).await.is_err() {
                        return;
                    }
                }
                Ok(Ok(None)) => break,
                Ok(Err(err)) => {
                    warn!(error = ?err, "extended CONNECT upstream error body stream failed");
                    sender.abort();
                    return;
                }
            }
        }
        let trailers = tokio::select! {
            _ = sender.closed() => return,
            recv = timeout(body_read_timeout, upstream.recv_trailers()) => recv,
        };
        match trailers {
            Err(_) => {
                warn!("extended CONNECT upstream error trailers timed out");
                sender.abort();
            }
            Ok(Ok(Some(trailers))) => match h1_headers_to_http(&trailers) {
                Ok(trailers) => {
                    let _ = sender.send_trailers(trailers).await;
                }
                Err(err) => {
                    warn!(error = ?err, "extended CONNECT upstream trailers were invalid");
                }
            },
            Ok(Ok(None)) => {}
            Ok(Err(err)) => {
                warn!(error = ?err, "extended CONNECT upstream error trailers failed");
            }
        }
    });
    body
}
