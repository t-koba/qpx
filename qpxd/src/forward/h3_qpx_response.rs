use crate::http::body::Body;
use crate::policy_context::{emit_audit_log, AuditRecord};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use hyper::{Response, StatusCode};
use qpx_observability::access_log::RequestLogContext;
use std::time::Duration;

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
            kind: "forward",
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
    pub(super) outcome: &'static str,
    pub(super) matched_rule: Option<&'a str>,
    pub(super) ext_authz_policy_id: Option<&'a str>,
    pub(super) log_context: &'a RequestLogContext,
}
