use crate::http::dispatch::DispatchOutcome;
use crate::http::protocol::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::http3::codec::{h1_headers_to_http, http_headers_to_h1};
use crate::policy_context::{AuditRecord, emit_audit_log};
use anyhow::Result;
use bytes::Bytes;
use hyper::{Response, StatusCode};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use qpx_observability::access_log::RequestLogContext;
use std::time::Duration;
use tokio::time::timeout;
use tracing::warn;

pub(super) async fn send_qpx_static_response(
    req_stream: &mut qpx_h3::RequestStream,
    status: StatusCode,
    body: &[u8],
    request_method: &http::Method,
    proxy_name: &str,
) -> Result<()> {
    const STATIC_RESPONSE_SEND_TIMEOUT: Duration = Duration::from_secs(30);

    let response = qpx_static_response(status, body)?;
    let response = finalize_response_for_request(
        request_method,
        http::Version::HTTP_3,
        proxy_name,
        response,
        false,
    );
    send_qpx_response_stream(
        req_stream,
        response,
        request_method,
        body.len(),
        STATIC_RESPONSE_SEND_TIMEOUT,
    )
    .await
}

fn qpx_static_response(status: StatusCode, body: &[u8]) -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .header(http::header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(Bytes::copy_from_slice(body)))?)
}

pub(super) async fn send_qpx_response_stream(
    req_stream: &mut qpx_h3::RequestStream,
    response: Response<Body>,
    request_method: &http::Method,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<()> {
    crate::http3::qpx_stream::send_qpx_response_stream(
        req_stream,
        response,
        request_method,
        max_body_bytes,
        body_read_timeout,
    )
    .await
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
        state.plan.limits.body.max_h3_response_body_bytes,
        Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
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
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        parts.status,
        "QPX HTTP/3 extended CONNECT response",
    )?;
    let mut downstream = Response::builder().status(status).body(Body::empty())?;
    *downstream.headers_mut() = h1_headers_to_http(&parts.headers)?;
    let downstream = finalize_response_with_headers(
        &http::Method::CONNECT,
        http::Version::HTTP_3,
        proxy_name,
        downstream,
        header_control,
        false,
    );
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        downstream.status(),
        "QPX HTTP/3 extended CONNECT response",
    )?;
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
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        parts.status,
        "QPX HTTP/3 extended CONNECT response",
    )?;
    let mut downstream = Response::builder()
        .status(status)
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
    let (mut sender, body) = Body::channel_with_capacity(16);
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

#[cfg(test)]
mod tests {
    use crate::forward::h3::qpx::response::*;

    #[test]
    fn finalize_qpx_connect_head_response_rejects_non_http_status_class() {
        let response = http::Response::builder()
            .status(700)
            .body(())
            .expect("response");
        let err = finalize_qpx_connect_head_response(response, "qpx-test", None)
            .expect_err("status should be rejected");
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn qpx_static_response_sets_exact_content_length() {
        let response =
            qpx_static_response(StatusCode::BAD_REQUEST, b"bad qpx request").expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(http::header::CONTENT_LENGTH),
            Some(&http::HeaderValue::from_static("15"))
        );
    }
}
