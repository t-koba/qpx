use crate::forward::h3::connect_response_body::define_upstream_error_response_body;
use crate::http::protocol::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::http3::codec::{h1_headers_to_http, http_headers_to_h1};
use anyhow::Result;
use bytes::Bytes;
use hyper::{Response, StatusCode};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use std::time::Duration;

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

pub(super) async fn send_qpx_response_stream<R: crate::http::response_carrier::ResponseCarrier>(
    req_stream: &mut qpx_h3::RequestStream,
    response: R,
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

pub(super) async fn send_qpx_policy_response<R: crate::http::response_carrier::ResponseCarrier>(
    req_stream: &mut qpx_h3::RequestStream,
    response: R,
    ctx: H3ConnectPolicyResponseContext<'_>,
) -> Result<()> {
    crate::forward::h3::connect::emit_h3_connect_policy_audit(&ctx, response.status().as_u16());
    send_qpx_response_stream(
        req_stream,
        response,
        &http::Method::CONNECT,
        ctx.state.plan.limits.body.max_h3_response_body_bytes,
        Duration::from_millis(ctx.state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
    )
    .await
}

pub(super) use crate::forward::h3::connect::H3ConnectPolicyResponseContext;

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

define_upstream_error_response_body!(
    body_from_upstream_qpx_stream,
    qpx_h3::RequestStream,
    |chunk| chunk,
);

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
