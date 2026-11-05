use crate::forward::h3::connect::finalize_h3_connect_response;
use crate::forward::h3::connect_response_body::define_upstream_error_response_body;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::http3::codec::h1_headers_to_http;
use anyhow::Result;
use bytes::Bytes;
use hyper::{Response, StatusCode};
use qpx_core::http_message::Response as OwnerResponse;
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

fn qpx_static_response(status: StatusCode, body: &[u8]) -> Result<OwnerResponse<Body>> {
    let content_length = u64::try_from(body.len())?;
    let mut response = OwnerResponse::new(Body::from(Bytes::copy_from_slice(body)));
    *response.status_mut() = status;
    response.headers_mut().set_content_length(content_length);
    Ok(response)
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
    ctx: H3ConnectAuditContext<'_>,
) -> Result<()> {
    crate::forward::h3::connect::emit_h3_connect_audit(&ctx, response.status().as_u16());
    send_qpx_response_stream(
        req_stream,
        response,
        &http::Method::CONNECT,
        ctx.state.plan.limits.body.max_h3_response_body_bytes,
        Duration::from_millis(ctx.state.plan.limits.timeouts.h3_read_timeout_ms.max(1)),
    )
    .await
}

pub(super) use crate::forward::h3::connect::H3ConnectAuditContext;

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
    Ok(finalize_h3_connect_response(
        proxy_name,
        downstream,
        header_control,
    ))
}

define_upstream_error_response_body!(
    body_from_upstream_qpx_stream,
    qpx_h3::RequestStream,
    |chunk| chunk,
);

#[cfg(test)]
mod tests {
    use crate::forward::h3::connect::finalize_h3_connect_head_response;
    use crate::forward::h3::qpx::response::*;

    #[test]
    fn finalize_qpx_connect_head_response_rejects_non_http_status_class() {
        let response = http::Response::builder()
            .status(700)
            .body(())
            .expect("response");
        let err = finalize_h3_connect_head_response(
            response,
            "qpx-test",
            None,
            "QPX HTTP/3 extended CONNECT response",
        )
        .expect_err("status should be rejected");
        assert!(err.to_string().contains("out of range"));
    }

    #[tokio::test]
    async fn qpx_static_response_preserves_content_length_and_body_at_egress() {
        for (body, expected_length) in [(&b"bad qpx request"[..], 15_u64), (&[][..], 0_u64)] {
            let response = qpx_static_response(StatusCode::BAD_REQUEST, body).expect("response");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().declared_content_length(),
                Ok(Some(expected_length))
            );

            let response = response
                .into_http_for_codec()
                .expect("valid static framing");
            let expected_length = expected_length.to_string();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response.headers().get(http::header::CONTENT_LENGTH),
                Some(&http::HeaderValue::from_str(&expected_length).expect("length header"))
            );
            let bytes = qpx_http::body::to_bytes(response.into_body())
                .await
                .expect("body bytes");
            assert_eq!(bytes.as_ref(), body);
        }
    }
}
