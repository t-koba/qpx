use crate::forward::h3::connect::finalize_h3_connect_owner_response;
use crate::forward::h3::connect_response_body::define_upstream_error_response_body;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::http3::codec::h1_headers_to_http;
use anyhow::Result;
use bytes::Bytes;
use hyper::StatusCode;
use qpx_core::http_message::{OrdinaryHeaderName, Response as OwnerResponse};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;
use std::time::Duration;

pub(super) async fn send_qpx_static_response(
    req_stream: &mut qpx_h3::RequestStream,
    status: StatusCode,
    body: &[u8],
    request_method: &http::Method,
    proxy_name: &str,
    send_timeout: Duration,
) -> Result<()> {
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
        send_timeout,
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
) -> Result<OwnerResponse<Body>> {
    let (parts, _) = response.into_parts();
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        parts.status,
        "QPX HTTP/3 extended CONNECT response",
    )?;
    let headers = h1_headers_to_http(&parts.headers)?;
    let downstream = owner_qpx_connect_error_response(
        status,
        &headers,
        body_from_upstream_qpx_stream(upstream, body_read_timeout),
    )?;
    Ok(finalize_h3_connect_owner_response(
        proxy_name,
        downstream,
        header_control,
    ))
}

fn owner_qpx_connect_error_response(
    status: StatusCode,
    headers: &http::HeaderMap,
    body: Body,
) -> Result<OwnerResponse<Body>> {
    let mut response = OwnerResponse::new(body);
    *response.status_mut() = status;
    for (name, value) in headers {
        if name == http::header::CONTENT_LENGTH {
            response
                .headers_mut()
                .append_content_length_value(value.clone());
        } else {
            let name = OrdinaryHeaderName::try_from(name.clone())?;
            response.headers_mut().append(name, value.clone());
        }
    }
    Ok(response)
}

define_upstream_error_response_body!(
    body_from_upstream_qpx_stream,
    qpx_h3::RequestStream,
    |chunk| chunk,
);

#[cfg(test)]
mod tests {
    use crate::forward::h3::connect::{
        finalize_h3_connect_head_response, finalize_h3_connect_response,
    };
    use crate::forward::h3::qpx::response::*;
    use qpx_core::config::HeaderControl;

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
    async fn qpx_connect_error_owner_preserves_import_and_finalized_output() {
        fn assert_headers_eq(actual: &http::HeaderMap, expected: &http::HeaderMap) {
            assert_eq!(actual, expected);
            for name in expected.keys() {
                let values = |headers: &http::HeaderMap| {
                    headers
                        .get_all(name)
                        .iter()
                        .map(|v| (v.as_bytes().to_vec(), v.is_sensitive()))
                        .collect::<Vec<_>>()
                };
                assert_eq!(values(actual), values(expected), "{name}");
            }
        }

        let control = CompiledHeaderControl::compile(&HeaderControl {
            response_set: [("x-finalized".into(), "configured".into())].into(),
            ..Default::default()
        })
        .expect("header control");
        let cases: [Vec<&[u8]>; 6] = [
            vec![],
            vec![b"0"],
            vec![b"4"],
            vec![b"4", b"4"],
            vec![b"invalid"],
            vec![b"4", b"5"],
        ];
        for lengths in cases {
            let mut decoded = http::HeaderMap::new();
            decoded.append("x-repeat", http::HeaderValue::from_static("first"));
            let mut sensitive =
                http::HeaderValue::from_bytes(b"second\x80").expect("opaque header bytes");
            sensitive.set_sensitive(true);
            decoded.append("x-repeat", sensitive);
            decoded.append("cookie", http::HeaderValue::from_static("a=1"));
            let mut cookie = http::HeaderValue::from_static("b=2");
            cookie.set_sensitive(true);
            decoded.append("cookie", cookie);
            decoded.append("set-cookie", http::HeaderValue::from_static("first=1"));
            decoded.append("set-cookie", http::HeaderValue::from_static("second=2"));
            decoded.append("x-finalized", http::HeaderValue::from_static("upstream"));
            for value in &lengths {
                let mut value = http::HeaderValue::from_bytes(value).expect("length value");
                value.set_sensitive(true);
                decoded.append(http::header::CONTENT_LENGTH, value);
            }
            let headers = h1_headers_to_http(&decoded).expect("convert H3 headers");
            let status = StatusCode::BAD_GATEWAY;
            let body = b"oops";

            // Compare the imported head before finalization can normalize framing.
            let imported = owner_qpx_connect_error_response(status, &headers, Body::empty())
                .expect("owner import")
                .into_http_for_library();
            assert_eq!(imported.status(), status);
            assert_eq!(imported.version(), http::Version::HTTP_11);
            assert_headers_eq(imported.headers(), &headers);
            let imported_lengths: Vec<_> = imported
                .headers()
                .get_all(http::header::CONTENT_LENGTH)
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect();
            assert_eq!(imported_lengths, lengths);

            let owner = owner_qpx_connect_error_response(status, &headers, Body::from(&body[..]))
                .expect("owner import");
            let actual = finalize_h3_connect_owner_response("qpx-test", owner, Some(&control))
                .into_http_for_library();
            let mut standard = http::Response::builder()
                .status(status)
                .body(Body::from(&body[..]))
                .expect("standard response");
            *standard.headers_mut() = headers;
            let expected = finalize_h3_connect_response("qpx-test", standard, Some(&control));
            assert_eq!(actual.status(), expected.status());
            assert_eq!(actual.version(), expected.version());
            assert_eq!(actual.version(), http::Version::HTTP_11);
            assert_headers_eq(actual.headers(), expected.headers());
            assert_eq!(actual.headers().get("x-finalized").unwrap(), "configured");
            let actual_body = qpx_http::body::to_bytes(actual.into_body())
                .await
                .expect("owner body");
            let expected_body = qpx_http::body::to_bytes(expected.into_body())
                .await
                .expect("standard body");
            assert_eq!(actual_body, expected_body);
            assert_eq!(actual_body.as_ref(), body);
        }
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
