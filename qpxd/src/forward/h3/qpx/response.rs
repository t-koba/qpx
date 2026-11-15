use crate::forward::h3::connect::finalize_h3_connect_owner_response;
use crate::forward::h3::connect_response_body::define_upstream_error_response_body;
use crate::http::protocol::l7::finalize_response_for_request;
#[cfg(test)]
use crate::http3::codec::h1_headers_to_http;
use crate::http3::codec::join_cookie_values;
use crate::runtime::{ExecutionPlan, RuntimeState};
use anyhow::Result;
use bytes::Bytes;
use hyper::StatusCode;
use qpx_core::http_message::{
    Headers as OwnerHeaders, OrdinaryHeaderName, Response as OwnerResponse,
};
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

pub(super) async fn send_qpx_response_stream_with_timeouts<
    R: crate::http::response_carrier::ResponseCarrier,
>(
    req_stream: &mut qpx_h3::RequestStream,
    response: R,
    request_method: &http::Method,
    max_body_bytes: usize,
    body_read_timeout: Duration,
    body_send_timeout: Duration,
) -> Result<()> {
    crate::http3::qpx_stream::send_qpx_response_stream_with_timeouts(
        req_stream,
        response,
        request_method,
        max_body_bytes,
        body_read_timeout,
        body_send_timeout,
    )
    .await
}

pub(super) async fn send_qpx_extended_connect_error_response(
    req_stream: &mut qpx_h3::RequestStream,
    response: OwnerResponse<Body>,
    state: &RuntimeState,
    selected_plan: &ExecutionPlan,
    body_read_timeout: Duration,
) -> Result<()> {
    let h3_read_timeout_ms = state.plan.limits.timeouts.h3_read_timeout_ms;
    send_qpx_response_stream_with_timeouts(
        req_stream,
        response,
        &http::Method::CONNECT,
        state.plan.limits.body.max_h3_response_body_bytes,
        body_read_timeout,
        crate::forward::h3::h3_response_send_timeout(
            h3_read_timeout_ms,
            Some(selected_plan.streaming.body_send_timeout_ms),
        ),
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
        crate::forward::h3::h3_response_send_timeout(
            ctx.state.plan.limits.timeouts.h3_read_timeout_ms,
            None,
        ),
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
    let response = owner_qpx_connect_error_response(response)?;
    let downstream =
        response.map_body(|_| body_from_upstream_qpx_stream(upstream, body_read_timeout));
    Ok(finalize_h3_connect_owner_response(
        proxy_name,
        downstream,
        header_control,
    ))
}

fn owner_qpx_connect_error_response(response: http::Response<()>) -> Result<OwnerResponse<()>> {
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        response.status(),
        "QPX HTTP/3 extended CONNECT response",
    )?;
    let mut response = OwnerResponse::from_http(response);
    *response.status_mut() = status;
    *response.version_mut() = http::Version::HTTP_11;
    response.extensions_mut().clear();
    join_qpx_h3_cookie_fields(response.headers_mut())?;
    Ok(response)
}

fn join_qpx_h3_cookie_fields(headers: &mut OwnerHeaders) -> Result<()> {
    let cookie = OrdinaryHeaderName::try_from(http::header::COOKIE)?;
    let mut values = headers.get_all(&cookie);
    let Some(first) = values.next() else {
        return Ok(());
    };
    let Some(second) = values.next() else {
        return Ok(());
    };

    let mut merged = join_cookie_values(first, second)?;
    for value in values {
        merged = join_cookie_values(&merged, value)?;
    }
    headers.insert(cookie, merged);
    Ok(())
}

#[cfg(test)]
fn legacy_owner_qpx_connect_error_response(
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
    use crate::http3::codec::http_headers_to_h1;
    use http::{Method, Response};
    use qpx_core::config::HeaderControl;
    use tokio::time::{Duration, Instant, timeout};

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

        let invalid = http::Response::builder()
            .status(700)
            .version(http::Version::HTTP_3)
            .body(())
            .expect("upstream error head");
        let err = owner_qpx_connect_error_response(invalid)
            .expect_err("error response status should be rejected");
        assert!(err.to_string().contains("out of range"));
    }

    #[tokio::test]
    async fn qpx_connect_error_owner_preserves_import_and_finalized_output() {
        #[derive(Clone, Debug, PartialEq, Eq)]
        struct UpstreamHeadMarker;

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
            decoded.append("cookie", http::HeaderValue::from_static(""));
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
            let joined_cookie = headers.get("cookie").expect("joined cookies");
            assert_eq!(joined_cookie.as_bytes(), b"a=1; ; b=2");
            assert!(joined_cookie.is_sensitive());
            let status = StatusCode::BAD_GATEWAY;
            let body = b"oops";

            // Compare the imported head before finalization can normalize framing.
            let imported = legacy_owner_qpx_connect_error_response(status, &headers, Body::empty())
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

            let mut direct_error_head = http::Response::builder()
                .status(status)
                .version(http::Version::HTTP_3)
                .body(())
                .expect("upstream error head");
            *direct_error_head.headers_mut() = decoded.clone();
            direct_error_head
                .extensions_mut()
                .insert(UpstreamHeadMarker);
            let direct_imported = owner_qpx_connect_error_response(direct_error_head)
                .expect("direct owner import")
                .into_http_for_library();
            assert_eq!(direct_imported.status(), status);
            assert_eq!(direct_imported.version(), http::Version::HTTP_11);
            assert_headers_eq(direct_imported.headers(), imported.headers());
            let direct_lengths: Vec<_> = direct_imported
                .headers()
                .get_all(http::header::CONTENT_LENGTH)
                .iter()
                .map(http::HeaderValue::as_bytes)
                .collect();
            assert_eq!(direct_lengths, lengths);
            assert!(
                direct_imported
                    .extensions()
                    .get::<UpstreamHeadMarker>()
                    .is_none()
            );

            let mut upstream_head = http::Response::builder()
                .status(StatusCode::OK)
                .version(http::Version::HTTP_3)
                .body(())
                .expect("upstream response head");
            *upstream_head.headers_mut() = decoded.clone();
            upstream_head.extensions_mut().insert(UpstreamHeadMarker);
            let actual_head = finalize_h3_connect_head_response(
                upstream_head,
                "qpx-test",
                Some(&control),
                "QPX HTTP/3 extended CONNECT response",
            )
            .expect("owner-finalized response head");
            let mut standard_head = http::Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .expect("standard response head");
            *standard_head.headers_mut() = headers.clone();
            let standard_head =
                finalize_h3_connect_response("qpx-test", standard_head, Some(&control));
            let mut expected_head = http::Response::builder()
                .status(standard_head.status())
                .body(())
                .expect("standard H3 response head");
            *expected_head.headers_mut() =
                http_headers_to_h1(standard_head.headers()).expect("convert standard H3 headers");
            assert_eq!(actual_head.status(), expected_head.status());
            assert_eq!(actual_head.version(), expected_head.version());
            assert_eq!(actual_head.version(), http::Version::HTTP_11);
            assert!(
                actual_head
                    .extensions()
                    .get::<UpstreamHeadMarker>()
                    .is_none()
            );
            assert_headers_eq(actual_head.headers(), expected_head.headers());

            let mut direct_error_head = http::Response::builder()
                .status(status)
                .version(http::Version::HTTP_3)
                .body(())
                .expect("upstream error head");
            *direct_error_head.headers_mut() = decoded;
            direct_error_head
                .extensions_mut()
                .insert(UpstreamHeadMarker);
            let owner = owner_qpx_connect_error_response(direct_error_head)
                .expect("direct owner import")
                .map_body(|_| Body::from(&body[..]));
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
    async fn selected_plan_send_budget_bounds_qpx_connect_error_under_flow_control() -> Result<()> {
        timeout(Duration::from_secs(5), async {
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

            let mut tasks = tokio::task::JoinSet::new();
            let (_client, conn, mut streams) =
                crate::http3::qpx_stream::test_support::qpx_loopback(&mut tasks, Some(1024))
                    .await?;
            let mut builder = ::h3::client::builder();
            builder.enable_extended_connect(true).enable_datagram(true);
            let (mut connection, mut sender) = builder
                .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
                .await?;
            tasks.spawn(async move {
                let _ = std::future::poll_fn(|cx| connection.poll_close(cx)).await;
            });
            let uri = http::Uri::builder()
                .scheme("https")
                .authority("localhost")
                .path_and_query("/.well-known/masque/udp/127.0.0.1/443/")
                .build()?;
            let mut request = http::Request::builder()
                .method(Method::CONNECT)
                .uri(uri)
                .body(())?;
            request
                .extensions_mut()
                .insert(::h3::ext::Protocol::CONNECT_UDP);
            let mut remote = sender.send_request(request).await?;
            remote.finish().await?;
            let mut local = timeout(Duration::from_secs(1), streams.recv())
                .await?
                .expect("captured extended-CONNECT stream");
            let response = OwnerResponse::from_http(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from(Bytes::from(vec![b'x'; 1024 * 1024])))?,
            );
            let body_read_timeout =
                Duration::from_millis(state.plan.limits.timeouts.h3_read_timeout_ms.max(1));
            let send_started = Instant::now();
            let (sent, received) = tokio::join!(
                send_qpx_extended_connect_error_response(
                    &mut local,
                    response,
                    &state,
                    selected_plan,
                    body_read_timeout,
                ),
                async {
                    let response = remote.recv_response().await?;
                    assert_eq!(response.status(), StatusCode::FORBIDDEN);
                    Ok::<_, anyhow::Error>(())
                }
            );
            received?;
            assert!(
                send_started.elapsed() < Duration::from_millis(500),
                "matched send timeout must win over the 2s read timeout"
            );
            let error = sent.expect_err("flow control must block the large error body");
            assert!(
                error
                    .to_string()
                    .contains("qpx-h3 response body send timed out"),
                "unexpected QPX send error: {error}"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await?
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
