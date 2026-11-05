#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
use qpx_core::config::ConnectUdpConfig;

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
mod backend_h3;
mod connect;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
mod connect_response_body;
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        feature = "http3-backend-qpx"
    ))
))]
mod invalid;
#[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
mod qpx;
#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
mod server_tls;
mod streaming;

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) use backend_h3::*;
#[cfg(all(
    feature = "http3",
    not(any(
        all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")),
        feature = "http3-backend-qpx"
    ))
))]
pub(crate) use invalid::*;
#[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
pub(crate) use qpx::*;

#[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
pub(super) fn resolve_connect_udp(config: Option<ConnectUdpConfig>) -> ConnectUdpConfig {
    config.unwrap_or(ConnectUdpConfig {
        enabled: false,
        idle_timeout_secs: 30,
        max_capsule_buffer_bytes: 256 * 1024,
        uri_template: None,
    })
}

#[cfg(feature = "http3")]
pub(crate) fn prepare_http3_listener_socket(
    listener_name: &str,
    udp_socket: std::net::UdpSocket,
    inherited_broker: Option<crate::http3::quinn_socket::QuinnBrokerStream>,
) -> anyhow::Result<crate::http3::quinn_socket::PreparedServerEndpointSocket> {
    crate::http3::quinn_socket::prepare_server_endpoint_socket(
        listener_name,
        crate::http3::quinn_socket::QuinnBrokerKind::Forward,
        udp_socket,
        inherited_broker,
        std::sync::Arc::new(crate::http3::quinn_socket::NoopQuinnUdpIngressFilter),
    )
}

/// Builds an owner-backed HTTP/3 502 status/body; callers retain finalization.
/// The fixed valid status and opaque body made the former HTTP builder infallible.
#[cfg(feature = "http3")]
pub(in crate::forward::h3) fn h3_bad_gateway_base_response(
    proxy_error: String,
) -> qpx_core::http_message::Response<qpx_http::body::Body> {
    let mut response =
        qpx_core::http_message::Response::new(qpx_http::body::Body::from(proxy_error));
    *response.status_mut() = http::StatusCode::BAD_GATEWAY;
    response
}

#[cfg(all(test, feature = "http3"))]
mod h3_bad_gateway_base_response_tests {
    use http::{Method, StatusCode, Version, header::CONTENT_LENGTH};
    use qpx_http::body::to_bytes;

    #[tokio::test]
    async fn ordinary_bad_gateway_preserves_status_body_and_absent_length() {
        for body in ["proxy error", ""] {
            for method in [Method::GET, Method::HEAD] {
                let response = super::h3_bad_gateway_base_response(body.to_owned());
                assert!(!response.headers().contains_content_length());
                let response = crate::http::protocol::l7::finalize_response_for_request(
                    &method,
                    Version::HTTP_3,
                    "qpx-test",
                    response,
                    false,
                )
                .into_http_for_codec()
                .expect("valid framing");
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
                assert!(!response.headers().contains_key(CONTENT_LENGTH));
                let bytes = to_bytes(response.into_body()).await.expect("body bytes");
                assert_eq!(
                    bytes.as_ref(),
                    if method == Method::HEAD {
                        b""
                    } else {
                        body.as_bytes()
                    }
                );
            }
        }
    }

    #[cfg(any(feature = "http3-backend-h3", feature = "http3-backend-qpx"))]
    #[tokio::test]
    async fn connect_bad_gateway_matches_previous_finalized_output() {
        use super::connect::{finalize_h3_connect_owner_response, finalize_h3_connect_response};
        use qpx_core::{config::HeaderControl, rules::CompiledHeaderControl};
        let control = CompiledHeaderControl::compile(&HeaderControl {
            response_set: [("x-error".into(), "configured".into())].into(),
            ..Default::default()
        })
        .expect("header control");
        for body in ["proxy error", "upstream CONNECT-UDP failed", ""] {
            let response = finalize_h3_connect_owner_response(
                "qpx-test",
                super::h3_bad_gateway_base_response(body.to_owned()),
                Some(&control),
            )
            .into_http_for_codec()
            .expect("valid framing");
            let previous = finalize_h3_connect_response(
                "qpx-test",
                http::Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(qpx_http::body::Body::from(body.to_owned()))
                    .expect("fixed valid status"),
                Some(&control),
            );
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(response.headers(), previous.headers());
            assert!(!response.headers().contains_key(CONTENT_LENGTH));
            let bytes = to_bytes(response.into_body()).await.expect("body bytes");
            assert_eq!(bytes.as_ref(), body.as_bytes());
            assert_eq!(
                bytes,
                to_bytes(previous.into_body()).await.expect("previous body")
            );
        }
    }
}
