#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
mod backend_h3;
mod connect;
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

/// Builds the raw HTTP/3 502 status/body; callers retain their own fallback and finalization.
#[cfg(feature = "http3")]
pub(in crate::forward::h3) fn h3_bad_gateway_base_response(
    proxy_error: String,
) -> http::Result<http::Response<qpx_http::body::Body>> {
    http::Response::builder()
        .status(http::StatusCode::BAD_GATEWAY)
        .body(qpx_http::body::Body::from(proxy_error))
}

#[cfg(all(test, feature = "http3"))]
mod h3_bad_gateway_base_response_tests {
    #[tokio::test]
    async fn bad_gateway_base_response_preserves_body_bytes() {
        let response = super::h3_bad_gateway_base_response("proxy error".to_owned())
            .expect("base response builds");
        assert_eq!(response.status(), http::StatusCode::BAD_GATEWAY);
        let bytes = qpx_http::body::to_bytes(response.into_body())
            .await
            .expect("body bytes");
        assert_eq!(bytes.as_ref(), b"proxy error");
    }
}
