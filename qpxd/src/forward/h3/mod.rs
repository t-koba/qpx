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
