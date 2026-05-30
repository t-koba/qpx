pub(crate) mod capsule;
#[cfg(feature = "http3")]
pub(crate) mod codec;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod datagram;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod listener;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod priority;
#[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
pub(crate) mod qpx_stream;
#[cfg(feature = "http3")]
pub(crate) mod quic;
pub(crate) mod quinn_socket;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod server;
#[cfg(feature = "http3")]
pub(crate) mod stream_limits;
