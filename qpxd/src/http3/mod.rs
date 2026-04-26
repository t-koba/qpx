pub(crate) mod capsule;
#[cfg(feature = "http3")]
pub(crate) mod codec;
#[cfg(all(feature = "http3", feature = "http3-backend-h3"))]
pub(crate) mod datagram;
#[cfg(all(feature = "http3", feature = "http3-backend-h3"))]
pub(crate) mod listener;
#[cfg(feature = "http3")]
pub(crate) mod quic;
pub(crate) mod quinn_socket;
#[cfg(all(feature = "http3", feature = "http3-backend-h3"))]
pub(crate) mod server;
