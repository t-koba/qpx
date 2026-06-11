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
#[cfg(feature = "http3")]
pub(crate) mod metrics;
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
#[cfg(feature = "http3")]
pub(crate) mod response_error;
#[cfg(feature = "http3")]
pub(crate) mod response_rpc;
#[cfg(feature = "http3")]
pub(crate) mod response_sse;
#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(crate) mod server;
#[cfg(feature = "http3")]
pub(crate) mod stream_limits;

#[cfg(feature = "http3-backend-h3")]
pub(crate) fn h3_buf_to_bytes(mut buf: impl bytes::Buf) -> bytes::Bytes {
    let len = buf.remaining();
    buf.copy_to_bytes(len)
}
