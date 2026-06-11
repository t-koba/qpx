//! HTTP/3 transport helpers used by qpx.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod client;
mod huffman;
mod protocol;
mod qpack;
mod qpack_fields;
mod response;
mod server;
mod sharding;
mod transport;

pub use client::{ClientSession, ExtendedConnectStream, open_extended_connect_stream};
pub use protocol::{PriorityUpdates, StreamPriority};
pub use server::{
    ConnectionInfo, Protocol, Request, RequestHandler, Settings, SupportLevel, WebTransportSession,
    serve_connection,
};
pub use transport::{
    BidiStream, OpenStreams, RequestRecvStream, RequestSendStream, RequestStream, StreamDatagrams,
    StreamRecv, StreamSend, UniRecvStream, UniSendStream,
};

/// Backend label for this HTTP/3 implementation.
pub const BACKEND_NAME: &str = "qpx-h3";

/// Error type used by qpx-h3 APIs.
#[derive(Debug, thiserror::Error)]
pub enum H3Error {
    /// I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// QUIC connection operation failed.
    #[error(transparent)]
    Connection(#[from] quinn::ConnectionError),
    /// QUIC stream was closed before the operation completed.
    #[error(transparent)]
    ClosedStream(#[from] quinn::ClosedStream),
    /// QUIC stream read failed.
    #[error(transparent)]
    Read(#[from] quinn::ReadError),
    /// QUIC stream read-exact operation failed.
    #[error(transparent)]
    ReadExact(#[from] quinn::ReadExactError),
    /// QUIC stream write failed.
    #[error(transparent)]
    Write(#[from] quinn::WriteError),
    /// HTTP type construction failed.
    #[error(transparent)]
    Http(#[from] http::Error),
    /// HTTP header name construction failed.
    #[error(transparent)]
    HeaderName(#[from] http::header::InvalidHeaderName),
    /// HTTP header value construction failed.
    #[error(transparent)]
    HeaderValue(#[from] http::header::InvalidHeaderValue),
    /// Backend, codec, or transport operation failed.
    #[error(transparent)]
    Backend(#[from] anyhow::Error),
}
/// Result type used by qpx-h3 APIs.
pub type H3Result<T> = std::result::Result<T, H3Error>;

/// Returns the support level exposed by this backend.
pub fn support_level() -> SupportLevel {
    SupportLevel::StreamingServer
}

#[doc(hidden)]
pub mod fuzz_support {
    pub fn decode_qpack(data: &[u8]) {
        crate::qpack::fuzz_qpack_decoder(data);
    }
}
