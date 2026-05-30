mod client;
mod huffman;
mod protocol;
mod qpack;
mod qpack_fields;
mod response;
mod server;
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

pub const BACKEND_NAME: &str = "qpx-h3";

pub fn support_level() -> SupportLevel {
    SupportLevel::StreamingServer
}

#[doc(hidden)]
pub mod fuzz_support {
    pub fn decode_qpack(data: &[u8]) {
        crate::qpack::fuzz_qpack_decoder(data);
    }
}
