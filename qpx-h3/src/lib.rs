mod client;
mod huffman;
mod protocol;
mod qpack;
mod qpack_fields;
mod response;
mod server;
mod transport;

pub use client::{open_extended_connect_stream, ExtendedConnectStream};
pub use server::{
    serve_connection, ConnectionInfo, Protocol, Request, RequestHandler, Response, Settings,
    SupportLevel, WebTransportSession,
};
pub use transport::{
    BidiStream, OpenStreams, RequestStream, StreamDatagrams, UniRecvStream, UniSendStream,
};

pub const BACKEND_NAME: &str = "qpx-h3";

pub fn support_level() -> SupportLevel {
    SupportLevel::BufferedServer
}

#[doc(hidden)]
pub mod fuzz_support {
    pub fn decode_qpack(data: &[u8]) {
        crate::qpack::fuzz_qpack_decoder(data);
    }
}
