mod codec;
mod connection;
#[cfg(test)]
mod decode;
mod dynamic_table;
mod encode;
mod encoder;
mod encoder_stream;
mod errors;
mod field_reader;
mod fields;
mod static_table;

#[cfg(test)]
mod tests;

pub(crate) use connection::QpackConnection;
pub(crate) use encoder_stream::EncoderStreamError;

pub(crate) use crate::qpack_fields::validate_h3_regular_field;
#[cfg(test)]
pub(crate) use decode::decode_request_head_from_fields;
pub(crate) use encode::{encode_request_head, encode_response_head, encode_trailers};
pub(crate) use encoder::fuzz_qpack_decoder;
#[cfg(test)]
pub(super) use errors::FieldDecodeError;
pub(crate) use errors::HeaderDecodeError;

#[cfg(test)]
use crate::qpack_fields::{append_header, validate_h3_response_field, validate_h3_trailer_field};
#[cfg(test)]
use codec::{encode_header_prefix, encode_prefixed_int, encode_string};
#[cfg(test)]
use dynamic_table::DecoderState;
#[cfg(test)]
use encoder::{decode_field_section_prefix, decode_required_insert_count};
#[cfg(test)]
use fields::decode_response_status;
#[cfg(test)]
use static_table::{STATIC_TABLE, static_field};

pub(crate) const DEFAULT_DYNAMIC_TABLE_CAPACITY: usize = 4096;
pub(crate) const DEFAULT_MAX_BLOCKED_STREAMS: u64 = 16;
pub(crate) const DEFAULT_ENCODER_STREAM_BUFFER_BYTES: usize = 1024 * 1024;
const HEADER_ENTRY_OVERHEAD: u64 = 32;
const DECODER_INSTRUCTION_QUEUE_DEPTH: usize = 1024;

#[derive(Debug)]
pub(crate) struct DecodedRequestHead {
    pub(crate) request: http::Request<()>,
    pub(crate) protocol: Option<String>,
}

#[derive(Debug)]
struct DecodedFields {
    fields: Vec<(String, Vec<u8>)>,
    dynamic_ref: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct DecodedResponseHead {
    pub(crate) response: http::Response<()>,
}
