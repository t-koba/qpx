use super::codec::{encode_header_prefix, encode_prefixed_int, encode_string};
use super::static_table::{static_exact_match, static_name_index};
use crate::H3Result as Result;
use crate::qpack_fields::validate_h3_regular_field;
use http::HeaderMap;

pub(crate) fn encode_request_head(
    head: &http::Request<()>,
    protocol: Option<&str>,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(request_head_capacity(head, protocol));
    encode_header_prefix(&mut out, 0, 0, 0);

    encode_field(&mut out, ":method", head.method().as_str().as_bytes());
    if let Some(scheme) = head.uri().scheme_str() {
        encode_field(&mut out, ":scheme", scheme.as_bytes());
    }
    if let Some(authority) = head.uri().authority() {
        encode_field(&mut out, ":authority", authority.as_str().as_bytes());
    }
    if let Some(path) = head.uri().path_and_query() {
        encode_field(&mut out, ":path", path.as_str().as_bytes());
    }
    if let Some(protocol) = protocol {
        encode_field(&mut out, ":protocol", protocol.as_bytes());
    }
    for (name, value) in head.headers() {
        validate_h3_regular_field(name.as_str(), value.as_bytes())?;
        encode_field(&mut out, name.as_str(), value.as_bytes());
    }
    Ok(out)
}

pub(crate) fn encode_response_head(head: &http::Response<()>) -> Vec<u8> {
    let mut out = Vec::with_capacity(response_head_capacity(head));
    encode_header_prefix(&mut out, 0, 0, 0);

    let status = status_bytes(head.status());
    encode_field(&mut out, ":status", &status);
    for (name, value) in head.headers() {
        encode_field(&mut out, name.as_str(), value.as_bytes());
    }
    out
}

pub(crate) fn encode_trailers(trailers: &HeaderMap) -> Vec<u8> {
    let mut out = Vec::with_capacity(header_map_capacity(trailers) + 8);
    encode_header_prefix(&mut out, 0, 0, 0);
    for (name, value) in trailers {
        encode_field(&mut out, name.as_str(), value.as_bytes());
    }
    out
}

fn encode_field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    if let Some(index) = static_exact_match(name, value) {
        encode_prefixed_int(out, 6, 0b11, index as u64);
        return;
    }
    if let Some(index) = static_name_index(name) {
        encode_prefixed_int(out, 4, 0b0101, index as u64);
        encode_string(out, 8, 0, value);
        return;
    }
    encode_string(out, 4, 0b0010, name.as_bytes());
    encode_string(out, 8, 0, value);
}

fn request_head_capacity(head: &http::Request<()>, protocol: Option<&str>) -> usize {
    let mut capacity = header_map_capacity(head.headers()) + 32;
    capacity += head.method().as_str().len();
    capacity += head.uri().scheme_str().map(str::len).unwrap_or_default();
    capacity += head
        .uri()
        .authority()
        .map(|authority| authority.as_str().len())
        .unwrap_or_default();
    capacity += head
        .uri()
        .path_and_query()
        .map(|path| path.as_str().len())
        .unwrap_or_default();
    capacity += protocol.map(str::len).unwrap_or_default();
    capacity
}

fn response_head_capacity(head: &http::Response<()>) -> usize {
    header_map_capacity(head.headers()) + 16
}

fn header_map_capacity(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 8)
        .sum()
}

fn status_bytes(status: http::StatusCode) -> [u8; 3] {
    let code = status.as_u16();
    [
        b'0' + ((code / 100) % 10) as u8,
        b'0' + ((code / 10) % 10) as u8,
        b'0' + (code % 10) as u8,
    ]
}
