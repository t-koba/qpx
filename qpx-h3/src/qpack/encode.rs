use super::codec::{encode_header_prefix, encode_prefixed_int, encode_string};
use super::static_table::{static_exact_match, static_name_index};
use anyhow::Result;
use http::HeaderMap;

pub(crate) fn encode_request_head(
    head: &http::Request<()>,
    protocol: Option<&str>,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_header_prefix(&mut out, 0, 0, 0, 0);

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
        encode_field(&mut out, name.as_str(), value.as_bytes());
    }
    Ok(out)
}

pub(crate) fn encode_response_head(head: &http::Response<()>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_header_prefix(&mut out, 0, 0, 0, 0);

    let status = head.status().as_u16().to_string();
    encode_field(&mut out, ":status", status.as_bytes());
    for (name, value) in head.headers() {
        encode_field(&mut out, name.as_str(), value.as_bytes());
    }
    out
}

pub(crate) fn encode_trailers(trailers: &HeaderMap) -> Vec<u8> {
    let mut out = Vec::new();
    encode_header_prefix(&mut out, 0, 0, 0, 0);
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
