use anyhow::{Result, anyhow};
use bytes::BytesMut;
use hyper::Version;
use hyper::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING};

pub(crate) const MAX_HEADER_BYTES: usize = 128 * 1024;

pub(crate) fn request_keep_alive(version: Version, headers: &HeaderMap) -> bool {
    match version {
        Version::HTTP_10 => has_connection_token(headers, "keep-alive"),
        _ => !has_connection_token(headers, "close"),
    }
}

pub(crate) fn has_connection_token(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

pub(crate) fn has_only_chunked_transfer_encoding(headers: &HeaderMap) -> Result<bool> {
    let mut tokens = Vec::new();
    for value in headers.get_all(TRANSFER_ENCODING).iter() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid transfer-encoding header"))?;
        for token in raw.split(',') {
            let token = token.trim();
            if !token.is_empty() {
                tokens.push(token);
            }
        }
    }
    match tokens.as_slice() {
        [] => Ok(false),
        [token] if token.eq_ignore_ascii_case("chunked") => Ok(true),
        _ => Err(anyhow!(
            "unsupported transfer-encoding: only a single chunked coding is supported"
        )),
    }
}

pub(crate) fn serialize_headers(headers: &HeaderMap, out: &mut Vec<u8>) -> Result<()> {
    for (name, value) in headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    Ok(())
}

pub(crate) fn find_crlf(buf: &BytesMut) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

pub(crate) fn parse_header_map(headers: &[httparse::Header<'_>]) -> Result<HeaderMap> {
    let mut out = HeaderMap::new();
    for header in headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())?;
        let value = HeaderValue::from_bytes(header.value)?;
        out.append(name, value);
    }
    Ok(out)
}

pub(crate) fn parse_version(version: Option<u8>, missing_message: &'static str) -> Result<Version> {
    match version {
        Some(0) => Ok(Version::HTTP_10),
        Some(1) => Ok(Version::HTTP_11),
        Some(other) => Err(anyhow!("unsupported HTTP version: 1.{}", other)),
        None => Err(anyhow!(missing_message)),
    }
}
