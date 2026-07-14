use anyhow::{Result, anyhow};
use bytes::{BufMut, BytesMut};
use hyper::Version;
use hyper::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_LENGTH,
    CONTENT_TYPE, COOKIE, DATE, ETAG, EXPECT, EXPIRES, FORWARDED, HOST, HeaderMap, HeaderName,
    HeaderValue, LAST_MODIFIED, SERVER, SET_COOKIE, TRAILER, TRANSFER_ENCODING, UPGRADE, VARY, VIA,
};
use memchr::memchr;
use std::cell::RefCell;

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

pub(crate) fn serialize_headers(headers: &HeaderMap, out: &mut impl BufMut) -> Result<()> {
    for (name, value) in headers {
        out.put_slice(name.as_str().as_bytes());
        out.put_slice(b": ");
        out.put_slice(value.as_bytes());
        out.put_slice(b"\r\n");
    }
    Ok(())
}

pub(crate) fn find_crlf(buf: &BytesMut) -> Option<usize> {
    let mut cursor = 0;
    while let Some(offset) = memchr(b'\r', &buf[cursor..]) {
        let index = cursor + offset;
        if buf.get(index + 1).copied() == Some(b'\n') {
            return Some(index);
        }
        cursor = index + 1;
    }
    None
}

pub(crate) fn parse_header_map(headers: &[httparse::Header<'_>]) -> Result<HeaderMap> {
    let mut out = HeaderMap::with_capacity(headers.len());
    parse_header_map_into(headers, &mut out, false)?;
    Ok(out)
}

pub(crate) fn parse_header_map_recycled(headers: &[httparse::Header<'_>]) -> Result<HeaderMap> {
    let mut out = super::header_pool::take(headers.len().saturating_add(4));
    parse_header_map_into(headers, &mut out, true)?;
    Ok(out)
}

pub(crate) fn parse_response_header_map_recycled(
    headers: &[httparse::Header<'_>],
) -> Result<HeaderMap> {
    let mut out = super::header_pool::take(headers.len().saturating_add(4));
    parse_header_map_into(headers, &mut out, true)?;
    Ok(out)
}

fn parse_header_map_into(
    headers: &[httparse::Header<'_>],
    out: &mut HeaderMap,
    intern_common_values: bool,
) -> Result<()> {
    for header in headers {
        let name = parse_header_name(header.name.as_bytes())?;
        let value = if intern_common_values {
            intern_common_header_value(&name, header.value)?
        } else {
            HeaderValue::from_bytes(header.value)?
        };
        out.append(name, value);
    }
    Ok(())
}

fn parse_header_name(raw: &[u8]) -> Result<HeaderName> {
    let known = match raw.len() {
        3 if raw.eq_ignore_ascii_case(b"age") => Some(http::header::AGE),
        3 if raw.eq_ignore_ascii_case(b"via") => Some(VIA),
        4 if raw.eq_ignore_ascii_case(b"date") => Some(DATE),
        4 if raw.eq_ignore_ascii_case(b"etag") => Some(ETAG),
        4 if raw.eq_ignore_ascii_case(b"host") => Some(HOST),
        4 if raw.eq_ignore_ascii_case(b"vary") => Some(VARY),
        6 if raw.eq_ignore_ascii_case(b"cookie") => Some(COOKIE),
        6 if raw.eq_ignore_ascii_case(b"expect") => Some(EXPECT),
        6 if raw.eq_ignore_ascii_case(b"server") => Some(SERVER),
        7 if raw.eq_ignore_ascii_case(b"expires") => Some(EXPIRES),
        7 if raw.eq_ignore_ascii_case(b"trailer") => Some(TRAILER),
        7 if raw.eq_ignore_ascii_case(b"upgrade") => Some(UPGRADE),
        9 if raw.eq_ignore_ascii_case(b"forwarded") => Some(FORWARDED),
        10 if raw.eq_ignore_ascii_case(b"connection") => Some(CONNECTION),
        10 if raw.eq_ignore_ascii_case(b"set-cookie") => Some(SET_COOKIE),
        12 if raw.eq_ignore_ascii_case(b"content-type") => Some(CONTENT_TYPE),
        13 if raw.eq_ignore_ascii_case(b"accept-ranges") => Some(ACCEPT_RANGES),
        13 if raw.eq_ignore_ascii_case(b"cache-control") => Some(CACHE_CONTROL),
        13 if raw.eq_ignore_ascii_case(b"last-modified") => Some(LAST_MODIFIED),
        14 if raw.eq_ignore_ascii_case(b"content-length") => Some(CONTENT_LENGTH),
        16 if raw.eq_ignore_ascii_case(b"content-encoding") => Some(CONTENT_ENCODING),
        16 if raw.eq_ignore_ascii_case(b"content-language") => Some(CONTENT_LANGUAGE),
        17 if raw.eq_ignore_ascii_case(b"transfer-encoding") => Some(TRANSFER_ENCODING),
        _ => None,
    };
    known.map_or_else(|| HeaderName::from_bytes(raw).map_err(Into::into), Ok)
}

const MAX_INTERNED_COMMON_VALUES_PER_NAME: usize = 4;
const MAX_INTERNED_COMMON_HEADER_VALUE_BYTES: usize = 256;
const INTERNED_COMMON_HEADER_NAME_COUNT: usize = 20;

thread_local! {
    static INTERNED_COMMON_HEADER_VALUES: RefCell<[Vec<HeaderValue>; INTERNED_COMMON_HEADER_NAME_COUNT]> =
        RefCell::new(std::array::from_fn(|_| Vec::new()));
}

fn intern_common_header_value(name: &HeaderName, raw: &[u8]) -> Result<HeaderValue> {
    if raw.len() > MAX_INTERNED_COMMON_HEADER_VALUE_BYTES {
        return HeaderValue::from_bytes(raw).map_err(Into::into);
    }
    let Some(slot) = common_header_value_slot(name) else {
        return HeaderValue::from_bytes(raw).map_err(Into::into);
    };
    INTERNED_COMMON_HEADER_VALUES.with_borrow_mut(|values_by_name| {
        let values = &mut values_by_name[slot];
        if let Some(cached) = values.iter().find(|cached| cached.as_bytes() == raw) {
            return Ok(cached.clone());
        }
        let value = HeaderValue::from_bytes(raw)?;
        if values.len() == MAX_INTERNED_COMMON_VALUES_PER_NAME {
            values.remove(0);
        }
        values.push(value.clone());
        Ok(value)
    })
}

fn common_header_value_slot(name: &HeaderName) -> Option<usize> {
    match name.as_str() {
        "accept-ranges" => Some(0),
        "age" => Some(1),
        "cache-control" => Some(2),
        "connection" => Some(3),
        "content-encoding" => Some(4),
        "content-language" => Some(5),
        "content-length" => Some(6),
        "content-type" => Some(7),
        "date" => Some(8),
        "etag" => Some(9),
        "expect" => Some(10),
        "expires" => Some(11),
        "host" => Some(12),
        "last-modified" => Some(13),
        "server" => Some(14),
        "trailer" => Some(15),
        "transfer-encoding" => Some(16),
        "upgrade" => Some(17),
        "vary" => Some(18),
        "via" => Some(19),
        _ => None,
    }
}

pub(crate) fn parse_version(version: Option<u8>, missing_message: &'static str) -> Result<Version> {
    match version {
        Some(0) => Ok(Version::HTTP_10),
        Some(1) => Ok(Version::HTTP_11),
        Some(other) => Err(anyhow!("unsupported HTTP version: 1.{}", other)),
        None => Err(anyhow!(missing_message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_parser_interns_bounded_non_sensitive_values() {
        let parsed = [httparse::Header {
            name: "Content-Type",
            value: b"application/qpx-intern-test",
        }];

        let first = parse_response_header_map_recycled(&parsed).expect("first parse");
        let second = parse_response_header_map_recycled(&parsed).expect("second parse");

        assert_eq!(
            first[http::header::CONTENT_TYPE].as_bytes().as_ptr(),
            second[http::header::CONTENT_TYPE].as_bytes().as_ptr()
        );
    }

    #[test]
    fn response_parser_never_interns_set_cookie_values() {
        let parsed = [httparse::Header {
            name: "Set-Cookie",
            value: b"session=qpx-sensitive-test; Secure; HttpOnly",
        }];

        let first = parse_response_header_map_recycled(&parsed).expect("first parse");
        let second = parse_response_header_map_recycled(&parsed).expect("second parse");

        assert_ne!(
            first[http::header::SET_COOKIE].as_bytes().as_ptr(),
            second[http::header::SET_COOKIE].as_bytes().as_ptr()
        );
    }

    #[test]
    fn request_parser_interns_host_but_not_cookie() {
        let parsed = [
            httparse::Header {
                name: "Host",
                value: b"example.test",
            },
            httparse::Header {
                name: "Cookie",
                value: b"session=qpx-sensitive-test",
            },
        ];

        let first = parse_header_map_recycled(&parsed).expect("first parse");
        let second = parse_header_map_recycled(&parsed).expect("second parse");

        assert_eq!(
            first[http::header::HOST].as_bytes().as_ptr(),
            second[http::header::HOST].as_bytes().as_ptr()
        );
        assert_ne!(
            first[http::header::COOKIE].as_bytes().as_ptr(),
            second[http::header::COOKIE].as_bytes().as_ptr()
        );
    }

    #[test]
    fn header_name_fast_path_is_case_insensitive_and_preserves_extensions() {
        assert_eq!(
            parse_header_name(b"cOnTeNt-LeNgTh").unwrap(),
            CONTENT_LENGTH
        );
        assert_eq!(
            parse_header_name(b"X-Qpx-Extension").unwrap(),
            HeaderName::from_static("x-qpx-extension")
        );
    }
}
