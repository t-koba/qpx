use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use http::header::{HeaderMap, HeaderName, HeaderValue};
use http::{Method, StatusCode, Version};
use std::cell::RefCell;
use std::sync::OnceLock;
use tracing::warn;

const MAX_POOLED_RAW_HEAD_BUFFERS: usize = 64;
const MAX_POOLED_RAW_HEAD_CAPACITY: usize = 128 * 1024;

thread_local! {
    static RAW_HEAD_BUFFERS: RefCell<Vec<BytesMut>> = const { RefCell::new(Vec::new()) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawHttp1BodyFraming {
    Empty,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

#[derive(Debug)]
pub(crate) struct RawHttp1ResponseHead {
    header_lines: BytesMut,
    proxy_status: Option<HeaderMap>,
    framing: RawHttp1BodyFraming,
    upstream_keep_alive: bool,
    has_date: bool,
    finalized: bool,
    status: StatusCode,
    materialized_headers: OnceLock<HeaderMap>,
    serialized_http11_head: OnceLock<Bytes>,
}

impl Clone for RawHttp1ResponseHead {
    fn clone(&self) -> Self {
        let mut header_lines = take_header_buffer(self.header_lines.len());
        header_lines.extend_from_slice(&self.header_lines);
        let serialized_http11_head = OnceLock::new();
        if let Some(serialized) = self.serialized_http11_head.get() {
            let _ = serialized_http11_head.set(serialized.clone());
        }
        let materialized_headers = OnceLock::new();
        if let Some(headers) = self.materialized_headers.get() {
            let _ = materialized_headers.set(headers.clone());
        }
        Self {
            header_lines,
            proxy_status: self.proxy_status.clone(),
            framing: self.framing,
            upstream_keep_alive: self.upstream_keep_alive,
            has_date: self.has_date,
            finalized: self.finalized,
            status: self.status,
            materialized_headers,
            serialized_http11_head,
        }
    }
}

impl Drop for RawHttp1ResponseHead {
    fn drop(&mut self) {
        let mut header_lines = std::mem::take(&mut self.header_lines);
        if header_lines.capacity() > MAX_POOLED_RAW_HEAD_CAPACITY {
            return;
        }
        header_lines.clear();
        let _ = RAW_HEAD_BUFFERS.try_with(|buffers| {
            let mut buffers = buffers.borrow_mut();
            if buffers.len() < MAX_POOLED_RAW_HEAD_BUFFERS {
                buffers.push(header_lines);
            }
        });
    }
}

impl RawHttp1ResponseHead {
    pub(crate) fn from_parsed(
        headers: &[httparse::Header<'_>],
        request_method: &Method,
        status: StatusCode,
        version: Version,
    ) -> Result<Self> {
        validate_field_values(headers)?;
        let content_length = parse_content_length(headers)?;
        let no_body = request_method == Method::HEAD
            || status.is_informational()
            || status == StatusCode::NO_CONTENT
            || status == StatusCode::RESET_CONTENT
            || status == StatusCode::NOT_MODIFIED;
        let chunked = if no_body {
            false
        } else {
            has_only_chunked_transfer_encoding(headers)?
        };
        let framing = if no_body || content_length == Some(0) {
            RawHttp1BodyFraming::Empty
        } else if chunked {
            RawHttp1BodyFraming::Chunked
        } else if let Some(length) = content_length {
            RawHttp1BodyFraming::ContentLength(length)
        } else {
            RawHttp1BodyFraming::CloseDelimited
        };
        let upstream_keep_alive = match version {
            Version::HTTP_10 => has_connection_token(headers, b"keep-alive"),
            _ => !has_connection_token(headers, b"close"),
        };
        let strip_content_length = (no_body && request_method != Method::HEAD) || chunked;
        let preserve_proxy_auth = status == StatusCode::PROXY_AUTHENTICATION_REQUIRED;
        let has_connection_header = headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("connection"));
        let header_capacity = headers
            .iter()
            .map(|header| header.name.len() + header.value.len() + 4)
            .sum::<usize>()
            .saturating_add(128);
        let mut header_lines = take_header_buffer(header_capacity);
        let mut proxy_status = None;
        let mut has_date = false;

        for header in headers {
            let name = header.name.as_bytes();
            if is_sanitized_hop_header(name, preserve_proxy_auth)
                || (has_connection_header && connection_lists_header(headers, name))
                || (strip_content_length && name.eq_ignore_ascii_case(b"content-length"))
            {
                continue;
            }
            if name.eq_ignore_ascii_case(b"proxy-status") {
                let map = proxy_status.get_or_insert_with(HeaderMap::new);
                map.append(
                    HeaderName::from_static("proxy-status"),
                    HeaderValue::from_bytes(header.value)?,
                );
                continue;
            }
            if name.eq_ignore_ascii_case(b"date") {
                has_date = true;
            }
            append_header_line(&mut header_lines, name, header.value);
        }

        Ok(Self {
            header_lines,
            proxy_status,
            framing,
            upstream_keep_alive,
            has_date,
            finalized: false,
            status,
            materialized_headers: OnceLock::new(),
            serialized_http11_head: OnceLock::new(),
        })
    }

    pub(crate) fn finalize(&mut self, request_version: Version, proxy_name: &str) {
        if self.finalized {
            return;
        }
        debug_assert!(self.materialized_headers.get().is_none());
        if !self.has_date {
            let date = crate::http::protocol::l7::cached_date_header_value();
            append_header_line(&mut self.header_lines, b"Date", date.as_bytes());
        }
        self.append_proxy_status(proxy_name);
        if let Some(via) =
            qpx_http::protocol::semantics::via_header_value(request_version, proxy_name)
        {
            append_header_line(&mut self.header_lines, b"Via", via.as_bytes());
        }
        self.finalized = true;
    }

    pub(crate) fn materialized_headers(&self) -> Result<HeaderMap> {
        if !self.finalized {
            return Err(anyhow!("raw HTTP/1 response head was not finalized"));
        }
        if let Some(headers) = self.materialized_headers.get() {
            return Ok(headers.clone());
        }

        let mut block = BytesMut::with_capacity(self.header_lines.len() + 2);
        block.extend_from_slice(&self.header_lines);
        block.extend_from_slice(b"\r\n");
        let mut parsed = [httparse::EMPTY_HEADER; 128];
        let headers = match httparse::parse_headers(&block, &mut parsed)? {
            httparse::Status::Complete((consumed, headers)) if consumed == block.len() => {
                crate::http::codec::h1_common::parse_header_map(headers)?
            }
            httparse::Status::Complete(_) => {
                return Err(anyhow!("raw HTTP/1 response head has trailing bytes"));
            }
            httparse::Status::Partial => {
                return Err(anyhow!("raw HTTP/1 response head is incomplete"));
            }
        };
        let _ = self.materialized_headers.set(headers);
        self.materialized_headers
            .get()
            .cloned()
            .ok_or_else(|| anyhow!("materialized response headers were not initialized"))
    }

    fn append_proxy_status(&mut self, proxy_name: &str) {
        if self.proxy_status.is_none() {
            match qpx_http::proxy_status::proxy_identifier_value(proxy_name) {
                Ok(value) => {
                    append_header_line(&mut self.header_lines, b"Proxy-Status", value.as_bytes());
                    return;
                }
                Err(error) => {
                    warn!(error = %error, "proxy identifier requires structured serialization");
                }
            }
        }

        let mut headers = self.proxy_status.take().unwrap_or_default();
        if let Err(error) = qpx_http::proxy_status::append_proxy_status(&mut headers, proxy_name) {
            warn!(error = %error, "discarding invalid inbound Proxy-Status field");
            headers.clear();
            if let Err(error) =
                qpx_http::proxy_status::append_proxy_status(&mut headers, proxy_name)
            {
                warn!(error = %error, "failed to emit Proxy-Status field");
                return;
            }
        }
        for value in headers.get_all("proxy-status") {
            append_header_line(&mut self.header_lines, b"Proxy-Status", value.as_bytes());
        }
    }

    pub(crate) fn header_lines(&self) -> &[u8] {
        self.header_lines.as_ref()
    }

    pub(crate) fn framing(&self) -> RawHttp1BodyFraming {
        self.framing
    }

    pub(crate) fn upstream_keep_alive(&self) -> bool {
        self.upstream_keep_alive
    }

    pub(crate) fn is_finalized(&self) -> bool {
        self.finalized
    }

    pub(crate) fn serialized_http11_head(&self) -> Bytes {
        debug_assert!(self.finalized);
        self.serialized_http11_head
            .get_or_init(|| {
                let reason = self.status.canonical_reason().unwrap_or("");
                let mut head = BytesMut::with_capacity(self.header_lines.len() + 32);
                head.extend_from_slice(b"HTTP/1.1 ");
                head.extend_from_slice(self.status.as_str().as_bytes());
                if !reason.is_empty() {
                    head.extend_from_slice(b" ");
                    head.extend_from_slice(reason.as_bytes());
                }
                head.extend_from_slice(b"\r\n");
                head.extend_from_slice(&self.header_lines);
                head.extend_from_slice(b"\r\n");
                head.freeze()
            })
            .clone()
    }
}

fn take_header_buffer(required_capacity: usize) -> BytesMut {
    RAW_HEAD_BUFFERS.with_borrow_mut(|buffers| {
        let mut buffer = buffers
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(required_capacity));
        buffer.clear();
        buffer.reserve(required_capacity);
        buffer
    })
}

fn append_header_line(out: &mut BytesMut, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

fn validate_field_values(headers: &[httparse::Header<'_>]) -> Result<()> {
    for header in headers {
        if header
            .value
            .iter()
            .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
        {
            return Err(anyhow!("invalid upstream HTTP field value"));
        }
    }
    Ok(())
}

fn parse_content_length(headers: &[httparse::Header<'_>]) -> Result<Option<u64>> {
    let mut parsed = None;
    for header in headers {
        if !header.name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let raw = std::str::from_utf8(header.value)
            .map_err(|_| anyhow!("invalid content-length header"))?;
        for part in raw.split(',') {
            let value = part
                .trim()
                .parse::<u64>()
                .map_err(|_| anyhow!("invalid content-length value: {}", part.trim()))?;
            match parsed {
                Some(existing) if existing != value => {
                    return Err(anyhow!("conflicting content-length values"));
                }
                Some(_) => {}
                None => parsed = Some(value),
            }
        }
    }
    Ok(parsed)
}

fn has_only_chunked_transfer_encoding(headers: &[httparse::Header<'_>]) -> Result<bool> {
    let mut count = 0usize;
    let mut chunked = false;
    for header in headers {
        if !header.name.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        let raw = std::str::from_utf8(header.value)
            .map_err(|_| anyhow!("invalid transfer-encoding header"))?;
        for token in raw
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            count += 1;
            chunked = token.eq_ignore_ascii_case("chunked");
        }
    }
    match (count, chunked) {
        (0, _) => Ok(false),
        (1, true) => Ok(true),
        _ => Err(anyhow!(
            "unsupported transfer-encoding: only a single chunked coding is supported"
        )),
    }
}

fn has_connection_token(headers: &[httparse::Header<'_>], expected: &[u8]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && header
                .value
                .split(|byte| *byte == b',')
                .map(trim_ascii)
                .any(|token| token.eq_ignore_ascii_case(expected))
    })
}

fn connection_lists_header(headers: &[httparse::Header<'_>], name: &[u8]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && header
                .value
                .split(|byte| *byte == b',')
                .map(trim_ascii)
                .any(|token| token.eq_ignore_ascii_case(name))
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn is_sanitized_hop_header(name: &[u8], preserve_proxy_auth: bool) -> bool {
    name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-authorization")
        || name.eq_ignore_ascii_case(b"proxy-connection")
        || name.eq_ignore_ascii_case(b"te")
        || name.eq_ignore_ascii_case(b"trailer")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"upgrade")
        || (!preserve_proxy_auth
            && (name.eq_ignore_ascii_case(b"proxy-authenticate")
                || name.eq_ignore_ascii_case(b"proxy-authentication-info")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_head_sanitizes_and_preserves_end_to_end_fields() {
        let headers = [
            httparse::Header {
                name: "Content-Length",
                value: b"4",
            },
            httparse::Header {
                name: "Connection",
                value: b"keep-alive, X-Hop",
            },
            httparse::Header {
                name: "X-Hop",
                value: b"discard",
            },
            httparse::Header {
                name: "Content-Type",
                value: b"text/plain",
            },
        ];
        let mut raw = RawHttp1ResponseHead::from_parsed(
            &headers,
            &Method::GET,
            StatusCode::OK,
            Version::HTTP_11,
        )
        .expect("raw head");
        raw.finalize(Version::HTTP_11, "qpx");
        let encoded = std::str::from_utf8(raw.header_lines()).expect("ASCII head");
        assert!(encoded.contains("Content-Length: 4\r\n"));
        assert!(encoded.contains("Content-Type: text/plain\r\n"));
        assert!(!encoded.contains("Connection:"));
        assert!(!encoded.contains("X-Hop:"));
        assert!(encoded.contains("Proxy-Status: qpx\r\n"));
        assert!(encoded.contains("Via: 1.1 qpx\r\n"));
        let materialized = raw.materialized_headers().expect("materialized headers");
        assert_eq!(materialized.get(http::header::CONTENT_LENGTH).unwrap(), "4");
        assert_eq!(materialized.get("content-type").unwrap(), "text/plain");
        assert_eq!(materialized.get("proxy-status").unwrap(), "qpx");
        assert_eq!(materialized.get("via").unwrap(), "1.1 qpx");
        assert!(!materialized.contains_key("connection"));
        assert!(!materialized.contains_key("x-hop"));
        assert_eq!(raw.framing(), RawHttp1BodyFraming::ContentLength(4));
        assert!(raw.upstream_keep_alive());
    }

    #[test]
    fn raw_head_rejects_conflicting_content_length() {
        let headers = [httparse::Header {
            name: "Content-Length",
            value: b"4, 5",
        }];
        let error = RawHttp1ResponseHead::from_parsed(
            &headers,
            &Method::GET,
            StatusCode::OK,
            Version::HTTP_11,
        )
        .expect_err("conflict");
        assert!(error.to_string().contains("conflicting content-length"));
    }

    #[test]
    fn connection_nominated_proxy_status_is_not_forwarded() {
        let headers = [
            httparse::Header {
                name: "Connection",
                value: b"Proxy-Status",
            },
            httparse::Header {
                name: "Proxy-Status",
                value: b"untrusted",
            },
            httparse::Header {
                name: "Content-Length",
                value: b"0",
            },
        ];
        let mut raw = RawHttp1ResponseHead::from_parsed(
            &headers,
            &Method::GET,
            StatusCode::OK,
            Version::HTTP_11,
        )
        .expect("raw head");
        raw.finalize(Version::HTTP_11, "qpx");
        let encoded = std::str::from_utf8(raw.header_lines()).expect("ASCII head");
        assert!(encoded.contains("Proxy-Status: qpx\r\n"));
        assert!(!encoded.contains("untrusted"));
    }
}
