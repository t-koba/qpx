use super::io::{
    determine_response_body_kind, fill_buffer_capped, response_body_allows_reuse,
    response_keep_alive,
};
#[cfg(test)]
use super::io::{
    fill_buffer, read_buf_with_timeout, read_crlf_line, read_limited_with_timeout,
    read_trailer_headers,
};
use super::{
    Http1ConnectionRecycler, INITIAL_READ_BUF_SIZE, InterimResponseHead, MAX_HEADER_BYTES,
    RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT, RawHttp1BodyFraming, RawHttp1ResponseHead,
};
#[cfg(test)]
use super::{MAX_CHUNKED_BODY_BYTES, READ_BUF_SIZE};
use crate::http::codec::h1_common::{parse_response_header_map_recycled, parse_version};
use anyhow::{Result, anyhow};
use bytes::{Buf, BytesMut};
use hyper::header::CONTENT_LENGTH;
use hyper::{HeaderMap, Method, Response, StatusCode, Version};
use qpx_http::body::Body;
use std::cell::RefCell;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
#[cfg(test)]
use tokio::time::Duration;

#[derive(Debug, Clone, Copy)]
pub(super) enum ResponseBodyKind {
    Empty,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

pub(super) struct ParsedResponseHead {
    pub(super) version: Version,
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body_kind: ResponseBodyKind,
}

#[derive(Clone)]
pub(super) struct RawParsedResponseHead {
    pub(super) version: Version,
    pub(super) status: StatusCode,
    pub(super) raw: Arc<RawHttp1ResponseHead>,
}

struct CachedFinalizedRawResponseHead {
    wire_head: Box<[u8]>,
    request_method: Method,
    request_version: Version,
    proxy_name: String,
    parsed: RawParsedResponseHead,
}

thread_local! {
    static FINALIZED_RAW_RESPONSE_HEAD: RefCell<Option<CachedFinalizedRawResponseHead>> =
        const { RefCell::new(None) };
}

pub(super) async fn read_response_head_with_interim<S>(
    stream: &mut S,
    mut buf: BytesMut,
    request_method: &Method,
) -> Result<(Vec<InterimResponseHead>, ParsedResponseHead, BytesMut)>
where
    S: AsyncRead + Unpin,
{
    buf.clear();
    buf.reserve(INITIAL_READ_BUF_SIZE);
    let mut interim = Vec::new();
    loop {
        let parsed = loop {
            if buf.is_empty() {
                fill_buffer_capped(
                    stream,
                    &mut buf,
                    1,
                    MAX_HEADER_BYTES,
                    RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
                    None,
                )
                .await?;
            }
            match try_parse_response_head(&buf, request_method)? {
                Some(parsed) => break parsed,
                None => {
                    fill_buffer_capped(
                        stream,
                        &mut buf,
                        1,
                        MAX_HEADER_BYTES,
                        RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
                        None,
                    )
                    .await?;
                }
            }
        };

        let (consumed, version, status, headers, body_kind) = parsed;
        buf.advance(consumed);
        if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
            interim.push(InterimResponseHead { status, headers });
            continue;
        }
        return Ok((
            interim,
            ParsedResponseHead {
                version,
                status,
                headers,
                body_kind,
            },
            buf,
        ));
    }
}

pub(super) async fn read_finalized_raw_response_head_with_interim<S>(
    stream: &mut S,
    buf: BytesMut,
    request_method: &Method,
    request_version: Version,
    proxy_name: &str,
) -> Result<(Vec<InterimResponseHead>, RawParsedResponseHead, BytesMut)>
where
    S: AsyncRead + Unpin,
{
    read_finalized_raw_response_head_with_interim_inner(
        stream,
        buf,
        request_method,
        request_version,
        proxy_name,
        true,
    )
    .await
}

pub(super) async fn read_finalized_raw_response_head_with_interim_under_external_deadline<S>(
    stream: &mut S,
    buf: BytesMut,
    request_method: &Method,
    request_version: Version,
    proxy_name: &str,
) -> Result<(Vec<InterimResponseHead>, RawParsedResponseHead, BytesMut)>
where
    S: AsyncRead + Unpin,
{
    read_finalized_raw_response_head_with_interim_inner(
        stream,
        buf,
        request_method,
        request_version,
        proxy_name,
        false,
    )
    .await
}

async fn read_finalized_raw_response_head_with_interim_inner<S>(
    stream: &mut S,
    mut buf: BytesMut,
    request_method: &Method,
    request_version: Version,
    proxy_name: &str,
    enforce_idle_timeout: bool,
) -> Result<(Vec<InterimResponseHead>, RawParsedResponseHead, BytesMut)>
where
    S: AsyncRead + Unpin,
{
    buf.clear();
    buf.reserve(INITIAL_READ_BUF_SIZE);
    let mut interim = Vec::new();
    loop {
        let parsed = loop {
            if buf.is_empty() {
                fill_raw_response_head_buffer(stream, &mut buf, enforce_idle_timeout).await?;
            }
            if let Some(cached) = cached_finalized_raw_response_head(
                &buf,
                request_method,
                request_version,
                proxy_name,
            ) {
                break (
                    cached.0,
                    cached.1.version,
                    cached.1.status,
                    None,
                    Some(cached.1.raw),
                );
            }
            match try_parse_raw_response_head(&buf, request_method)? {
                Some(parsed) => break parsed,
                None => {
                    fill_raw_response_head_buffer(stream, &mut buf, enforce_idle_timeout).await?;
                }
            }
        };

        let (consumed, version, status, headers, raw) = parsed;
        let wire_head = raw
            .as_ref()
            .is_some_and(|head| !head.is_finalized())
            .then(|| Box::<[u8]>::from(&buf[..consumed]));
        buf.advance(consumed);
        if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
            let headers = headers
                .ok_or_else(|| anyhow!("informational raw response is missing parsed headers"))?;
            interim.push(InterimResponseHead { status, headers });
            continue;
        }
        let mut raw =
            raw.ok_or_else(|| anyhow!("final raw response is missing response metadata"))?;
        if !raw.is_finalized() {
            Arc::make_mut(&mut raw).finalize(request_version, proxy_name);
            let wire_head = wire_head
                .ok_or_else(|| anyhow!("new raw response is missing its serialized head"))?;
            cache_finalized_raw_response_head(
                wire_head,
                request_method,
                request_version,
                proxy_name,
                version,
                status,
                raw.clone(),
            );
        }
        return Ok((
            interim,
            RawParsedResponseHead {
                version,
                status,
                raw,
            },
            buf,
        ));
    }
}

async fn fill_raw_response_head_buffer<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    enforce_idle_timeout: bool,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    if enforce_idle_timeout {
        return fill_buffer_capped(
            stream,
            buf,
            1,
            MAX_HEADER_BYTES,
            RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
            None,
        )
        .await;
    }
    if buf.len() >= MAX_HEADER_BYTES {
        return Err(anyhow!("HTTP/1 header block exceeded configured limit"));
    }
    buf.reserve(1);
    if stream.read_buf(buf).await? == 0 {
        return Err(super::UpstreamConnectionClosed.into());
    }
    Ok(())
}

fn cached_finalized_raw_response_head(
    buf: &[u8],
    request_method: &Method,
    request_version: Version,
    proxy_name: &str,
) -> Option<(usize, RawParsedResponseHead)> {
    FINALIZED_RAW_RESPONSE_HEAD.with_borrow(|cache| {
        let cached = cache.as_ref()?;
        let consumed = cached.wire_head.len();
        (cached.request_method == *request_method
            && cached.request_version == request_version
            && cached.proxy_name == proxy_name
            && buf.len() >= consumed
            && &buf[..consumed] == cached.wire_head.as_ref())
        .then(|| (consumed, cached.parsed.clone()))
    })
}

fn cache_finalized_raw_response_head(
    wire_head: Box<[u8]>,
    request_method: &Method,
    request_version: Version,
    proxy_name: &str,
    version: Version,
    status: StatusCode,
    raw: Arc<RawHttp1ResponseHead>,
) {
    FINALIZED_RAW_RESPONSE_HEAD.with_borrow_mut(|cache| {
        *cache = Some(CachedFinalizedRawResponseHead {
            wire_head,
            request_method: request_method.clone(),
            request_version,
            proxy_name: proxy_name.to_owned(),
            parsed: RawParsedResponseHead {
                version,
                status,
                raw,
            },
        });
    });
}

const COMMON_HTTP1_RESPONSE_HEADERS: usize = 32;
const MAX_HTTP1_RESPONSE_HEADERS: usize = 128;

type ParsedResponseHeadTuple = (usize, Version, StatusCode, HeaderMap, ResponseBodyKind);
type RawParsedResponseHeadTuple = (
    usize,
    Version,
    StatusCode,
    Option<HeaderMap>,
    Option<Arc<RawHttp1ResponseHead>>,
);

fn try_parse_response_head(
    buf: &[u8],
    request_method: &Method,
) -> Result<Option<ParsedResponseHeadTuple>> {
    let mut common_headers =
        [const { std::mem::MaybeUninit::uninit() }; COMMON_HTTP1_RESPONSE_HEADERS];
    let mut response = httparse::Response::new(&mut []);
    match httparse::ParserConfig::default().parse_response_with_uninit_headers(
        &mut response,
        buf,
        &mut common_headers,
    ) {
        Ok(httparse::Status::Complete(consumed)) => {
            return finish_parsed_response_head(&response, consumed, request_method).map(Some);
        }
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => {}
        Err(error) => return Err(error.into()),
    }

    let mut maximum_headers =
        [const { std::mem::MaybeUninit::uninit() }; MAX_HTTP1_RESPONSE_HEADERS];
    let mut response = httparse::Response::new(&mut []);
    match httparse::ParserConfig::default().parse_response_with_uninit_headers(
        &mut response,
        buf,
        &mut maximum_headers,
    ) {
        Ok(httparse::Status::Complete(consumed)) => {
            finish_parsed_response_head(&response, consumed, request_method).map(Some)
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn try_parse_raw_response_head(
    buf: &[u8],
    request_method: &Method,
) -> Result<Option<RawParsedResponseHeadTuple>> {
    let mut common_headers =
        [const { std::mem::MaybeUninit::uninit() }; COMMON_HTTP1_RESPONSE_HEADERS];
    let mut response = httparse::Response::new(&mut []);
    match httparse::ParserConfig::default().parse_response_with_uninit_headers(
        &mut response,
        buf,
        &mut common_headers,
    ) {
        Ok(httparse::Status::Complete(consumed)) => {
            return finish_raw_response_head(&response, consumed, request_method).map(Some);
        }
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => {}
        Err(error) => return Err(error.into()),
    }

    let mut maximum_headers =
        [const { std::mem::MaybeUninit::uninit() }; MAX_HTTP1_RESPONSE_HEADERS];
    let mut response = httparse::Response::new(&mut []);
    match httparse::ParserConfig::default().parse_response_with_uninit_headers(
        &mut response,
        buf,
        &mut maximum_headers,
    ) {
        Ok(httparse::Status::Complete(consumed)) => {
            finish_raw_response_head(&response, consumed, request_method).map(Some)
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn finish_raw_response_head(
    response: &httparse::Response<'_, '_>,
    consumed: usize,
    request_method: &Method,
) -> Result<RawParsedResponseHeadTuple> {
    let version = parse_version(response.version, "missing upstream HTTP version")?;
    let code = response
        .code
        .ok_or_else(|| anyhow!("upstream response missing status code"))?;
    if !(100..=599).contains(&code) {
        return Err(anyhow!("upstream response status is out of range: {code}"));
    }
    let status = StatusCode::from_u16(code)?;
    if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
        return Ok((
            consumed,
            version,
            status,
            Some(parse_response_header_map_recycled(response.headers)?),
            None,
        ));
    }
    Ok((
        consumed,
        version,
        status,
        None,
        Some(Arc::new(RawHttp1ResponseHead::from_parsed(
            response.headers,
            request_method,
            status,
            version,
        )?)),
    ))
}

fn finish_parsed_response_head(
    response: &httparse::Response<'_, '_>,
    consumed: usize,
    request_method: &Method,
) -> Result<ParsedResponseHeadTuple> {
    let version = parse_version(response.version, "missing upstream HTTP version")?;
    let code = response
        .code
        .ok_or_else(|| anyhow!("upstream response missing status code"))?;
    if !(100..=599).contains(&code) {
        return Err(anyhow!("upstream response status is out of range: {code}"));
    }
    let status = StatusCode::from_u16(code)?;
    let headers = parse_response_header_map_recycled(response.headers)?;
    let body_kind = determine_response_body_kind(request_method, status, &headers)?;
    Ok((consumed, version, status, headers, body_kind))
}

pub(super) fn build_response<S>(
    stream: S,
    mut head: ParsedResponseHead,
    mut prefix: BytesMut,
    write_buf: BytesMut,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Response<Body>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if matches!(head.body_kind, ResponseBodyKind::Chunked) {
        head.headers.remove(CONTENT_LENGTH);
    }
    let upstream_reusable = head.status != StatusCode::SWITCHING_PROTOCOLS
        && response_keep_alive(head.version, &head.headers);
    let body = match head.body_kind {
        ResponseBodyKind::Empty => {
            if let Some(recycler) = recycler.filter(|_| upstream_reusable && prefix.is_empty()) {
                recycler.recycle(stream, prefix, write_buf);
            }
            Body::empty()
        }
        ResponseBodyKind::ContentLength(length) if prefix.len() as u64 >= length => {
            let bytes = prefix.split_to(length as usize).freeze();
            if let Some(recycler) = recycler.filter(|_| upstream_reusable && prefix.is_empty()) {
                recycler.recycle(stream, prefix, write_buf);
            }
            Body::from(bytes)
        }
        kind => Body::wrap(super::body::Http1ResponseBody::new(
            stream,
            prefix,
            kind,
            write_buf,
            recycler.filter(|_| response_body_allows_reuse(kind) && upstream_reusable),
        )),
    }
    .mark_read_timeout_enforced()
    .mark_trailers_sanitized();
    let mut response = Response::new(body);
    *response.status_mut() = head.status;
    *response.version_mut() = head.version;
    *response.headers_mut() = head.headers;
    response
}

pub(super) fn build_raw_response<S>(
    stream: S,
    head: RawParsedResponseHead,
    prefix: BytesMut,
    write_buf: BytesMut,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Response<Body>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    build_raw_response_inner(
        stream,
        head,
        prefix,
        write_buf,
        recycler,
        None,
        super::MAX_EMITTED_BODY_FRAME_SIZE,
    )
}

pub(super) fn build_materialized_raw_response<S>(
    stream: S,
    head: RawParsedResponseHead,
    prefix: BytesMut,
    write_buf: BytesMut,
    recycler: Option<Http1ConnectionRecycler<S>>,
    max_body_frame_size: usize,
) -> Result<Response<Body>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let headers = head.raw.materialized_headers()?;
    Ok(build_raw_response_inner(
        stream,
        head,
        prefix,
        write_buf,
        recycler,
        Some(headers),
        max_body_frame_size,
    ))
}

fn build_raw_response_inner<S>(
    stream: S,
    head: RawParsedResponseHead,
    mut prefix: BytesMut,
    write_buf: BytesMut,
    recycler: Option<Http1ConnectionRecycler<S>>,
    materialized_headers: Option<HeaderMap>,
    max_body_frame_size: usize,
) -> Response<Body>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let body_kind = match head.raw.framing() {
        RawHttp1BodyFraming::Empty => ResponseBodyKind::Empty,
        RawHttp1BodyFraming::ContentLength(length) => ResponseBodyKind::ContentLength(length),
        RawHttp1BodyFraming::Chunked => ResponseBodyKind::Chunked,
        RawHttp1BodyFraming::CloseDelimited => ResponseBodyKind::CloseDelimited,
    };
    let upstream_reusable =
        head.status != StatusCode::SWITCHING_PROTOCOLS && head.raw.upstream_keep_alive();
    let body = match body_kind {
        ResponseBodyKind::Empty => {
            if let Some(recycler) = recycler.filter(|_| upstream_reusable && prefix.is_empty()) {
                recycler.recycle(stream, prefix, write_buf);
            }
            Body::empty()
        }
        ResponseBodyKind::ContentLength(length) if prefix.len() as u64 >= length => {
            let bytes = prefix.split_to(length as usize).freeze();
            if let Some(recycler) = recycler.filter(|_| upstream_reusable && prefix.is_empty()) {
                recycler.recycle(stream, prefix, write_buf);
            }
            Body::from(bytes)
        }
        kind => Body::wrap(super::body::Http1ResponseBody::new_with_max_frame_size(
            stream,
            prefix,
            kind,
            write_buf,
            recycler.filter(|_| response_body_allows_reuse(kind) && upstream_reusable),
            max_body_frame_size,
        )),
    }
    .mark_read_timeout_enforced()
    .mark_trailers_sanitized();
    let mut response = Response::new(body);
    *response.status_mut() = head.status;
    *response.version_mut() = head.version;
    if let Some(headers) = materialized_headers {
        *response.headers_mut() = headers;
    } else {
        response.extensions_mut().insert(head.raw);
    }
    response
}

#[cfg(test)]
pub(super) async fn forward_close_delimited_body<S>(
    mut stream: S,
    mut prefix: BytesMut,
    sender: &mut qpx_http::body::Sender,
    read_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !prefix.is_empty() {
        sender.send_data(prefix.split().freeze()).await?;
    }
    let mut chunk = BytesMut::with_capacity(READ_BUF_SIZE);
    loop {
        chunk.clear();
        chunk.reserve(READ_BUF_SIZE);
        let n = read_buf_with_timeout(&mut stream, &mut chunk, read_timeout, Some(sender)).await?;
        if n == 0 {
            return Ok(());
        }
        sender.send_data(chunk.split().freeze()).await?;
    }
}

#[cfg(test)]
pub(super) async fn forward_chunked_body<S>(
    mut stream: S,
    mut buf: BytesMut,
    sender: &mut qpx_http::body::Sender,
    read_timeout: Duration,
) -> Result<(S, BytesMut)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut total_body_bytes = 0u64;
    loop {
        let line = read_crlf_line(&mut stream, &mut buf, read_timeout, sender).await?;
        let size_token = line
            .split(|b| *b == b';')
            .next()
            .ok_or_else(|| anyhow!("invalid chunk-size line"))?;
        let size_str = std::str::from_utf8(size_token)?.trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| anyhow!("invalid chunk-size: {}", size_str))?;
        total_body_bytes = total_body_bytes
            .checked_add(size as u64)
            .ok_or_else(|| anyhow!("chunked response body size overflow"))?;
        if total_body_bytes > MAX_CHUNKED_BODY_BYTES {
            return Err(anyhow!(
                "chunked response body exceeds hard cap of {} bytes",
                MAX_CHUNKED_BODY_BYTES
            ));
        }
        if size == 0 {
            let trailers =
                read_trailer_headers(&mut stream, &mut buf, read_timeout, sender).await?;
            if let Some(trailers) = trailers {
                sender.send_trailers(trailers).await?;
            }
            return Ok((stream, buf));
        }

        forward_chunk_payload_segmented(&mut stream, &mut buf, size, sender, read_timeout).await?;
    }
}

#[cfg(test)]
async fn forward_chunk_payload_segmented<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    mut remaining: usize,
    sender: &mut qpx_http::body::Sender,
    read_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut chunk = BytesMut::with_capacity(READ_BUF_SIZE);
    while remaining > 0 {
        if !buf.is_empty() {
            let take = buf.len().min(remaining).min(READ_BUF_SIZE);
            sender.send_data(buf.split_to(take).freeze()).await?;
            remaining -= take;
            continue;
        }

        let cap = remaining.min(READ_BUF_SIZE);
        chunk.clear();
        chunk.resize(cap, 0);
        let n = read_limited_with_timeout(stream, &mut chunk[..cap], read_timeout, Some(&*sender))
            .await?;
        if n == 0 {
            return Err(anyhow!(
                "peer connection closed before chunk payload completed"
            ));
        }
        chunk.truncate(n);
        sender.send_data(chunk.split().freeze()).await?;
        remaining -= n;
    }

    fill_buffer(stream, buf, 2, read_timeout, Some(&*sender)).await?;
    if &buf[..2] != b"\r\n" {
        return Err(anyhow!("chunk payload missing trailing CRLF"));
    }
    buf.advance(2);
    Ok(())
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    #[test]
    fn response_head_parser_promotes_storage_for_many_headers() {
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n".to_vec();
        for index in 0..40 {
            raw.extend_from_slice(format!("X-Test-{index}: value\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");

        let parsed = try_parse_response_head(&raw, &Method::GET)
            .expect("parse")
            .expect("complete");
        assert_eq!(parsed.3.len(), 41);
    }
}
