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
    RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
};
#[cfg(test)]
use super::{MAX_CHUNKED_BODY_BYTES, READ_BUF_SIZE};
use crate::http::codec::h1_common::{parse_header_map, parse_version};
use anyhow::{Result, anyhow};
use bytes::{Buf, BytesMut};
use hyper::header::CONTENT_LENGTH;
use hyper::{HeaderMap, Method, Response, StatusCode, Version};
use qpx_http::body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
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
            let mut headers = [httparse::EMPTY_HEADER; 128];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(&buf)? {
                httparse::Status::Complete(consumed) => {
                    let version = parse_version(response.version, "missing upstream HTTP version")?;
                    let code = response
                        .code
                        .ok_or_else(|| anyhow!("upstream response missing status code"))?;
                    if !(100..=599).contains(&code) {
                        return Err(anyhow!("upstream response status is out of range: {code}"));
                    }
                    let status = StatusCode::from_u16(code)?;
                    let headers = parse_header_map(response.headers)?;
                    let body_kind = determine_response_body_kind(request_method, status, &headers)?;
                    break (consumed, version, status, headers, body_kind);
                }
                httparse::Status::Partial => {
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
    let body = match head.body_kind {
        ResponseBodyKind::Empty => {
            if let Some(recycler) = recycler
                && head.status != StatusCode::SWITCHING_PROTOCOLS
                && prefix.is_empty()
                && response_keep_alive(head.version, &head.headers)
            {
                recycler.recycle(stream, prefix, write_buf);
            }
            Body::empty()
        }
        ResponseBodyKind::ContentLength(length)
            if length <= usize::MAX as u64 && prefix.len() >= length as usize =>
        {
            let body = Body::from(prefix.split_to(length as usize).freeze());
            if let Some(recycler) = recycler
                && prefix.is_empty()
                && response_keep_alive(head.version, &head.headers)
            {
                recycler.recycle(stream, prefix, write_buf);
            }
            body
        }
        kind => Body::wrap(super::body::Http1ResponseBody::new(
            stream,
            prefix,
            kind,
            write_buf,
            recycler.filter(|_| {
                response_body_allows_reuse(kind) && response_keep_alive(head.version, &head.headers)
            }),
        )),
    };
    let mut response = Response::builder()
        .status(head.status)
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()));
    *response.version_mut() = head.version;
    *response.headers_mut() = head.headers;
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
