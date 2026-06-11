use super::io::{
    determine_response_body_kind, fill_buffer, fill_buffer_capped, read_buf_with_timeout,
    read_crlf_line, read_limited_with_timeout, read_trailer_headers, response_body_allows_reuse,
    response_keep_alive,
};
use super::{
    Http1ConnectionRecycler, InterimResponseHead, MAX_CHUNKED_BODY_BYTES, MAX_HEADER_BYTES,
    RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT, READ_BUF_SIZE,
};
use crate::http::codec::h1_common::{parse_header_map, parse_version};
use anyhow::{Result, anyhow};
use bytes::{Buf, BytesMut};
use hyper::header::CONTENT_LENGTH;
use hyper::{HeaderMap, Method, Response, StatusCode, Version};
use qpx_http::body::Body;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Duration;
use tracing::warn;

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
    request_method: &Method,
) -> Result<(Vec<InterimResponseHead>, ParsedResponseHead, BytesMut)>
where
    S: AsyncRead + Unpin,
{
    let mut buf = BytesMut::with_capacity(4096);
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
    prefix: BytesMut,
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
                tokio::spawn(async move {
                    recycler.recycle(stream).await;
                });
            }
            Body::empty()
        }
        kind => spawn_response_body(
            stream,
            prefix,
            kind,
            recycler.filter(|_| {
                response_body_allows_reuse(kind) && response_keep_alive(head.version, &head.headers)
            }),
        ),
    };
    let mut response = Response::builder()
        .status(head.status)
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()));
    *response.version_mut() = head.version;
    *response.headers_mut() = head.headers;
    response
}

fn spawn_response_body<S>(
    stream: S,
    prefix: BytesMut,
    kind: ResponseBodyKind,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Body
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, body) = Body::channel_with_capacity(16);
    tokio::spawn(async move {
        let result = match kind {
            ResponseBodyKind::Empty => Ok(None),
            ResponseBodyKind::ContentLength(length) => forward_content_length_body(
                stream,
                prefix,
                length,
                &mut sender,
                RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
            )
            .await
            .map(Some),
            ResponseBodyKind::CloseDelimited => forward_close_delimited_body(
                stream,
                prefix,
                &mut sender,
                RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
            )
            .await
            .map(|()| None),
            ResponseBodyKind::Chunked => forward_chunked_body(
                stream,
                prefix,
                &mut sender,
                RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
            )
            .await
            .map(Some),
        };
        match result {
            Ok(Some((stream, leftover))) => {
                if let Some(recycler) = recycler
                    && leftover.is_empty()
                {
                    recycler.recycle(stream).await;
                }
            }
            Ok(None) => {}
            Err(err) => {
                warn!(error = ?err, "reverse_edges raw http/1 response body relay failed");
                sender.abort();
            }
        }
    });
    body
}

async fn forward_content_length_body<S>(
    mut stream: S,
    mut prefix: BytesMut,
    mut remaining: u64,
    sender: &mut qpx_http::body::Sender,
    read_timeout: Duration,
) -> Result<(S, BytesMut)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if remaining == 0 {
        return Ok((stream, prefix));
    }
    if !prefix.is_empty() {
        let take = std::cmp::min(prefix.len() as u64, remaining) as usize;
        if take > 0 {
            sender.send_data(prefix.split_to(take).freeze()).await?;
            remaining -= take as u64;
        }
    }
    let mut chunk = BytesMut::with_capacity(READ_BUF_SIZE);
    while remaining > 0 {
        let cap = std::cmp::min(READ_BUF_SIZE as u64, remaining) as usize;
        chunk.clear();
        chunk.resize(cap, 0);
        let n =
            read_limited_with_timeout(&mut stream, &mut chunk[..cap], read_timeout, Some(sender))
                .await?;
        if n == 0 {
            return Err(anyhow!(
                "upstream response closed before content-length completed"
            ));
        }
        chunk.truncate(n);
        sender.send_data(chunk.split().freeze()).await?;
        remaining -= n as u64;
    }
    Ok((stream, prefix))
}

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
