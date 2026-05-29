use super::{MAX_HEADER_BYTES, parse_declared_content_length, response::ResponseBodyKind};
use crate::http::codec::h1_common::{
    find_crlf, has_connection_token, has_only_chunked_transfer_encoding, parse_header_map,
};
use anyhow::{Result, anyhow};
use bytes::{Buf, BytesMut};
use hyper::header::HeaderMap;
use hyper::{Method, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Duration, timeout};

pub(super) async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    read_timeout: Duration,
    sender: &crate::http::body::Sender,
) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(idx) = find_crlf(buf) {
            let mut line = buf.split_to(idx + 2);
            line.truncate(idx);
            return Ok(line.to_vec());
        }
        fill_buffer_capped(stream, buf, 1, MAX_HEADER_BYTES, read_timeout, Some(sender)).await?;
    }
}

pub(super) async fn read_trailer_headers<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    read_timeout: Duration,
    sender: &crate::http::body::Sender,
) -> Result<Option<HeaderMap>>
where
    S: AsyncRead + Unpin,
{
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 128];
        match httparse::parse_headers(buf.as_ref(), &mut headers)? {
            httparse::Status::Complete((consumed, parsed)) => {
                if parsed.is_empty() {
                    buf.advance(consumed);
                    return Ok(None);
                }
                let trailers = parse_header_map(parsed)?;
                buf.advance(consumed);
                return Ok(Some(trailers));
            }
            httparse::Status::Partial => {
                fill_buffer_capped(stream, buf, 1, MAX_HEADER_BYTES, read_timeout, Some(sender))
                    .await?
            }
        }
    }
}

pub(super) async fn fill_buffer<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    min_len: usize,
    read_timeout: Duration,
    sender: Option<&crate::http::body::Sender>,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    while buf.len() < min_len {
        let n = read_buf_with_timeout(stream, buf, read_timeout, sender).await?;
        if n == 0 {
            return Err(anyhow!("upstream connection closed unexpectedly"));
        }
    }
    Ok(())
}

pub(super) async fn fill_buffer_capped<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    min_len: usize,
    max_len: usize,
    read_timeout: Duration,
    sender: Option<&crate::http::body::Sender>,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    while buf.len() < min_len {
        if buf.len() >= max_len {
            return Err(anyhow!("HTTP/1 header block exceeded configured limit"));
        }
        let n = read_buf_with_timeout(stream, buf, read_timeout, sender).await?;
        if n == 0 {
            return Err(anyhow!("upstream connection closed unexpectedly"));
        }
    }
    Ok(())
}

pub(super) async fn read_buf_with_timeout<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    read_timeout: Duration,
    sender: Option<&crate::http::body::Sender>,
) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    if let Some(sender) = sender {
        tokio::select! {
            result = timeout(read_timeout, stream.read_buf(buf)) => {
                result
                    .map_err(|_| anyhow!("raw HTTP/1 upstream body read timed out"))?
                    .map_err(Into::into)
            }
            _ = sender.closed() => Err(anyhow!("downstream response body receiver closed")),
        }
    } else {
        timeout(read_timeout, stream.read_buf(buf))
            .await
            .map_err(|_| anyhow!("raw HTTP/1 upstream body read timed out"))?
            .map_err(Into::into)
    }
}

pub(super) async fn read_limited_with_timeout<S>(
    stream: &mut S,
    buf: &mut [u8],
    read_timeout: Duration,
    sender: Option<&crate::http::body::Sender>,
) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    if let Some(sender) = sender {
        tokio::select! {
            result = timeout(read_timeout, stream.read(buf)) => {
                result
                    .map_err(|_| anyhow!("raw HTTP/1 upstream body read timed out"))?
                    .map_err(Into::into)
            }
            _ = sender.closed() => Err(anyhow!("downstream response body receiver closed")),
        }
    } else {
        timeout(read_timeout, stream.read(buf))
            .await
            .map_err(|_| anyhow!("raw HTTP/1 upstream body read timed out"))?
            .map_err(Into::into)
    }
}

pub(super) fn determine_response_body_kind(
    request_method: &Method,
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<ResponseBodyKind> {
    if *request_method == Method::HEAD
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::RESET_CONTENT
        || status == StatusCode::NOT_MODIFIED
    {
        return Ok(ResponseBodyKind::Empty);
    }

    if has_chunked_transfer_encoding(headers)? {
        return Ok(ResponseBodyKind::Chunked);
    }
    if let Some(length) = parse_declared_content_length(headers)? {
        return Ok(if length == 0 {
            ResponseBodyKind::Empty
        } else {
            ResponseBodyKind::ContentLength(length)
        });
    }
    Ok(ResponseBodyKind::CloseDelimited)
}

fn has_chunked_transfer_encoding(headers: &HeaderMap) -> Result<bool> {
    has_only_chunked_transfer_encoding(headers)
}

pub(super) fn response_body_allows_reuse(kind: ResponseBodyKind) -> bool {
    !matches!(kind, ResponseBodyKind::CloseDelimited)
}

pub(super) fn response_keep_alive(version: Version, headers: &HeaderMap) -> bool {
    match version {
        Version::HTTP_10 => has_connection_token(headers, "keep-alive"),
        _ => !has_connection_token(headers, "close"),
    }
}
