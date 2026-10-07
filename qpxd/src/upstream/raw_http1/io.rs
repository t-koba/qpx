use super::{UpstreamConnectionClosed, parse_declared_content_length, response::ResponseBodyKind};
use crate::http::codec::h1_common::{has_connection_token, has_only_chunked_transfer_encoding};
use crate::http::codec::lazy_timeout::timeout_after_pending;
use anyhow::{Result, anyhow};
use bytes::BytesMut;
use hyper::header::HeaderMap;
use hyper::{Method, StatusCode, Version};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::Duration;

pub(super) async fn fill_buffer_capped<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    min_len: usize,
    max_len: usize,
    read_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    while buf.len() < min_len {
        if buf.len() >= max_len {
            return Err(anyhow!("HTTP/1 header block exceeded configured limit"));
        }
        let n = timeout_after_pending(read_timeout, stream.read_buf(buf))
            .await
            .map_err(|_| anyhow!("raw HTTP/1 upstream body read timed out"))??;
        if n == 0 {
            return Err(UpstreamConnectionClosed.into());
        }
    }
    Ok(())
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

    if has_only_chunked_transfer_encoding(headers)? {
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

pub(super) fn response_body_allows_reuse(kind: ResponseBodyKind) -> bool {
    !matches!(kind, ResponseBodyKind::CloseDelimited)
}

pub(super) fn response_keep_alive(version: Version, headers: &HeaderMap) -> bool {
    match version {
        Version::HTTP_10 => has_connection_token(headers, "keep-alive"),
        _ => !has_connection_token(headers, "close"),
    }
}
