use super::zero_copy::ZeroCopySocket;
use super::{RESPONSE_WRITE_TIMEOUT, has_chunked_transfer_encoding, parse_declared_content_length};
use crate::http::codec::h1_common::serialize_headers;
use crate::http::codec::lazy_timeout::timeout_after_pending;
use crate::upstream::raw_http1::{
    InterimResponseHead, RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT, READ_BUF_SIZE, RawHttp1BodyFraming,
    RawHttp1ResponseHead, RawHttp1ResponseRelay,
};
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{Method, Response, StatusCode, Version};
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, HeaderMap, HeaderValue, TRAILER, TRANSFER_ENCODING,
};
use qpx_http::body::Body;
use std::future::{Future, poll_fn};
use std::io::{Error as IoError, ErrorKind, IoSlice};
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Duration;

enum ResponseBodyKind {
    Empty,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ConnectionHeaderMode {
    Omit,
    Close,
    KeepAlive,
    Preserve,
}

#[expect(
    clippy::too_many_arguments,
    reason = "response relay keeps protocol state and the reusable connection buffer explicit"
)]
pub(crate) async fn send_http1_response_with_interim<W>(
    writer: &mut W,
    request_version: Version,
    request_method: &Method,
    response: Response<Body>,
    interim: &[InterimResponseHead],
    request_keep_alive: bool,
    body_read_timeout: Duration,
    head_buf: &mut BytesMut,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    send_http1_response_with_interim_zero_copy(
        writer,
        request_version,
        request_method,
        response,
        interim,
        request_keep_alive,
        body_read_timeout,
        head_buf,
        None,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "response relay keeps protocol state and zero-copy capability explicit"
)]
pub(super) async fn send_http1_response_with_interim_zero_copy<W>(
    writer: &mut W,
    request_version: Version,
    request_method: &Method,
    response: Response<Body>,
    interim: &[InterimResponseHead],
    request_keep_alive: bool,
    body_read_timeout: Duration,
    head_buf: &mut BytesMut,
    mut zero_copy: Option<&mut ZeroCopySocket>,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
{
    if request_version == Version::HTTP_11 {
        for head in interim {
            if !head.status.is_informational() {
                return Err(anyhow!(
                    "non-informational interim status for HTTP/1: {}",
                    head.status
                ));
            }
            if head.status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(anyhow!("HTTP/1 interim responses must not use 101"));
            }
            let mut headers = head.headers.clone();
            qpx_http::protocol::semantics::sanitize_interim_response_headers(&mut headers);
            write_status_and_headers(
                writer,
                head_buf,
                Version::HTTP_11,
                head.status,
                &headers,
                ConnectionHeaderMode::Omit,
            )
            .await?;
        }
    }

    let (mut parts, mut body) = response.into_parts();
    let raw_head = parts.extensions.remove::<Arc<RawHttp1ResponseHead>>();
    let mut headers = parts.headers;
    let no_body = request_method == Method::HEAD
        || parts.status.is_informational()
        || parts.status == StatusCode::NO_CONTENT
        || parts.status == StatusCode::RESET_CONTENT
        || parts.status == StatusCode::NOT_MODIFIED
        || (request_method == Method::CONNECT && parts.status.is_success());
    let body_kind = if let Some(raw) = raw_head.as_ref() {
        if !raw.is_finalized() {
            return Err(anyhow!("raw HTTP/1 response head was not finalized"));
        }
        match raw.framing() {
            RawHttp1BodyFraming::Empty => ResponseBodyKind::Empty,
            RawHttp1BodyFraming::ContentLength(length) => ResponseBodyKind::ContentLength(length),
            RawHttp1BodyFraming::Chunked => ResponseBodyKind::Chunked,
            RawHttp1BodyFraming::CloseDelimited if request_version == Version::HTTP_11 => {
                ResponseBodyKind::Chunked
            }
            RawHttp1BodyFraming::CloseDelimited => ResponseBodyKind::CloseDelimited,
        }
    } else {
        let declared_length = parse_declared_content_length(&headers)?;
        let has_chunked = has_chunked_transfer_encoding(&headers)?;
        if no_body {
            if request_method != Method::HEAD {
                headers.remove(CONTENT_LENGTH);
            }
            headers.remove(TRANSFER_ENCODING);
            headers.remove(TRAILER);
            ResponseBodyKind::Empty
        } else if has_chunked {
            ResponseBodyKind::Chunked
        } else if let Some(length) = declared_length {
            if length == 0 {
                ResponseBodyKind::Empty
            } else {
                ResponseBodyKind::ContentLength(length)
            }
        } else if request_version == Version::HTTP_11 {
            headers.remove(CONTENT_LENGTH);
            headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
            ResponseBodyKind::Chunked
        } else {
            ResponseBodyKind::CloseDelimited
        }
    };

    let file_region = if zero_copy.is_some()
        && let ResponseBodyKind::ContentLength(length) = body_kind
    {
        match body.take_file_region_without_trailers() {
            Some(region) if region.len() == length => Some(region),
            Some(region) => {
                return Err(anyhow!(
                    "zero-copy file region length {} does not match content-length {length}",
                    region.len()
                ));
            }
            None => None,
        }
    } else {
        None
    };

    let mut first_chunk = None;
    let mut first_trailers = None;
    let mut first_body_error = None;
    let mut body_data_finished = false;
    if !matches!(body_kind, ResponseBodyKind::Empty) && file_region.is_none() {
        match poll_response_body_data_now(&mut body).await {
            Ok(Poll::Ready(chunk)) => {
                body_data_finished = chunk.is_none();
                first_chunk = chunk;
            }
            Ok(Poll::Pending) => {}
            Err(err) => first_body_error = Some(err),
        }
        if first_body_error.is_none() && body_data_finished {
            match poll_response_trailers_now(&mut body).await {
                Ok(trailers) => first_trailers = trailers,
                Err(err) => first_body_error = Some(err),
            }
        }
    }

    let emit_trailers = if matches!(body_kind, ResponseBodyKind::Chunked) {
        prepare_http1_trailer_metadata(&mut headers, first_trailers.as_mut())
    } else {
        false
    };

    let keep_alive = request_keep_alive
        && request_version == Version::HTTP_11
        && !matches!(body_kind, ResponseBodyKind::CloseDelimited)
        && parts.status != StatusCode::SWITCHING_PROTOCOLS
        // RFC 9931 requires an HTTP/1.1 proxy server to close the connection
        // after every rejected CONNECT request. Successful CONNECT also takes
        // ownership of the connection as a tunnel, so no CONNECT response can
        // return to the HTTP/1.1 request loop.
        && request_method != Method::CONNECT;
    let connection_mode = determine_connection_header_mode(
        request_version,
        request_method,
        parts.status,
        &headers,
        keep_alive,
    );
    if let Some(raw) = raw_head.as_ref() {
        serialize_status_and_raw_headers(
            head_buf,
            request_version,
            parts.status,
            raw.header_lines(),
            &headers,
            connection_mode,
            matches!(body_kind, ResponseBodyKind::Chunked),
        );
    } else {
        serialize_status_and_headers(
            head_buf,
            request_version,
            parts.status,
            &headers,
            connection_mode,
        );
    }
    crate::http::codec::header_pool::recycle(headers);
    let head = head_buf.as_ref();

    match body_kind {
        ResponseBodyKind::Empty => write_all_with_timeout(writer, head).await?,
        ResponseBodyKind::ContentLength(length) => {
            if let Some(region) = file_region {
                write_all_with_timeout(writer, head).await?;
                let socket = zero_copy
                    .as_deref_mut()
                    .ok_or_else(|| anyhow!("zero-copy socket is unavailable"))?;
                timeout_after_pending(RESPONSE_WRITE_TIMEOUT, socket.send_file(&region))
                    .await
                    .map_err(|_| anyhow!("HTTP/1 zero-copy response write timed out"))??;
                flush_with_timeout(writer).await?;
                return Ok(keep_alive);
            }
            if let Some(err) = first_body_error.take() {
                write_all_with_timeout(writer, head).await?;
                return Err(err);
            }
            let remaining =
                write_head_and_first_content_length_chunk(writer, head, first_chunk, length)
                    .await?;
            if remaining != 0 || !http_body::Body::is_end_stream(&body) {
                write_content_length_response_body(writer, &mut body, remaining, body_read_timeout)
                    .await?;
            }
        }
        ResponseBodyKind::Chunked => {
            if let Some(err) = first_body_error.take() {
                write_all_with_timeout(writer, head).await?;
                return Err(err);
            }
            write_head_and_first_chunked_chunk(writer, head, first_chunk).await?;
            write_chunked_response_body(
                writer,
                &mut body,
                None,
                first_trailers,
                emit_trailers,
                body_read_timeout,
            )
            .await?;
        }
        ResponseBodyKind::CloseDelimited => {
            if let Some(err) = first_body_error.take() {
                write_all_with_timeout(writer, head).await?;
                return Err(err);
            }
            write_head_and_first_close_delimited_chunk(writer, head, first_chunk).await?;
            write_close_delimited_response_body(writer, &mut body, None, body_read_timeout).await?;
        }
    }
    flush_with_timeout(writer).await?;
    Ok(keep_alive)
}

pub(crate) async fn send_raw_http1_response_relay_with_interim<W, S>(
    writer: &mut W,
    request_version: Version,
    request_method: &Method,
    mut response: RawHttp1ResponseRelay<S>,
    request_keep_alive: bool,
    head_buf: &mut BytesMut,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if request_version == Version::HTTP_11 {
        for head in &response.interim {
            if !head.status.is_informational() {
                return Err(anyhow!(
                    "non-informational interim status for HTTP/1: {}",
                    head.status
                ));
            }
            if head.status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(anyhow!("HTTP/1 interim responses must not use 101"));
            }
            let mut headers = head.headers.clone();
            qpx_http::protocol::semantics::sanitize_interim_response_headers(&mut headers);
            write_status_and_headers(
                writer,
                head_buf,
                Version::HTTP_11,
                head.status,
                &headers,
                ConnectionHeaderMode::Omit,
            )
            .await?;
        }
    }

    if !response.raw.is_finalized() {
        return Err(anyhow!("raw HTTP/1 response head was not finalized"));
    }
    let body_kind = match response.raw.framing() {
        RawHttp1BodyFraming::Empty => ResponseBodyKind::Empty,
        RawHttp1BodyFraming::ContentLength(length) => ResponseBodyKind::ContentLength(length),
        RawHttp1BodyFraming::Chunked | RawHttp1BodyFraming::CloseDelimited => {
            return Err(anyhow!("direct raw HTTP/1 relay requires bounded framing"));
        }
    };
    let keep_alive = request_keep_alive
        && request_version == Version::HTTP_11
        && response.status != StatusCode::SWITCHING_PROTOCOLS
        && request_method != Method::CONNECT;
    let connection_mode = if keep_alive {
        ConnectionHeaderMode::Omit
    } else {
        ConnectionHeaderMode::Close
    };
    let cached_head = (connection_mode == ConnectionHeaderMode::Omit
        && request_version == Version::HTTP_11)
        .then(|| response.raw.serialized_http11_head());
    let head = match cached_head.as_ref() {
        Some(head) => head.as_ref(),
        None => {
            serialize_status_and_raw_headers(
                head_buf,
                request_version,
                response.status,
                response.raw.header_lines(),
                &HeaderMap::new(),
                connection_mode,
                false,
            );
            head_buf.as_ref()
        }
    };

    match body_kind {
        ResponseBodyKind::Empty => {
            write_all_with_timeout(writer, head).await?;
            recycle_direct_raw_upstream_if_clean(&mut response);
        }
        ResponseBodyKind::ContentLength(length) => {
            relay_direct_content_length_response(writer, head, &mut response, length).await?;
        }
        ResponseBodyKind::Chunked | ResponseBodyKind::CloseDelimited => unreachable!(),
    }
    flush_with_timeout(writer).await?;
    Ok(keep_alive)
}

async fn relay_direct_content_length_response<W, S>(
    writer: &mut W,
    head: &[u8],
    response: &mut RawHttp1ResponseRelay<S>,
    length: u64,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let first_len = response.read_buf.len().min(length as usize);
    if first_len == 0 {
        write_all_with_timeout(writer, head).await?;
    } else {
        write_vectored_all_with_timeout(writer, &[head, &response.read_buf[..first_len]]).await?;
        response.read_buf.advance(first_len);
    }

    let mut remaining = length - first_len as u64;
    while remaining > 0 {
        if response.read_buf.is_empty() {
            let read_size = remaining.min(READ_BUF_SIZE as u64) as usize;
            response.read_buf.reserve(read_size);
            let mut limited = (&mut response.read_buf).limit(read_size);
            let Some(stream) = response.stream.as_mut() else {
                return Err(anyhow!("raw HTTP/1 relay stream is unavailable"));
            };
            let read = timeout_after_pending(
                RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
                stream.read_buf(&mut limited),
            )
            .await
            .map_err(|_| anyhow!("HTTP/1 response body read timed out"))??;
            if read == 0 {
                return Err(anyhow!(
                    "response body ended before declared content-length was satisfied"
                ));
            }
            drain_ready_direct_relay_bytes(response, read_size - read).await?;
        }
        let take = response.read_buf.len().min(remaining as usize);
        write_all_with_timeout(writer, &response.read_buf[..take]).await?;
        response.read_buf.advance(take);
        remaining -= take as u64;
    }
    recycle_direct_raw_upstream_if_clean(response);
    Ok(())
}

async fn drain_ready_direct_relay_bytes<S>(
    response: &mut RawHttp1ResponseRelay<S>,
    mut remaining_capacity: usize,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some(stream) = response.stream.as_mut() else {
        return Err(anyhow!("raw HTTP/1 relay stream is unavailable"));
    };
    while remaining_capacity > 0 {
        response.read_buf.reserve(remaining_capacity);
        let mut limited = (&mut response.read_buf).limit(remaining_capacity);
        let read = poll_fn(|cx| {
            let future = stream.read_buf(&mut limited);
            let mut future = std::pin::pin!(future);
            match Future::poll(future.as_mut(), cx) {
                Poll::Ready(result) => Poll::Ready(result.map(Some)),
                Poll::Pending => Poll::Ready(Ok(None)),
            }
        })
        .await?;
        match read {
            Some(0) | None => break,
            Some(read) => remaining_capacity -= read,
        }
    }
    Ok(())
}

fn recycle_direct_raw_upstream_if_clean<S>(response: &mut RawHttp1ResponseRelay<S>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !response.read_buf.is_empty() || !response.raw.upstream_keep_alive() {
        return;
    }
    let (Some(stream), Some(recycler)) = (response.stream.take(), response.recycler.take()) else {
        return;
    };
    recycler.recycle(
        stream,
        std::mem::take(&mut response.read_buf),
        std::mem::take(&mut response.write_buf),
    );
}

pub(super) async fn write_status_and_headers<W>(
    writer: &mut W,
    head_buf: &mut BytesMut,
    version: Version,
    status: StatusCode,
    headers: &HeaderMap,
    connection_mode: ConnectionHeaderMode,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    serialize_status_and_headers(head_buf, version, status, headers, connection_mode);
    write_all_with_timeout(writer, head_buf).await?;
    Ok(())
}

fn serialize_status_and_headers(
    head: &mut BytesMut,
    version: Version,
    status: StatusCode,
    headers: &HeaderMap,
    connection_mode: ConnectionHeaderMode,
) {
    head.clear();
    head.reserve(512);
    let version = match version {
        Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    };
    let reason = status.canonical_reason().unwrap_or("");
    head.extend_from_slice(version.as_bytes());
    head.extend_from_slice(b" ");
    head.extend_from_slice(status.as_str().as_bytes());
    if !reason.is_empty() {
        head.extend_from_slice(b" ");
        head.extend_from_slice(reason.as_bytes());
    }
    head.extend_from_slice(b"\r\n");

    for (name, value) in headers {
        if name == CONNECTION || name.as_str().eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    match connection_mode {
        ConnectionHeaderMode::Omit => {}
        ConnectionHeaderMode::Close => {
            head.extend_from_slice(b"Connection: close\r\n");
        }
        ConnectionHeaderMode::KeepAlive => {
            head.extend_from_slice(b"Connection: keep-alive\r\n");
        }
        ConnectionHeaderMode::Preserve => {
            for value in headers.get_all(CONNECTION) {
                head.extend_from_slice(b"Connection: ");
                head.extend_from_slice(value.as_bytes());
                head.extend_from_slice(b"\r\n");
            }
        }
    }
    head.extend_from_slice(b"\r\n");
}

fn serialize_status_and_raw_headers(
    head: &mut BytesMut,
    version: Version,
    status: StatusCode,
    raw_header_lines: &[u8],
    additional_headers: &HeaderMap,
    connection_mode: ConnectionHeaderMode,
    chunked: bool,
) {
    head.clear();
    head.reserve(raw_header_lines.len().saturating_add(128));
    let version = match version {
        Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    };
    let reason = status.canonical_reason().unwrap_or("");
    head.extend_from_slice(version.as_bytes());
    head.extend_from_slice(b" ");
    head.extend_from_slice(status.as_str().as_bytes());
    if !reason.is_empty() {
        head.extend_from_slice(b" ");
        head.extend_from_slice(reason.as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    head.extend_from_slice(raw_header_lines);
    for (name, value) in additional_headers {
        if name == CONNECTION || name.as_str().eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    if chunked {
        head.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    match connection_mode {
        ConnectionHeaderMode::Omit => {}
        ConnectionHeaderMode::Close => head.extend_from_slice(b"Connection: close\r\n"),
        ConnectionHeaderMode::KeepAlive => {
            head.extend_from_slice(b"Connection: keep-alive\r\n");
        }
        ConnectionHeaderMode::Preserve => {
            for value in additional_headers.get_all(CONNECTION) {
                head.extend_from_slice(b"Connection: ");
                head.extend_from_slice(value.as_bytes());
                head.extend_from_slice(b"\r\n");
            }
        }
    }
    head.extend_from_slice(b"\r\n");
}

async fn write_content_length_response_body<W>(
    writer: &mut W,
    body: &mut Body,
    mut remaining: u64,
    body_read_timeout: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(chunk) = read_response_body_chunk(body, body_read_timeout).await? {
        let chunk = chunk?;
        let chunk_len = chunk.len() as u64;
        if chunk_len > remaining {
            return Err(anyhow!("response body exceeded declared content-length"));
        }
        if !chunk.is_empty() {
            write_all_with_timeout(writer, &chunk).await?;
        }
        remaining -= chunk_len;
    }
    if remaining != 0 {
        return Err(anyhow!(
            "response body ended before declared content-length was satisfied"
        ));
    }
    if read_response_trailers(body, body_read_timeout)
        .await?
        .is_some()
    {
        return Err(anyhow!(
            "response trailers require chunked transfer-encoding"
        ));
    }
    Ok(())
}

async fn write_chunked_response_body<W>(
    writer: &mut W,
    body: &mut Body,
    first_chunk: Option<Bytes>,
    first_trailers: Option<HeaderMap>,
    emit_trailers: bool,
    body_read_timeout: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if let Some(chunk) = first_chunk {
        write_chunk(writer, &chunk).await?;
    }
    while let Some(chunk) = read_response_body_chunk(body, body_read_timeout).await? {
        write_chunk(writer, &chunk?).await?;
    }
    let mut trailers = match first_trailers {
        Some(trailers) => Some(trailers),
        None => read_response_trailers(body, body_read_timeout).await?,
    };
    write_all_with_timeout(writer, b"0\r\n").await?;
    if let Some(trailers) = trailers.as_mut() {
        let _ = qpx_http::protocol::semantics::sanitize_response_trailers(trailers);
        if emit_trailers && !trailers.is_empty() {
            let mut out = Vec::with_capacity(256);
            serialize_headers(trailers, &mut out)?;
            write_all_with_timeout(writer, &out).await?;
        }
    }
    write_all_with_timeout(writer, b"\r\n").await?;
    Ok(())
}

async fn write_close_delimited_response_body<W>(
    writer: &mut W,
    body: &mut Body,
    first_chunk: Option<Bytes>,
    body_read_timeout: Duration,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if let Some(chunk) = first_chunk
        && !chunk.is_empty()
    {
        write_all_with_timeout(writer, &chunk).await?;
    }
    while let Some(chunk) = read_response_body_chunk(body, body_read_timeout).await? {
        let chunk = chunk?;
        if !chunk.is_empty() {
            write_all_with_timeout(writer, &chunk).await?;
        }
    }
    Ok(())
}

async fn read_response_body_chunk(
    body: &mut Body,
    body_read_timeout: Duration,
) -> Result<Option<Result<Bytes, qpx_http::body::BodyError>>> {
    timeout_after_pending(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("HTTP/1 response body read timed out"))
}

async fn read_response_trailers(
    body: &mut Body,
    body_read_timeout: Duration,
) -> Result<Option<HeaderMap>> {
    timeout_after_pending(body_read_timeout, body.trailers())
        .await
        .map_err(|_| anyhow!("HTTP/1 response trailer read timed out"))?
        .map_err(Into::into)
}

async fn write_chunk<W>(writer: &mut W, chunk: &Bytes) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if chunk.is_empty() {
        return Ok(());
    }
    let mut header = [0_u8; 18];
    let header = chunk_size_header(chunk.len(), &mut header);
    write_vectored_all_with_timeout(writer, &[header, chunk, b"\r\n"]).await?;
    Ok(())
}

async fn write_head_and_first_content_length_chunk<W>(
    writer: &mut W,
    head: &[u8],
    first_chunk: Option<Bytes>,
    length: u64,
) -> Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let Some(chunk) = first_chunk else {
        write_all_with_timeout(writer, head).await?;
        return Ok(length);
    };
    let chunk_len = chunk.len() as u64;
    if chunk_len > length {
        return Err(anyhow!("response body exceeded declared content-length"));
    }
    if chunk.is_empty() {
        write_all_with_timeout(writer, head).await?;
    } else {
        write_vectored_all_with_timeout(writer, &[head, &chunk]).await?;
    }
    Ok(length - chunk_len)
}

async fn write_head_and_first_chunked_chunk<W>(
    writer: &mut W,
    head: &[u8],
    first_chunk: Option<Bytes>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(chunk) = first_chunk.filter(|chunk| !chunk.is_empty()) else {
        write_all_with_timeout(writer, head).await?;
        return Ok(());
    };
    let mut chunk_header = [0_u8; 18];
    let chunk_header = chunk_size_header(chunk.len(), &mut chunk_header);
    write_vectored_all_with_timeout(writer, &[head, chunk_header, &chunk, b"\r\n"]).await
}

async fn write_head_and_first_close_delimited_chunk<W>(
    writer: &mut W,
    head: &[u8],
    first_chunk: Option<Bytes>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let Some(chunk) = first_chunk.filter(|chunk| !chunk.is_empty()) else {
        write_all_with_timeout(writer, head).await?;
        return Ok(());
    };
    write_vectored_all_with_timeout(writer, &[head, &chunk]).await
}

async fn write_all_with_timeout<W>(writer: &mut W, bytes: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout_after_pending(RESPONSE_WRITE_TIMEOUT, writer.write_all(bytes))
        .await
        .map_err(|_| anyhow!("HTTP/1 response write timed out"))?
        .map_err(Into::into)
}

async fn write_vectored_all_with_timeout<W>(writer: &mut W, slices: &[&[u8]]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout_after_pending(RESPONSE_WRITE_TIMEOUT, write_vectored_all(writer, slices))
        .await
        .map_err(|_| anyhow!("HTTP/1 response write timed out"))?
        .map_err(Into::into)
}

async fn write_vectored_all<W>(writer: &mut W, slices: &[&[u8]]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut index = 0usize;
    let mut offset = 0usize;
    while index < slices.len() {
        while index < slices.len() && offset == slices[index].len() {
            index += 1;
            offset = 0;
        }
        if index >= slices.len() {
            return Ok(());
        }
        let mut io_slices = std::array::from_fn::<_, 4, _>(|_| IoSlice::new(&[]));
        let mut io_slice_count = 0usize;
        io_slices[io_slice_count] = IoSlice::new(&slices[index][offset..]);
        io_slice_count += 1;
        for slice in &slices[index + 1..] {
            if !slice.is_empty() {
                if io_slice_count == io_slices.len() {
                    break;
                }
                io_slices[io_slice_count] = IoSlice::new(slice);
                io_slice_count += 1;
            }
        }
        let written = writer.write_vectored(&io_slices[..io_slice_count]).await?;
        if written == 0 {
            return Err(IoError::new(
                ErrorKind::WriteZero,
                "failed to write HTTP/1 response",
            ));
        }
        advance_slices(slices, &mut index, &mut offset, written);
    }
    Ok(())
}

fn advance_slices(slices: &[&[u8]], index: &mut usize, offset: &mut usize, written: usize) {
    let mut remaining = written;
    while remaining > 0 && *index < slices.len() {
        let available = slices[*index].len() - *offset;
        if remaining < available {
            *offset += remaining;
            return;
        }
        remaining -= available;
        *index += 1;
        *offset = 0;
    }
}

fn chunk_size_header(len: usize, out: &mut [u8; 18]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut value = len;
    let mut cursor = 16;
    if value == 0 {
        cursor -= 1;
        out[cursor] = b'0';
    } else {
        while value > 0 {
            cursor -= 1;
            out[cursor] = HEX[value & 0x0f];
            value >>= 4;
        }
    }
    let digits = 16 - cursor;
    out.copy_within(cursor..16, 0);
    out[digits] = b'\r';
    out[digits + 1] = b'\n';
    &out[..digits + 2]
}

async fn poll_response_body_data_now(body: &mut Body) -> Result<Poll<Option<Bytes>>> {
    poll_fn(|cx| {
        let future = body.data();
        let mut future = std::pin::pin!(future);
        match Future::poll(future.as_mut(), cx) {
            Poll::Ready(chunk) => {
                Poll::Ready(chunk.transpose().map(Poll::Ready).map_err(Into::into))
            }
            Poll::Pending => Poll::Ready(Ok(Poll::Pending)),
        }
    })
    .await
}

async fn poll_response_trailers_now(body: &mut Body) -> Result<Option<HeaderMap>> {
    poll_fn(|cx| {
        let future = body.trailers();
        let mut future = std::pin::pin!(future);
        match Future::poll(future.as_mut(), cx) {
            Poll::Ready(trailers) => Poll::Ready(trailers.map_err(Into::into)),
            Poll::Pending => Poll::Ready(Ok(None)),
        }
    })
    .await
}

async fn flush_with_timeout<W>(writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout_after_pending(RESPONSE_WRITE_TIMEOUT, writer.flush())
        .await
        .map_err(|_| anyhow!("HTTP/1 response flush timed out"))?
        .map_err(Into::into)
}

fn determine_connection_header_mode(
    request_version: Version,
    request_method: &Method,
    status: StatusCode,
    headers: &HeaderMap,
    keep_alive: bool,
) -> ConnectionHeaderMode {
    if status.is_informational() {
        if headers.contains_key(CONNECTION) {
            return ConnectionHeaderMode::Preserve;
        }
        return ConnectionHeaderMode::Omit;
    }
    if status == StatusCode::SWITCHING_PROTOCOLS && headers.contains_key(CONNECTION) {
        return ConnectionHeaderMode::Preserve;
    }
    if request_method == Method::CONNECT && status.is_success() {
        if headers.contains_key(CONNECTION) {
            return ConnectionHeaderMode::Preserve;
        }
        return ConnectionHeaderMode::Omit;
    }
    if !keep_alive {
        return ConnectionHeaderMode::Close;
    }
    if request_version == Version::HTTP_10 {
        return ConnectionHeaderMode::KeepAlive;
    }
    ConnectionHeaderMode::Omit
}

pub(super) fn http1_upgrade_accepted(
    request_upgrade: bool,
    request_method: &Method,
    status: StatusCode,
) -> bool {
    (request_upgrade && status == StatusCode::SWITCHING_PROTOCOLS)
        || (request_method == Method::CONNECT && status.is_success())
}

fn prepare_http1_trailer_metadata(
    headers: &mut HeaderMap,
    first_trailers: Option<&mut HeaderMap>,
) -> bool {
    if headers.contains_key(TRAILER) {
        return true;
    }
    let Some(trailers) = first_trailers else {
        return false;
    };
    let _ = qpx_http::protocol::semantics::sanitize_response_trailers(trailers);
    let Some(value) = serialize_trailer_field_names(trailers) else {
        return false;
    };
    headers.insert(TRAILER, value);
    true
}

fn serialize_trailer_field_names(trailers: &HeaderMap) -> Option<HeaderValue> {
    let mut names = Vec::<String>::new();
    for name in trailers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        if !names.iter().any(|existing| existing == &lower) {
            names.push(lower);
        }
    }
    if names.is_empty() {
        return None;
    }
    HeaderValue::from_str(names.join(", ").as_str()).ok()
}
