use super::{RESPONSE_WRITE_TIMEOUT, has_chunked_transfer_encoding, parse_declared_content_length};
use crate::http::codec::h1_common::serialize_headers;
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::{Method, Response, StatusCode, Version};
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, HeaderMap, HeaderValue, TRAILER, TRANSFER_ENCODING,
};
use qpx_http::body::Body;
use std::future::{Future, poll_fn};
use std::io::{Error as IoError, ErrorKind, IoSlice};
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::time::{Duration, timeout};

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

pub(super) async fn send_http1_response_with_interim<W>(
    writer: &mut WriteHalf<W>,
    request_version: Version,
    request_method: &Method,
    response: Response<Body>,
    interim: &[InterimResponseHead],
    request_keep_alive: bool,
    body_read_timeout: Duration,
) -> Result<bool>
where
    W: AsyncRead + AsyncWrite + Unpin,
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
                Version::HTTP_11,
                head.status,
                &headers,
                ConnectionHeaderMode::Omit,
            )
            .await?;
        }
    }

    let (parts, mut body) = response.into_parts();
    let mut headers = parts.headers;
    let no_body = request_method == Method::HEAD
        || parts.status.is_informational()
        || parts.status == StatusCode::NO_CONTENT
        || parts.status == StatusCode::RESET_CONTENT
        || parts.status == StatusCode::NOT_MODIFIED
        || (request_method == Method::CONNECT && parts.status.is_success());
    let declared_length = parse_declared_content_length(&headers)?;
    let has_chunked = has_chunked_transfer_encoding(&headers)?;
    let body_kind = if no_body {
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
    };

    let mut first_chunk = None;
    let mut first_trailers = None;
    let mut first_body_error = None;
    let mut body_data_finished = false;
    if !matches!(body_kind, ResponseBodyKind::Empty) {
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
        && !(request_method == Method::CONNECT && parts.status.is_success());
    let connection_mode = determine_connection_header_mode(
        request_version,
        request_method,
        parts.status,
        &headers,
        keep_alive,
    );
    let head =
        serialize_status_and_headers(request_version, parts.status, &headers, connection_mode);

    match body_kind {
        ResponseBodyKind::Empty => write_all_with_timeout(writer, &head).await?,
        ResponseBodyKind::ContentLength(length) => {
            if let Some(err) = first_body_error.take() {
                write_all_with_timeout(writer, &head).await?;
                return Err(err);
            }
            let remaining =
                write_head_and_first_content_length_chunk(writer, &head, first_chunk, length)
                    .await?;
            write_content_length_response_body(writer, &mut body, remaining, body_read_timeout)
                .await?;
        }
        ResponseBodyKind::Chunked => {
            if let Some(err) = first_body_error.take() {
                write_all_with_timeout(writer, &head).await?;
                return Err(err);
            }
            write_head_and_first_chunked_chunk(writer, &head, first_chunk).await?;
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
                write_all_with_timeout(writer, &head).await?;
                return Err(err);
            }
            write_head_and_first_close_delimited_chunk(writer, &head, first_chunk).await?;
            write_close_delimited_response_body(writer, &mut body, None, body_read_timeout).await?;
        }
    }
    flush_with_timeout(writer).await?;
    Ok(keep_alive)
}

pub(super) async fn write_status_and_headers<W>(
    writer: &mut WriteHalf<W>,
    version: Version,
    status: StatusCode,
    headers: &HeaderMap,
    connection_mode: ConnectionHeaderMode,
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    let head = serialize_status_and_headers(version, status, headers, connection_mode);
    write_all_with_timeout(writer, &head).await?;
    Ok(())
}

fn serialize_status_and_headers(
    version: Version,
    status: StatusCode,
    headers: &HeaderMap,
    connection_mode: ConnectionHeaderMode,
) -> Vec<u8> {
    let mut head = Vec::with_capacity(512);
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
    head
}

async fn write_content_length_response_body<W>(
    writer: &mut WriteHalf<W>,
    body: &mut Body,
    mut remaining: u64,
    body_read_timeout: Duration,
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
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
    writer: &mut WriteHalf<W>,
    body: &mut Body,
    first_chunk: Option<Bytes>,
    first_trailers: Option<HeaderMap>,
    emit_trailers: bool,
    body_read_timeout: Duration,
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
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
    writer: &mut WriteHalf<W>,
    body: &mut Body,
    first_chunk: Option<Bytes>,
    body_read_timeout: Duration,
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
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
    timeout(body_read_timeout, body.data())
        .await
        .map_err(|_| anyhow!("HTTP/1 response body read timed out"))
}

async fn read_response_trailers(
    body: &mut Body,
    body_read_timeout: Duration,
) -> Result<Option<HeaderMap>> {
    timeout(body_read_timeout, body.trailers())
        .await
        .map_err(|_| anyhow!("HTTP/1 response trailer read timed out"))?
        .map_err(Into::into)
}

async fn write_chunk<W>(writer: &mut WriteHalf<W>, chunk: &Bytes) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
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
    writer: &mut WriteHalf<W>,
    head: &[u8],
    first_chunk: Option<Bytes>,
    length: u64,
) -> Result<u64>
where
    W: AsyncRead + AsyncWrite + Unpin,
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
    writer: &mut WriteHalf<W>,
    head: &[u8],
    first_chunk: Option<Bytes>,
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
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
    writer: &mut WriteHalf<W>,
    head: &[u8],
    first_chunk: Option<Bytes>,
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    let Some(chunk) = first_chunk.filter(|chunk| !chunk.is_empty()) else {
        write_all_with_timeout(writer, head).await?;
        return Ok(());
    };
    write_vectored_all_with_timeout(writer, &[head, &chunk]).await
}

async fn write_all_with_timeout<W>(writer: &mut WriteHalf<W>, bytes: &[u8]) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    timeout(RESPONSE_WRITE_TIMEOUT, writer.write_all(bytes))
        .await
        .map_err(|_| anyhow!("HTTP/1 response write timed out"))?
        .map_err(Into::into)
}

async fn write_vectored_all_with_timeout<W>(
    writer: &mut WriteHalf<W>,
    slices: &[&[u8]],
) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    timeout(RESPONSE_WRITE_TIMEOUT, write_vectored_all(writer, slices))
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

async fn flush_with_timeout<W>(writer: &mut WriteHalf<W>) -> Result<()>
where
    W: AsyncRead + AsyncWrite + Unpin,
{
    timeout(RESPONSE_WRITE_TIMEOUT, writer.flush())
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
