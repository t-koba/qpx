use super::{RESPONSE_WRITE_TIMEOUT, has_chunked_transfer_encoding, parse_declared_content_length};
use crate::http::body::Body;
use crate::http::codec::h1_common::serialize_headers;
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use http::{Method, Response, StatusCode, Version};
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, HeaderMap, HeaderValue, TRAILER, TRANSFER_ENCODING,
};
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
            crate::http::protocol::semantics::sanitize_interim_response_headers(&mut headers);
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
    let first_chunk: Option<Bytes> = None;
    let mut first_trailers: Option<HeaderMap> = None;

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
    write_status_and_headers(
        writer,
        request_version,
        parts.status,
        &headers,
        connection_mode,
    )
    .await?;

    match body_kind {
        ResponseBodyKind::Empty => {}
        ResponseBodyKind::ContentLength(length) => {
            write_content_length_response_body(writer, &mut body, length, body_read_timeout)
                .await?;
        }
        ResponseBodyKind::Chunked => {
            write_chunked_response_body(
                writer,
                &mut body,
                first_chunk,
                first_trailers,
                emit_trailers,
                body_read_timeout,
            )
            .await?;
        }
        ResponseBodyKind::CloseDelimited => {
            write_close_delimited_response_body(writer, &mut body, first_chunk, body_read_timeout)
                .await?;
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
    write_all_with_timeout(writer, &head).await?;
    Ok(())
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
        let _ = crate::http::protocol::semantics::sanitize_response_trailers(trailers);
        if emit_trailers && !trailers.is_empty() {
            serialize_headers(trailers, &mut Vec::new())?;
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
) -> Result<Option<Result<Bytes, crate::http::body::BodyError>>> {
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
    let header = format!("{:X}\r\n", chunk.len());
    write_all_with_timeout(writer, header.as_bytes()).await?;
    write_all_with_timeout(writer, chunk).await?;
    write_all_with_timeout(writer, b"\r\n").await?;
    Ok(())
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
    let _ = crate::http::protocol::semantics::sanitize_response_trailers(trailers);
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
