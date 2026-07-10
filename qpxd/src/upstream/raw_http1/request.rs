use super::parse_declared_content_length;
use crate::http::codec::h1_common::serialize_headers;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue, TRAILER, TRANSFER_ENCODING,
};
use hyper::{Request, Version};
use qpx_http::body::Body;
use std::future::{Future, poll_fn};
use std::io::{Error as IoError, ErrorKind, IoSlice};
use std::task::Poll;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub(super) async fn write_http1_request<S>(stream: &mut S, req: Request<Body>) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let (parts, mut body) = req.into_parts();
    let target = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let mut headers = parts.headers;
    let declared_length = parse_declared_content_length(&headers)?;
    let first_chunk = if declared_length.is_none() {
        poll_body_data_now(&mut body).await?
    } else {
        None
    };
    let first_trailers = if declared_length.is_none() && first_chunk.is_none() {
        poll_body_trailers_now(&mut body).await?
    } else {
        None
    };
    let use_chunked = declared_length.is_none()
        && (first_chunk.is_some()
            || first_trailers.is_some()
            || !http_body::Body::is_end_stream(&body));
    let announced_trailers = first_trailers
        .as_ref()
        .and_then(announced_request_trailer_names);

    headers.remove(CONNECTION);
    headers.remove(HeaderName::from_static("proxy-connection"));
    headers.remove(TRANSFER_ENCODING);
    headers.remove(TRAILER);
    if use_chunked {
        headers.remove(CONTENT_LENGTH);
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        if let Some(names) = announced_trailers.as_deref()
            && let Ok(value) = HeaderValue::from_str(names)
        {
            headers.insert(TRAILER, value);
        }
    } else if declared_length.is_none() {
        headers.remove(CONTENT_LENGTH);
    }

    let mut head = Vec::with_capacity(512);
    let version = match parts.version {
        Version::HTTP_10 => "HTTP/1.0",
        _ => "HTTP/1.1",
    };
    head.extend_from_slice(parts.method.as_str().as_bytes());
    head.extend_from_slice(b" ");
    head.extend_from_slice(target.as_bytes());
    head.extend_from_slice(b" ");
    head.extend_from_slice(version.as_bytes());
    head.extend_from_slice(b"\r\n");
    serialize_headers(&headers, &mut head)?;
    head.extend_from_slice(b"\r\n");
    stream.write_all(&head).await?;

    match declared_length {
        Some(length) => write_content_length_body(stream, &mut body, length).await?,
        None if use_chunked => {
            write_chunked_body(
                stream,
                &mut body,
                first_chunk,
                first_trailers,
                use_chunked || announced_trailers.is_some(),
            )
            .await?
        }
        None => {}
    }
    stream.flush().await?;
    Ok(())
}

async fn poll_body_data_now(body: &mut Body) -> Result<Option<Bytes>> {
    poll_fn(|cx| {
        let future = body.data();
        let mut future = std::pin::pin!(future);
        match Future::poll(future.as_mut(), cx) {
            Poll::Ready(chunk) => Poll::Ready(chunk.transpose().map_err(Into::into)),
            Poll::Pending => Poll::Ready(Ok(None)),
        }
    })
    .await
}

async fn poll_body_trailers_now(body: &mut Body) -> Result<Option<HeaderMap>> {
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

async fn write_content_length_body<S>(
    stream: &mut S,
    body: &mut Body,
    mut remaining: u64,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        let chunk_len = chunk.len() as u64;
        if chunk_len > remaining {
            return Err(anyhow!("request body exceeded declared content-length"));
        }
        if !chunk.is_empty() {
            stream.write_all(&chunk).await?;
        }
        remaining -= chunk_len;
    }
    if remaining != 0 {
        return Err(anyhow!(
            "request body ended before declared content-length was satisfied"
        ));
    }
    if body.trailers().await?.is_some() {
        return Err(anyhow!(
            "request trailers require chunked transfer-encoding"
        ));
    }
    Ok(())
}

async fn write_chunked_body<S>(
    stream: &mut S,
    body: &mut Body,
    first_chunk: Option<Bytes>,
    first_trailers: Option<HeaderMap>,
    allow_trailers: bool,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if let Some(chunk) = first_chunk {
        write_chunk(stream, &chunk).await?;
    }
    while let Some(chunk) = body.data().await {
        write_chunk(stream, &chunk?).await?;
    }
    let trailers = match first_trailers {
        Some(trailers) => Some(trailers),
        None => body.trailers().await?,
    };
    stream.write_all(b"0\r\n").await?;
    if let Some(trailers) = trailers {
        if !allow_trailers {
            return Err(anyhow!(
                "request trailers require Trailer metadata before forwarding"
            ));
        }
        qpx_http::protocol::semantics::validate_request_trailers(&trailers)
            .map_err(|err| anyhow!("invalid HTTP/1 request trailers: {err:?}"))?;
        let mut trailer_block = Vec::with_capacity(256);
        serialize_headers(&trailers, &mut trailer_block)?;
        stream.write_all(&trailer_block).await?;
    }
    stream.write_all(b"\r\n").await?;
    Ok(())
}

fn announced_request_trailer_names(trailers: &HeaderMap) -> Option<String> {
    if qpx_http::protocol::semantics::validate_request_trailers(trailers).is_err() {
        return None;
    }
    let mut names = Vec::new();
    for name in trailers.keys() {
        if name == TRAILER
            || name == CONTENT_LENGTH
            || name == TRANSFER_ENCODING
            || name == CONNECTION
        {
            continue;
        }
        names.push(name.as_str().to_string());
    }
    (!names.is_empty()).then(|| names.join(", "))
}

async fn write_chunk<S>(stream: &mut S, chunk: &Bytes) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if chunk.is_empty() {
        return Ok(());
    }
    let mut header = [0_u8; 18];
    let header = chunk_size_header(chunk.len(), &mut header);
    write_vectored_all(stream, &[header, chunk, b"\r\n"]).await?;
    Ok(())
}

async fn write_vectored_all<S>(stream: &mut S, slices: &[&[u8]]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
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
        let written = stream.write_vectored(&io_slices[..io_slice_count]).await?;
        if written == 0 {
            return Err(IoError::new(
                ErrorKind::WriteZero,
                "failed to write HTTP/1 request",
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
