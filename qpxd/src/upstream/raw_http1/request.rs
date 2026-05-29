use super::parse_declared_content_length;
use crate::http::body::Body;
use crate::http::codec::h1_common::serialize_headers;
use anyhow::{Result, anyhow};
use bytes::Bytes;
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue, TRAILER, TRANSFER_ENCODING,
};
use hyper::{Request, Version};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::Duration;

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
    tokio::select! {
        biased;
        chunk = body.data() => chunk.transpose().map_err(Into::into),
        _ = tokio::time::sleep(Duration::ZERO) => Ok(None),
    }
}

async fn poll_body_trailers_now(body: &mut Body) -> Result<Option<HeaderMap>> {
    tokio::select! {
        biased;
        trailers = body.trailers() => trailers.map_err(Into::into),
        _ = tokio::time::sleep(Duration::ZERO) => Ok(None),
    }
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
        crate::http::protocol::semantics::validate_request_trailers(&trailers)
            .map_err(|err| anyhow!("invalid HTTP/1 request trailers: {err:?}"))?;
        let mut trailer_block = Vec::with_capacity(256);
        serialize_headers(&trailers, &mut trailer_block)?;
        stream.write_all(&trailer_block).await?;
    }
    stream.write_all(b"\r\n").await?;
    Ok(())
}

fn announced_request_trailer_names(trailers: &HeaderMap) -> Option<String> {
    if crate::http::protocol::semantics::validate_request_trailers(trailers).is_err() {
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
    let header = format!("{:X}\r\n", chunk.len());
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(chunk).await?;
    stream.write_all(b"\r\n").await?;
    Ok(())
}
