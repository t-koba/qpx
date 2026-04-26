use crate::http::body::Body;
use crate::tls::UpstreamCertificateInfo;
use anyhow::{anyhow, Result};
use bytes::{Buf, Bytes, BytesMut};
use hyper::header::{
    HeaderMap, HeaderName, HeaderValue, CONNECTION, CONTENT_LENGTH, TRAILER, TRANSFER_ENCODING,
};
use hyper::{Method, Request, Response, StatusCode, Version};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::warn;

const MAX_HEADER_BYTES: usize = 128 * 1024;
const READ_BUF_SIZE: usize = 16 * 1024;
const MAX_CHUNKED_BODY_BYTES: u64 = 1024 * 1024 * 1024;
const RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub(crate) struct InterimResponseHead {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
}

pub(crate) struct Http1ResponseWithInterim {
    pub(crate) interim: Vec<InterimResponseHead>,
    pub(crate) response: Response<Body>,
    pub(crate) upstream_cert: Option<UpstreamCertificateInfo>,
}

#[derive(Debug, Clone, Copy)]
enum ResponseBodyKind {
    Empty,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

struct ParsedResponseHead {
    version: Version,
    status: StatusCode,
    headers: HeaderMap,
    body_kind: ResponseBodyKind,
}

type RecycleFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type RecycleFn<S> = dyn Fn(S) -> RecycleFuture + Send + Sync;

#[derive(Clone)]
pub(crate) struct Http1ConnectionRecycler<S> {
    recycle: Arc<RecycleFn<S>>,
}

impl<S> Http1ConnectionRecycler<S> {
    pub(crate) fn new<F, Fut>(recycle: F) -> Self
    where
        F: Fn(S) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            recycle: Arc::new(move |stream| Box::pin(recycle(stream))),
        }
    }

    pub(crate) fn from_idle(idle: Arc<Mutex<Vec<S>>>) -> Self
    where
        S: Send + 'static,
    {
        Self::new(move |stream| {
            let idle = idle.clone();
            async move {
                idle.lock().await.push(stream);
            }
        })
    }

    async fn recycle(&self, stream: S) {
        (self.recycle)(stream).await;
    }
}

pub(crate) async fn send_http1_request_with_interim<S>(
    stream: S,
    req: Request<Body>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_http1_request_with_interim_inner(stream, req, None).await
}

pub(crate) async fn send_http1_request_with_interim_reusable<S>(
    stream: S,
    req: Request<Body>,
    recycler: Http1ConnectionRecycler<S>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    send_http1_request_with_interim_inner(stream, req, Some(recycler)).await
}

async fn send_http1_request_with_interim_inner<S>(
    mut stream: S,
    req: Request<Body>,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Result<Http1ResponseWithInterim>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request_method = req.method().clone();
    write_http1_request(&mut stream, req).await?;
    let (interim, final_head, buffered_body) =
        read_response_head_with_interim(&mut stream, &request_method).await?;
    let response = build_response(stream, final_head, buffered_body, recycler);
    Ok(Http1ResponseWithInterim {
        interim,
        response,
        upstream_cert: None,
    })
}

async fn write_http1_request<S>(stream: &mut S, req: Request<Body>) -> Result<()>
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
        if let Some(names) = announced_trailers.as_deref() {
            if let Ok(value) = HeaderValue::from_str(names) {
                headers.insert(TRAILER, value);
            }
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

fn serialize_headers(headers: &HeaderMap, out: &mut Vec<u8>) -> Result<()> {
    for (name, value) in headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
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
        if allow_trailers && crate::http::semantics::validate_request_trailers(&trailers).is_ok() {
            let mut trailer_block = Vec::with_capacity(256);
            serialize_headers(&trailers, &mut trailer_block)?;
            stream.write_all(&trailer_block).await?;
        }
    }
    stream.write_all(b"\r\n").await?;
    Ok(())
}

fn announced_request_trailer_names(trailers: &HeaderMap) -> Option<String> {
    if crate::http::semantics::validate_request_trailers(trailers).is_err() {
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

async fn read_response_head_with_interim<S>(
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
                    let version = parse_version(response.version)?;
                    let status = StatusCode::from_u16(
                        response
                            .code
                            .ok_or_else(|| anyhow!("upstream response missing status code"))?,
                    )?;
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

fn build_response<S>(
    stream: S,
    head: ParsedResponseHead,
    prefix: BytesMut,
    recycler: Option<Http1ConnectionRecycler<S>>,
) -> Response<Body>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let body = match head.body_kind {
        ResponseBodyKind::Empty => {
            if let Some(recycler) = recycler {
                if head.status != StatusCode::SWITCHING_PROTOCOLS
                    && prefix.is_empty()
                    && response_keep_alive(head.version, &head.headers)
                {
                    tokio::spawn(async move {
                        recycler.recycle(stream).await;
                    });
                }
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
        .expect("build response");
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
    let (mut sender, body) = Body::channel();
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
                if let Some(recycler) = recycler {
                    if leftover.is_empty() {
                        recycler.recycle(stream).await;
                    }
                }
            }
            Ok(None) => {}
            Err(err) => {
                warn!(error = ?err, "reverse raw http/1 response body relay failed");
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
    sender: &mut crate::http::body::Sender,
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
    let mut buf = vec![0u8; READ_BUF_SIZE];
    while remaining > 0 {
        let cap = std::cmp::min(buf.len() as u64, remaining) as usize;
        let n = read_with_timeout(&mut stream, &mut buf[..cap], read_timeout).await?;
        if n == 0 {
            return Err(anyhow!(
                "upstream response closed before content-length completed"
            ));
        }
        sender.send_data(Bytes::copy_from_slice(&buf[..n])).await?;
        remaining -= n as u64;
    }
    Ok((stream, prefix))
}

async fn forward_close_delimited_body<S>(
    mut stream: S,
    mut prefix: BytesMut,
    sender: &mut crate::http::body::Sender,
    read_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !prefix.is_empty() {
        sender.send_data(prefix.split().freeze()).await?;
    }
    let mut buf = vec![0u8; READ_BUF_SIZE];
    loop {
        let n = read_with_timeout(&mut stream, &mut buf, read_timeout).await?;
        if n == 0 {
            return Ok(());
        }
        sender.send_data(Bytes::copy_from_slice(&buf[..n])).await?;
    }
}

async fn forward_chunked_body<S>(
    mut stream: S,
    mut buf: BytesMut,
    sender: &mut crate::http::body::Sender,
    read_timeout: Duration,
) -> Result<(S, BytesMut)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut total_body_bytes = 0u64;
    loop {
        let line = read_crlf_line(&mut stream, &mut buf, read_timeout).await?;
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
            let trailers = read_trailer_headers(&mut stream, &mut buf, read_timeout).await?;
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
    sender: &mut crate::http::body::Sender,
    read_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut scratch = vec![0u8; READ_BUF_SIZE];
    while remaining > 0 {
        if !buf.is_empty() {
            let take = buf.len().min(remaining).min(READ_BUF_SIZE);
            sender.send_data(buf.split_to(take).freeze()).await?;
            remaining -= take;
            continue;
        }

        let cap = remaining.min(READ_BUF_SIZE);
        let n = read_with_timeout(stream, &mut scratch[..cap], read_timeout).await?;
        if n == 0 {
            return Err(anyhow!(
                "peer connection closed before chunk payload completed"
            ));
        }
        sender
            .send_data(Bytes::copy_from_slice(&scratch[..n]))
            .await?;
        remaining -= n;
    }

    fill_buffer(stream, buf, 2, read_timeout).await?;
    if &buf[..2] != b"\r\n" {
        return Err(anyhow!("chunk payload missing trailing CRLF"));
    }
    buf.advance(2);
    Ok(())
}

async fn read_crlf_line<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    read_timeout: Duration,
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
        fill_buffer_capped(stream, buf, 1, MAX_HEADER_BYTES, read_timeout).await?;
    }
}

async fn read_trailer_headers<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    read_timeout: Duration,
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
                fill_buffer_capped(stream, buf, 1, MAX_HEADER_BYTES, read_timeout).await?
            }
        }
    }
}

async fn fill_buffer<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    min_len: usize,
    read_timeout: Duration,
) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    while buf.len() < min_len {
        let n = read_buf_with_timeout(stream, buf, read_timeout).await?;
        if n == 0 {
            return Err(anyhow!("upstream connection closed unexpectedly"));
        }
    }
    Ok(())
}

async fn fill_buffer_capped<S>(
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
        let n = read_buf_with_timeout(stream, buf, read_timeout).await?;
        if n == 0 {
            return Err(anyhow!("upstream connection closed unexpectedly"));
        }
    }
    Ok(())
}

async fn read_with_timeout<S>(
    stream: &mut S,
    buf: &mut [u8],
    read_timeout: Duration,
) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    timeout(read_timeout, stream.read(buf))
        .await
        .map_err(|_| anyhow!("raw HTTP/1 upstream body read timed out"))?
        .map_err(Into::into)
}

async fn read_buf_with_timeout<S>(
    stream: &mut S,
    buf: &mut BytesMut,
    read_timeout: Duration,
) -> Result<usize>
where
    S: AsyncRead + Unpin,
{
    timeout(read_timeout, stream.read_buf(buf))
        .await
        .map_err(|_| anyhow!("raw HTTP/1 upstream body read timed out"))?
        .map_err(Into::into)
}

fn find_crlf(buf: &BytesMut) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

fn parse_header_map(headers: &[httparse::Header<'_>]) -> Result<HeaderMap> {
    let mut out = HeaderMap::new();
    for header in headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())?;
        let value = HeaderValue::from_bytes(header.value)?;
        out.append(name, value);
    }
    Ok(out)
}

fn parse_version(version: Option<u8>) -> Result<Version> {
    match version {
        Some(0) => Ok(Version::HTTP_10),
        Some(1) => Ok(Version::HTTP_11),
        Some(other) => Err(anyhow!("unsupported HTTP version: 1.{}", other)),
        None => Err(anyhow!("missing upstream HTTP version")),
    }
}

fn determine_response_body_kind(
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
    let mut saw_transfer_encoding = false;
    let mut last = None::<String>;
    for value in headers.get_all(TRANSFER_ENCODING).iter() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid transfer-encoding header"))?;
        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            saw_transfer_encoding = true;
            last = Some(token.to_ascii_lowercase());
        }
    }
    if !saw_transfer_encoding {
        return Ok(false);
    }
    match last.as_deref() {
        Some("chunked") => Ok(true),
        Some(other) => Err(anyhow!(
            "unsupported upstream transfer-encoding final coding: {}",
            other
        )),
        None => Ok(false),
    }
}

fn parse_declared_content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut parsed = None::<u64>;
    for value in headers.get_all(CONTENT_LENGTH).iter() {
        let raw = value
            .to_str()
            .map_err(|_| anyhow!("invalid content-length header"))?;
        for part in raw.split(',') {
            let len = part
                .trim()
                .parse::<u64>()
                .map_err(|_| anyhow!("invalid content-length value: {}", part.trim()))?;
            match parsed {
                Some(existing) if existing != len => {
                    return Err(anyhow!("conflicting content-length values"))
                }
                Some(_) => {}
                None => parsed = Some(len),
            }
        }
    }
    Ok(parsed)
}

fn response_body_allows_reuse(kind: ResponseBodyKind) -> bool {
    !matches!(kind, ResponseBodyKind::CloseDelimited)
}

fn response_keep_alive(version: Version, headers: &HeaderMap) -> bool {
    match version {
        Version::HTTP_10 => has_connection_token(headers, "keep-alive"),
        _ => !has_connection_token(headers, "close"),
    }
}

fn has_connection_token(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn send_http1_request_with_interim_parses_early_hints() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("read request");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(std::str::from_utf8(&raw)
                .expect("utf8")
                .starts_with("GET /asset HTTP/1.1\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 103 Early Hints\r\nLink: </app.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                )
                .await
                .expect("write response");
        });

        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let response = send_http1_request_with_interim(
            stream,
            Request::builder()
                .method(Method::GET)
                .uri("/asset")
                .header("host", "origin.test")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("proxy response");

        assert_eq!(response.interim.len(), 1);
        assert_eq!(
            response.interim[0].status,
            StatusCode::from_u16(103).unwrap()
        );
        assert_eq!(
            response.interim[0]
                .headers
                .get("link")
                .and_then(|value| value.to_str().ok()),
            Some("</app.css>; rel=preload; as=style")
        );
        assert_eq!(response.response.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(response.response.into_body())
                .await
                .expect("body bytes"),
            Bytes::from_static(b"OK")
        );
    }

    #[tokio::test]
    async fn switching_protocols_is_not_parsed_as_interim() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("read request");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .expect("write response");
        });

        let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let response = send_http1_request_with_interim(
            stream,
            Request::builder()
                .method(Method::GET)
                .uri("/chat")
                .header("host", "origin.test")
                .header("connection", "upgrade")
                .header("upgrade", "websocket")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("proxy response");

        assert!(response.interim.is_empty());
        assert_eq!(response.response.status(), StatusCode::SWITCHING_PROTOCOLS);
    }

    #[test]
    fn parse_declared_content_length_accepts_repeated_equal_values() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("12"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("12"));
        assert_eq!(parse_declared_content_length(&headers).unwrap(), Some(12));
    }

    #[test]
    fn reset_content_response_has_no_body_and_allows_reuse() {
        let headers = HeaderMap::new();
        let kind = determine_response_body_kind(&Method::GET, StatusCode::RESET_CONTENT, &headers)
            .expect("body kind");
        assert!(matches!(kind, ResponseBodyKind::Empty));
        assert!(response_body_allows_reuse(kind));
    }

    #[tokio::test]
    async fn chunked_response_reader_rejects_oversized_chunk_before_payload_allocation() {
        let (mut origin, proxy) = tokio::io::duplex(1024);
        origin
            .write_all(b"40000001\r\n")
            .await
            .expect("write chunk header");
        drop(origin);
        let (mut sender, _body) = Body::channel();

        let err = forward_chunked_body(
            proxy,
            BytesMut::new(),
            &mut sender,
            RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
        )
        .await
        .expect_err("oversized chunk");
        assert!(
            err.to_string().contains("chunked response body exceeds"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn write_http1_request_announces_chunked_request_trailers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                if raw
                    .windows(b"x-checksum: abc123\r\n\r\n".len())
                    .any(|w| w == b"x-checksum: abc123\r\n\r\n")
                {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("response");
            raw
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let (mut sender, body) = Body::channel();
        tokio::spawn(async move {
            let mut trailers = HeaderMap::new();
            trailers.insert(
                HeaderName::from_static("x-checksum"),
                HeaderValue::from_static("abc123"),
            );
            let _ = sender.send_trailers(trailers).await;
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("/trailers")
            .header("host", "origin.test")
            .body(body)
            .expect("request");
        let _ = send_http1_request_with_interim(stream, request).await;
        let raw = server.await.expect("server");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(text.contains("trailer: x-checksum\r\n"));
        assert!(text.contains("x-checksum: abc123\r\n"));
    }
}
