use crate::http::body::Body;
use crate::http::codec::h1_common::{
    MAX_HEADER_BYTES, has_connection_token, has_only_chunked_transfer_encoding, parse_header_map,
    parse_version, request_keep_alive,
};
use crate::http::codec::h1_request_body::{
    forward_chunked_request_body, forward_content_length_request_body,
};
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::{Result, anyhow};
use bytes::{Buf, BytesMut};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use hyper::header::{CONTENT_LENGTH, EXPECT, HeaderMap};
use qpx_observability::RequestHandler;
use std::convert::Infallible;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};

mod response;

use self::response::{
    ConnectionHeaderMode, http1_upgrade_accepted, send_http1_response_with_interim,
    write_status_and_headers,
};
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestBodyKind {
    Empty,
    ContentLength(u64),
    Chunked,
}

struct ParsedRequestHead {
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body_kind: RequestBodyKind,
    consumed: usize,
    keep_alive: bool,
    upgrade: bool,
    send_continue: bool,
}

type BodyReadResult<I> = Result<(ReadHalf<I>, BytesMut)>;

#[cfg(test)]
pub(crate) async fn serve_http1_with_interim<I, S>(
    io: I,
    service: S,
    header_read_timeout: Duration,
) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: RequestHandler<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    serve_http1_with_interim_and_capacity(io, service, header_read_timeout, 16).await
}

pub(crate) async fn serve_http1_with_interim_and_capacity<I, S>(
    io: I,
    service: S,
    header_read_timeout: Duration,
    body_channel_capacity: usize,
) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: RequestHandler<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let (mut read_half, mut write_half) = tokio::io::split(io);
    let mut read_buf = BytesMut::new();

    loop {
        let parsed =
            match read_http1_request_head(&mut read_half, &mut read_buf, header_read_timeout).await
            {
                Ok(Some(parsed)) => parsed,
                Ok(None) => return Ok(()),
                Err(err) => {
                    write_status_and_headers(
                        &mut write_half,
                        Version::HTTP_11,
                        StatusCode::BAD_REQUEST,
                        &HeaderMap::new(),
                        ConnectionHeaderMode::Close,
                    )
                    .await?;
                    let _ = write_half.shutdown().await;
                    return Err(err);
                }
            };

        read_buf.advance(parsed.consumed);
        let mut request = Request::builder()
            .method(parsed.method.clone())
            .uri(parsed.uri)
            .body(Body::empty())?;
        *request.version_mut() = parsed.version;
        *request.headers_mut() = parsed.headers;

        if parsed.upgrade || parsed.method == Method::CONNECT {
            if parsed.body_kind != RequestBodyKind::Empty {
                write_status_and_headers(
                    &mut write_half,
                    parsed.version,
                    StatusCode::BAD_REQUEST,
                    &HeaderMap::new(),
                    ConnectionHeaderMode::Close,
                )
                .await?;
                let _ = write_half.shutdown().await;
                return Err(anyhow!(
                    "HTTP/1 CONNECT and Upgrade requests must not include request bodies"
                ));
            }
            let upgrade_commit = crate::http::protocol::upgrade::install(&mut request);
            let mut response = match service.call(request).await {
                Ok(response) => response,
                Err(impossible) => match impossible {},
            };
            let interim = response
                .extensions_mut()
                .remove::<Vec<InterimResponseHead>>()
                .unwrap_or_default();
            let status = response.status();
            let keep_alive = send_http1_response_with_interim(
                &mut write_half,
                parsed.version,
                &parsed.method,
                response,
                &interim,
                parsed.keep_alive,
                header_read_timeout,
            )
            .await?;
            if http1_upgrade_accepted(parsed.upgrade, &parsed.method, status) {
                let io = read_half.unsplit(write_half);
                let io = crate::http::protocol::io_prefix::PrefixedIo::new(io, read_buf.freeze());
                upgrade_commit.resolve_with_io(io);
                return Ok(());
            }
            if !keep_alive {
                return Ok(());
            }
            continue;
        }

        let body_prefix = read_buf.split();
        if parsed.send_continue {
            write_half
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await?;
            write_half.flush().await?;
        }

        let (body, body_task) = spawn_request_body(
            read_half,
            body_prefix,
            parsed.body_kind,
            header_read_timeout,
            body_channel_capacity,
        );
        *request.body_mut() = body;

        let mut response = match service.call(request).await {
            Ok(response) => response,
            Err(impossible) => match impossible {},
        };
        let interim = response
            .extensions_mut()
            .remove::<Vec<InterimResponseHead>>()
            .unwrap_or_default();
        let keep_alive = send_http1_response_with_interim(
            &mut write_half,
            parsed.version,
            &parsed.method,
            response,
            &interim,
            parsed.keep_alive,
            header_read_timeout,
        )
        .await?;

        if !keep_alive {
            body_task.abort();
            return Ok(());
        }

        let (next_read_half, next_buf) = body_task.await??;
        read_half = next_read_half;
        read_buf = next_buf;
    }
}

fn spawn_request_body<I>(
    read_half: ReadHalf<I>,
    read_buf: BytesMut,
    kind: RequestBodyKind,
    read_timeout: Duration,
    body_channel_capacity: usize,
) -> (Body, JoinHandle<BodyReadResult<I>>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match kind {
        RequestBodyKind::Empty => (
            Body::empty(),
            tokio::spawn(async move { Ok((read_half, read_buf)) }),
        ),
        RequestBodyKind::ContentLength(length) => {
            let (sender, body) = Body::channel_with_capacity(body_channel_capacity.max(1));
            let task = tokio::spawn(async move {
                forward_content_length_request_body(
                    read_half,
                    read_buf,
                    length,
                    sender,
                    read_timeout,
                )
                .await
            });
            (body, task)
        }
        RequestBodyKind::Chunked => {
            let (sender, body) = Body::channel_with_capacity(body_channel_capacity.max(1));
            let task = tokio::spawn(async move {
                forward_chunked_request_body(read_half, read_buf, sender, read_timeout).await
            });
            (body, task)
        }
    }
}

async fn read_http1_request_head<R>(
    reader: &mut R,
    buf: &mut BytesMut,
    header_read_timeout: Duration,
) -> Result<Option<ParsedRequestHead>>
where
    R: AsyncRead + Unpin,
{
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 128];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(buf.as_ref())? {
            httparse::Status::Complete(consumed) => {
                let method = request
                    .method
                    .ok_or_else(|| anyhow!("missing request method"))?
                    .parse::<Method>()
                    .map_err(|_| anyhow!("invalid request method"))?;
                let target = request
                    .path
                    .ok_or_else(|| anyhow!("missing request target"))?;
                let uri = target
                    .parse::<Uri>()
                    .or_else(|_| Uri::builder().path_and_query(target).build())
                    .map_err(|err| anyhow!("invalid request target: {err}"))?;
                let version = parse_version(request.version, "missing HTTP version")?;
                let headers = parse_header_map(request.headers)?;
                let body_kind = determine_request_body_kind(&headers)?;
                let keep_alive = request_keep_alive(version, &headers);
                let upgrade = request_has_upgrade(&headers);
                let send_continue = version == Version::HTTP_11
                    && body_kind != RequestBodyKind::Empty
                    && expect_continue(&headers)
                    && crate::http::protocol::semantics::validate_expect_header(&headers).is_ok();
                return Ok(Some(ParsedRequestHead {
                    method,
                    uri,
                    version,
                    headers,
                    body_kind,
                    consumed,
                    keep_alive,
                    upgrade,
                    send_continue,
                }));
            }
            httparse::Status::Partial => {
                if buf.len() >= MAX_HEADER_BYTES {
                    return Err(anyhow!(
                        "HTTP/1 request header block exceeded configured limit"
                    ));
                }
                let n = match timeout(header_read_timeout, reader.read_buf(buf)).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(err)) => return Err(err.into()),
                    Err(_) => return Err(anyhow!("HTTP/1 request header read timed out")),
                };
                if n == 0 {
                    if buf.is_empty() {
                        return Ok(None);
                    }
                    return Err(anyhow!("client connection closed mid-header"));
                }
            }
        }
    }
}

#[doc(hidden)]
pub(crate) fn fuzz_parse_http1_request_head(bytes: &[u8]) {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut headers);
    if let Ok(httparse::Status::Complete(_)) = request.parse(bytes) {
        let _ = request
            .method
            .and_then(|method| method.parse::<Method>().ok());
        let _ = request.path.and_then(|target| {
            target
                .parse::<Uri>()
                .or_else(|_| Uri::builder().path_and_query(target).build())
                .ok()
        });
        let _ = parse_version(request.version, "missing HTTP version");
        if let Ok(headers) = parse_header_map(request.headers) {
            let _ = determine_request_body_kind(&headers);
            let _ = request_keep_alive(Version::HTTP_11, &headers);
            let _ = request_has_upgrade(&headers);
        }
    }
}

fn request_has_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(hyper::header::UPGRADE) && has_connection_token(headers, "upgrade")
}

fn expect_continue(headers: &HeaderMap) -> bool {
    headers
        .get_all(EXPECT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(','))
        .any(|part| part.trim().eq_ignore_ascii_case("100-continue"))
}

fn determine_request_body_kind(headers: &HeaderMap) -> Result<RequestBodyKind> {
    let has_chunked = has_chunked_transfer_encoding(headers)?;
    let declared_length = parse_declared_content_length(headers)?;
    if has_chunked && declared_length.is_some() {
        return Err(anyhow!(
            "both transfer-encoding and content-length are present"
        ));
    }
    if has_chunked {
        return Ok(RequestBodyKind::Chunked);
    }
    if let Some(length) = declared_length {
        return Ok(if length == 0 {
            RequestBodyKind::Empty
        } else {
            RequestBodyKind::ContentLength(length)
        });
    }
    Ok(RequestBodyKind::Empty)
}

fn has_chunked_transfer_encoding(headers: &HeaderMap) -> Result<bool> {
    has_only_chunked_transfer_encoding(headers)
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
                    return Err(anyhow!("conflicting content-length values"));
                }
                Some(_) => {}
                None => parsed = Some(len),
            }
        }
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests;
