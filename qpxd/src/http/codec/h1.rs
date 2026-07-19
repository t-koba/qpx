use crate::http::codec::h1_common::{
    MAX_HEADER_BYTES, has_connection_token, has_only_chunked_transfer_encoding, parse_header_map,
    parse_header_map_recycled, parse_version, request_keep_alive,
};
use crate::http::codec::h1_request_body::{
    forward_chunked_request_body, forward_content_length_request_body,
};
use crate::http::codec::lazy_timeout::timeout_after_pending;
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use hyper::header::{CONTENT_LENGTH, EXPECT, HeaderMap};
use qpx_http::body::Body;
use qpx_observability::RequestHandler;
use std::convert::Infallible;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::Duration;

mod response;
mod zero_copy;

use self::response::{ConnectionHeaderMode, http1_upgrade_accepted, write_status_and_headers};
pub(crate) use self::response::{
    send_http1_response_with_interim, send_raw_http1_response_relay_with_interim,
    send_static_http1_response,
};
use self::zero_copy::ZeroCopySocket;
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestBodyKind {
    Empty,
    ContentLength(u64),
    Chunked,
}

#[derive(Debug)]
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

type BodyReadResult<R> = Result<(R, BytesMut)>;

enum RequestBodyRead<R>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    Inline { read_half: R, read_buf: BytesMut },
    Spawned(JoinHandle<BodyReadResult<R>>),
}

struct ServeHttp1PartsOptions<U> {
    header_read_timeout: Duration,
    body_channel_capacity: usize,
    zero_copy: Option<ZeroCopySocket>,
    reunite: U,
}

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
{
    let (read_half, write_half) = tokio::io::split(io);
    serve_http1_parts(
        read_half,
        write_half,
        BytesMut::new(),
        service,
        ServeHttp1PartsOptions {
            header_read_timeout,
            body_channel_capacity,
            zero_copy: None,
            reunite: |read_half: tokio::io::ReadHalf<I>, write_half: tokio::io::WriteHalf<I>| {
                Ok(read_half.unsplit(write_half))
            },
        },
    )
    .await
}

pub(crate) async fn serve_http1_tcp_with_interim_and_capacity<S>(
    io: TcpStream,
    prefix: Bytes,
    service: S,
    header_read_timeout: Duration,
    body_channel_capacity: usize,
) -> Result<()>
where
    S: RequestHandler<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Send
        + Sync
        + 'static,
{
    let zero_copy = ZeroCopySocket::for_tcp(&io);
    let read_buf = prefix
        .try_into_mut()
        .unwrap_or_else(|prefix| BytesMut::from(prefix.as_ref()));
    let (read_half, write_half) = io.into_split();
    serve_http1_parts(
        read_half,
        write_half,
        read_buf,
        service,
        ServeHttp1PartsOptions {
            header_read_timeout,
            body_channel_capacity,
            zero_copy,
            reunite: |read_half: tokio::net::tcp::OwnedReadHalf,
                      write_half: tokio::net::tcp::OwnedWriteHalf| {
                read_half
                    .reunite(write_half)
                    .map_err(|_| anyhow!("failed to reunite HTTP/1 TCP stream"))
            },
        },
    )
    .await
}

async fn serve_http1_parts<R, W, S, U, I>(
    mut read_half: R,
    mut write_half: W,
    mut read_buf: BytesMut,
    service: S,
    options: ServeHttp1PartsOptions<U>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    S: RequestHandler<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Send
        + Sync
        + 'static,
    U: FnOnce(R, W) -> Result<I>,
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ServeHttp1PartsOptions {
        header_read_timeout,
        body_channel_capacity,
        mut zero_copy,
        reunite,
    } = options;
    let mut reunite = Some(reunite);
    let mut response_head_buf = BytesMut::with_capacity(512);

    loop {
        let parsed =
            match read_http1_request_head(&mut read_half, &mut read_buf, header_read_timeout).await
            {
                Ok(Some(parsed)) => parsed,
                Ok(None) => return Ok(()),
                Err(err) => {
                    let status = if err.downcast_ref::<RequestHeaderFieldsTooLarge>().is_some() {
                        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
                    } else {
                        StatusCode::BAD_REQUEST
                    };
                    write_status_and_headers(
                        &mut write_half,
                        &mut response_head_buf,
                        Version::HTTP_11,
                        status,
                        &HeaderMap::new(),
                        ConnectionHeaderMode::Close,
                    )
                    .await?;
                    let _ = write_half.shutdown().await;
                    return Err(err);
                }
            };

        read_buf.advance(parsed.consumed);
        let mut request = Request::new(Body::empty());
        *request.method_mut() = parsed.method.clone();
        *request.uri_mut() = parsed.uri;
        *request.version_mut() = parsed.version;
        *request.headers_mut() = parsed.headers;
        if parsed.upgrade || parsed.method == Method::CONNECT {
            if parsed.body_kind != RequestBodyKind::Empty {
                write_status_and_headers(
                    &mut write_half,
                    &mut response_head_buf,
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
                &mut response_head_buf,
            )
            .await?;
            if http1_upgrade_accepted(parsed.upgrade, &parsed.method, status) {
                let reunite = reunite
                    .take()
                    .ok_or_else(|| anyhow!("HTTP/1 stream was already reunited"))?;
                let io = reunite(read_half, write_half)?;
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

        let (body, body_read) = prepare_request_body(
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
        let keep_alive = response::send_http1_response_with_interim_zero_copy(
            &mut write_half,
            parsed.version,
            &parsed.method,
            response,
            &interim,
            parsed.keep_alive,
            header_read_timeout,
            &mut response_head_buf,
            zero_copy.as_mut(),
        )
        .await?;

        if !keep_alive {
            if let RequestBodyRead::Spawned(body_task) = body_read {
                body_task.abort();
            }
            return Ok(());
        }

        match body_read {
            RequestBodyRead::Inline {
                read_half: next_read_half,
                read_buf: next_buf,
            } => {
                read_half = next_read_half;
                read_buf = next_buf;
            }
            RequestBodyRead::Spawned(body_task) => {
                let (next_read_half, next_buf) = body_task.await??;
                read_half = next_read_half;
                read_buf = next_buf;
            }
        }
    }
}

fn prepare_request_body<R>(
    read_half: R,
    read_buf: BytesMut,
    kind: RequestBodyKind,
    read_timeout: Duration,
    body_channel_capacity: usize,
) -> (Body, RequestBodyRead<R>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    match kind {
        RequestBodyKind::Empty => (
            Body::empty(),
            RequestBodyRead::Inline {
                read_half,
                read_buf,
            },
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
            (body, RequestBodyRead::Spawned(task))
        }
        RequestBodyKind::Chunked => {
            let (sender, body) = Body::channel_with_capacity(body_channel_capacity.max(1));
            let task = tokio::spawn(async move {
                forward_chunked_request_body(read_half, read_buf, sender, read_timeout).await
            });
            (body, RequestBodyRead::Spawned(task))
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
        if buf.is_empty() {
            let n = match timeout_after_pending(header_read_timeout, reader.read_buf(buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(err)) => return Err(err.into()),
                Err(_) => return Err(anyhow!("HTTP/1 request header read timed out")),
            };
            if n == 0 {
                return Ok(None);
            }
        }
        match try_parse_http1_request_head(buf.as_ref())? {
            Some(parsed) => return Ok(Some(parsed)),
            None => {
                if buf.len() >= MAX_HEADER_BYTES {
                    return Err(RequestHeaderFieldsTooLarge.into());
                }
                let n = match timeout_after_pending(header_read_timeout, reader.read_buf(buf)).await
                {
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

const COMMON_HTTP1_REQUEST_HEADERS: usize = 32;
const MAX_HTTP1_REQUEST_HEADERS: usize = 128;

fn try_parse_http1_request_head(buf: &[u8]) -> Result<Option<ParsedRequestHead>> {
    let mut common_headers =
        [const { std::mem::MaybeUninit::uninit() }; COMMON_HTTP1_REQUEST_HEADERS];
    let mut request = httparse::Request::new(&mut []);
    match httparse::ParserConfig::default().parse_request_with_uninit_headers(
        &mut request,
        buf,
        &mut common_headers,
    ) {
        Ok(httparse::Status::Complete(consumed)) => {
            return finish_parsed_http1_request(&request, consumed).map(Some);
        }
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => {}
        Err(error) => return Err(error.into()),
    }

    let mut maximum_headers =
        [const { std::mem::MaybeUninit::uninit() }; MAX_HTTP1_REQUEST_HEADERS];
    let mut request = httparse::Request::new(&mut []);
    match httparse::ParserConfig::default().parse_request_with_uninit_headers(
        &mut request,
        buf,
        &mut maximum_headers,
    ) {
        Ok(httparse::Status::Complete(consumed)) => {
            finish_parsed_http1_request(&request, consumed).map(Some)
        }
        Ok(httparse::Status::Partial) => Ok(None),
        Err(httparse::Error::TooManyHeaders) => Err(RequestHeaderFieldsTooLarge.into()),
        Err(error) => Err(error.into()),
    }
}

fn finish_parsed_http1_request(
    request: &httparse::Request<'_, '_>,
    consumed: usize,
) -> Result<ParsedRequestHead> {
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
    let headers = parse_header_map_recycled(request.headers)?;
    let body_kind = determine_request_body_kind(&headers)?;
    let keep_alive = request_keep_alive(version, &headers);
    let upgrade = request_has_upgrade(&headers);
    let send_continue = version == Version::HTTP_11
        && body_kind != RequestBodyKind::Empty
        && expect_continue(&headers)
        && qpx_http::protocol::semantics::validate_expect_header(&headers).is_ok();
    Ok(ParsedRequestHead {
        method,
        uri,
        version,
        headers,
        body_kind,
        consumed,
        keep_alive,
        upgrade,
        send_continue,
    })
}

#[derive(Debug, thiserror::Error)]
#[error("HTTP/1 request header fields exceeded configured limits")]
struct RequestHeaderFieldsTooLarge;

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
