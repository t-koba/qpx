use crate::http::body::Body;
use crate::http::http1_common::{
    MAX_HEADER_BYTES, has_connection_token, has_only_chunked_transfer_encoding, parse_header_map,
    parse_version, request_keep_alive, serialize_headers,
};
use crate::http::http1_request_body::{
    forward_chunked_request_body, forward_content_length_request_body,
};
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::{Result, anyhow};
use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use hyper::header::{
    CONNECTION, CONTENT_LENGTH, EXPECT, HeaderMap, HeaderValue, TRAILER, TRANSFER_ENCODING,
};
use qpx_observability::RequestHandler;
use std::convert::Infallible;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
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

enum ResponseBodyKind {
    Empty,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionHeaderMode {
    Omit,
    Close,
    KeepAlive,
    Preserve,
}

pub async fn serve_http1_with_interim<I, S>(
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
            let upgrade_commit = crate::http::upgrade::install(&mut request);
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
                let io = crate::io_prefix::PrefixedIo::new(io, read_buf.freeze());
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
            let (sender, body) = Body::channel();
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
            let (sender, body) = Body::channel();
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
                    && expect_continue(&headers);
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
pub fn fuzz_parse_http1_request_head(bytes: &[u8]) {
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

async fn send_http1_response_with_interim<W>(
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
            crate::http::semantics::sanitize_interim_response_headers(&mut headers);
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

async fn write_status_and_headers<W>(
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
        let _ = crate::http::semantics::sanitize_response_trailers(trailers);
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

fn http1_upgrade_accepted(
    request_upgrade: bool,
    request_method: &Method,
    status: StatusCode,
) -> bool {
    (request_upgrade && status == StatusCode::SWITCHING_PROTOCOLS)
        || (request_method == Method::CONNECT && status.is_success())
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
    let _ = crate::http::semantics::sanitize_response_trailers(trailers);
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
mod tests {
    use super::*;
    use qpx_observability::RequestHandler;
    use std::pin::Pin;
    use tokio::net::{TcpListener, TcpStream};

    #[derive(Clone)]
    struct StaticInterimService;

    impl RequestHandler<Request<Body>> for StaticInterimService {
        type Response = Response<Body>;
        type Error = Infallible;
        type Future =
            Pin<Box<dyn std::future::Future<Output = Result<Response<Body>, Infallible>> + Send>>;

        fn call(&self, _req: Request<Body>) -> Self::Future {
            Box::pin(async move {
                let interim = vec![InterimResponseHead {
                    status: StatusCode::from_u16(103).expect("103"),
                    headers: {
                        let mut headers = HeaderMap::new();
                        headers.insert(
                            hyper::header::LINK,
                            HeaderValue::from_static("</app.css>; rel=preload; as=style"),
                        );
                        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("99"));
                        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
                        headers.insert(
                            hyper::header::TRAILER,
                            HeaderValue::from_static("x-trailer"),
                        );
                        headers
                    },
                }];
                let mut response = Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_LENGTH, "2")
                    .body(Body::from("OK"))
                    .expect("response");
                response.extensions_mut().insert(interim);
                Ok(response)
            })
        }
    }

    #[tokio::test]
    async fn serve_http1_with_interim_emits_early_hints() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            serve_http1_with_interim(socket, StaticInterimService, Duration::from_secs(1))
                .await
                .expect("serve");
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(
                b"GET /asset HTTP/1.1\r\nHost: reverse_edges.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(text.contains("HTTP/1.1 103"));
        assert!(text.contains("</app.css>; rel=preload; as=style"));
        let interim_head = text.split("HTTP/1.1 200").next().expect("interim head");
        assert!(!interim_head.contains("Content-Length"));
        assert!(!interim_head.contains("Transfer-Encoding"));
        assert!(!interim_head.contains("Trailer"));
        assert!(text.contains("HTTP/1.1 200"));
        assert!(text.ends_with("OK"));
    }

    #[tokio::test]
    async fn serve_http1_with_interim_parse_error_sends_connection_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let _ = serve_http1_with_interim(socket, StaticInterimService, Duration::from_secs(1))
                .await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(b"BAD REQUEST\r\n\r\n")
            .await
            .expect("write malformed request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(text.starts_with("HTTP/1.1 400"));
        assert!(text.contains("Connection: close"));
    }

    #[tokio::test]
    async fn send_http1_response_with_interim_preserves_upgrade_connection_header() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (read_half, mut write_half) = tokio::io::split(server);
        let response = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(CONNECTION, "upgrade")
            .header(hyper::header::UPGRADE, "websocket")
            .body(Body::empty())
            .expect("response");

        let keep_alive = send_http1_response_with_interim(
            &mut write_half,
            Version::HTTP_11,
            &Method::GET,
            response,
            &[],
            true,
            Duration::from_secs(30),
        )
        .await
        .expect("send response");
        drop(write_half);
        drop(read_half);

        assert!(!keep_alive);
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(text.starts_with("HTTP/1.1 101"));
        assert!(text.contains("Connection: upgrade"));
        assert!(!text.contains("Connection: close"));
    }

    #[tokio::test]
    async fn send_http1_head_preserves_content_length_and_removes_trailer() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (read_half, mut write_half) = tokio::io::split(server);
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, "123")
            .header(TRAILER, "x-end")
            .body(Body::from("not serialized"))
            .expect("response");

        let keep_alive = send_http1_response_with_interim(
            &mut write_half,
            Version::HTTP_11,
            &Method::HEAD,
            response,
            &[],
            true,
            Duration::from_secs(30),
        )
        .await
        .expect("send response");
        drop(write_half);
        drop(read_half);

        assert!(keep_alive);
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8(raw).expect("utf8");
        let lower = text.to_ascii_lowercase();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(lower.contains("content-length: 123"));
        assert!(!lower.contains("trailer:"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn send_http1_no_body_status_removes_trailer_metadata() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (read_half, mut write_half) = tokio::io::split(server);
        let response = Response::builder()
            .status(StatusCode::RESET_CONTENT)
            .header(CONTENT_LENGTH, "7")
            .header(TRAILER, "x-end")
            .body(Body::empty())
            .expect("response");

        let keep_alive = send_http1_response_with_interim(
            &mut write_half,
            Version::HTTP_11,
            &Method::GET,
            response,
            &[],
            true,
            Duration::from_secs(30),
        )
        .await
        .expect("send response");
        drop(write_half);
        drop(read_half);

        assert!(keep_alive);
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(text.starts_with("HTTP/1.1 205"));
        assert!(!text.contains("Content-Length:"));
        assert!(!text.contains("Trailer:"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn request_transfer_encoding_allows_only_chunked_singleton() {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(
            determine_request_body_kind(&headers).expect("chunked"),
            RequestBodyKind::Chunked
        );

        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));
        assert!(determine_request_body_kind(&headers).is_err());
    }
}
