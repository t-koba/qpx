use super::io::{determine_response_body_kind, response_body_allows_reuse};
use super::response::{
    ParsedResponseHead, RawParsedResponseHead, ResponseBodyKind, build_raw_response,
    build_response, forward_chunked_body, forward_close_delimited_body,
};
use super::{
    Http1ConnectionRecycler, INITIAL_READ_BUF_SIZE, RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT,
    RawHttp1ResponseHead, parse_declared_content_length, send_http1_request_with_interim,
};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::header::{CONTENT_LENGTH, HeaderName, HeaderValue, TRANSFER_ENCODING};
use hyper::{HeaderMap, Method, Request, StatusCode, Version};
use qpx_http::body::Body;
use qpx_http::body::to_bytes;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;

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
        assert!(
            std::str::from_utf8(&raw)
                .expect("utf8")
                .starts_with("GET /asset HTTP/1.1\r\n")
        );
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
async fn upstream_response_rejects_non_http_status_class() {
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
            .write_all(b"HTTP/1.1 700 Weird\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("write response");
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let result = send_http1_request_with_interim(
        stream,
        Request::builder()
            .method(Method::GET)
            .uri("/status")
            .header("host", "origin.test")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    let err = match result {
        Ok(_) => panic!("6xx upstream response status must fail"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("out of range"), "{err}");
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
async fn chunked_response_build_removes_conflicting_content_length() {
    let mut headers = HeaderMap::new();
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("999"));
    let (stream, _peer) = tokio::io::duplex(64);
    let response = build_response(
        stream,
        ParsedResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::OK,
            headers,
            body_kind: ResponseBodyKind::Chunked,
        },
        BytesMut::new(),
        BytesMut::new(),
        None,
    );
    assert!(!response.headers().contains_key(CONTENT_LENGTH));
}

#[tokio::test]
async fn inline_content_length_response_recycles_before_body_release() {
    let (stream, _peer) = tokio::io::duplex(64);
    let recycled = Arc::new(AtomicUsize::new(0));
    let recycled_capacity = Arc::new(AtomicUsize::new(0));
    let recycled_write_capacity = Arc::new(AtomicUsize::new(0));
    let recycled_in_closure = recycled.clone();
    let capacity_in_closure = recycled_capacity.clone();
    let write_capacity_in_closure = recycled_write_capacity.clone();
    let mut prefix = BytesMut::with_capacity(4096);
    prefix.extend_from_slice(b"OK");
    let response = build_response(
        stream,
        ParsedResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body_kind: ResponseBodyKind::ContentLength(2),
        },
        prefix,
        BytesMut::with_capacity(512),
        Some(Http1ConnectionRecycler::new(
            move |_stream, read_buf, write_buf| {
                recycled_in_closure.fetch_add(1, Ordering::SeqCst);
                capacity_in_closure.store(read_buf.capacity(), Ordering::SeqCst);
                write_capacity_in_closure.store(write_buf.capacity(), Ordering::SeqCst);
            },
        )),
    );

    assert_eq!(recycled.load(Ordering::SeqCst), 1);
    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        Bytes::from_static(b"OK")
    );
    assert_eq!(recycled.load(Ordering::SeqCst), 1);
    assert!(recycled_capacity.load(Ordering::SeqCst) >= INITIAL_READ_BUF_SIZE);
    assert!(recycled_write_capacity.load(Ordering::SeqCst) >= 512);
}

#[tokio::test]
async fn inline_raw_content_length_response_recycles_before_body_release() {
    let (stream, _peer) = tokio::io::duplex(64);
    let recycled = Arc::new(AtomicUsize::new(0));
    let recycled_in_closure = recycled.clone();
    let mut prefix = BytesMut::with_capacity(INITIAL_READ_BUF_SIZE);
    prefix.extend_from_slice(b"OK");
    let headers = [httparse::Header {
        name: "Content-Length",
        value: b"2",
    }];
    let mut raw =
        RawHttp1ResponseHead::from_parsed(&headers, &Method::GET, StatusCode::OK, Version::HTTP_11)
            .expect("raw response head");
    raw.finalize(Version::HTTP_2, "qpx");
    let response = build_raw_response(
        stream,
        RawParsedResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::OK,
            raw: Arc::new(raw),
        },
        prefix,
        BytesMut::with_capacity(512),
        Some(Http1ConnectionRecycler::new(
            move |_stream, _read_buf, _write_buf| {
                recycled_in_closure.fetch_add(1, Ordering::SeqCst);
            },
        )),
    );

    assert_eq!(recycled.load(Ordering::SeqCst), 1);
    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        Bytes::from_static(b"OK")
    );
}

#[tokio::test]
async fn pull_content_length_response_recycles_after_complete_body() {
    let (proxy, mut origin) = tokio::io::duplex(64);
    let recycled = Arc::new(AtomicUsize::new(0));
    let recycled_in_closure = recycled.clone();
    let response = build_response(
        proxy,
        ParsedResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body_kind: ResponseBodyKind::ContentLength(2),
        },
        BytesMut::from(&b"O"[..]),
        BytesMut::new(),
        Some(Http1ConnectionRecycler::new(
            move |_stream, _read_buf, _write_buf| {
                recycled_in_closure.fetch_add(1, Ordering::SeqCst);
            },
        )),
    );
    origin.write_all(b"K").await.expect("write body");

    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        Bytes::from_static(b"OK")
    );
    assert_eq!(recycled.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn short_content_length_response_uses_bounded_read_capacity() {
    let max_read_capacity = Arc::new(AtomicUsize::new(0));
    let stream = RecordingStream::new(Bytes::from_static(b"OK"), max_read_capacity.clone());
    let response = build_response(
        stream,
        ParsedResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body_kind: ResponseBodyKind::ContentLength(2),
        },
        BytesMut::with_capacity(INITIAL_READ_BUF_SIZE),
        BytesMut::new(),
        None,
    );

    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        Bytes::from_static(b"OK")
    );
    assert!(
        max_read_capacity.load(Ordering::SeqCst) <= INITIAL_READ_BUF_SIZE,
        "short body read unexpectedly reserved more than the initial response buffer"
    );
}

#[tokio::test]
async fn pull_content_length_response_does_not_recycle_with_leftover_bytes() {
    let (proxy, mut origin) = tokio::io::duplex(64);
    let recycled = Arc::new(AtomicUsize::new(0));
    let recycled_in_closure = recycled.clone();
    let response = build_response(
        proxy,
        ParsedResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body_kind: ResponseBodyKind::ContentLength(2),
        },
        BytesMut::from(&b"O"[..]),
        BytesMut::new(),
        Some(Http1ConnectionRecycler::new(
            move |_stream, _read_buf, _write_buf| {
                recycled_in_closure.fetch_add(1, Ordering::SeqCst);
            },
        )),
    );
    origin.write_all(b"KEXTRA").await.expect("write body");

    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        Bytes::from_static(b"OK")
    );
    assert_eq!(recycled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn chunked_response_reader_rejects_oversized_chunk_before_payload_allocation() {
    let (mut origin, proxy) = tokio::io::duplex(1024);
    origin
        .write_all(b"40000001\r\n")
        .await
        .expect("write chunk header");
    drop(origin);
    let (mut sender, _body) = Body::channel_with_capacity(16);

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
async fn chunked_response_reader_sanitizes_trailers_before_exposure() {
    let (proxy, origin) = tokio::io::duplex(64);
    drop(origin);
    let response = build_response(
        proxy,
        ParsedResponseHead {
            version: Version::HTTP_11,
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body_kind: ResponseBodyKind::Chunked,
        },
        BytesMut::from(&b"0\r\nContent-Length: 9\r\nX-Checksum: valid\r\n\r\n"[..]),
        BytesMut::new(),
        None,
    );
    let mut body = response.into_body();

    let frame = body
        .frame()
        .await
        .expect("trailer frame")
        .expect("valid trailer frame");
    let trailers = frame.into_trailers().expect("trailers");
    assert!(!trailers.contains_key(CONTENT_LENGTH));
    assert_eq!(
        trailers.get("x-checksum"),
        Some(&HeaderValue::from_static("valid"))
    );
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn response_body_relay_exits_when_downstream_body_is_dropped() {
    let (stream, _peer) = tokio::io::duplex(64);
    let (mut sender, body) = Body::channel();
    let relay = tokio::spawn(async move {
        forward_close_delimited_body(
            stream,
            BytesMut::new(),
            &mut sender,
            Duration::from_secs(30),
        )
        .await
    });

    drop(body);

    let err = tokio::time::timeout(Duration::from_millis(200), relay)
        .await
        .expect("relay should observe downstream close")
        .expect("relay task")
        .expect_err("relay must stop without waiting for upstream read timeout");
    assert!(
        format!("{err:?}").contains("downstream response body receiver closed"),
        "unexpected error: {err:?}"
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
    let mut trailers = HeaderMap::new();
    trailers.insert(
        HeaderName::from_static("x-checksum"),
        HeaderValue::from_static("abc123"),
    );
    let body = Body::replay(Bytes::new(), Some(trailers));
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

struct RecordingStream {
    input: Bytes,
    offset: usize,
    max_read_capacity: Arc<AtomicUsize>,
}

impl RecordingStream {
    fn new(input: Bytes, max_read_capacity: Arc<AtomicUsize>) -> Self {
        Self {
            input,
            offset: 0,
            max_read_capacity,
        }
    }
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.max_read_capacity
            .fetch_max(buf.remaining(), Ordering::SeqCst);
        let remaining = &self.input[self.offset..];
        let len = remaining.len().min(buf.remaining());
        buf.put_slice(&remaining[..len]);
        self.offset += len;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
