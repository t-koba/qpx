use super::io::{determine_response_body_kind, response_body_allows_reuse};
use super::response::{
    ParsedResponseHead, RawParsedResponseHead, ResponseBodyKind, build_raw_response,
    build_response, forward_chunked_body, forward_close_delimited_body,
    read_finalized_raw_response_head_with_interim,
    read_finalized_raw_response_head_with_interim_under_external_deadline,
    read_response_head_with_interim,
};
use super::{
    Http1ConnectionRecycler, INITIAL_READ_BUF_SIZE, MAX_HEADER_BYTES,
    RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT, RawHttp1ResponseHead, UpstreamConnectionClosed,
    parse_declared_content_length, send_http1_request_with_interim,
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
async fn send_http1_request_with_interim_preserves_absolute_form_target() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        crate::test_util::read_request_head(&mut stream, &mut raw, &mut buf).await;
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .expect("write response");
        raw
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let response = send_http1_request_with_interim(
        stream,
        Request::builder()
            .method(Method::GET)
            .uri("http://origin.example.test/path?view=all")
            .header("host", "origin.example.test")
            .body(Body::empty())
            .expect("request"),
    )
    .await
    .expect("proxy response");
    assert_eq!(response.response.status(), StatusCode::NO_CONTENT);
    let raw = server.await.expect("server");
    assert!(
        String::from_utf8_lossy(&raw)
            .starts_with("GET http://origin.example.test/path?view=all HTTP/1.1\r\n"),
        "request was not serialized with absolute-form:\n{}",
        String::from_utf8_lossy(&raw)
    );
}

#[tokio::test]
async fn send_http1_request_with_interim_parses_early_hints() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        crate::test_util::read_request_head(&mut stream, &mut raw, &mut buf).await;
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
            .headers_for_egress()
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
async fn partial_upstream_response_heads_progress_and_stay_within_the_limit() {
    let response_bytes = Bytes::from_static(
        b"HTTP/1.1 200 OK\r\nX-Partial: segmented\r\nContent-Length: 4\r\n\r\nBODY",
    );
    let mut parsed_reader = RecordingStream::segmented(response_bytes.clone(), 11, false);
    let (interim, parsed, remainder) =
        read_response_head_with_interim(&mut parsed_reader, BytesMut::new(), &Method::GET)
            .await
            .expect("read fragmented response head");
    assert!(interim.is_empty());
    assert_eq!(parsed.status, StatusCode::OK);
    assert!(matches!(
        parsed.body_kind,
        ResponseBodyKind::ContentLength(4)
    ));
    assert_eq!(remainder.as_ref(), b"BODY");
    assert!(parsed_reader.read_polls > 1);

    let mut raw_reader = RecordingStream::segmented(response_bytes, 11, false);
    let (interim, parsed, remainder) = read_finalized_raw_response_head_with_interim(
        &mut raw_reader,
        BytesMut::new(),
        &Method::GET,
        Version::HTTP_11,
        "segmented-timed-test",
    )
    .await
    .expect("read fragmented raw response head");
    assert!(interim.is_empty());
    assert_eq!(parsed.status, StatusCode::OK);
    assert_eq!(remainder.as_ref(), b"BODY");
    assert!(raw_reader.read_polls > 1);

    let mut incomplete_head = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
    incomplete_head.resize(MAX_HEADER_BYTES, b'x');
    let incomplete_head = Bytes::from(incomplete_head);
    let mut limited_reader = RecordingStream::segmented(incomplete_head.clone(), usize::MAX, false);
    let read_buf = BytesMut::with_capacity(MAX_HEADER_BYTES * 2);
    let error =
        match read_response_head_with_interim(&mut limited_reader, read_buf, &Method::GET).await {
            Ok(_) => panic!("partial head at the byte cap must fail"),
            Err(error) => error,
        };
    assert!(
        error
            .to_string()
            .contains("HTTP/1 header block exceeded configured limit")
    );
    assert_eq!(limited_reader.read_polls, 1);

    let mut raw_limited_reader = RecordingStream::segmented(incomplete_head, usize::MAX, false);
    let read_buf = BytesMut::with_capacity(MAX_HEADER_BYTES * 2);
    let error = match read_finalized_raw_response_head_with_interim(
        &mut raw_limited_reader,
        read_buf,
        &Method::GET,
        Version::HTTP_11,
        "partial-at-limit-test",
    )
    .await
    {
        Ok(_) => panic!("partial raw head at the byte cap must fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("HTTP/1 header block exceeded configured limit")
    );
    assert_eq!(raw_limited_reader.read_polls, 1);

    let partial = Bytes::from_static(b"HTTP/1.1 200 OK\r\nX-Partial:");
    let mut eof_reader = RecordingStream::segmented(partial.clone(), usize::MAX, false);
    let error =
        match read_response_head_with_interim(&mut eof_reader, BytesMut::new(), &Method::GET).await
        {
            Ok(_) => panic!("EOF after partial response head must fail"),
            Err(error) => error,
        };
    assert!(error.downcast_ref::<UpstreamConnectionClosed>().is_some());
    assert_eq!(eof_reader.read_polls, 2);

    let mut stalled_reader = RecordingStream::segmented(partial, usize::MAX, true);
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        read_response_head_with_interim(&mut stalled_reader, BytesMut::new(), &Method::GET),
    )
    .await;
    assert!(
        result.is_err(),
        "partial input must yield to the outer deadline"
    );
    assert!(stalled_reader.read_polls >= 2);
}

#[tokio::test]
async fn raw_upstream_response_head_yields_on_stall_and_fails_closed() {
    let partial = Bytes::from_static(b"HTTP/1.1 200 OK\r\nX-Partial:");

    let mut eof_reader = RecordingStream::segmented(partial.clone(), usize::MAX, false);
    let error = match read_finalized_raw_response_head_with_interim(
        &mut eof_reader,
        BytesMut::new(),
        &Method::GET,
        Version::HTTP_11,
        "spin-raw-eof-test",
    )
    .await
    {
        Ok(_) => panic!("EOF after partial raw response head must fail"),
        Err(error) => error,
    };
    assert!(error.downcast_ref::<UpstreamConnectionClosed>().is_some());
    assert_eq!(eof_reader.read_polls, 2);

    let mut stalled_reader = RecordingStream::segmented(partial, usize::MAX, true);
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        read_finalized_raw_response_head_with_interim(
            &mut stalled_reader,
            BytesMut::new(),
            &Method::GET,
            Version::HTTP_11,
            "spin-raw-stall-test",
        ),
    )
    .await;
    assert!(
        result.is_err(),
        "partial raw input must yield to the outer deadline"
    );
    assert!(stalled_reader.read_polls >= 2);
}

#[tokio::test]
async fn external_deadline_raw_response_head_progresses_and_stays_bounded() {
    let response_bytes = Bytes::from_static(
        b"HTTP/1.1 200 OK\r\nX-Partial: segmented\r\nContent-Length: 4\r\n\r\nBODY",
    );
    let mut segmented_reader = RecordingStream::segmented(response_bytes, 11, false);
    let (interim, parsed, remainder) =
        read_finalized_raw_response_head_with_interim_under_external_deadline(
            &mut segmented_reader,
            BytesMut::new(),
            &Method::GET,
            Version::HTTP_11,
            "spin-ext-segmented-test",
        )
        .await
        .expect("read fragmented raw response head under external deadline");
    assert!(interim.is_empty());
    assert_eq!(parsed.status, StatusCode::OK);
    assert_eq!(remainder.as_ref(), b"BODY");
    assert!(segmented_reader.read_polls > 1);

    let partial = Bytes::from_static(b"HTTP/1.1 200 OK\r\nX-Partial:");
    let mut stalled_reader = RecordingStream::segmented(partial.clone(), usize::MAX, true);
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        read_finalized_raw_response_head_with_interim_under_external_deadline(
            &mut stalled_reader,
            BytesMut::new(),
            &Method::GET,
            Version::HTTP_11,
            "spin-ext-stall-test",
        ),
    )
    .await;
    assert!(
        result.is_err(),
        "partial raw input must yield to the external deadline"
    );
    assert!(stalled_reader.read_polls >= 2);

    let mut incomplete_head = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
    incomplete_head.resize(MAX_HEADER_BYTES, b'x');
    let mut limited_reader =
        RecordingStream::segmented(Bytes::from(incomplete_head), usize::MAX, false);
    let error = match read_finalized_raw_response_head_with_interim_under_external_deadline(
        &mut limited_reader,
        BytesMut::with_capacity(MAX_HEADER_BYTES * 2),
        &Method::GET,
        Version::HTTP_11,
        "spin-ext-cap-test",
    )
    .await
    {
        Ok(_) => panic!("partial raw head at the byte cap must fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("HTTP/1 header block exceeded configured limit")
    );
    assert_eq!(limited_reader.read_polls, 1);

    let mut eof_reader = RecordingStream::segmented(partial, usize::MAX, false);
    let error = match read_finalized_raw_response_head_with_interim_under_external_deadline(
        &mut eof_reader,
        BytesMut::new(),
        &Method::GET,
        Version::HTTP_11,
        "spin-ext-eof-test",
    )
    .await
    {
        Ok(_) => panic!("EOF after partial raw response head must fail"),
        Err(error) => error,
    };
    assert!(error.downcast_ref::<UpstreamConnectionClosed>().is_some());
    assert_eq!(eof_reader.read_polls, 2);
}

#[tokio::test]
async fn upstream_response_rejects_non_http_status_class() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        crate::test_util::read_request_head(&mut stream, &mut raw, &mut buf).await;
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
        crate::test_util::read_request_head(&mut stream, &mut raw, &mut buf).await;
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
fn parse_declared_content_length_refuses_a_signed_member() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("+12"));
    let error = parse_declared_content_length(&headers).expect_err("signed length");
    assert_eq!(error.to_string(), "invalid content-length value");
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
    raw.finalize("qpx");
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

/// The content-length field lines of a written request.
///
/// The field's name is matched case-insensitively, as HTTP requires, and
/// the carriage return of the line ending is not part of the value.
fn content_length_lines(head: &str) -> Vec<String> {
    head.lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .map(str::to_string)
        .collect()
}

/// Writes a request that declares a length of 42 and returns the bytes
/// that reached the wire.
async fn write_request_with_content_length(headers: HeaderMap) -> String {
    let body = Body::replay(Bytes::from(vec![b'x'; 42]), None);
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/upload")
        .body(body)
        .expect("request");
    *request.headers_mut() = headers;
    let mut written = Vec::new();
    let mut head = BytesMut::new();
    super::request::write_http1_request(&mut written, request, &mut head)
        .await
        .expect("written request");
    String::from_utf8(written).expect("UTF-8 request")
}

#[tokio::test]
async fn write_http1_request_writes_one_canonical_content_length_line_for_a_comma_list() {
    // RFC 9110 section 8.6: the value a sender writes is one decimal, so
    // a comma list of equal members leaves as one field line whose value
    // is the resolved decimal.
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_LENGTH, HeaderValue::from_static("42, 42"));

    let written = write_request_with_content_length(headers).await;

    assert_eq!(content_length_lines(&written), vec!["content-length: 42"]);
}

#[tokio::test]
async fn write_http1_request_writes_one_canonical_content_length_line_for_two_values() {
    // RFC 9110 section 8.6: the field is one field, so two values that
    // carried it leave as one line whose value is the resolved decimal.
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));
    headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));

    let written = write_request_with_content_length(headers).await;

    assert_eq!(content_length_lines(&written), vec!["content-length: 42"]);
}

#[tokio::test]
async fn write_http1_request_keeps_a_single_content_length_value() {
    // A value that already is the canonical one reaches the wire as it
    // was received.
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));

    let written = write_request_with_content_length(headers).await;

    assert_eq!(content_length_lines(&written), vec!["content-length: 42"]);
}

#[tokio::test]
async fn write_http1_request_does_not_invent_a_content_length() {
    // A request that carried no field carries none on the wire.
    let written = write_request_with_content_length(HeaderMap::new()).await;

    assert!(content_length_lines(&written).is_empty());
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
    max_read_size: usize,
    pending_after_input: bool,
    read_polls: usize,
}

impl RecordingStream {
    fn new(input: Bytes, max_read_capacity: Arc<AtomicUsize>) -> Self {
        Self {
            input,
            offset: 0,
            max_read_capacity,
            max_read_size: usize::MAX,
            pending_after_input: false,
            read_polls: 0,
        }
    }

    fn segmented(input: Bytes, max_read_size: usize, pending_after_input: bool) -> Self {
        Self {
            input,
            offset: 0,
            max_read_capacity: Arc::new(AtomicUsize::new(0)),
            max_read_size,
            pending_after_input,
            read_polls: 0,
        }
    }
}

impl AsyncRead for RecordingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.read_polls += 1;
        this.max_read_capacity
            .fetch_max(buf.remaining(), Ordering::SeqCst);
        if this.offset == this.input.len() && this.pending_after_input {
            return Poll::Pending;
        }
        let remaining = &this.input[this.offset..];
        let len = remaining.len().min(buf.remaining()).min(this.max_read_size);
        buf.put_slice(&remaining[..len]);
        this.offset += len;
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

#[tokio::test]
async fn finalized_raw_head_cache_preserves_upstream_via_protocol() {
    for downstream_version in [Version::HTTP_11, Version::HTTP_2] {
        for (wire, upstream_version, expected_via) in [
            (
                &b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\nVia: 1.0 first\r\nVia: 1.1 second\r\n\r\nBODY"[..],
                Version::HTTP_10,
                "1.0 via-cache-test",
            ),
            (
                &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nVia: 1.0 first\r\nVia: 1.1 second\r\n\r\nBODY"[..],
                Version::HTTP_11,
                "1.1 via-cache-test",
            ),
        ] {
            let mut stream = wire;
            let (interim, parsed, remainder) = read_finalized_raw_response_head_with_interim(
                &mut stream,
                BytesMut::new(),
                &Method::GET,
                downstream_version,
                "via-cache-test",
            )
            .await
            .expect("read finalized upstream head");
            assert!(interim.is_empty());
            assert_eq!(parsed.version, upstream_version);
            assert_eq!(remainder.as_ref(), b"BODY");
            let headers = parsed.raw.materialized_headers().expect("headers");
            let via: Vec<_> = headers
                .get_all("via")
                .iter()
                .map(|value| value.to_str().expect("Via value"))
                .collect();
            assert_eq!(via, ["1.0 first", "1.1 second", expected_via]);

            // The external-deadline reader used by direct reverse relay must
            // reuse the same finalized head for an identical cache key.
            let mut stream = wire;
            let (_, cached, remainder) =
                super::response::read_finalized_raw_response_head_with_interim_under_external_deadline(
                    &mut stream,
                    BytesMut::new(),
                    &Method::GET,
                    downstream_version,
                    "via-cache-test",
                )
                .await
                .expect("read cached upstream head");
            assert!(Arc::ptr_eq(&parsed.raw, &cached.raw), "finalized cache hit");
            assert_eq!(cached.version, upstream_version);
            assert_eq!(cached.raw.materialized_headers().expect("cached headers"), headers);
            assert_eq!(remainder.as_ref(), b"BODY");
        }
    }
}

#[tokio::test]
async fn raw_direct_relay_finalization_preserves_upstream_via_protocol() {
    let headers = [
        httparse::Header {
            name: "Content-Length",
            value: b"0",
        },
        httparse::Header {
            name: "Via",
            value: b"1.1 earlier",
        },
    ];
    let raw = Arc::new(
        RawHttp1ResponseHead::from_parsed(&headers, &Method::GET, StatusCode::OK, Version::HTTP_10)
            .expect("upstream HTTP/1.0 head"),
    );
    let (stream, _peer) = tokio::io::duplex(64);
    let mut relay = super::RawHttp1ResponseRelay {
        interim: Vec::new(),
        version: Version::HTTP_10,
        status: StatusCode::OK,
        raw: raw.clone(),
        stream: Some(stream),
        read_buf: BytesMut::new(),
        write_buf: BytesMut::new(),
        recycler: None,
        active_permit: None,
    };
    assert!(relay.supports_direct_relay(0));
    relay.finalize("qpx");
    relay.finalize("qpx");
    assert!(
        !raw.is_finalized(),
        "relay finalized a clone of the shared head"
    );
    let serialized = relay.raw.serialized_http11_head();
    let wire = std::str::from_utf8(&serialized).expect("ASCII response");
    assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(wire.find("Via: 1.1 earlier\r\n").unwrap() < wire.find("Via: 1.0 qpx\r\n").unwrap());
    assert_eq!(wire.matches("Via: 1.0 qpx\r\n").count(), 1);
}

#[tokio::test]
async fn finalized_raw_head_cache_key_coheres_across_versions() {
    // The wire head carries the upstream protocol, so H1.0 and H1.1 wires
    // must never share a cache entry, while the downstream version
    // partition must not change the received-protocol.
    async fn via_for(wire: &[u8], downstream: Version) -> Vec<String> {
        let mut stream = wire;
        let (_, parsed, _) = read_finalized_raw_response_head_with_interim(
            &mut stream,
            BytesMut::new(),
            &Method::GET,
            downstream,
            "via-coherence",
        )
        .await
        .expect("read finalized head");
        parsed
            .raw
            .materialized_headers()
            .expect("headers")
            .get_all("via")
            .iter()
            .map(|value| value.to_str().expect("Via value").to_owned())
            .collect()
    }

    let http10_wire = &b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
    let http11_wire = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];

    // Same downstream, different upstream versions: cache key must
    // distinguish the wire head.
    assert_eq!(
        via_for(http10_wire, Version::HTTP_11).await,
        vec!["1.0 via-coherence".to_owned()]
    );
    assert_eq!(
        via_for(http11_wire, Version::HTTP_11).await,
        vec!["1.1 via-coherence".to_owned()]
    );
    // Same upstream wire across downstream versions: received-protocol stays
    // upstream-derived regardless of cache hit or re-parse.
    assert_eq!(
        via_for(http10_wire, Version::HTTP_11).await,
        via_for(http10_wire, Version::HTTP_2).await
    );
    assert_eq!(
        via_for(http11_wire, Version::HTTP_11).await,
        via_for(http11_wire, Version::HTTP_2).await
    );
}
