use super::io::{determine_response_body_kind, response_body_allows_reuse};
use super::response::{
    ParsedResponseHead, ResponseBodyKind, build_response, forward_chunked_body,
    forward_close_delimited_body,
};
use super::{
    RAW_HTTP1_RESPONSE_BODY_IDLE_TIMEOUT, parse_declared_content_length,
    send_http1_request_with_interim,
};
use crate::http::body::Body;
use crate::http::body::to_bytes;
use bytes::{Bytes, BytesMut};
use hyper::header::{CONTENT_LENGTH, HeaderName, HeaderValue, TRANSFER_ENCODING};
use hyper::{HeaderMap, Method, Request, StatusCode, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        None,
    );
    assert!(!response.headers().contains_key(CONTENT_LENGTH));
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
    let (mut sender, body) = Body::channel_with_capacity(16);
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
