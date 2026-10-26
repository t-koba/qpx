use super::*;
use bytes::Bytes;
use http_body::Frame;
use hyper::header::{CONNECTION, CONTENT_LENGTH, HeaderValue, TRAILER, TRANSFER_ENCODING};
use qpx_observability::RequestHandler;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::{TcpListener, TcpStream};

fn request_head_with_total_bytes(total_bytes: usize) -> Vec<u8> {
    let prefix = b"GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: ";
    let suffix = b"\r\n\r\n";
    assert!(total_bytes >= prefix.len() + suffix.len());
    let mut request = Vec::with_capacity(total_bytes);
    request.extend_from_slice(prefix);
    request.resize(total_bytes - suffix.len(), b'x');
    request.extend_from_slice(suffix);
    assert_eq!(request.len(), total_bytes);
    request
}

#[test]
fn request_head_parser_marks_empty_path_absolute_form_options() {
    for (request_line, expected) in [
        ("OPTIONS http://example.test HTTP/1.1", true),
        ("OPTIONS http://example.test?view=all HTTP/1.1", false),
        ("OPTIONS http://example.test/ HTTP/1.1", false),
        ("GET http://example.test HTTP/1.1", false),
        ("OPTIONS * HTTP/1.1", false),
    ] {
        let raw = format!("{request_line}\r\nHost: example.test\r\n\r\n");
        let parsed = try_parse_http1_request_head(raw.as_bytes())
            .expect("parse")
            .expect("complete");
        assert_eq!(
            parsed.empty_path_absolute_options, expected,
            "{request_line}"
        );
    }
}

#[test]
fn request_head_parser_promotes_storage_for_many_headers() {
    let mut raw = b"GET / HTTP/1.1\r\nHost: example.test\r\n".to_vec();
    for index in 0..40 {
        raw.extend_from_slice(format!("X-Test-{index}: value\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");

    let parsed = try_parse_http1_request_head(&raw)
        .expect("parse")
        .expect("complete");
    assert_eq!(parsed.headers.len(), 41);

    let exact = request_head_with_total_bytes(MAX_HEADER_BYTES);
    let parsed = try_parse_http1_request_head(&exact)
        .expect("parse exact limit")
        .expect("complete exact limit");
    assert_eq!(parsed.consumed, MAX_HEADER_BYTES);
    let oversized = request_head_with_total_bytes(MAX_HEADER_BYTES + 1);
    let error = try_parse_http1_request_head(&oversized).expect_err("byte limit");
    assert!(
        error
            .downcast_ref::<RequestHeaderFieldsTooLarge>()
            .is_some()
    );
}

#[test]
fn request_head_parser_rejects_more_than_maximum_headers() {
    let mut raw = b"GET / HTTP/1.1\r\nHost: example.test\r\n".to_vec();
    for index in 0..MAX_HTTP1_REQUEST_HEADERS {
        raw.extend_from_slice(format!("X-Test-{index}: value\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");

    let error = try_parse_http1_request_head(&raw).expect_err("header limit");
    assert!(
        error
            .downcast_ref::<RequestHeaderFieldsTooLarge>()
            .is_some()
    );
}

struct PendingThenDataBody {
    state: u8,
}

impl http_body::Body for PendingThenDataBody {
    type Data = Bytes;
    type Error = qpx_http::body::BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.state {
            0 => {
                self.state = 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            1 => {
                self.state = 2;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"delayed")))))
            }
            _ => Poll::Ready(None),
        }
    }
}

struct CompleteAfterDataBody {
    emitted: bool,
}

impl http_body::Body for CompleteAfterDataBody {
    type Data = Bytes;
    type Error = qpx_http::body::BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        assert!(!self.emitted, "completed body must not be polled again");
        self.emitted = true;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"complete")))))
    }

    fn is_end_stream(&self) -> bool {
        self.emitted
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(if self.emitted { 0 } else { 8 })
    }
}

#[derive(Clone)]
struct StaticInterimService;

impl RequestHandler<Request<Body>> for StaticInterimService {
    type Response = Response<Body>;
    type Error = Infallible;

    async fn call(&self, _req: Request<Body>) -> Result<Response<Body>, Infallible> {
        let interim = vec![InterimResponseHead::new(
            StatusCode::from_u16(103).expect("103"),
            {
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
        )];
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, "2")
            .body(Body::from("OK"))
            .expect("response");
        response.extensions_mut().insert(interim);
        Ok(response)
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
        .write_all(b"GET /asset HTTP/1.1\r\nHost: reverse_edges.test\r\nConnection: close\r\n\r\n")
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
async fn tcp_owned_halves_serve_prefetched_http1_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        serve_http1_tcp_with_interim_and_capacity(
            socket,
            Bytes::from_static(
                b"GET /asset HTTP/1.1\r\nHost: reverse_edges.test\r\nConnection: close\r\n\r\n",
            ),
            StaticInterimService,
            Duration::from_secs(1),
            16,
        )
        .await
        .expect("serve");
    });

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8(raw).expect("utf8");
    assert!(text.contains("HTTP/1.1 103"));
    assert!(text.contains("HTTP/1.1 200"));
    assert!(text.ends_with("OK"));
}

#[tokio::test]
async fn serve_http1_with_interim_parse_errors_send_connection_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (socket, _) = listener.accept().await.expect("accept");
            let _ = serve_http1_with_interim(socket, StaticInterimService, Duration::from_secs(1))
                .await;
        }
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

    let mut stream = TcpStream::connect(addr).await.expect("reconnect");
    stream
        .write_all(&request_head_with_total_bytes(MAX_HEADER_BYTES + 1))
        .await
        .expect("write oversized request");
    // An oversized request can leave bytes unread in the socket receive queue.
    // Closing with unread data may produce a TCP reset after the response, so
    // read through the response head instead of requiring a clean EOF.
    let mut raw = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let read = stream.read(&mut chunk).await.expect("read response head");
        assert_ne!(read, 0, "response ended before its header terminator");
        raw.extend_from_slice(&chunk[..read]);
        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8(raw).expect("utf8");
    assert!(text.starts_with("HTTP/1.1 431"));
    assert!(text.contains("Connection: close"));

    // Bounded post-header read: accept a clean EOF or the TCP reset observed
    // on macOS when closing with unread request bytes queued. The timeout
    // fails a still-open connection instead of passing immediately, and the
    // byte cap bounds the drain if the peer keeps sending.
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut drained: usize = 0;
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) => break,
                Ok(read) => {
                    drained += read;
                    assert!(
                        drained <= 8 * 1024,
                        "peer sent {drained} bytes after 431 header without closing"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                Err(error) => panic!("read after 431 response: {error}"),
            }
        }
    })
    .await
    .expect("connection remained open after 431 response");
    server.await.expect("server task");
}

#[tokio::test]
async fn request_header_reader_enforces_count_and_byte_limits() {
    let mut request = String::from("GET / HTTP/1.1\r\nHost: example.com\r\n");
    for index in 0..130 {
        request.push_str(&format!("X-Test-{index}: value\r\n"));
    }
    request.push_str("\r\n");
    let mut reader = tokio::io::empty();
    let mut buffer = BytesMut::from(request.as_bytes());
    let error = read_http1_request_head(&mut reader, &mut buffer, Duration::from_secs(1))
        .await
        .expect_err("header count must be capped");
    assert!(
        error
            .downcast_ref::<RequestHeaderFieldsTooLarge>()
            .is_some()
    );

    let exact_request = request_head_with_total_bytes(MAX_HEADER_BYTES);
    let mut exact_reader =
        tokio::io::BufReader::with_capacity(4093, std::io::Cursor::new(exact_request));
    let mut buffer = BytesMut::with_capacity(MAX_HEADER_BYTES * 2);
    let parsed = read_http1_request_head(&mut exact_reader, &mut buffer, Duration::from_secs(5))
        .await
        .expect("read exact-limit head")
        .expect("complete head");
    assert_eq!(parsed.consumed, MAX_HEADER_BYTES);
    assert_eq!(buffer.len(), MAX_HEADER_BYTES);

    let oversized_request = request_head_with_total_bytes(MAX_HEADER_BYTES + 1);
    let mut oversized_reader =
        tokio::io::BufReader::with_capacity(4093, std::io::Cursor::new(oversized_request));
    let mut buffer = BytesMut::with_capacity(MAX_HEADER_BYTES * 2);
    let error = read_http1_request_head(&mut oversized_reader, &mut buffer, Duration::from_secs(5))
        .await
        .expect_err("oversized head");
    assert!(
        error
            .downcast_ref::<RequestHeaderFieldsTooLarge>()
            .is_some()
    );
    assert_eq!(buffer.len(), MAX_HEADER_BYTES);

    let body = vec![b'b'; MAX_HEADER_BYTES + 1];
    let head = format!(
        "POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let head_len = head.len();
    let mut buffer = BytesMut::with_capacity(head_len + body.len());
    buffer.extend_from_slice(head.as_bytes());
    buffer.extend_from_slice(&body);
    let mut reader = tokio::io::empty();
    let parsed = read_http1_request_head(&mut reader, &mut buffer, Duration::from_secs(1))
        .await
        .expect("read head with buffered body")
        .expect("complete head");
    assert_eq!(parsed.consumed, head_len);
    assert_eq!(
        parsed.body_kind,
        RequestBodyKind::ContentLength(body.len() as u64)
    );
    assert_eq!(&buffer[parsed.consumed..], body.as_slice());
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
    let mut head_buf = BytesMut::new();

    let keep_alive = send_http1_response_with_interim(
        &mut write_half,
        Version::HTTP_11,
        &Method::GET,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
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
async fn content_length_response_does_not_repoll_completed_body() {
    let (mut client, server) = tokio::io::duplex(4096);
    let (read_half, mut write_half) = tokio::io::split(server);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, "8")
        .body(Body::wrap(CompleteAfterDataBody { emitted: false }))
        .expect("response");
    let mut head_buf = BytesMut::new();

    let keep_alive = send_http1_response_with_interim(
        &mut write_half,
        Version::HTTP_11,
        &Method::GET,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
    )
    .await
    .expect("send response");
    drop(write_half);
    drop(read_half);

    assert!(keep_alive);
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.expect("read response");
    assert!(raw.ends_with(b"\r\n\r\ncomplete"));
}

#[tokio::test(flavor = "current_thread")]
async fn static_response_recycles_header_storage() {
    let mut retained = Vec::new();
    for _ in 0..64 {
        retained.push(qpx_http::header_pool::take(1));
    }
    let mut headers = HeaderMap::with_capacity(31);
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("2"));
    let expected_capacity = headers.capacity();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("listener address");
    let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
    let mut client = client.expect("connect");
    let (mut server, _) = accepted.expect("accept");
    let mut head_buf = BytesMut::new();
    let keep_alive = send_static_http1_response(
        &mut server,
        &Method::GET,
        StatusCode::OK,
        headers,
        Bytes::from_static(b"OK"),
        true,
        &mut head_buf,
    )
    .await
    .expect("send static response");
    assert!(keep_alive);

    let recycled = qpx_http::header_pool::take(1);
    assert!(recycled.capacity() >= expected_capacity);
    qpx_http::header_pool::recycle(recycled);
    for map in retained {
        qpx_http::header_pool::recycle(map);
    }

    let mut raw = vec![0; head_buf.len() + 2];
    client.read_exact(&mut raw).await.expect("read response");
    assert!(raw.ends_with(b"OK"));
}

/// The content-length field lines of a response head.
fn content_length_lines(head: &[u8]) -> Vec<String> {
    std::str::from_utf8(head)
        .expect("ASCII head")
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| line.to_ascii_lowercase().starts_with("content-length:"))
        .map(str::to_string)
        .collect()
}

#[tokio::test]
async fn static_response_writes_one_canonical_content_length_line() {
    // RFC 9110 section 8.6: the value a sender writes is one decimal, so
    // a comma list of equal members leaves as one field line whose value
    // is the resolved decimal, and two field lines of that name leave as
    // one as well.
    for values in [vec!["42, 42"], vec!["42", "42"]] {
        let mut headers = HeaderMap::with_capacity(4);
        for value in &values {
            headers.append(CONTENT_LENGTH, HeaderValue::from_str(value).expect("value"));
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("listener address");
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let mut client = client.expect("connect");
        let (mut server, _) = accepted.expect("accept");
        let mut head_buf = BytesMut::new();
        send_static_http1_response(
            &mut server,
            &Method::GET,
            StatusCode::OK,
            headers,
            Bytes::from_static(&[b'x'; 42]),
            true,
            &mut head_buf,
        )
        .await
        .expect("send static response");

        let mut raw = vec![0; head_buf.len() + 42];
        client.read_exact(&mut raw).await.expect("read response");
        assert_eq!(content_length_lines(&raw), vec!["content-length: 42"]);
    }
}

#[tokio::test]
async fn finalized_raw_response_head_uses_direct_http1_serialization() {
    let (mut client, server) = tokio::io::duplex(4096);
    let (read_half, mut write_half) = tokio::io::split(server);
    let parsed = [
        httparse::Header {
            name: "Content-Length",
            value: b"4",
        },
        httparse::Header {
            name: "Connection",
            value: b"X-Hop",
        },
        httparse::Header {
            name: "X-Hop",
            value: b"discard",
        },
        httparse::Header {
            name: "Content-Type",
            value: b"text/plain",
        },
    ];
    let mut raw_head = crate::upstream::raw_http1::RawHttp1ResponseHead::from_parsed(
        &parsed,
        &Method::GET,
        StatusCode::OK,
        Version::HTTP_11,
    )
    .expect("raw response head");
    raw_head.finalize("qpx");
    let mut response = Response::new(Body::from("body"));
    response.extensions_mut().insert(Arc::new(raw_head));
    let mut head_buf = BytesMut::new();

    let keep_alive = send_http1_response_with_interim(
        &mut write_half,
        Version::HTTP_11,
        &Method::GET,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
    )
    .await
    .expect("send response");
    drop(write_half);
    drop(read_half);

    assert!(keep_alive);
    let mut encoded = Vec::new();
    client
        .read_to_end(&mut encoded)
        .await
        .expect("read response");
    let text = String::from_utf8(encoded).expect("UTF-8 response");
    assert!(text.contains("Content-Length: 4\r\n"));
    assert!(text.contains("Content-Type: text/plain\r\n"));
    assert!(text.contains("Proxy-Status: qpx\r\n"));
    assert!(text.contains("Via: 1.1 qpx\r\n"));
    assert!(!text.contains("Connection: X-Hop"));
    assert!(!text.contains("X-Hop:"));
    assert!(text.ends_with("\r\n\r\nbody"));
}

#[tokio::test]
async fn direct_content_length_relay_preserves_pipelined_upstream_bytes() {
    check_raw_relay_with_interim(false).await;
}

#[tokio::test]
async fn interim_precedes_unchanged_raw_final_http1_relay() {
    check_raw_relay_with_interim(true).await;
}

async fn check_raw_relay_with_interim(with_interim: bool) {
    let upstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream address");
    let upstream_server = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.expect("accept upstream");
        stream.write_all(b"BODYNEXT").await.expect("write upstream");
    });
    let upstream = TcpStream::connect(upstream_addr)
        .await
        .expect("connect upstream");

    let parsed = [
        httparse::Header {
            name: "Content-Length",
            value: b"4",
        },
        httparse::Header {
            name: "x-Mixed",
            value: b"kept-\xff",
        },
        httparse::Header {
            name: "Set-Cookie",
            value: b"raw=1",
        },
        httparse::Header {
            name: "Set-Cookie",
            value: b"raw=2",
        },
    ];
    let mut raw_head = crate::upstream::raw_http1::RawHttp1ResponseHead::from_parsed(
        &parsed,
        &Method::GET,
        StatusCode::OK,
        Version::HTTP_11,
    )
    .expect("raw response head");
    raw_head.finalize("qpx");
    let mut expected_final = raw_head.serialized_http11_head().to_vec();
    expected_final.extend_from_slice(b"BODY");

    let (recycled_tx, mut recycled_rx) = tokio::sync::mpsc::unbounded_channel();
    let relay = crate::upstream::raw_http1::RawHttp1ResponseRelay {
        interim: if with_interim {
            ordered_interim_heads()
        } else {
            Vec::new()
        },
        version: Version::HTTP_11,
        status: StatusCode::OK,
        raw: Arc::new(raw_head),
        stream: Some(upstream),
        read_buf: BytesMut::new(),
        write_buf: BytesMut::new(),
        recycler: Some(crate::upstream::raw_http1::Http1ConnectionRecycler::new(
            move |stream, read_buf, _write_buf| {
                recycled_tx
                    .send((stream, read_buf))
                    .expect("send recycled connection");
            },
        )),
        active_permit: None,
    };

    let downstream_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind downstream");
    let downstream_addr = downstream_listener
        .local_addr()
        .expect("downstream address");
    let downstream_server = tokio::spawn(async move {
        let (mut stream, _) = downstream_listener
            .accept()
            .await
            .expect("accept downstream");
        let mut head_buf = BytesMut::new();
        let (keep_alive, reusable) = send_raw_http1_response_relay_with_interim(
            &mut stream,
            Version::HTTP_11,
            &Method::GET,
            relay,
            true,
            &mut head_buf,
        )
        .await
        .expect("relay response");
        assert!(keep_alive);
        assert!(reusable.is_none());
    });

    let mut downstream = TcpStream::connect(downstream_addr)
        .await
        .expect("connect downstream");
    let mut encoded = Vec::new();
    downstream
        .read_to_end(&mut encoded)
        .await
        .expect("read downstream");
    downstream_server.await.expect("downstream task");
    upstream_server.await.expect("upstream task");
    if with_interim {
        assert_ordered_interim_wire(&encoded);
    }
    let final_offset = encoded
        .windows(b"HTTP/1.1 200 OK".len())
        .position(|w| w == b"HTTP/1.1 200 OK")
        .unwrap();
    assert_eq!(&encoded[final_offset..], expected_final);
    assert!(encoded.ends_with(b"\r\n\r\nBODY"));

    let (mut recycled, read_buf) = tokio::time::timeout(Duration::from_secs(1), recycled_rx.recv())
        .await
        .expect("recycle timeout")
        .expect("recycled connection");
    assert!(read_buf.is_empty());
    let mut next = [0_u8; 4];
    recycled
        .read_exact(&mut next)
        .await
        .expect("read pipelined bytes");
    assert_eq!(&next, b"NEXT");
}

#[tokio::test]
async fn rejected_connect_closes_http1_connection() {
    let (mut client, server) = tokio::io::duplex(4096);
    let (read_half, mut write_half) = tokio::io::split(server);
    let response = Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("response");
    let mut head_buf = BytesMut::new();

    let keep_alive = send_http1_response_with_interim(
        &mut write_half,
        Version::HTTP_11,
        &Method::CONNECT,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
    )
    .await
    .expect("send response");
    drop(write_half);
    drop(read_half);

    assert!(!keep_alive);
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8(raw).expect("utf8");
    assert!(text.starts_with("HTTP/1.1 407"));
    assert!(text.contains("Connection: close"));
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
    let mut head_buf = BytesMut::new();

    let keep_alive = send_http1_response_with_interim(
        &mut write_half,
        Version::HTTP_11,
        &Method::HEAD,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
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
    let mut head_buf = BytesMut::new();

    let keep_alive = send_http1_response_with_interim(
        &mut write_half,
        Version::HTTP_11,
        &Method::GET,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
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

#[tokio::test]
async fn send_http1_response_stops_when_response_body_limit_is_exceeded() {
    let (mut client, server) = tokio::io::duplex(4096);
    let (read_half, mut write_half) = tokio::io::split(server);
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::from("abcde").limit_bytes(4))
        .expect("response");
    let mut head_buf = BytesMut::new();

    let err = send_http1_response_with_interim(
        &mut write_half,
        Version::HTTP_11,
        &Method::GET,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
    )
    .await
    .expect_err("response body cap should fail the send");
    drop(write_half);
    drop(read_half);

    assert!(err.to_string().contains("response body limit exceeded"));
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8(raw).expect("utf8");
    assert!(text.starts_with("HTTP/1.1 200"));
    assert!(!text.ends_with("abcde"));
}

#[tokio::test]
async fn response_data_pending_does_not_trigger_destructive_trailer_poll() {
    let (mut client, server) = tokio::io::duplex(4096);
    let (read_half, mut write_half) = tokio::io::split(server);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_LENGTH, "7")
        .body(Body::wrap(PendingThenDataBody { state: 0 }))
        .expect("response");
    let mut head_buf = BytesMut::new();

    let keep_alive = send_http1_response_with_interim(
        &mut write_half,
        Version::HTTP_11,
        &Method::GET,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
    )
    .await
    .expect("send response");
    drop(write_half);
    drop(read_half);

    assert!(keep_alive);
    let mut raw = Vec::new();
    client.read_to_end(&mut raw).await.expect("read response");
    assert!(raw.ends_with(b"\r\n\r\ndelayed"));
}

#[test]
fn request_transfer_encoding_allows_only_chunked_singleton() {
    let mut headers = HeaderMap::new();
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    assert_eq!(
        determine_request_body_kind(&headers, Version::HTTP_11).expect("chunked"),
        RequestBodyKind::Chunked
    );

    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip, chunked"));
    assert!(determine_request_body_kind(&headers, Version::HTTP_11).is_err());
}

#[tokio::test]
async fn unsupported_expect_with_100_continue_does_not_send_interim_continue() {
    let mut reader = tokio::io::empty();
    let mut buf = BytesMut::from(
        &b"POST / HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue, x-qpx-unknown\r\nContent-Length: 1\r\n\r\n"[..],
    );
    let parsed = read_http1_request_head(&mut reader, &mut buf, Duration::from_secs(1))
        .await
        .expect("parse")
        .expect("head");
    assert!(!parsed.send_continue);
    assert!(
        qpx_http::protocol::semantics::validate_expect_header(&parsed.headers).is_err(),
        "preflight must still reject the unsupported Expect token"
    );
}

#[tokio::test]
async fn raw_response_via_uses_upstream_version_for_http11_downstream() {
    let parsed = [
        httparse::Header {
            name: "Content-Length",
            value: b"4",
        },
        httparse::Header {
            name: "Via",
            value: b"1.0 first",
        },
        httparse::Header {
            name: "Via",
            value: b"1.1 second",
        },
    ];
    let raw = Arc::new(
        crate::upstream::raw_http1::RawHttp1ResponseHead::from_parsed(
            &parsed,
            &Method::GET,
            StatusCode::OK,
            Version::HTTP_10,
        )
        .expect("upstream HTTP/1.0 head"),
    );
    let mut response = Response::builder()
        .version(Version::HTTP_10)
        .body(Body::from("body"))
        .expect("upstream response");
    response.extensions_mut().insert(raw.clone());

    crate::http::protocol::l7::finalize_response_in_place(
        &Method::GET,
        Version::HTTP_11,
        "qpx",
        &mut response,
        false,
    );
    assert_eq!(response.version(), Version::HTTP_10);
    assert!(
        !raw.is_finalized(),
        "shared unfinalized head stays unchanged"
    );
    let finalized = response
        .extensions()
        .get::<Arc<crate::upstream::raw_http1::RawHttp1ResponseHead>>()
        .expect("finalized raw head");
    let headers = finalized.materialized_headers().expect("materialized head");
    let via: Vec<_> = headers
        .get_all("via")
        .iter()
        .map(|value| value.to_str().expect("Via value"))
        .collect();
    assert_eq!(via, ["1.0 first", "1.1 second", "1.0 qpx"]);

    // Clone after warming both header caches and finalize again: neither the
    // upstream provenance nor the already-appended Via may change.
    let serialized = finalized.serialized_http11_head();
    let mut cloned = finalized.as_ref().clone();
    cloned.finalize("qpx");
    assert_eq!(
        cloned.materialized_headers().expect("cloned headers"),
        headers
    );
    assert_eq!(cloned.serialized_http11_head(), serialized);
    assert!(serialized.starts_with(b"HTTP/1.1 200 OK\r\n"));

    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let mut head_buf = BytesMut::new();
    let keep_alive = send_http1_response_with_interim(
        &mut writer,
        Version::HTTP_11,
        &Method::GET,
        response,
        &[],
        true,
        Duration::from_secs(30),
        &mut head_buf,
    )
    .await
    .expect("encode downstream response");
    drop(writer);
    let mut wire = Vec::new();
    reader.read_to_end(&mut wire).await.expect("read response");
    let wire = std::str::from_utf8(&wire).expect("ASCII response");
    assert!(keep_alive);
    assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(wire.contains("Via: 1.0 first\r\nVia: 1.1 second\r\n"));
    assert!(wire.find("Via: 1.1 second\r\n").unwrap() < wire.find("Via: 1.0 qpx\r\n").unwrap());
    assert!(wire.ends_with("\r\n\r\nbody"));
}

#[test]
fn invalid_content_length_diagnostic_does_not_echo_userinfo() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_static("http://synthetic-user:synthetic-pass@host/"),
    );
    let error = determine_request_body_kind(&headers, http::Version::HTTP_11).unwrap_err();
    assert_eq!(error.to_string(), "invalid content-length value");
    assert!(!format!("{error:?}").contains("synthetic-"));
}

#[test]
fn http10_with_any_transfer_encoding_is_faulty_framing() {
    for raw in [
        "POST / HTTP/1.0\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.0\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
        "POST / HTTP/1.0\r\nHost: example.test\r\nTransfer-Encoding: gzip\r\n\r\n",
    ] {
        let error =
            try_parse_http1_request_head(raw.as_bytes()).expect_err("HTTP/1.0 + TE must fail");
        assert!(
            error.to_string().contains("transfer-encoding"),
            "unexpected error for {raw:?}: {error}"
        );
    }

    // Controls: valid HTTP/1.0 without TE and valid HTTP/1.1 chunked still parse.
    let parsed = try_parse_http1_request_head(b"GET / HTTP/1.0\r\nHost: example.test\r\n\r\n")
        .expect("valid HTTP/1.0")
        .expect("complete");
    assert_eq!(parsed.body_kind, RequestBodyKind::Empty);

    let parsed = try_parse_http1_request_head(
        b"POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .expect("valid HTTP/1.1 chunked")
    .expect("complete");
    assert_eq!(parsed.body_kind, RequestBodyKind::Chunked);
}

#[derive(Clone)]
struct CountingService {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl RequestHandler<Request<Body>> for CountingService {
    type Response = Response<Body>;
    type Error = Infallible;

    async fn call(&self, _req: Request<Body>) -> Result<Response<Body>, Infallible> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_LENGTH, "2")
            .body(Body::from("OK"))
            .expect("response"))
    }
}

async fn read_http1_response_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut chunk = [0; 1024];
    loop {
        let read = stream.read(&mut chunk).await.expect("read response head");
        assert_ne!(read, 0, "connection ended before response head");
        raw.extend_from_slice(&chunk[..read]);
        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    raw
}

#[tokio::test]
async fn http10_transfer_encoding_is_rejected_and_closes_without_reaching_service() {
    for head in [
        // Lone chunked framing.
        "POST /first HTTP/1.0\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        // Chunked framing that also carries Content-Length.
        "POST /first HTTP/1.0\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\nhello",
    ] {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = CountingService {
            calls: Arc::clone(&calls),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let _ = serve_http1_with_interim(socket, service, Duration::from_secs(5)).await;
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        // Pipeline a valid second request: it must never reach the service
        // because the faulty first head closes the connection.
        let pipelined = format!(
            "{head}GET /second HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(pipelined.as_bytes())
            .await
            .expect("write pipelined requests");

        let head_bytes = read_http1_response_head(&mut stream).await;
        let text = String::from_utf8(head_bytes).expect("utf8");
        assert!(
            text.starts_with("HTTP/1.1 400"),
            "expected 400 for {head:?}, got {text:?}"
        );
        assert!(text.contains("Connection: close"));

        // The server closes after the faulty head; no second response follows.
        let mut rest = Vec::new();
        match tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest)).await {
            Ok(Ok(_)) => assert!(
                !rest.windows(12).any(|w| w == b"HTTP/1.1 200"),
                "pipelined request must not receive a second response for {head:?}"
            ),
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Ok(Err(error)) => panic!("read after 400 response: {error}"),
            Err(_) => panic!("connection remained open after 400 for {head:?}"),
        }
        server.await.expect("server task");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "faulty HTTP/1.0 head {head:?} must not reach the service"
        );
    }
}

#[tokio::test]
async fn http11_chunked_and_http10_plain_controls_reach_service() {
    for request in [
        // Valid chunked control: empty chunked body.
        "POST /chunked HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        // Valid HTTP/1.0 without Transfer-Encoding.
        "GET /plain HTTP/1.0\r\nHost: example.test\r\n\r\n",
    ] {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = CountingService {
            calls: Arc::clone(&calls),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            serve_http1_with_interim(socket, service, Duration::from_secs(5))
                .await
                .expect("serve control");
        });

        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write control request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        let text = String::from_utf8(raw).expect("utf8");
        assert!(
            text.contains("HTTP/1.1 200") || text.contains("HTTP/1.0 200"),
            "expected 200 for {request:?}, got {text:?}"
        );
        assert!(
            text.ends_with("OK"),
            "control body for {request:?}: {text:?}"
        );
        server.await.expect("server task");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "control {request:?} must reach the service"
        );
    }
}

fn ordered_interim_heads() -> Vec<InterimResponseHead> {
    let mut headers = HeaderMap::new();
    for value in ["</one>; rel=preload", "</two>; rel=preload"] {
        headers.append("link", HeaderValue::from_static(value));
    }
    for value in ["a=1", "b=2"] {
        headers.append("set-cookie", HeaderValue::from_static(value));
    }
    headers.insert("x-opaque", HeaderValue::from_bytes(b"opaque-\xff").unwrap());
    headers.insert(CONNECTION, HeaderValue::from_static("x-private"));
    headers.insert("x-private", HeaderValue::from_static("remove-me"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("invalid"));
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
    headers.insert("trailer", HeaderValue::from_static("x-trailer"));
    vec![
        InterimResponseHead::new(StatusCode::CONTINUE, HeaderMap::new()),
        InterimResponseHead::new(StatusCode::EARLY_HINTS, headers.clone()),
        InterimResponseHead::new(StatusCode::EARLY_HINTS, headers),
    ]
}

fn assert_ordered_interim_wire(raw: &[u8]) {
    let expected = b"HTTP/1.1 100 Continue\r\n\r\n";
    assert!(raw.starts_with(expected));
    let mut remaining = &raw[expected.len()..];
    for _ in 0..2 {
        assert!(remaining.starts_with(b"HTTP/1.1 103 Early Hints\r\n"));
        let end = remaining.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let head = &remaining[..end];
        for field in [
            b"link: </one>; rel=preload\r\nlink: </two>; rel=preload\r\n".as_slice(),
            b"set-cookie: a=1\r\nset-cookie: b=2\r\n",
            b"x-opaque: opaque-\xff\r\n",
        ] {
            assert!(
                head.windows(field.len()).any(|w| w == field),
                "missing {field:?} in {head:?}"
            );
        }
        for removed in [
            "Connection:",
            "X-Private:",
            "Content-Length:",
            "Transfer-Encoding:",
            "Trailer:",
        ] {
            assert!(
                !head
                    .windows(removed.len())
                    .any(|w| w.eq_ignore_ascii_case(removed.as_bytes()))
            );
        }
        remaining = &remaining[end..];
    }
    assert!(remaining.starts_with(b"HTTP/1.1 200 OK\r\n"));
}

#[tokio::test]
async fn interim_heads_keep_order_and_bytes_at_http1_egress() {
    for version in [Version::HTTP_11, Version::HTTP_10] {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let response = Response::builder()
            .header(CONTENT_LENGTH, "2")
            .body(Body::from("OK"))
            .unwrap();
        send_http1_response_with_interim(
            &mut server,
            version,
            &Method::GET,
            response,
            &ordered_interim_heads(),
            false,
            Duration::from_secs(1),
            &mut BytesMut::new(),
        )
        .await
        .unwrap();
        drop(server);
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).await.unwrap();
        if version == Version::HTTP_11 {
            assert_ordered_interim_wire(&wire);
        } else {
            assert!(wire.starts_with(b"HTTP/1.0 200 OK\r\n"));
            assert!(!wire.windows(3).any(|w| w == b"103"));
            assert!(!wire.windows(3).any(|w| w == b"100"));
        }
        assert!(wire.ends_with(b"\r\n\r\nOK"));
    }
}

#[tokio::test]
async fn interim_egress_rejects_101_and_final_status_before_writing() {
    for status in [StatusCode::SWITCHING_PROTOCOLS, StatusCode::OK] {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let interim = [InterimResponseHead::new(status, HeaderMap::new())];
        assert!(
            send_http1_response_with_interim(
                &mut server,
                Version::HTTP_11,
                &Method::GET,
                Response::new(Body::empty()),
                &interim,
                false,
                Duration::from_secs(1),
                &mut BytesMut::new(),
            )
            .await
            .is_err()
        );
        drop(server);
        let mut wire = Vec::new();
        client.read_to_end(&mut wire).await.unwrap();
        assert!(wire.is_empty());
    }
}
