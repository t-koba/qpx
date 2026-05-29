use super::*;
use hyper::header::{CONNECTION, CONTENT_LENGTH, HeaderValue, TRAILER, TRANSFER_ENCODING};
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
async fn serve_http1_with_interim_parse_error_sends_connection_close() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let _ =
            serve_http1_with_interim(socket, StaticInterimService, Duration::from_secs(1)).await;
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
        crate::http::protocol::semantics::validate_expect_header(&parsed.headers).is_err(),
        "preflight must still reject the unsupported Expect token"
    );
}
