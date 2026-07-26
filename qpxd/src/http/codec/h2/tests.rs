use crate::http::codec::h2::*;
use http_body::Body as _;
use hyper::StatusCode;
use qpx_http::body::to_bytes;
use qpx_observability::RequestHandler;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn scheduler_buffer_budget_preserves_single_stream_throughput_and_bounds_multiplexing() {
    assert_eq!(h2_scheduler_buffer_budget(0), 64 * 1024);
    assert_eq!(h2_scheduler_buffer_budget(1), 64 * 1024);
    assert_eq!(h2_scheduler_buffer_budget(2), 32 * 1024);
    assert_eq!(h2_scheduler_buffer_budget(4), 16 * 1024);
    assert_eq!(h2_scheduler_buffer_budget(100), 16 * 1024);
}

#[test]
fn upstream_read_ahead_shrinks_with_downstream_multiplexing() {
    assert_eq!(
        H2DownstreamLoad::new(1).upstream_response_frame_size(),
        1024 * 1024
    );
    assert_eq!(
        H2DownstreamLoad::new(8).upstream_response_frame_size(),
        1024 * 1024
    );
    assert_eq!(
        H2DownstreamLoad::new(9).upstream_response_frame_size(),
        256 * 1024
    );
    assert_eq!(
        H2DownstreamLoad::new(31).upstream_response_frame_size(),
        256 * 1024
    );
    assert_eq!(
        H2DownstreamLoad::new(32).upstream_response_frame_size(),
        64 * 1024
    );
    assert_eq!(
        H2DownstreamLoad::new(100).upstream_response_frame_size(),
        64 * 1024
    );
}

#[derive(Clone)]
struct StaticInterimService;

impl RequestHandler<Request<Body>> for StaticInterimService {
    type Response = Response<Body>;
    type Error = std::convert::Infallible;

    async fn call(&self, _req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        let interim = vec![InterimResponseHead {
            status: StatusCode::from_u16(103).expect("103"),
            headers: {
                let mut headers = http::HeaderMap::new();
                headers.insert(
                    http::header::LINK,
                    http::HeaderValue::from_static("</app.css>; rel=preload; as=style"),
                );
                headers.insert(http::header::CONTENT_LENGTH, "99".parse().unwrap());
                headers.insert(http::header::TRAILER, "x-trailer".parse().unwrap());
                headers.insert(http::header::TRANSFER_ENCODING, "chunked".parse().unwrap());
                headers
            },
        }];
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("OK"))
            .expect("response");
        response.extensions_mut().insert(interim);
        Ok(response)
    }
}

async fn serve_one_h2(socket: TcpStream) -> Result<()> {
    let mut conn = h2::server::handshake(socket).await?;
    while let Some(result) = conn.accept().await {
        let (request, respond) = result?;
        tokio::spawn(async move {
            let service = StaticInterimService;
            let request = h2_request_to_hyper(request).expect("request");
            let request_method = request.method().clone();
            let mut response = service.call(request).await.expect("response");
            let interim = response
                .extensions_mut()
                .remove::<Vec<InterimResponseHead>>()
                .unwrap_or_default();
            send_h2_response_with_interim(
                respond,
                response,
                &interim,
                &request_method,
                false,
                H2_BODY_IDLE_TIMEOUT,
                1,
            )
            .await
            .expect("send response");
        });
    }
    poll_fn(|cx| conn.poll_closed(cx)).await?;
    Ok(())
}

#[tokio::test]
async fn send_h2_response_with_interim_emits_early_hints() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        serve_one_h2(socket).await.expect("serve");
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        connection.await.expect("client connection");
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("GET")
        .uri("https://reverse_edges.test/asset")
        .body(())
        .expect("request");
    let (mut response_future, _) = client.send_request(request, true).expect("send");

    let interim = poll_fn(|cx| response_future.poll_informational(cx)).await;
    let interim = interim
        .expect("informational state")
        .expect("informational ok");
    assert_eq!(interim.status(), ::http::StatusCode::EARLY_HINTS);
    assert_eq!(
        interim
            .headers()
            .get(::http::header::LINK)
            .and_then(|value: &::http::HeaderValue| value.to_str().ok()),
        Some("</app.css>; rel=preload; as=style")
    );
    assert!(
        !interim
            .headers()
            .contains_key(::http::header::CONTENT_LENGTH)
    );
    assert!(!interim.headers().contains_key(::http::header::TRAILER));
    assert!(
        !interim
            .headers()
            .contains_key(::http::header::TRANSFER_ENCODING)
    );

    let response = response_future.await.expect("final response");
    assert_eq!(response.status(), ::http::StatusCode::OK);
}

#[tokio::test]
async fn send_h2_response_waits_for_peer_flow_control_capacity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (completed_tx, mut completed_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut conn = h2::server::handshake(socket).await.expect("handshake");
        let (request, respond) = conn
            .accept()
            .await
            .expect("request")
            .expect("valid request");
        assert!(request.body().is_end_stream());
        tokio::spawn(async move {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_LENGTH, 256 * 1024)
                .body(Body::from(Bytes::from(vec![b'x'; 256 * 1024])))
                .expect("response");
            send_h2_response_with_interim(
                respond,
                response,
                &[],
                &hyper::Method::GET,
                false,
                H2_BODY_IDLE_TIMEOUT,
                1,
            )
            .await
            .expect("send response");
            completed_tx.send(()).expect("completion receiver");
        });
        poll_fn(|cx| conn.poll_closed(cx))
            .await
            .expect("server connection");
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(1024);
    builder.initial_connection_window_size(1024);
    let (client, connection) = builder
        .handshake::<_, Bytes>(socket)
        .await
        .expect("handshake");
    tokio::spawn(async move {
        connection.await.expect("client connection");
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("GET")
        .uri("https://reverse_edges.test/flow-controlled")
        .body(())
        .expect("request");
    let (response_future, _) = client.send_request(request, true).expect("send");
    let response = response_future.await.expect("response");
    assert!(
        timeout(Duration::from_millis(50), &mut completed_rx)
            .await
            .is_err(),
        "response sender completed before the peer released capacity"
    );

    let response = h2_response_to_hyper(response).expect("convert response");
    let body = to_bytes(response.into_body()).await.expect("response body");
    assert_eq!(body.len(), 256 * 1024);
    timeout(Duration::from_secs(1), completed_rx)
        .await
        .expect("response sender completion timeout")
        .expect("response sender completion");
}

#[tokio::test]
async fn send_h2_response_strips_body_framing_for_no_body_status() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut conn = h2::server::handshake(socket).await.expect("handshake");
        while let Some(result) = conn.accept().await {
            let (_request, respond) = result.expect("request");
            tokio::spawn(async move {
                let response = Response::builder()
                    .status(StatusCode::RESET_CONTENT)
                    .header(http::header::CONTENT_LENGTH, "7")
                    .header(http::header::TRANSFER_ENCODING, "chunked")
                    .header(http::header::TRAILER, "x-trailer")
                    .body(Body::from("payload"))
                    .expect("response");
                send_h2_response_with_interim(
                    respond,
                    response,
                    &[],
                    &hyper::Method::GET,
                    false,
                    H2_BODY_IDLE_TIMEOUT,
                    1,
                )
                .await
                .expect("send response");
            });
        }
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("GET")
        .uri("https://reverse_edges.test/reset")
        .body(())
        .expect("request");
    let (response_future, _) = client.send_request(request, true).expect("send");
    let response = response_future.await.expect("response");
    assert_eq!(response.status(), ::http::StatusCode::RESET_CONTENT);
    assert!(
        !response
            .headers()
            .contains_key(::http::header::CONTENT_LENGTH)
    );
    assert!(
        !response
            .headers()
            .contains_key(::http::header::TRANSFER_ENCODING)
    );
    assert!(!response.headers().contains_key(::http::header::TRAILER));
    let body = h2_response_to_hyper(response).expect("convert");
    assert!(to_bytes(body.into_body()).await.expect("body").is_empty());
}

#[tokio::test]
async fn empty_h2_response_releases_inflight_immediately() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut connection = h2::server::handshake(socket).await.expect("handshake");
        let (request, mut respond) = connection
            .accept()
            .await
            .expect("request state")
            .expect("request");
        drop(request);
        let response = ::http::Response::builder()
            .status(::http::StatusCode::NO_CONTENT)
            .body(())
            .expect("response");
        respond
            .send_response(response, true)
            .expect("send response");
        poll_fn(|cx| connection.poll_closed(cx))
            .await
            .expect("connection close");
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (mut client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("GET")
        .uri("https://reverse_edges.test/empty")
        .body(())
        .expect("request");
    let (response, _) = client.send_request(request, true).expect("send request");
    let response = response.await.expect("response");
    let inflight = Arc::new(AtomicUsize::new(1));

    let converted = h2_response_to_hyper_with_inflight(response, Some(inflight.clone()))
        .expect("convert response");

    assert!(converted.body().is_end_stream());
    assert_eq!(inflight.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn send_h2_response_sanitizes_response_trailers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut conn = h2::server::handshake(socket).await.expect("handshake");
        while let Some(result) = conn.accept().await {
            let (_request, respond) = result.expect("request");
            tokio::spawn(async move {
                let mut trailers = http::HeaderMap::new();
                trailers.insert(http::header::CONTENT_LENGTH, "2".parse().unwrap());
                trailers.insert(
                    http::header::AUTHORIZATION,
                    "Bearer secret".parse().unwrap(),
                );
                trailers.insert("x-allowed-trailer", "ok".parse().unwrap());
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::replay(Bytes::from_static(b"OK"), Some(trailers)))
                    .expect("response");
                send_h2_response_with_interim(
                    respond,
                    response,
                    &[],
                    &hyper::Method::GET,
                    false,
                    H2_BODY_IDLE_TIMEOUT,
                    1,
                )
                .await
                .expect("send response");
            });
        }
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("GET")
        .uri("https://reverse_edges.test/trailers")
        .body(())
        .expect("request");
    let (response_future, _) = client.send_request(request, true).expect("send");
    let response = response_future.await.expect("response");
    let mut body = h2_response_to_hyper(response).expect("convert").into_body();
    assert_eq!(
        body.data().await.expect("data").expect("chunk"),
        Bytes::from_static(b"OK")
    );
    let trailers = body.trailers().await.expect("trailers").expect("present");
    assert!(!trailers.contains_key(http::header::CONTENT_LENGTH));
    assert!(!trailers.contains_key(http::header::AUTHORIZATION));
    assert_eq!(
        trailers
            .get("x-allowed-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("ok")
    );
}

#[tokio::test]
async fn early_h2_response_drains_abandoned_request_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut conn = h2::server::handshake(socket).await.expect("handshake");
        while let Some(result) = conn.accept().await {
            let (request, respond) = result.expect("request");
            tokio::spawn(async move {
                let mut request = h2_request_to_hyper(request).expect("convert request");
                assert_eq!(
                    request
                        .body_mut()
                        .data()
                        .await
                        .expect("request data")
                        .expect("first chunk"),
                    Bytes::from_static(b"first")
                );
                drop(request);

                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().expect("grpc status"));
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::replay(
                        Bytes::from_static(b"response"),
                        Some(trailers),
                    ))
                    .expect("response");
                send_h2_response_with_interim(
                    respond,
                    response,
                    &[],
                    &hyper::Method::POST,
                    false,
                    H2_BODY_IDLE_TIMEOUT,
                    1,
                )
                .await
                .expect("send response");
            });
        }
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        connection.await.expect("client connection");
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("POST")
        .uri("https://reverse_edges.test/grpc")
        .body(())
        .expect("request");
    let (response_future, mut send_stream) = client.send_request(request, false).expect("send");
    send_stream
        .send_data(Bytes::from_static(b"first"), false)
        .expect("first chunk");
    send_stream
        .send_data(Bytes::from_static(b"second"), true)
        .expect("second chunk");

    let response = response_future.await.expect("response");
    let mut body = h2_response_to_hyper(response)
        .expect("convert response")
        .into_body();
    assert_eq!(
        body.data().await.expect("response data").expect("chunk"),
        Bytes::from_static(b"response")
    );
    let trailers = body.trailers().await.expect("trailers").expect("present");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
}

#[tokio::test]
async fn send_h2_response_with_interim_rejects_content_length_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut conn = h2::server::handshake(socket).await.expect("handshake");
        while let Some(result) = conn.accept().await {
            let (_request, respond) = result.expect("request");
            tokio::spawn(async move {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header(http::header::CONTENT_LENGTH, "4")
                    .body(Body::from("OK"))
                    .expect("response");
                let err = send_h2_response_with_interim(
                    respond,
                    response,
                    &[],
                    &hyper::Method::GET,
                    false,
                    H2_BODY_IDLE_TIMEOUT,
                    1,
                )
                .await
                .expect_err("mismatch should fail");
                assert!(
                    err.to_string()
                        .contains("ended before declared content-length")
                );
            });
        }
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("GET")
        .uri("https://reverse_edges.test/mismatch")
        .body(())
        .expect("request");
    let (response_future, _) = client.send_request(request, true).expect("send");
    let err = response_future.await.expect_err("response should reset");
    assert!(err.is_reset());
    assert_eq!(err.reason(), Some(Reason::PROTOCOL_ERROR));
}

#[tokio::test]
async fn send_h2_response_resets_when_response_body_limit_is_exceeded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut conn = h2::server::handshake(socket).await.expect("handshake");
        if let Some(result) = conn.accept().await {
            let (_request, respond) = result.expect("request");
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("abcde").limit_bytes(4))
                .expect("response");
            let err = send_h2_response_with_interim(
                respond,
                response,
                &[],
                &hyper::Method::GET,
                false,
                H2_BODY_IDLE_TIMEOUT,
                1,
            )
            .await
            .expect_err("response body cap should fail the send");
            let _ = result_tx.send(err.to_string());
        }
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("GET")
        .uri("https://reverse_edges.test/limited")
        .body(())
        .expect("request");
    let (response_future, _) = client.send_request(request, true).expect("send");
    match response_future.await {
        Ok(response) => {
            let mut body = response.into_body();
            let body_err = body
                .data()
                .await
                .expect("body result")
                .expect_err("body should reset");
            assert!(body_err.is_reset());
            assert_eq!(body_err.reason(), Some(Reason::CANCEL));
        }
        Err(err) => {
            assert!(
                err.is_reset() || err.is_io(),
                "unexpected H2 response error after body cap: {err}"
            );
        }
    }

    let server_err = result_rx.await.expect("server result");
    assert!(server_err.contains("response body limit exceeded"));
}

#[tokio::test]
async fn send_h2_response_with_interim_preserves_successful_extended_connect_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut builder = h2::server::Builder::new();
        builder.enable_connect_protocol();
        let mut conn = builder.handshake(socket).await.expect("handshake");
        while let Some(result) = conn.accept().await {
            let (_request, respond) = result.expect("request");
            tokio::spawn(async move {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("tunnel-bytes"))
                    .expect("response");
                send_h2_response_with_interim(
                    respond,
                    response,
                    &[],
                    &hyper::Method::CONNECT,
                    true,
                    H2_BODY_IDLE_TIMEOUT,
                    1,
                )
                .await
                .expect("send response");
            });
        }
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = client.ready().await.expect("ready");
    let mut request = ::http::Request::builder()
        .method("CONNECT")
        .uri("https://reverse_edges.test/chat")
        .body(())
        .expect("request");
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from("websocket"));
    let (response_future, _) = client.send_request(request, true).expect("send");
    let response = response_future.await.expect("response");
    let body = h2_response_to_hyper(response).expect("convert");
    assert_eq!(
        to_bytes(body.into_body()).await.expect("body"),
        "tunnel-bytes"
    );
}

#[tokio::test]
async fn h2_request_to_hyper_rejects_content_length_mismatch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let mut conn = h2::server::handshake(socket).await.expect("handshake");
        let Some(result) = conn.accept().await else {
            panic!("request");
        };
        let (request, _respond) = result.expect("request");
        let request = h2_request_to_hyper(request).expect("convert");
        let err = to_bytes(request.into_body())
            .await
            .expect_err("mismatch should fail");
        assert!(
            err.to_string().contains("content-length mismatch")
                || err.to_string().contains("body aborted")
                || err.to_string().contains("stream error detected"),
            "unexpected error: {err}"
        );
    });

    let socket = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(socket).await.expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut client = client.ready().await.expect("ready");
    let request = ::http::Request::builder()
        .method("POST")
        .uri("https://reverse_edges.test/upload")
        .header(::http::header::CONTENT_LENGTH, "4")
        .body(())
        .expect("request");
    let (_response_future, mut send_stream) = client.send_request(request, false).expect("send");
    send_stream
        .send_data(Bytes::from_static(b"OK"), true)
        .expect("data");

    server.await.expect("server");
}

#[test]
fn h2_cookie_fields_are_merged_for_generic_context() {
    let mut headers = ::http::HeaderMap::new();
    headers.append(
        ::http::header::COOKIE,
        ::http::HeaderValue::from_static("a=1"),
    );
    headers.append(
        ::http::header::COOKIE,
        ::http::HeaderValue::from_static("b=2"),
    );

    let converted = h1_headers_to_http(&headers).expect("convert headers");
    let cookie = converted
        .get(http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("cookie header");
    assert_eq!(cookie, "a=1; b=2");
    assert_eq!(converted.get_all(http::header::COOKIE).iter().count(), 1);
}
