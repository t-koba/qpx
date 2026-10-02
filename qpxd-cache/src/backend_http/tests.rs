use super::body::collect_body_limited;
use super::*;

#[tokio::test]
async fn collect_body_limited_rejects_large_payload() {
    let err = collect_body_limited(Body::from(vec![0_u8; 5]), 4)
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("payload too large"));
}

#[tokio::test]
async fn pooled_sender_waits_for_previous_response_completion() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::oneshot;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind HTTP cache server");
    let addr = listener.local_addr().expect("HTTP cache address");
    let (release_tx, release_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept HTTP cache client");
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.expect("read HTTP request head"));
        }
        {
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n")
                .await
                .expect("write first response head");
            release_rx.await.expect("release first response body");
            socket.write_all(b"body").await.expect("write first body");
        }
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(socket.read_u8().await.expect("read second request head"));
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnext")
            .await
            .expect("write second response");
    });
    let backend = HttpCacheBackend {
        endpoint: format!("http://{addr}"),
        timeout: Duration::from_secs(5),
        max_object_bytes: 1024,
        auth_header: None,
        user_agent: None,
        idle: Arc::new(AsyncMutex::new(Vec::new())),
        active: Arc::new(Semaphore::new(HTTP_CACHE_MAX_ACTIVE_OPERATIONS)),
    };
    let mut sender = backend
        .checkout_sender("http", "127.0.0.1", addr.port())
        .await
        .expect("initial sender readiness");
    let request = || {
        Request::builder()
            .uri("/")
            .header(HOST, addr.to_string())
            .body(Body::empty())
            .expect("HTTP cache request")
    };
    let response = sender
        .send_request(request())
        .await
        .expect("first response");
    backend.idle.lock().await.push(sender);
    let mut checkout = Box::pin(backend.checkout_sender("http", "127.0.0.1", addr.port()));
    assert!(
        poll_fn(|cx| Poll::Ready(matches!(checkout.as_mut().poll(cx), Poll::Pending))).await,
        "pooled sender must remain pending while its response body is incomplete"
    );
    release_tx.send(()).expect("release HTTP response");
    assert_eq!(
        collect_body_limited(Body::from(response.into_body()), 1024)
            .await
            .expect("collect first response"),
        b"body"[..]
    );
    let mut sender = checkout.await.expect("pooled sender readiness");
    let response = sender
        .send_request(request())
        .await
        .expect("second response");
    assert_eq!(
        collect_body_limited(Body::from(response.into_body()), 1024)
            .await
            .expect("collect second response"),
        b"next"[..]
    );
    server.await.expect("HTTP cache server completion");
}
