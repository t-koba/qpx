use crate::http::body::size::*;
use http::header::CONTENT_LENGTH;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn buffer_request_body_rejects_before_exceeding_hard_cap() {
    let req = Request::builder()
        .body(Body::from(vec![0_u8; 5]))
        .expect("request");
    let err = buffer_request_body(req, 4, Duration::from_secs(1))
        .await
        .expect_err("body over cap must fail");
    assert!(is_observed_body_limit_exceeded(&err));
}

#[tokio::test]
async fn observe_response_body_size_rejects_before_exceeding_hard_cap() {
    let response = Response::builder()
        .body(Body::from(vec![0_u8; 5]))
        .expect("response");
    let err = observe_response_body_size(response, 4, Duration::from_secs(1))
        .await
        .expect_err("body over cap must fail");
    assert!(is_observed_body_limit_exceeded(&err));
}

#[tokio::test]
async fn observe_request_body_size_uses_content_length_without_buffering() {
    let (_sender, body) = Body::channel();
    let req = Request::builder()
        .header(CONTENT_LENGTH, "4")
        .body(body)
        .expect("request");

    let req = timeout(
        Duration::from_millis(25),
        observe_request_body_size(req, 8, Duration::from_secs(1)),
    )
    .await
    .expect("content-length size observation must not wait for body")
    .expect("observe");
    assert_eq!(observed_request_size(&req), Some(4));
}

#[tokio::test]
async fn limit_request_body_streams_unknown_length_without_prebuffering() {
    let (mut sender, body) = Body::channel();
    let req = Request::builder().body(body).expect("request");
    let mut body = timeout(Duration::from_millis(25), async {
        limit_request_body(req, 4).map(Request::into_body)
    })
    .await
    .expect("limit setup must not wait for body")
    .expect("limit body");

    sender
        .send_data(Bytes::from_static(b"abcd"))
        .await
        .expect("send first chunk");
    assert_eq!(
        body.data()
            .await
            .expect("first frame")
            .expect("first chunk"),
        Bytes::from_static(b"abcd")
    );

    sender
        .send_data(Bytes::from_static(b"e"))
        .await
        .expect("send over-limit chunk");
    let err = body
        .data()
        .await
        .expect("over-limit frame")
        .expect_err("body limit must fail while streaming");
    assert!(err.to_string().contains("request body exceeds hard cap"));
}

#[tokio::test]
async fn observe_response_body_size_rejects_content_length_over_cap_without_buffering() {
    let (_sender, body) = Body::channel();
    let response = Response::builder()
        .header(CONTENT_LENGTH, "9")
        .body(body)
        .expect("response");

    let err = timeout(
        Duration::from_millis(25),
        observe_response_body_size(response, 8, Duration::from_secs(1)),
    )
    .await
    .expect("content-length limit check must not wait for body")
    .expect_err("must fail");
    assert!(is_observed_body_limit_exceeded(&err));
}

#[tokio::test]
async fn observe_request_body_size_without_content_length_replays_from_spool_only() {
    let payload = vec![b'x'; OBSERVED_BODY_MEMORY_BYTES + 1];
    let req = Request::builder()
        .body(Body::from(payload.clone()))
        .expect("request");

    let req = observe_request_body_size(req, payload.len(), Duration::from_secs(1))
        .await
        .expect("observed");

    assert_eq!(observed_request_size(&req), Some(payload.len() as u64));
    assert!(!has_observed_request_bytes(&req));
    let replayed = crate::http::body::to_bytes(req.into_body())
        .await
        .expect("replayed body");
    assert_eq!(replayed.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn observe_request_body_size_without_content_length_keeps_small_body_in_memory() {
    let payload = vec![b'x'; OBSERVED_BODY_MEMORY_BYTES];
    let req = Request::builder()
        .body(Body::from(payload.clone()))
        .expect("request");

    let req = observe_request_body_size(req, payload.len(), Duration::from_secs(1))
        .await
        .expect("observed");

    assert_eq!(observed_request_size(&req), Some(payload.len() as u64));
    let replayed = crate::http::body::to_bytes(req.into_body())
        .await
        .expect("replayed body");
    assert_eq!(replayed.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn buffer_request_body_times_out_idle_body() {
    let (_sender, body) = Body::channel();
    let req = Request::builder().body(body).expect("request");

    let err = buffer_request_body(req, 1024, Duration::from_millis(10))
        .await
        .expect_err("idle body must time out");
    assert!(err.to_string().contains("observed body read timed out"));
}

#[tokio::test]
async fn buffer_request_body_spools_large_observed_body() {
    let payload = vec![b'x'; OBSERVED_BODY_MEMORY_BYTES + 1];
    let req = Request::builder()
        .body(Body::from(payload.clone()))
        .expect("request");

    let req = buffer_request_body(req, payload.len(), Duration::from_secs(1))
        .await
        .expect("buffered");
    let observed = req
        .extensions()
        .get::<ObservedBodyBytes>()
        .expect("observed body");
    let path = match &observed.storage {
        ObservedBodyStorage::File(file) => file.path.clone(),
        ObservedBodyStorage::Memory(_) => panic!("large observed body should spool"),
    };
    assert!(path.exists());
    assert_eq!(
        observed_request_bytes(&req)
            .expect("observed bytes")
            .as_ref(),
        payload.as_slice()
    );

    let replayed = crate::http::body::to_bytes(req.into_body())
        .await
        .expect("replayed body");
    assert_eq!(replayed.as_ref(), payload.as_slice());
    assert!(!path.exists());
}
