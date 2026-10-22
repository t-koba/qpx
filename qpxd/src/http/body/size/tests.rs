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
async fn observed_body_spool_errors_remain_typed() {
    let err: anyhow::Error = ObservedBodySpoolError::Io {
        direction: "request",
        reason: "request.body",
        operation: "write",
        source: std::io::Error::other("spool write failed"),
    }
    .into();
    assert!(is_observed_body_spool_error(&err));
    assert!(err.to_string().contains("spool write failed"));
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
async fn observe_request_body_size_uses_a_comma_list_of_equal_members() {
    let (_sender, body) = Body::channel();
    let req = Request::builder()
        .header(CONTENT_LENGTH, "4, 4")
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

#[test]
fn observed_request_size_reads_the_declaration_through_the_owner() {
    // A leading plus sign is not a member of the grammar, so the request
    // declares no length and its body is observed rather than sized from
    // the declaration.
    let req = Request::builder()
        .header(CONTENT_LENGTH, "+4")
        .body(Body::empty())
        .expect("request");
    assert_eq!(observed_request_size(&req), None);

    // Two values that disagree declare no length either.
    let req = Request::builder()
        .header(CONTENT_LENGTH, "4")
        .header(CONTENT_LENGTH, "5")
        .body(Body::empty())
        .expect("request");
    assert_eq!(observed_request_size(&req), None);
}

#[test]
fn observed_response_size_reads_the_declaration_through_the_owner() {
    let response = Response::builder()
        .header(CONTENT_LENGTH, "9, 9")
        .body(Body::empty())
        .expect("response");
    assert_eq!(observed_response_size(&response), Some(9));
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

#[test]
fn limit_request_body_keeps_empty_body_at_end_of_stream() {
    let req = Request::builder().body(Body::empty()).expect("request");

    let req = limit_request_body(req, 4).expect("limit body");

    assert!(http_body::Body::is_end_stream(req.body()));
    assert_eq!(http_body::Body::size_hint(req.body()).exact(), Some(0));
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
    let replayed = qpx_http::body::to_bytes(req.into_body())
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
    let replayed = qpx_http::body::to_bytes(req.into_body())
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
        ObservedBodyStorage::File(file) => file.path().to_path_buf(),
        ObservedBodyStorage::Memory(_) => panic!("large observed body should spool"),
    };
    assert!(path.exists());
    assert_eq!(
        observed_request_bytes(&req)
            .expect("observed bytes")
            .as_ref(),
        payload.as_slice()
    );

    let replayed = qpx_http::body::to_bytes(req.into_body())
        .await
        .expect("replayed body");
    assert_eq!(replayed.as_ref(), payload.as_slice());
    assert!(!path.exists());
}

/// The number of spool files this thread's collections have created so far.
fn created_spool_count() -> usize {
    created_spool_paths().len()
}

/// Waits until this thread's collections created a spool file.
///
/// The wait observes the collection itself, so it never depends on how long
/// the write to the spool file takes.
async fn wait_for_created_spool_file(before: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while created_spool_count() <= before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the body never spilled to a spool file"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A body chunk that is large enough to leave the in-memory buffer.
fn spilling_chunk() -> Bytes {
    Bytes::from(vec![b'x'; OBSERVED_BODY_MEMORY_BYTES + 1])
}

// The secure temp file helper provides owner-only spool files on unix and on
// Windows. A platform without either mechanism has no owner-only temporary
// file, so the collection must fail before it spills rather than write the
// body to a file other users could read.
#[tokio::test]
#[cfg(not(any(unix, windows)))]
async fn a_body_that_needs_a_spool_file_fails_closed_without_owner_only_permissions() {
    let chunk = Bytes::from(vec![b'x'; OBSERVED_BODY_MEMORY_BYTES + 1]);
    let body = Body::replay_chunks(vec![chunk.clone(), Bytes::from_static(b"!")], None);
    let req = Request::builder().body(body).expect("request");

    let err = buffer_request_body(req, chunk.len(), Duration::from_secs(1))
        .await
        .expect_err("a body that needs a spool file must not be stored unprotected");
    assert!(is_observed_body_spool_error(&err));
    let message = format!("{err:#}");
    assert!(message.contains("owner-only file permissions"), "{message}");
}

#[tokio::test]
async fn failed_request_body_collection_after_spill_removes_the_spool_file() {
    let before = created_spool_count();
    let chunk = spilling_chunk();
    let body = Body::replay_chunks(vec![chunk.clone(), Bytes::from_static(b"!")], None);
    let req = Request::builder().body(body).expect("request");

    let err = buffer_request_body(req, chunk.len(), Duration::from_secs(1))
        .await
        .expect_err("body over cap must fail");

    assert!(is_observed_body_limit_exceeded(&err));
    let created = created_spool_paths();
    assert_eq!(
        created.len(),
        before + 1,
        "the body must have spilled to exactly one spool file"
    );
    for path in &created[before..] {
        assert!(!path.exists(), "spool file left behind: {path:?}");
    }
}

#[tokio::test]
async fn failed_request_body_size_collection_after_spill_removes_the_spool_file() {
    let before = created_spool_count();
    let chunk = spilling_chunk();
    let body = Body::replay_chunks(vec![chunk.clone(), Bytes::from_static(b"!")], None);
    let req = Request::builder().body(body).expect("request");

    let err = observe_request_body_size(req, chunk.len(), Duration::from_secs(1))
        .await
        .expect_err("body over cap must fail");

    assert!(is_observed_body_limit_exceeded(&err));
    let created = created_spool_paths();
    assert_eq!(
        created.len(),
        before + 1,
        "the body must have spilled to exactly one spool file"
    );
    for path in &created[before..] {
        assert!(!path.exists(), "spool file left behind: {path:?}");
    }
}

#[tokio::test]
async fn cancelled_request_body_collection_after_spill_removes_the_spool_file() {
    let before = created_spool_count();
    let (mut sender, body) = Body::channel();
    let req = Request::builder().body(body).expect("request");
    sender
        .send_data(spilling_chunk())
        .await
        .expect("send the chunk that spills to disk");

    tokio::select! {
        biased;
        () = wait_for_created_spool_file(before) => {}
        result = buffer_request_body(req, 1024 * 1024, Duration::from_secs(30)) => {
            let _ = result;
            panic!("the collection must not finish before it is cancelled");
        }
    }

    let created = created_spool_paths();
    assert_eq!(
        created.len(),
        before + 1,
        "the body must have spilled to exactly one spool file"
    );
    for path in &created[before..] {
        assert!(!path.exists(), "spool file left behind: {path:?}");
    }
}

#[tokio::test]
async fn cancelled_request_body_size_collection_after_spill_removes_the_spool_file() {
    let before = created_spool_count();
    let (mut sender, body) = Body::channel();
    let req = Request::builder().body(body).expect("request");
    sender
        .send_data(spilling_chunk())
        .await
        .expect("send the chunk that spills to disk");

    tokio::select! {
        biased;
        () = wait_for_created_spool_file(before) => {}
        result = observe_request_body_size(req, 1024 * 1024, Duration::from_secs(30)) => {
            let _ = result;
            panic!("the collection must not finish before it is cancelled");
        }
    }

    let created = created_spool_paths();
    assert_eq!(
        created.len(),
        before + 1,
        "the body must have spilled to exactly one spool file"
    );
    for path in &created[before..] {
        assert!(!path.exists(), "spool file left behind: {path:?}");
    }
}
