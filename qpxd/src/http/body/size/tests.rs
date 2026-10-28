use crate::http::body::size::*;
use http::header::CONTENT_LENGTH;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn buffer_request_body_rejects_before_exceeding_hard_cap() {
    let req = Request::from_http(
        http::Request::builder()
            .body(Body::from(vec![0_u8; 5]))
            .expect("request"),
    );
    let err = buffer_request_body(req, 4, Duration::from_secs(1))
        .await
        .expect_err("body over cap must fail");
    assert!(is_observed_body_limit_exceeded(&err));
}

#[tokio::test]
async fn observe_response_body_size_rejects_before_exceeding_hard_cap() {
    let response = qpx_core::http_message::Response::from_http(
        http::Response::builder()
            .body(Body::from(vec![0_u8; 5]))
            .expect("response"),
    );
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
    let req = Request::from_http(
        http::Request::builder()
            .header(CONTENT_LENGTH, "4")
            .body(body)
            .expect("request"),
    );

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
    let req = Request::from_http(
        http::Request::builder()
            .header(CONTENT_LENGTH, "4, 4")
            .body(body)
            .expect("request"),
    );

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
    let req = Request::from_http(
        http::Request::builder()
            .header(CONTENT_LENGTH, "+4")
            .body(Body::empty())
            .expect("request"),
    );
    assert_eq!(observed_request_size(&req), None);

    // Two values that disagree declare no length either.
    let req = Request::from_http(
        http::Request::builder()
            .header(CONTENT_LENGTH, "4")
            .header(CONTENT_LENGTH, "5")
            .body(Body::empty())
            .expect("request"),
    );
    assert_eq!(observed_request_size(&req), None);
}

#[test]
fn observed_response_size_reads_the_declaration_through_the_owner() {
    let response = qpx_core::http_message::Response::from_http(
        http::Response::builder()
            .header(CONTENT_LENGTH, "9, 9")
            .body(Body::empty())
            .expect("response"),
    );
    assert_eq!(observed_response_size(&response), Some(9));
}

#[tokio::test]
async fn limit_request_body_streams_unknown_length_without_prebuffering() {
    let (mut sender, body) = Body::channel();
    let req = Request::from_http(http::Request::builder().body(body).expect("request"));
    let mut body = timeout(Duration::from_millis(25), async {
        limit_request_body(req, 4).map(|req| req.into_head_and_body().1)
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
    let req = Request::from_http(
        http::Request::builder()
            .body(Body::empty())
            .expect("request"),
    );

    let req = limit_request_body(req, 4).expect("limit body");

    assert!(http_body::Body::is_end_stream(req.body()));
    assert_eq!(http_body::Body::size_hint(req.body()).exact(), Some(0));
}

#[tokio::test]
async fn observe_response_body_size_rejects_content_length_over_cap_without_buffering() {
    let (_sender, body) = Body::channel();
    let response = qpx_core::http_message::Response::from_http(
        http::Response::builder()
            .header(CONTENT_LENGTH, "9")
            .body(body)
            .expect("response"),
    );

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
    let req = Request::from_http(
        http::Request::builder()
            .body(Body::from(payload.clone()))
            .expect("request"),
    );

    let req = observe_request_body_size(req, payload.len(), Duration::from_secs(1))
        .await
        .expect("observed");

    assert_eq!(observed_request_size(&req), Some(payload.len() as u64));
    assert!(!has_observed_request_bytes(&req));
    let replayed = qpx_http::body::to_bytes(req.into_head_and_body().1)
        .await
        .expect("replayed body");
    assert_eq!(replayed.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn observe_request_body_size_without_content_length_keeps_small_body_in_memory() {
    let payload = vec![b'x'; OBSERVED_BODY_MEMORY_BYTES];
    let req = Request::from_http(
        http::Request::builder()
            .body(Body::from(payload.clone()))
            .expect("request"),
    );

    let req = observe_request_body_size(req, payload.len(), Duration::from_secs(1))
        .await
        .expect("observed");

    assert_eq!(observed_request_size(&req), Some(payload.len() as u64));
    let replayed = qpx_http::body::to_bytes(req.into_head_and_body().1)
        .await
        .expect("replayed body");
    assert_eq!(replayed.as_ref(), payload.as_slice());
}

#[tokio::test]
async fn buffer_request_body_times_out_idle_body() {
    let (_sender, body) = Body::channel();
    let req = Request::from_http(http::Request::builder().body(body).expect("request"));

    let err = buffer_request_body(req, 1024, Duration::from_millis(10))
        .await
        .expect_err("idle body must time out");
    assert!(err.to_string().contains("observed body read timed out"));
}

#[tokio::test]
async fn buffer_request_body_spools_large_observed_body() {
    let payload = vec![b'x'; OBSERVED_BODY_MEMORY_BYTES + 1];
    let req = Request::from_http(
        http::Request::builder()
            .body(Body::from(payload.clone()))
            .expect("request"),
    );

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
    let reader = observed_request_body_reader(&req).expect("observed reader");
    assert_eq!(
        observed_request_bytes(&req)
            .expect("observed bytes")
            .as_ref(),
        payload.as_slice()
    );

    let replayed = qpx_http::body::to_bytes(req.into_head_and_body().1)
        .await
        .expect("replayed body");
    assert_eq!(replayed.as_ref(), payload.as_slice());
    assert!(path.exists());
    drop(reader);
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
    let req = Request::from_http(http::Request::builder().body(body).expect("request"));

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
    let req = Request::from_http(http::Request::builder().body(body).expect("request"));

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
    let req = Request::from_http(http::Request::builder().body(body).expect("request"));

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
    let req = Request::from_http(http::Request::builder().body(body).expect("request"));
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
    let req = Request::from_http(http::Request::builder().body(body).expect("request"));
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

#[tokio::test]
async fn request_body_stages_preserve_owned_heads_extensions_and_trailers() {
    use qpx_core::http_message::OrdinaryHeaderName;

    #[derive(Clone, Debug, PartialEq)]
    struct Marker(u8);

    for keep_bytes in [false, true] {
        let mut trailers = HeaderMap::new();
        trailers.append("x-trailer", http::HeaderValue::from_static("first"));
        trailers.append("x-trailer", http::HeaderValue::from_static("second"));
        let mut req = Request::new(Body::replay_chunks(
            vec![Bytes::from_static(b"ab"), Bytes::from_static(b"cd")],
            Some(trailers.clone()),
        ));
        *req.method_mut() = http::Method::POST;
        *req.uri_mut() = "/owned?query=yes".parse().unwrap();
        *req.version_mut() = http::Version::HTTP_2;
        req.extensions_mut().insert(Marker(7));
        let name = OrdinaryHeaderName::try_from("x-policy").unwrap();
        let mut sensitive = http::HeaderValue::from_static("first");
        sensitive.set_sensitive(true);
        req.headers_mut().append(name.clone(), sensitive);
        req.headers_mut()
            .append(name, http::HeaderValue::from_static("second"));
        // A malformed declaration must stay literal and fall back to body observation.
        req.headers_mut()
            .append_content_length_value(http::HeaderValue::from_static("+4"));
        let headers = req.headers().clone();
        let mut req =
            observe_request_body(req, keep_bytes, 4, Duration::from_secs(1), "request.body")
                .await
                .unwrap();
        assert_eq!(req.headers(), &headers);
        assert_eq!(req.method(), http::Method::POST);
        assert_eq!(req.uri(), "/owned?query=yes");
        assert_eq!(req.version(), http::Version::HTTP_2);
        assert_eq!(req.extensions().get::<Marker>(), Some(&Marker(7)));
        assert_eq!(observed_request_size(&req), Some(4));
        assert_eq!(has_observed_request_bytes(&req), keep_bytes);
        if keep_bytes {
            assert_eq!(observed_request_trailers(&req), Some(&trailers));
        }
        let mut replay = Vec::new();
        while let Some(data) = req.body_mut().data().await {
            replay.extend_from_slice(&data.unwrap());
        }
        assert_eq!(replay, b"abcd");
        assert_eq!(req.body_mut().trailers().await.unwrap(), Some(trailers));
    }
}

#[tokio::test]
async fn request_streaming_limit_preserves_head_and_trailers_at_exact_cap() {
    let mut trailers = HeaderMap::new();
    trailers.insert("x-trailer", http::HeaderValue::from_static("done"));
    let mut req = Request::new(Body::replay_chunks(
        vec![Bytes::from_static(b"abcd")],
        Some(trailers.clone()),
    ));
    req.extensions_mut().insert(17_u32);
    req.headers_mut().set_content_length(4);
    let headers = req.headers().clone();
    let mut req = limit_request_body(req, 4).unwrap();
    assert_eq!(req.headers(), &headers);
    assert_eq!(req.extensions().get::<u32>(), Some(&17));
    assert_eq!(req.body_mut().data().await.unwrap().unwrap(), b"abcd"[..]);
    assert!(req.body_mut().data().await.is_none());
    assert_eq!(req.body_mut().trailers().await.unwrap(), Some(trailers));
}

#[tokio::test]
async fn zero_request_declaration_does_not_wait_for_body_or_change_headers() {
    let (_sender, body) = Body::channel();
    let mut req = Request::new(body);
    req.headers_mut()
        .append_content_length_value(http::HeaderValue::from_static("0, 0"));
    let headers = req.headers().clone();
    let req = timeout(
        Duration::from_millis(25),
        observe_request_body_size(req, 0, Duration::from_secs(1)),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(req.headers(), &headers);
    assert_eq!(observed_request_size(&req), Some(0));
    assert!(!has_observed_request_bytes(&req));
}

#[tokio::test]
async fn owned_request_rpc_observation_keeps_summary_and_context() {
    use qpx_core::http_message::OrdinaryHeaderName;
    let mut req = Request::new(Body::from(vec![0, 0, 0, 0, 2, b'o', b'k']));
    *req.method_mut() = http::Method::POST;
    *req.uri_mut() = "/example.Service/Call".parse().unwrap();
    req.headers_mut().insert(
        OrdinaryHeaderName::try_from("content-type").unwrap(),
        http::HeaderValue::from_static("application/grpc+proto"),
    );
    let req = buffer_request_body_with_reason(req, 7, Duration::from_secs(1), "rpc.body")
        .await
        .unwrap();
    assert!(
        req.extensions()
            .get::<PrecomputedRpcBodySummary>()
            .is_some()
    );
    let rpc = crate::http::rpc::inspect_request(&req).await;
    assert_eq!(rpc.protocol.as_deref(), Some("grpc"));
    assert_eq!(rpc.service.as_deref(), Some("example.Service"));
    assert_eq!(rpc.method.as_deref(), Some("Call"));
    assert_eq!(rpc.request_message_count, Some(1));
    assert_eq!(rpc.request_message_bytes, Some(2));
    assert_eq!(rpc.message_size, Some(2));
}
