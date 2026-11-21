use super::shm::{downstream_body_closed, read_shm_response_meta_after_body_writer};
#[cfg(unix)]
use super::shm::{remove_ipc_shm_path, write_request_body_to_shm};
use anyhow::Result;
#[cfg(unix)]
use bytes::Bytes;
use qpx_core::ipc::meta::IpcResponseMeta;
use qpx_core::ipc::protocol::write_frame;
use qpx_core::shm_ring::ShmRingBuffer;
use qpx_http::body::Body;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::Duration;
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

#[cfg(unix)]
fn temp_shm_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("qpx-ipc-client-tests-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create ipc test shm dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("secure ipc test shm dir");
    }
    dir.join(format!("{name}-{nonce}.shm"))
}

#[tokio::test]
#[cfg(unix)]
async fn shm_body_writer_does_not_push_eof_after_body_error() {
    let req_path = temp_shm_path("ipc-body-writer");
    let mut reader = ShmRingBuffer::create_or_open(&req_path, 64 * 1024).unwrap();
    let writer = ShmRingBuffer::create_or_open(&req_path, 64 * 1024).unwrap();

    let (mut sender, mut body) = Body::channel_with_capacity(16);
    sender.send_data(Bytes::from_static(b"abc")).await.unwrap();
    sender.abort();

    let err = match write_request_body_to_shm(&mut body, writer, None, Duration::from_secs(1)).await
    {
        Ok(_) => panic!("body error should propagate"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("request body read failed"));

    let first = reader.try_pop().unwrap().expect("payload");
    assert_eq!(first, b"abc");
    let waited = timeout(Duration::from_millis(100), reader.wait_for_data()).await;
    assert!(waited.is_err(), "unexpected clean EOF in request ring");

    remove_ipc_shm_path(req_path);
}

#[tokio::test]
#[cfg(unix)]
async fn shm_body_writer_enforces_request_body_limit() {
    let req_path = temp_shm_path("ipc-body-limit");
    let writer = ShmRingBuffer::create_or_open(&req_path, 64 * 1024).unwrap();
    let mut body = Body::from(Bytes::from_static(b"abcdef"));

    let err =
        match write_request_body_to_shm(&mut body, writer, Some(4), Duration::from_secs(1)).await {
            Ok(_) => panic!("body limit should fail"),
            Err(err) => err,
        };

    assert!(err.to_string().contains("max_request_bytes"));
    remove_ipc_shm_path(req_path);
}

#[tokio::test]
async fn shm_response_meta_returns_before_body_writer_after_fast_response() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let response_meta = IpcResponseMeta {
        status: 200,
        headers: qpx_core::ipc::meta::IpcResponseHeaders::from_pairs(vec![(
            "content-type".to_string(),
            "text/plain".to_string(),
        )]),
    };
    let writer = tokio::spawn(async move {
        write_frame(&mut server, &response_meta)
            .await
            .expect("write response meta");
    });
    let mut body_writer =
        tokio::spawn(async move { std::future::pending::<Result<ShmRingBuffer>>().await });
    let read_task = tokio::spawn(async move {
        read_shm_response_meta_after_body_writer(&mut client, &mut body_writer).await
    });

    tokio::task::yield_now().await;
    let (meta, req_ring) = read_task
        .await
        .expect("join read task")
        .expect("read response meta");
    assert_eq!(meta.status, 200);
    assert!(req_ring.is_none());
    writer.await.expect("join writer");
}

#[tokio::test]
#[cfg(unix)]
async fn shm_response_meta_survives_writer_completion_mid_frame() {
    use std::future::poll_fn;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll, Waker};
    use tokio::io::AsyncWriteExt;

    let (mut client, mut server) = tokio::io::duplex(4096);
    let shm_path = temp_shm_path("ipc-response-meta-mid-frame");
    let ring = ShmRingBuffer::create_or_open(&shm_path, 64 * 1024).unwrap();

    let response_meta = IpcResponseMeta {
        status: 200,
        headers: qpx_core::ipc::meta::IpcResponseHeaders::from_pairs(vec![(
            "content-type".to_string(),
            "text/plain".to_string(),
        )]),
    };
    let mut frame = Vec::new();
    write_frame(&mut frame, &response_meta).await.unwrap();
    assert!(frame.len() > 9, "frame must have a payload past its header");

    let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel::<()>();
    let writer_done = Arc::new(AtomicBool::new(false));
    let observed_done = Arc::clone(&writer_done);
    let mut body_writer = tokio::spawn(async move {
        gate_rx.await.expect("writer gate");
        let result: Result<ShmRingBuffer> = Ok(ring);
        observed_done.store(true, Ordering::SeqCst);
        let _ = finish_tx.send(());
        result
    });

    server.write_all(&frame[..9]).await.unwrap();

    let mut read = Box::pin(read_shm_response_meta_after_body_writer(
        &mut client,
        &mut body_writer,
    ));
    let mut context = Context::from_waker(Waker::noop());
    let mut once = Box::pin(poll_fn(|cx| read.as_mut().poll(cx)));
    assert!(
        matches!(once.as_mut().poll(&mut context), Poll::Pending),
        "header read should be pending"
    );

    gate_tx.send(()).expect("release writer gate");
    timeout(Duration::from_secs(2), async {
        while !writer_done.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("writer done flag");
    finish_rx.await.expect("body writer completion");

    let mut after_writer = Box::pin(poll_fn(|cx| read.as_mut().poll(cx)));
    assert!(
        matches!(after_writer.as_mut().poll(&mut context), Poll::Pending),
        "writer completion should leave frame payload pending"
    );

    server.write_all(&frame[9..]).await.unwrap();
    let (meta, response_ring) = timeout(Duration::from_secs(2), read)
        .await
        .expect("read response meta after writer completion")
        .expect("response meta result");
    assert_eq!(meta.status, 200);
    assert!(response_ring.is_some(), "writer ring must be returned");

    remove_ipc_shm_path(shm_path);
}

#[tokio::test]
async fn downstream_body_closed_reports_dropped_receiver() {
    let (sender, body) = Body::channel_with_capacity(16);
    drop(body);

    let mut sender = sender;
    assert!(downstream_body_closed(&mut sender).await);
    assert!(sender.is_closed());
}

async fn proxy_tcp_response(
    meta: IpcResponseMeta,
) -> Result<qpx_core::http_message::Response<Body>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = url::Url::parse(&format!("ipc://{}", listener.local_addr()?))?;
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _: qpx_core::ipc::meta::IpcRequestMeta =
            qpx_core::ipc::protocol::read_frame(&mut stream)
                .await
                .unwrap();
        let mut request_body = Vec::new();
        stream.read_to_end(&mut request_body).await.unwrap();
        assert_eq!(request_body, b"request");
        write_frame(&mut stream, &meta).await.unwrap();
        stream.write_all(b"response").await.unwrap();
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let result = super::proxy_ipc(
            &crate::pool::PoolRegistry::new(),
            qpx_core::http_message::Request::new(Body::from("request")),
            &url,
            "test",
        )
        .await;
        server.await.unwrap();
        result
    })
    .await?
}

#[tokio::test]
async fn ipc_response_owner_preserves_metadata_and_streaming_body() {
    use qpx_core::http_content_length::ContentLengthError;

    for (lengths, declared) in [
        (vec![], Ok(None)),
        (vec!["0"], Ok(Some(0))),
        (vec!["invalid"], Err(ContentLengthError::InvalidValue)),
        (vec!["3", "4"], Err(ContentLengthError::Conflicting)),
        (vec!["003", "3"], Ok(Some(3))),
    ] {
        // Keep the raw declarations, including invalid and conflicting values, at ingress.
        let mut pairs = vec![
            ("Content-Type".to_string(), "text/plain".to_string()),
            ("Set-Cookie".to_string(), "a=1".to_string()),
            ("set-cookie".to_string(), "b=2".to_string()),
            ("X-Dup".to_string(), "first".to_string()),
            ("x-dup".to_string(), "second".to_string()),
        ];
        pairs.extend(
            lengths
                .iter()
                .map(|value| ("Content-Length".to_string(), value.to_string())),
        );
        let meta = IpcResponseMeta {
            status: 201,
            headers: qpx_core::ipc::meta::IpcResponseHeaders::from_pairs(pairs),
        };
        let mut response = proxy_tcp_response(meta).await.unwrap();
        assert_eq!(response.status(), 201);
        assert_eq!(response.version(), hyper::Version::HTTP_11);
        assert_eq!(response.headers().declared_content_length(), declared);
        for (name, expected) in [
            ("content-type", vec!["text/plain"]),
            ("set-cookie", vec!["a=1", "b=2"]),
            ("x-dup", vec!["first", "second"]),
            ("content-length", lengths),
        ] {
            let actual = response
                .headers()
                .selected_fields_for_serialization(&[name.parse().unwrap()])
                .remove(name)
                .unwrap_or_default();
            assert_eq!(actual, expected);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.body_mut().data().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(body, b"response");
    }
}

#[tokio::test]
async fn ipc_response_owner_retains_status_and_header_validation() {
    for (status, name, value) in [
        (99, "x-test", "ok"),
        (600, "x-test", "ok"),
        (700, "x-test", "ok"),
        (200, "bad name", "ok"),
        (200, "x-test", "bad\r\nvalue"),
    ] {
        let result = proxy_tcp_response(IpcResponseMeta {
            status,
            headers: qpx_core::ipc::meta::IpcResponseHeaders::from_pairs(vec![(
                name.to_string(),
                value.to_string(),
            )]),
        })
        .await;
        assert!(result.is_err(), "accepted {status} {name}: {value:?}");
    }
}

#[tokio::test]
async fn invalid_content_length_is_rejected_before_ipc_checkout() {
    use super::{IpcUpstream, IpcUpstreamRequestContext};
    use hyper::header::HeaderValue;
    use qpx_core::http_message::Request as OwnerRequest;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe listener");
    let upstream = IpcUpstream {
        mode: qpx_core::config::IpcMode::Tcp,
        backend: super::backend::IpcBackend::Tcp {
            host: "127.0.0.1".to_owned(),
            port: listener.local_addr().expect("local addr").port(),
        },
        timeout: Duration::from_secs(1),
        max_request_bytes: None,
        max_response_bytes: None,
    };
    for lengths in [vec!["invalid"], vec!["3", "4"]] {
        let mut req = OwnerRequest::new(Body::empty());
        for length in lengths {
            req.headers_mut()
                .append_content_length_value(HeaderValue::from_static(length));
        }
        let err = timeout(
            Duration::from_secs(2),
            super::proxy_ipc_upstream(
                &crate::pool::PoolRegistry::new(),
                req,
                &upstream,
                "test",
                IpcUpstreamRequestContext {
                    conn: Default::default(),
                    verified_identity: None,
                    authorization_decision: None,
                    route_timeout: Duration::from_secs(1),
                },
            ),
        )
        .await
        .expect("rejection must not hang")
        .expect_err("invalid declaration must be refused");
        assert!(
            err.to_string().contains("content-length"),
            "unexpected error: {err:#}"
        );
    }
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "invalid requests must not check out an IPC connection"
    );
}
