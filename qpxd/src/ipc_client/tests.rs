use super::proxy::validate_ipc_response_status;
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
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use tokio::time::{Duration, timeout};

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
        headers: vec![("content-type".to_string(), "text/plain".to_string())],
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

#[test]
fn ipc_response_status_rejects_non_http_status_class() {
    let err = validate_ipc_response_status(700).expect_err("6xx IPC status must fail");
    assert!(err.to_string().contains("out of range"));
}

#[tokio::test]
async fn downstream_body_closed_reports_dropped_receiver() {
    let (sender, body) = Body::channel_with_capacity(16);
    drop(body);

    let mut sender = sender;
    assert!(downstream_body_closed(&mut sender).await);
    assert!(sender.is_closed());
}

#[tokio::test]
#[cfg(unix)]
async fn shm_response_corruption_aborts_the_downstream_body() {
    use super::shm::read_shm_response_body;
    use std::os::unix::fs::FileExt;

    for corrupt in [false, true] {
        let path = temp_shm_path("ipc-response-corruption");
        let mut ring = ShmRingBuffer::create_or_open(&path, 64 * 1024).unwrap();
        assert!(ring.try_push(b"response").unwrap());
        if corrupt {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .read(true)
                .open(&path)
                .unwrap();
            let mut header_length = [0; 4];
            file.read_exact_at(&mut header_length, 44).unwrap();
            file.write_all_at(
                &u32::MAX.to_le_bytes(),
                u32::from_le_bytes(header_length).into(),
            )
            .unwrap();
        } else {
            assert!(ring.try_push(&[]).unwrap());
        }
        let (mut sender, mut body) = Body::channel_with_capacity(16);
        let reusable =
            read_shm_response_body(&mut sender, &mut ring, None, Duration::from_secs(1)).await;
        drop(sender);
        let chunk = timeout(Duration::from_secs(1), body.data()).await.unwrap();
        ring.unlink_doorbells().unwrap();
        drop(ring);
        remove_ipc_shm_path(&path);
        if corrupt {
            assert!(!reusable, "corrupted response must not be reused");
            assert!(
                matches!(chunk, Some(Err(_))),
                "corrupted response must remain a body error"
            );
        } else {
            assert!(reusable, "complete response must remain reusable");
            assert_eq!(chunk.unwrap().unwrap(), Bytes::from_static(b"response"));
            assert!(
                body.data().await.is_none(),
                "explicit ring EOF must remain successful"
            );
        }
    }
}
