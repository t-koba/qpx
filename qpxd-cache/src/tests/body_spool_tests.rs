use super::super::types::created_spool_paths;
use crate::CachedBody;
use bytes::Bytes;
use qpx_http::body::Body;
use qpx_http::body::spool::SpoolFile;
use std::time::Duration;

/// A body chunk that is large enough to leave the in-memory buffer.
fn spilling_chunk() -> Bytes {
    Bytes::from(vec![b'x'; 64 * 1024 + 1])
}

/// Waits until this thread's collections created a spool file.
///
/// The wait observes the collection itself, so it never depends on how long
/// the write to the spool file takes.
async fn wait_for_created_spool_file(before: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while created_spool_paths().len() <= before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the body never spilled to a spool file"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn failed_cache_body_collection_after_spill_removes_the_spool_file() {
    let before = created_spool_paths().len();
    let (mut sender, body) = Body::channel();
    let chunk = spilling_chunk();
    sender
        .send_data(chunk.clone())
        .await
        .expect("send the chunk that spills to disk");
    // A second chunk that pushes the body over the limit fails the collection
    // after the spill.
    sender
        .send_data(Bytes::from_static(b"!"))
        .await
        .expect("send the over-limit chunk");

    let err = CachedBody::from_body_limited(body, chunk.len(), Duration::from_secs(1))
        .await
        .expect_err("body over cap must fail");
    assert!(
        err.to_string().contains("exceeds configured limit"),
        "unexpected error: {err}"
    );

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
async fn cancelled_cache_body_collection_after_spill_removes_the_spool_file() {
    let before = created_spool_paths().len();
    let (mut sender, body) = Body::channel();
    sender
        .send_data(spilling_chunk())
        .await
        .expect("send the chunk that spills to disk");
    // The sender stays alive, so the collection waits for more data and can be
    // cancelled after the spill.
    let _keep_open = sender;

    tokio::select! {
        biased;
        () = wait_for_created_spool_file(before) => {}
        result = CachedBody::from_body_limited(body, 1024 * 1024, Duration::from_secs(30)) => {
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
async fn a_spooled_cache_body_removes_its_file_when_released() {
    let before = created_spool_paths().len();
    let chunk = spilling_chunk();
    let body = CachedBody::from_body_limited(
        Body::from(chunk.clone()),
        chunk.len(),
        Duration::from_secs(1),
    )
    .await
    .expect("buffered");

    let created = created_spool_paths();
    assert_eq!(
        created.len(),
        before + 1,
        "the body must have spilled to exactly one spool file"
    );
    let path = created[before].clone();
    assert!(
        path.exists(),
        "the spool file must exist while it is in use"
    );
    drop(body);
    assert!(!path.exists(), "spool file left behind: {path:?}");
}

#[tokio::test]
async fn the_cache_body_spool_guard_unlinks_its_file_when_dropped() {
    let path = std::env::temp_dir().join(format!(
        "qpx-cache-spool-guard-test-{}-{:?}.body",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, b"guarded").expect("write the guarded file");
    let handle = tokio::fs::File::from_std(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open the guarded file"),
    );
    assert!(path.exists());
    drop(SpoolFile::new(handle, path.clone(), "cache_body"));
    assert!(!path.exists(), "spool file left behind: {path:?}");
}
