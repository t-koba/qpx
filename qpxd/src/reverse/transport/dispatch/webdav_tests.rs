use super::*;
use futures_util::{future::join_all, poll};
use std::task::Poll;
use tokio::sync::Semaphore;

fn service(root: &std::path::Path) -> Arc<crate::reverse::router::WebDavOriginService> {
    let data_root = root.join("data");
    std::fs::create_dir(&data_root).expect("create real WebDAV data root");
    std::fs::write(data_root.join("asset"), vec![b'x'; 1024 * 1024])
        .expect("write real WebDAV asset");
    let data = qpx_webdav::FileSystemDataStore::open(&data_root).expect("open real data store");
    let metadata = qpx_webdav::RedbMetadataStore::open(root.join("metadata.redb"))
        .expect("open real metadata store");
    Arc::new(qpx_webdav::WebDavService::new(Arc::new(
        qpx_webdav::PersistentWebDavStore::new(data, metadata),
    )))
}

#[tokio::test]
async fn webdav_read_admission_releases_before_file_body_consumption() {
    let directory = tempfile::tempdir().expect("real WebDAV directory");
    let service = service(directory.path());
    let admission = Arc::new(Semaphore::new(2));
    let identity = crate::policy_context::ResolvedIdentity::default();
    let requests = (0..8).map(|_| {
        execute_webdav_service(
            Request::builder()
                .uri("/asset")
                .body(Body::empty())
                .unwrap(),
            service.clone(),
            &identity,
            1024 * 1024,
            true,
            None,
            Some(&admission),
        )
    });
    let responses = timeout(Duration::from_secs(5), join_all(requests))
        .await
        .expect("concurrent reads complete before consuming any body");
    for response in responses {
        let response = response.expect("read real WebDAV asset");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[http::header::CONTENT_LENGTH], "1048576");
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(response.body().has_file_region());
        } else {
            assert_eq!(
                qpx_http::body::to_bytes(response.into_body())
                    .await
                    .unwrap()
                    .len(),
                1024 * 1024
            );
        }
    }
    assert_eq!(admission.available_permits(), 2);
}

#[tokio::test]
async fn webdav_cancelled_read_does_not_block_mutations_or_leak_admission() {
    let directory = tempfile::tempdir().expect("real WebDAV directory");
    let service = service(directory.path());
    let admission = Arc::new(Semaphore::new(1));
    let identity = crate::policy_context::ResolvedIdentity::default();
    let held = admission.clone().acquire_owned().await.unwrap();
    let mut queued = Box::pin(execute_webdav_service(
        Request::builder()
            .uri("/asset")
            .body(Body::empty())
            .unwrap(),
        service.clone(),
        &identity,
        1024 * 1024,
        true,
        None,
        Some(&admission),
    ));
    assert!(matches!(poll!(queued.as_mut()), Poll::Pending));
    drop(queued);
    let updated = timeout(
        Duration::from_secs(5),
        execute_webdav_service(
            Request::builder()
                .method(http::Method::PUT)
                .uri("/updated")
                .body(Body::from("updated"))
                .unwrap(),
            service.clone(),
            &identity,
            1024 * 1024,
            false,
            None,
            Some(&admission),
        ),
    )
    .await
    .expect("mutation completes while read admission is occupied")
    .expect("write real WebDAV resource");
    assert_eq!(updated.status(), StatusCode::CREATED);
    assert_eq!(admission.available_permits(), 0);
    drop(held);
    let response = timeout(
        Duration::from_secs(5),
        execute_webdav_service(
            Request::builder()
                .uri("/updated")
                .body(Body::empty())
                .unwrap(),
            service,
            &identity,
            1024 * 1024,
            false,
            None,
            Some(&admission),
        ),
    )
    .await
    .expect("read admission remains usable after cancellation")
    .expect("read updated real resource");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        qpx_http::body::to_bytes(response.into_body())
            .await
            .unwrap(),
        "updated"
    );
    assert_eq!(admission.available_permits(), 1);
}
