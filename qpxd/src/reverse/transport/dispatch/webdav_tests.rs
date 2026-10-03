use super::execute_webdav_service;
use crate::policy_context::ResolvedIdentity;
use crate::runtime::{Runtime, RuntimeState};
use http::Request;
use qpx_http::body::Body;
use std::sync::Arc;

#[tokio::test]
async fn webdav_queued_cancellation_and_response_release_admission() {
    let directory = tempfile::tempdir().expect("temporary WebDAV directory");
    let root = directory.path().join("data");
    std::fs::create_dir(&root).expect("create WebDAV root");
    std::fs::write(root.join("snapshot"), vec![42; 1024 * 1024])
        .expect("write real WebDAV resource");
    let metadata = directory.path().join("metadata.redb");
    let config_path = directory.path().join("qpx.yaml");
    std::fs::write(
        &config_path,
        format!(
            "runtime:\n  worker_threads: 2\n  max_blocking_threads: 1\norigins:\n  webdav:\n  - name: files\n    root: {}\n    metadata: {}\nedges:\n- kind: reverse\n  name: dav\n  listen: 127.0.0.1:19080\n  routes:\n  - match:\n      path: [\"/**\"]\n    target:\n      type: webdav\n      origin: files\n",
            root.display(),
            metadata.display(),
        ),
    )
    .expect("write WebDAV configuration");
    let config = qpx_core::config::load_config(&config_path).expect("load WebDAV configuration");
    let state = RuntimeState::build(config.clone()).expect("build WebDAV runtime state");
    let slots = state
        .webdav_blocking_slots
        .as_ref()
        .expect("WebDAV admission")
        .clone();
    assert_eq!(slots.available_permits(), 1);
    let store = qpx_webdav::PersistentWebDavStore::new(
        qpx_webdav::FileSystemDataStore::open(&root).expect("open WebDAV filesystem"),
        qpx_webdav::RedbMetadataStore::open(&metadata).expect("open WebDAV metadata"),
    );
    let service = Arc::new(qpx_webdav::WebDavService::new(Arc::new(store)));
    let identity = ResolvedIdentity::default();
    let request = || {
        Request::builder()
            .uri("/snapshot")
            .body(Body::empty())
            .expect("GET request")
    };
    let held = slots.clone().acquire_owned().await.expect("hold admission");
    let mut queued = Box::pin(execute_webdav_service(
        request(),
        service.clone(),
        &state,
        &identity,
        1024,
        true,
        None,
    ));
    assert!(futures_util::poll!(queued.as_mut()).is_pending());
    drop(queued);
    assert_eq!(slots.available_permits(), 0);
    drop(held);
    let response = execute_webdav_service(request(), service, &state, &identity, 1024, true, None)
        .await
        .expect("serve real WebDAV file");
    assert_eq!(response.status(), http::StatusCode::OK);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(response.body().has_file_region());
    assert_eq!(slots.available_permits(), 1);

    let runtime = Runtime::new(config.clone()).expect("build reload runtime");
    let old_slots = runtime
        .state()
        .webdav_blocking_slots
        .as_ref()
        .expect("old admission")
        .clone();
    let held = old_slots
        .clone()
        .acquire_owned()
        .await
        .expect("hold old admission");
    let mut without_origins = config.clone();
    without_origins.http.origins.webdav.clear();
    without_origins.edges.clear();
    runtime.swap(RuntimeState::build(without_origins).expect("remove WebDAV origins"));
    runtime.swap(RuntimeState::build(config).expect("build reload state"));
    let new_slots = runtime
        .state()
        .webdav_blocking_slots
        .as_ref()
        .expect("new admission")
        .clone();
    assert!(Arc::ptr_eq(&old_slots, &new_slots));
    assert_eq!(new_slots.available_permits(), 0);
    drop(held);
    assert_eq!(new_slots.available_permits(), 1);
}
