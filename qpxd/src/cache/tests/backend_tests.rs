use super::*;

#[tokio::test]
async fn cache_backend_default_put_object_rejects_file_backed_body() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "qpx-cache-default-backend-test-{}-{unique}.body",
        std::process::id()
    ));
    let mut file = std::fs::File::create(&path).expect("temp file");
    file.write_all(b"spooled").expect("write body");
    file.flush().expect("flush body");
    drop(file);

    let body = CachedBody::from_spooled_file(path.clone(), 7);
    let backend = DefaultPutObjectBackend;
    let err = CacheBackend::put_object(&backend, "ns", "key", &body, 60)
        .await
        .expect_err("default put_object must not read file-backed bodies into memory");
    assert!(
        err.to_string()
            .contains("must implement streaming put_object"),
        "unexpected error: {err}"
    );

    let err = CacheBackend::put_object_stream(
        &backend,
        "ns",
        "key",
        Body::from("spooled"),
        1024,
        Duration::from_secs(1),
        60,
    )
    .await
    .expect_err("default put_object_stream must fail closed");
    assert!(
        err.to_string()
            .contains("must implement streaming put_object_stream"),
        "unexpected error: {err}"
    );

    let err = CacheBackend::get_object_stream(&backend, "ns", "key", 7, None)
        .await
        .expect_err("default get_object_stream must fail closed");
    assert!(
        err.to_string()
            .contains("must implement streaming get_object_stream"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_file(path);
}
