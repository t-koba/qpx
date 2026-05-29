use super::*;

#[tokio::test]
async fn cache_backend_default_put_object_rejects_file_backed_body() {
    let (mut file, path) =
        qpx_core::secure_file::create_secure_temp_file("qpx-cache-test", ".body")
            .expect("temp file");
    file.write_all(b"spooled").expect("write body");
    file.flush().expect("flush body");
    drop(file);

    let body = CachedBody::from_spooled_file(path, 7);
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
}
