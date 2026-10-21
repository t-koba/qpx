use super::body::collect_body_limited;
use super::*;

#[tokio::test]
async fn collect_body_limited_rejects_large_payload() {
    let err = collect_body_limited(Body::from(vec![0_u8; 5]), 4)
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("payload too large"));
}

#[tokio::test]
async fn http_response_stream_error_does_not_complete_put_or_write_metadata() {
    use crate::types::BodyStreamWriteOptions;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listen");
    let endpoint = format!("http://{}", listener.local_addr().expect("address"));
    let backend = HttpCacheBackend::new(
        CacheBackendConfig {
            name: "http".to_string(),
            kind: "http".to_string(),
            endpoint,
            path: None,
            max_bytes: None,
            sweep_interval_secs: 60,
            timeout_ms: 2000,
            max_object_bytes: 1024,
            auth_header_env: None,
        },
        None,
    )
    .expect("backend");
    let (mut sender, body) = Body::channel();
    sender
        .send_data(bytes::Bytes::from_static(b"partial"))
        .await
        .expect("data");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            assert!(reader.read_line(&mut line).await.expect("request head") > 0);
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
        }
        assert!(head.starts_with("PUT "));
        assert!(
            head.to_ascii_lowercase()
                .contains("transfer-encoding: chunked\r\n")
        );
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("chunk length");
        let len = usize::from_str_radix(line.trim(), 16).expect("chunk size");
        let mut chunk = vec![0; len + 2];
        reader.read_exact(&mut chunk).await.expect("chunk bytes");
        assert_eq!(chunk, b"partial\r\n");
        sender.abort();
        // The gateway must commit only on normal PUT completion. Here it
        // receives EOF with no terminal chunk, so there is nothing to publish.
        let mut tail = Vec::new();
        reader
            .read_to_end(&mut tail)
            .await
            .expect("connection closes");
        assert!(tail.is_empty(), "unexpected PUT completion: {tail:?}");
    });
    backend
        .put_response(
            "ns",
            "variant",
            body,
            BodyStreamWriteOptions {
                max_body_bytes: 1024,
                body_read_timeout: Duration::from_secs(1),
                ttl_secs: 60,
            },
            Box::new(|_| panic!("metadata must not be encoded after a stream error")),
        )
        .await
        .expect_err("reject body stream error");
    timeout(Duration::from_secs(3), server)
        .await
        .expect("server completes")
        .expect("server");
}

/// A backend whose server answers every request with the given raw response.
///
/// The server keeps accepting connections, so a request that is retried gets
/// the same answer, and the caller aborts it when the exchange is done.
async fn backend_serving(
    response: &'static str,
    max_object_bytes: usize,
) -> (HttpCacheBackend, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listen");
    let endpoint = format!("http://{}", listener.local_addr().expect("address"));
    let backend = HttpCacheBackend::new(
        CacheBackendConfig {
            name: "http".to_string(),
            kind: "http".to_string(),
            endpoint,
            path: None,
            max_bytes: None,
            sweep_interval_secs: 60,
            timeout_ms: 2000,
            max_object_bytes,
            auth_header_env: None,
        },
        None,
    )
    .expect("backend");
    let server = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0_u8; 1];
                if stream.read_exact(&mut byte).await.is_err() {
                    return;
                }
                head.push(byte[0]);
            }
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
            let _ = stream.flush().await;
        }
    });
    (backend, server)
}

#[tokio::test]
async fn the_cache_backend_measures_a_comma_list_of_equal_members_against_its_limit() {
    let (backend, server) =
        backend_serving("HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello", 4).await;
    let err = backend
        .get("ns", "key")
        .await
        .expect_err("the declared length is measured against the limit");
    assert!(
        err.to_string()
            .contains("http cache backend response payload too large: 5 > 4"),
        "{err}"
    );
    server.abort();
}

#[tokio::test]
async fn the_cache_backend_reports_a_miss_when_the_declared_length_is_not_the_expected_one() {
    let (backend, server) =
        backend_serving("HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello", 1024).await;
    let found = backend
        .get_object_stream("ns", "key", 6, None)
        .await
        .expect("the response is judged by the length it declares");
    assert!(
        found.is_none(),
        "a response that declares another length is not the object the cache asked for"
    );
    server.abort();
}

#[tokio::test]
async fn the_cache_backend_never_sees_a_declaration_the_owner_refuses() {
    let (backend, server) =
        backend_serving("HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello", 1024).await;
    let err = backend
        .get("ns", "key")
        .await
        .expect_err("a signed declaration is refused before the response arrives");
    assert!(
        err.to_string().to_lowercase().contains("content-length"),
        "{err}"
    );
    server.abort();
}
