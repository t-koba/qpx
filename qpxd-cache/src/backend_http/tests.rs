use super::body::collect_body_limited;
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            writer_mode: Default::default(),
            commit_lock_stripes: 64,
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
            writer_mode: Default::default(),
            commit_lock_stripes: 64,
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

fn backend_at(endpoint: String, timeout_ms: u64, name: &str) -> HttpCacheBackend {
    HttpCacheBackend::new(
        CacheBackendConfig {
            writer_mode: Default::default(),
            commit_lock_stripes: 64,
            name: name.to_string(),
            kind: "http".to_string(),
            endpoint,
            path: None,
            max_bytes: None,
            sweep_interval_secs: 60,
            timeout_ms,
            max_object_bytes: 1024,
            auth_header_env: None,
        },
        None,
    )
    .expect("backend")
}

/// HTTP gateway implementing only the writer-lease contract: conditional
/// create (`If-None-Match: *`) and conditional release (`If-Match: <etag>`).
async fn spawn_lease_gateway() -> (
    String,
    Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listen");
    let addr = listener.local_addr().expect("address");
    let leases: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        Arc::new(Default::default());
    let server_leases = leases.clone();
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let leases = server_leases.clone();
            tokio::spawn(async move {
                loop {
                    let mut request_line = String::new();
                    let read = reader_read_line(&mut stream, &mut request_line).await;
                    if read == 0 {
                        return;
                    }
                    let mut headers = std::collections::HashMap::new();
                    loop {
                        let mut line = String::new();
                        if reader_read_line(&mut stream, &mut line).await == 0 {
                            return;
                        }
                        if line == "\r\n" {
                            break;
                        }
                        if let Some((name, value)) = line.trim_end().split_once(':') {
                            headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                        }
                    }
                    let content_len: usize = headers
                        .get("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0_u8; content_len];
                    let _ = stream.read_exact(&mut body).await;
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let reply = if !path.ends_with("/_writer_lock") {
                        "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n"
                    } else {
                        let mut leases = leases.lock().expect("lease map");
                        match method.as_str() {
                            "PUT"
                                if headers.get("if-none-match").map(String::as_str)
                                    == Some("*") =>
                            {
                                match leases.entry(path.clone()) {
                                    std::collections::hash_map::Entry::Vacant(entry) => {
                                        entry.insert(String::from_utf8(body).expect("utf8 token"));
                                        "HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n"
                                    }
                                    std::collections::hash_map::Entry::Occupied(_) => {
                                        "HTTP/1.1 412 Precondition Failed\r\ncontent-length: 0\r\n\r\n"
                                    }
                                }
                            }
                            "DELETE" => {
                                let expected = format!(
                                    "\"{}\"",
                                    leases.get(&path).map(String::as_str).unwrap_or("")
                                );
                                if headers.get("if-match").map(String::as_str)
                                    == Some(expected.as_str())
                                    && leases.remove(&path).is_some()
                                {
                                    "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n"
                                } else {
                                    "HTTP/1.1 412 Precondition Failed\r\ncontent-length: 0\r\n\r\n"
                                }
                            }
                            _ => "HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n",
                        }
                    };
                    if stream.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (format!("http://{addr}"), leases, server)
}

async fn reader_read_line(stream: &mut tokio::net::TcpStream, line: &mut String) -> usize {
    let mut byte = [0_u8; 1];
    let mut read = 0;
    loop {
        let n = stream.read(&mut byte).await.expect("client read");
        if n == 0 {
            return read;
        }
        read += n;
        line.push(byte[0] as char);
        if byte[0] == b'\n' {
            return read;
        }
    }
}

#[tokio::test]
async fn independent_http_clients_get_one_namespace_writer() {
    let (endpoint, _leases, server) = spawn_lease_gateway().await;
    let first = backend_at(endpoint.clone(), 500, "http-a");
    let second = backend_at(endpoint, 500, "http-b");

    let held = first.lock_commit("ns", "primary-a").await.unwrap().unwrap();
    let denied = second
        .lock_commit("ns", "primary-b")
        .await
        .err()
        .expect("contention");
    assert!(denied.to_string().contains("already has an active writer"));

    held.release().await.unwrap();
    let acquired = second
        .lock_commit("ns", "primary-b")
        .await
        .expect("lease available after release")
        .unwrap();
    acquired.release().await.unwrap();
    server.abort();
}

#[tokio::test]
async fn http_lease_fails_closed_when_gateway_lacks_conditional_create() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listen");
    let endpoint = format!("http://{}", listener.local_addr().expect("address"));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = [0_u8; 1024];
        let _ = stream.read(&mut buf).await;
        stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n")
            .await
            .expect("reply");
    });
    let backend = backend_at(endpoint, 500, "http");
    let err = backend
        .lock_commit("ns", "primary")
        .await
        .err()
        .expect("unsupported lease must fail closed");
    assert!(
        err.to_string()
            .contains("does not implement the writer lease")
    );
    server.abort();
}
