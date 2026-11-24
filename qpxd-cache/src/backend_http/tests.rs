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
            writer_lease_ttl_ms: 5_000,
            allow_local_only_remote_coordination: false,
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
            writer_lease_ttl_ms: 5_000,
            allow_local_only_remote_coordination: false,
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
    backend_at_with_ttl(endpoint, timeout_ms, 5_000, name)
}

fn backend_at_with_ttl(
    endpoint: String,
    timeout_ms: u64,
    writer_lease_ttl_ms: u64,
    name: &str,
) -> HttpCacheBackend {
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
            writer_lease_ttl_ms,
            allow_local_only_remote_coordination: false,
            max_object_bytes: 1024,
            auth_header_env: None,
        },
        None,
    )
    .expect("backend")
}

#[test]
fn http_backend_rejects_lease_ttl_shorter_than_a_heartbeat_tick() {
    let config = CacheBackendConfig {
        writer_mode: Default::default(),
        commit_lock_stripes: 64,
        name: "http".to_string(),
        kind: "http".to_string(),
        endpoint: "http://127.0.0.1:1".to_string(),
        path: None,
        max_bytes: None,
        sweep_interval_secs: 60,
        timeout_ms: 500,
        writer_lease_ttl_ms: 29,
        allow_local_only_remote_coordination: false,
        max_object_bytes: 1024,
        auth_header_env: None,
    };
    let err = HttpCacheBackend::new(config, None)
        .err()
        .expect("sub-tick lease must be rejected");
    assert!(err.to_string().contains("at least 30"), "{err}");
}

/// How the gateway mishandles the first successful conditional create.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CreateFault {
    None,
    /// Apply the create, signal the token, then close without a reply.
    DropReply,
    /// Apply the create, signal the token, then never acknowledge it.
    HangReply,
}

/// HTTP gateway implementing only the writer-lease contract: conditional
/// create (`If-None-Match: *`) and conditional release (`If-Match: <etag>`).
async fn spawn_lease_gateway() -> (
    String,
    Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    tokio::task::JoinHandle<()>,
) {
    let (endpoint, leases, _applied, _deleted, _renewed, server) =
        spawn_lease_gateway_with(CreateFault::None).await;
    (endpoint, leases, server)
}

/// Same gateway, with a deterministic ambiguous-create fault and channels that
/// announce the applied token and each token-checked deletion.
#[allow(clippy::type_complexity)]
async fn spawn_lease_gateway_with(
    fault: CreateFault,
) -> (
    String,
    Arc<std::sync::Mutex<std::collections::HashMap<String, String>>>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listen");
    let addr = listener.local_addr().expect("address");
    let leases: Arc<std::sync::Mutex<std::collections::HashMap<String, String>>> =
        Arc::new(Default::default());
    let expiries: Arc<std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>> =
        Arc::new(Default::default());
    let server_leases = leases.clone();
    let server_expiries = expiries.clone();
    let (applied_tx, applied_rx) = mpsc::unbounded_channel();
    let (deleted_tx, deleted_rx) = mpsc::unbounded_channel();
    let (renewed_tx, renewed_rx) = mpsc::unbounded_channel();
    let fault = Arc::new(std::sync::Mutex::new(fault));
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let leases = server_leases.clone();
            let expiries = server_expiries.clone();
            let applied = applied_tx.clone();
            let deleted = deleted_tx.clone();
            let renewed = renewed_tx.clone();
            let fault = fault.clone();
            tokio::spawn(async move {
                // The gateway honors the client's bound and clears an expired
                // lease before evaluating any conditional operation.
                fn live(
                    leases: &mut std::collections::HashMap<String, String>,
                    expiries: &mut std::collections::HashMap<String, std::time::Instant>,
                    path: &str,
                ) {
                    if expiries
                        .get(path)
                        .is_some_and(|at| *at <= std::time::Instant::now())
                    {
                        leases.remove(path);
                        expiries.remove(path);
                    }
                }
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
                    // Read the declaration through its owner, exactly as the
                    // production gateway would, instead of parsing it again.
                    let mut owner_headers = http::HeaderMap::new();
                    for (name, value) in &headers {
                        if let (Ok(name), Ok(value)) = (
                            http::HeaderName::from_bytes(name.as_bytes()),
                            http::HeaderValue::from_str(value),
                        ) {
                            owner_headers.insert(name, value);
                        }
                    }
                    let content_len =
                        qpx_core::http_content_length::declared_content_length(&owner_headers)
                            .ok()
                            .flatten()
                            .unwrap_or(0) as usize;
                    let mut body = vec![0_u8; content_len];
                    let _ = stream.read_exact(&mut body).await;
                    let mut parts = request_line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let reply = if !path.ends_with("/_writer_lock") {
                        // Object mutations must carry the live lease token.
                        // The check and the map update are one gateway
                        // operation, so a stale holder cannot win a race.
                        let namespace = path
                            .strip_prefix("/v1/cache/")
                            .and_then(|rest| rest.split('/').next())
                            .unwrap_or("");
                        let lease_path = format!("/v1/cache/{namespace}/_writer_lock");
                        let presented = headers.get("x-qpx-writer-lease").map(String::as_str);
                        let holder = leases.lock().expect("lease map").get(&lease_path).cloned();
                        let authorized = holder.is_some() && presented == holder.as_deref();
                        match method.as_str() {
                            "PUT" if authorized => {
                                leases.lock().expect("lease map").insert(
                                    path.clone(),
                                    String::from_utf8_lossy(&body).into_owned(),
                                );
                                "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_string()
                            }
                            "DELETE" if authorized => {
                                leases.lock().expect("lease map").remove(&path);
                                "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n".to_string()
                            }
                            "GET" => match leases.lock().expect("lease map").get(&path) {
                                Some(value) => format!(
                                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                                    value.len(),
                                    value
                                ),
                                None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n"
                                    .to_string(),
                            },
                            _ => "HTTP/1.1 409 Conflict\r\ncontent-length: 0\r\n\r\n".to_string(),
                        }
                    } else {
                        let mut leases = leases.lock().expect("lease map");
                        {
                            let mut expiries = expiries.lock().expect("lease expiries");
                            live(&mut leases, &mut expiries, &path);
                        }
                        match method.as_str() {
                            "PUT"
                                if headers.get("if-none-match").map(String::as_str)
                                    == Some("*") =>
                            {
                                match leases.entry(path.clone()) {
                                    std::collections::hash_map::Entry::Vacant(entry) => {
                                        let token = String::from_utf8(body).expect("utf8 token");
                                        let ttl_ms: u64 = headers
                                            .get("x-qpx-writer-lease-ttl-ms")
                                            .and_then(|v| v.parse().ok())
                                            .expect("lease ttl header");
                                        expiries.lock().expect("lease expiries").insert(
                                            path.clone(),
                                            std::time::Instant::now()
                                                + std::time::Duration::from_millis(ttl_ms),
                                        );
                                        entry.insert(token.clone());
                                        let mode = {
                                            let mut fault = fault.lock().expect("fault");
                                            let mode = *fault;
                                            *fault = CreateFault::None;
                                            mode
                                        };
                                        if mode != CreateFault::None {
                                            let _ = applied.send(token);
                                            match mode {
                                                CreateFault::DropReply => return,
                                                CreateFault::HangReply => continue,
                                                CreateFault::None => {}
                                            }
                                        }
                                        "HTTP/1.1 201 Created\r\ncontent-length: 0\r\n\r\n".to_string()
                                    }
                                    std::collections::hash_map::Entry::Occupied(_) => {
                                        "HTTP/1.1 412 Precondition Failed\r\ncontent-length: 0\r\n\r\n".to_string()
                                    }
                                }
                            }
                            "PUT" => {
                                let expected = format!(
                                    "\"{}\"",
                                    leases.get(&path).map(String::as_str).unwrap_or("")
                                );
                                if headers.get("if-match").map(String::as_str) == Some(expected.as_str()) {
                                    let ttl_ms: u64 = headers
                                        .get("x-qpx-writer-lease-ttl-ms")
                                        .and_then(|v| v.parse().ok())
                                        .expect("lease ttl header");
                                    expiries.lock().expect("lease expiries").insert(
                                        path.clone(),
                                        std::time::Instant::now()
                                            + std::time::Duration::from_millis(ttl_ms),
                                    );
                                    let _ = renewed.send(path.clone());
                                    "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n".to_string()
                                } else {
                                    "HTTP/1.1 412 Precondition Failed\r\ncontent-length: 0\r\n\r\n".to_string()
                                }
                            }
                            "GET" => {
                                live(&mut leases, &mut expiries.lock().expect("lease expiries"), &path);
                                match leases.get(&path) {
                                    Some(token) => format!(
                                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                                        token.len(), token
                                    ),
                                    None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_string(),
                                }
                            }
                            "DELETE" => {
                                {
                                    let mut expiries = expiries.lock().expect("lease expiries");
                                    live(&mut leases, &mut expiries, &path);
                                }
                                let expected = format!(
                                    "\"{}\"",
                                    leases.get(&path).map(String::as_str).unwrap_or("")
                                );
                                if headers.get("if-match").map(String::as_str)
                                    == Some(expected.as_str())
                                    && leases.remove(&path).is_some()
                                {
                                    expiries.lock().expect("lease expiries").remove(&path);
                                    let _ = deleted.send(expected.trim_matches('\"').to_string());
                                    "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n".to_string()
                                } else {
                                    "HTTP/1.1 412 Precondition Failed\r\ncontent-length: 0\r\n\r\n".to_string()
                                }
                            }
                            _ => "HTTP/1.1 405 Method Not Allowed\r\ncontent-length: 0\r\n\r\n".to_string(),
                        }
                    };
                    if stream.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (
        format!("http://{addr}"),
        leases,
        applied_rx,
        deleted_rx,
        renewed_rx,
        server,
    )
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
async fn http_backend_without_writer_lease_fails_closed_by_default() {
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
        .expect("no lease endpoint and no opt-in must fail closed");
    assert!(
        err.to_string().contains("no writer lease endpoint"),
        "{err}"
    );
    server.abort();
}

#[tokio::test]
async fn http_local_only_coordination_is_explicitly_opt_in() {
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
    let backend = HttpCacheBackend::new(
        CacheBackendConfig {
            writer_mode: Default::default(),
            commit_lock_stripes: 64,
            name: "http-local-only".to_string(),
            kind: "http".to_string(),
            endpoint,
            path: None,
            max_bytes: None,
            sweep_interval_secs: 60,
            timeout_ms: 500,
            writer_lease_ttl_ms: 5_000,
            allow_local_only_remote_coordination: true,
            max_object_bytes: 1024,
            auth_header_env: None,
        },
        None,
    )
    .expect("backend");
    let lease = backend
        .lock_commit("ns", "primary")
        .await
        .expect("opt-in legacy gateway is accepted");
    assert!(
        lease.is_none(),
        "only process-local coordination is claimed"
    );
    server.abort();
}

#[tokio::test]
async fn http_lost_create_reply_is_released_and_fences_the_stale_holder() {
    let (endpoint, leases, mut applied, mut deleted, _renewed, server) =
        spawn_lease_gateway_with(CreateFault::DropReply).await;
    let first = backend_at(endpoint.clone(), 500, "http-a");
    let second = backend_at(endpoint.clone(), 500, "http-b");

    let first_acquire = tokio::spawn(async move { first.lock_commit("ns", "primary-a").await });
    let stale = timeout(Duration::from_secs(2), applied.recv())
        .await
        .expect("conditional create was applied")
        .expect("applied signal");
    let outcome = timeout(Duration::from_secs(3), first_acquire)
        .await
        .expect("acquisition terminates after the lost reply")
        .expect("task");
    let err = match outcome {
        Ok(_) => panic!("a lost create reply must not be reported as a held lease"),
        Err(err) => err,
    };
    assert!(
        !err.to_string()
            .contains("does not implement the writer lease"),
        "{err}"
    );
    // Cleanup is a fenced delete of the same token, awaited before the error.
    let cleaned = timeout(Duration::from_secs(2), deleted.recv())
        .await
        .expect("live client cleaned up")
        .expect("deleted signal");
    assert_eq!(cleaned, stale);
    assert!(leases.lock().expect("lease map").is_empty());

    let held = second
        .lock_commit("ns", "primary-b")
        .await
        .expect("second client can acquire")
        .expect("lease");
    let current = {
        let leases = leases.lock().expect("lease map");
        assert_eq!(leases.len(), 1);
        leases.values().next().unwrap().clone()
    };
    assert_ne!(current, stale);

    // A stale holder with the old token cannot revoke the new lease.
    let uri = format!("{endpoint}/v1/cache/ns/_writer_lock")
        .parse::<Uri>()
        .expect("lease uri");
    let mut req = owner_request(Method::DELETE, uri, Body::empty());
    req.headers_mut().insert(
        ord("if-match"),
        http::HeaderValue::from_str(&format!("\"{stale}\"")).expect("token header"),
    );
    let status = second.send_status(req).await.expect("stale delete sent");
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(leases.lock().expect("lease map").len(), 1);

    held.release().await.expect("second client releases");
    assert!(leases.lock().expect("lease map").is_empty());
    server.abort();
}

#[tokio::test]
async fn cancelled_http_acquisition_releases_the_applied_lease() {
    let (endpoint, leases, mut applied, mut deleted, _renewed, server) =
        spawn_lease_gateway_with(CreateFault::HangReply).await;
    let backend = backend_at(endpoint.clone(), 2000, "http-a");

    let acquire = tokio::spawn(async move { backend.lock_commit("ns", "primary-a").await });
    let token = timeout(Duration::from_secs(2), applied.recv())
        .await
        .expect("conditional create was applied")
        .expect("applied signal");
    assert!(!leases.lock().expect("lease map").is_empty());
    acquire.abort();
    let aborted = acquire.await;
    assert!(
        matches!(aborted, Err(err) if err.is_cancelled()),
        "acquisition was cancelled before its acknowledgement"
    );

    let cleaned = timeout(Duration::from_secs(2), deleted.recv())
        .await
        .expect("Drop fallback cleaned up")
        .expect("deleted signal");
    assert_eq!(cleaned, token);
    assert!(leases.lock().expect("lease map").is_empty());

    let second = backend_at(endpoint, 500, "http-b");
    let held = timeout(
        Duration::from_secs(3),
        second.lock_commit("ns", "primary-b"),
    )
    .await
    .expect("second client can acquire")
    .expect("acquisition")
    .expect("lease");
    held.release().await.expect("second client releases");
    server.abort();
}

#[tokio::test]
async fn http_fenced_publication_cannot_overwrite_the_successors_index() {
    let (endpoint, leases, server) = spawn_lease_gateway().await;
    let backend = backend_at(endpoint, 500, "http");
    let lease = backend
        .lock_commit("ns", "primary")
        .await
        .expect("lease")
        .expect("backend lease");
    let token = lease.fence_token().expect("holder token").to_string();
    let index_path = "/v1/cache/ns/index";
    backend
        .put_fenced("ns", "index", b"first", 60, Some(&token), None)
        .await
        .expect("current writer publishes");

    leases.lock().expect("lease map").insert(
        "/v1/cache/ns/_writer_lock".to_string(),
        "successor".to_string(),
    );
    backend
        .put_fenced("ns", "index", b"successor", 60, Some("successor"), None)
        .await
        .expect("successor publishes");

    let err = backend
        .put_fenced("ns", "index", b"stale", 60, Some(&token), None)
        .await
        .expect_err("stale writer must be fenced by the gateway");
    assert!(err.to_string().contains("409"), "{err}");
    assert_eq!(
        leases
            .lock()
            .expect("map")
            .get(index_path)
            .map(String::as_str),
        Some("successor"),
        "stale writer must not change the published index"
    );

    backend
        .delete_fenced("ns", "index", Some(&token), None)
        .await
        .expect_err("stale writer cannot retire the successor's index");
    assert_eq!(
        leases
            .lock()
            .expect("map")
            .get(index_path)
            .map(String::as_str),
        Some("successor")
    );
    server.abort();
}

#[tokio::test]
async fn expired_http_lease_is_reclaimable_and_fences_the_old_holder() {
    let (endpoint, leases, server) = spawn_lease_gateway().await;
    let first = backend_at_with_ttl(endpoint.clone(), 500, 40, "http-a");
    let second = backend_at(endpoint, 500, "http-b");

    let old = HttpCommitLease::acquire(&first, "ns")
        .await
        .expect("first lease")
        .expect("backend lease");
    // Simulate a writer that died without cleanup: stop its renewal but keep
    // the token, so the gateway expires the lease within a bounded time.
    old.stop.notify_one();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let current = second
        .lock_commit("ns", "primary-b")
        .await
        .expect("second lease after expiry")
        .expect("backend lease");
    assert_eq!(leases.lock().expect("lease map").len(), 1);

    let err = old
        .validate()
        .await
        .expect_err("the expired holder cannot publish");
    assert!(err.to_string().contains("no longer held"), "{err}");
    current.validate().await.expect("current holder is valid");

    current.release().await.expect("release current lease");
    server.abort();
}

#[tokio::test]
async fn http_heartbeat_keeps_a_live_writer_lease_past_its_initial_ttl() {
    let (endpoint, leases, _applied, _deleted, mut renewed, server) =
        spawn_lease_gateway_with(CreateFault::None).await;
    let first = backend_at_with_ttl(endpoint.clone(), 500, 300, "http-a");
    let second = backend_at(endpoint, 500, "http-b");

    let held = first
        .lock_commit("ns", "primary-a")
        .await
        .expect("first lease")
        .expect("backend lease");
    // Two observed renewals prove the heartbeat ran after acquisition. Waiting
    // for the gateway's own signal avoids a fixed sleep racing the lease TTL.
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(5), renewed.recv())
            .await
            .expect("heartbeat renewed the lease")
            .expect("renewal signal");
    }
    held.validate().await.expect("heartbeat renewed the lease");
    assert_eq!(leases.lock().expect("lease map").len(), 1);
    let denied = second
        .lock_commit("ns", "primary-b")
        .await
        .err()
        .expect("renewed lease still excludes the second writer");
    assert!(denied.to_string().contains("already has an active writer"));

    held.release().await.expect("release renewed lease");
    server.abort();
}

#[tokio::test]
async fn http_validate_rejects_a_lease_whose_heartbeat_was_revoked() {
    let (endpoint, _leases, _server) = spawn_lease_gateway().await;
    let backend = backend_at_with_ttl(endpoint, 500, 30, "http");
    let held = HttpCommitLease::acquire(&backend, "ns")
        .await
        .expect("lease")
        .expect("backend lease");
    held.stop.notify_one();
    held.revoked
        .store(true, std::sync::atomic::Ordering::Release);
    let err = held
        .validate()
        .await
        .expect_err("revoked lease cannot publish");
    assert!(err.to_string().contains("was not renewed"), "{err}");
    drop(held);
}
