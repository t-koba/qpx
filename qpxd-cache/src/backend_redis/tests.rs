use crate::types::CacheBackend;
use bytes::BytesMut;
use qpx_core::config::CacheBackendConfig;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;

use super::protocol::{read_bulk_string, read_integer};
use super::{RedisCacheBackend, RedisConnection, RedisTransport, release_redis_lease};

fn cfg(endpoint: &str) -> CacheBackendConfig {
    CacheBackendConfig {
        writer_mode: Default::default(),
        commit_lock_stripes: 64,
        name: "cache-a".to_string(),
        kind: "redis".to_string(),
        endpoint: endpoint.to_string(),
        path: None,
        max_bytes: None,
        sweep_interval_secs: 60,
        timeout_ms: 500,
        max_object_bytes: 1024,
        auth_header_env: None,
    }
}

#[test]
fn parse_plain_redis_tcp() {
    let backend = RedisCacheBackend::new(cfg("redis://cache.internal:6380/2")).expect("backend");
    assert!(matches!(
        backend.client.transport,
        RedisTransport::Tcp { .. }
    ));
    assert_eq!(backend.client.db, Some(2));
    assert!(backend.client.tls_domain.is_none());
}

#[test]
fn parse_rediss_enables_tls() {
    let backend = RedisCacheBackend::new(cfg("rediss://cache.internal:6380/5")).expect("backend");
    assert!(matches!(
        backend.client.transport,
        RedisTransport::Tcp { .. }
    ));
    assert_eq!(backend.client.db, Some(5));
    assert!(backend.client.tls_domain.is_some());
}

#[cfg(unix)]
#[test]
fn parse_redis_unix_socket_endpoint() {
    let backend =
        RedisCacheBackend::new(cfg("redis+unix:///tmp/redis.sock?db=1")).expect("backend");
    assert!(matches!(
        backend.client.transport,
        RedisTransport::Unix { .. }
    ));
    assert_eq!(backend.client.db, Some(1));
    assert!(backend.client.tls_domain.is_none());
}

#[tokio::test]
async fn read_bulk_string_rejects_over_limit() {
    let (client, mut server) = tokio::io::duplex(64);
    tokio::spawn(async move {
        let _ = server.write_all(b"$5\r\nhello\r\n").await;
    });
    let mut conn = RedisConnection {
        stream: Box::new(client),
        read_buf: BytesMut::with_capacity(64),
    };
    let err = read_bulk_string(&mut conn, Duration::from_secs(1), 4)
        .await
        .expect_err("must fail");
    assert!(err.to_string().contains("payload too large"));
}

#[tokio::test]
async fn buffered_resp_parser_preserves_bulk_payload_after_line_overread() {
    let (client, mut server) = tokio::io::duplex(64);
    tokio::spawn(async move {
        let _ = server.write_all(b"$5\r\nhello\r\n:7\r\n").await;
    });
    let mut conn = RedisConnection {
        stream: Box::new(client),
        read_buf: BytesMut::with_capacity(64),
    };
    let value = read_bulk_string(&mut conn, Duration::from_secs(1), 16)
        .await
        .expect("read succeeds")
        .expect("bulk value");
    assert_eq!(value.as_ref(), b"hello");
    assert_eq!(
        read_integer(&mut conn, Duration::from_secs(1))
            .await
            .expect("integer"),
        7
    );
}

#[tokio::test]
async fn redis_response_stream_error_never_renames_staged_body() {
    use crate::types::{BodyStreamWriteOptions, CacheBackend};
    use qpx_http::body::Body;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    async fn command(reader: &mut BufReader<tokio::io::DuplexStream>) -> Vec<Vec<u8>> {
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("array header");
        let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
        let mut parts = Vec::new();
        for _ in 0..count {
            line.clear();
            reader.read_line(&mut line).await.expect("bulk header");
            let len: usize = line.trim().strip_prefix('$').unwrap().parse().unwrap();
            let mut data = vec![0; len + 2];
            reader.read_exact(&mut data).await.expect("bulk bytes");
            assert_eq!(&data[len..], b"\r\n");
            data.truncate(len);
            parts.push(data);
        }
        parts
    }

    let backend = RedisCacheBackend::new(cfg("redis://unused.invalid")).expect("backend");
    let (client, server) = tokio::io::duplex(4096);
    backend.client.idle.lock().await.push(RedisConnection {
        stream: Box::new(client),
        read_buf: BytesMut::new(),
    });
    let (mut sender, body) = Body::channel();
    sender
        .send_data(bytes::Bytes::from_static(b"partial"))
        .await
        .expect("data");
    let server = tokio::spawn(async move {
        let mut reader = BufReader::new(server);
        let init = command(&mut reader).await;
        assert_eq!(init[0], b"SET");
        assert!(String::from_utf8_lossy(&init[1]).contains(":tmp:"));
        assert!(init[2].is_empty());
        assert_eq!(init[3], b"EX");
        assert_eq!(init[4], b"60");
        reader
            .get_mut()
            .write_all(b"+OK\r\n")
            .await
            .expect("SET reply");
        let append = command(&mut reader).await;
        assert_eq!(append[0], b"APPEND");
        assert_eq!(append[1], init[1]);
        assert_eq!(append[2], b"partial");
        // Abort only after staged bytes exist. No RENAME or metadata SET may
        // follow; the failed connection is closed, and the temp key expires.
        sender.abort();
        reader
            .get_mut()
            .write_all(b":7\r\n")
            .await
            .expect("APPEND reply");
        let mut remaining = Vec::new();
        reader
            .read_to_end(&mut remaining)
            .await
            .expect("connection closes");
        assert!(
            remaining.is_empty(),
            "unexpected publish command: {remaining:?}"
        );
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
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("server completes")
        .expect("server");
}

/// Minimal RESP server whose SET NX and compare-and-delete are the only
/// atomic operations used by the writer lease. Each connection is independent,
/// like a separate qpx process.
async fn spawn_writer_lease_server() -> (
    String,
    Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    async fn command(reader: &mut BufReader<tokio::net::TcpStream>) -> Option<Vec<String>> {
        let mut head = String::new();
        if reader.read_line(&mut head).await.ok()? == 0 {
            return None;
        }
        let count: usize = head.trim().strip_prefix('*')?.parse().ok()?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let mut len_line = String::new();
            reader.read_line(&mut len_line).await.ok()?;
            let len: usize = len_line.trim().strip_prefix('$')?.parse().ok()?;
            let mut arg = vec![0_u8; len + 2];
            reader.read_exact(&mut arg).await.ok()?;
            out.push(String::from_utf8(arg[..len].to_vec()).ok()?);
        }
        Some(out)
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listen");
    let addr = listener.local_addr().expect("address");
    let locks: Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>> =
        Arc::new(Default::default());
    let server_locks = locks.clone();
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let locks = server_locks.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                while let Some(parts) = command(&mut reader).await {
                    let reply = match parts.first().map(String::as_str) {
                        Some("SET") if parts.get(3).map(String::as_str) == Some("NX") => {
                            let mut locks = locks.lock().await;
                            match locks.entry(parts[1].clone()) {
                                std::collections::hash_map::Entry::Vacant(entry) => {
                                    entry.insert(parts[2].clone());
                                    "+OK\r\n".to_string()
                                }
                                std::collections::hash_map::Entry::Occupied(_) => {
                                    "$-1\r\n".to_string()
                                }
                            }
                        }
                        Some("SELECT") => "+OK\r\n".to_string(),
                        Some("EVAL") => {
                            // The lease script is compare-and-delete on KEYS[1]/ARGV[1].
                            let mut locks = locks.lock().await;
                            let held = locks.get(&parts[3]).map(String::as_str) == Some(&parts[4]);
                            if held {
                                locks.remove(&parts[3]);
                            }
                            format!(":{}\r\n", u8::from(held))
                        }
                        _ => "-ERR unsupported test command\r\n".to_string(),
                    };
                    if reader.write_all(reply.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (format!("redis://{addr}/0"), locks, server)
}

#[tokio::test]
async fn independent_redis_clients_get_one_namespace_writer() {
    let (endpoint, _locks, server) = spawn_writer_lease_server().await;
    let first = RedisCacheBackend::new(cfg(&endpoint)).expect("first backend");
    let mut second_config = cfg(&endpoint);
    second_config.name = "cache-b".to_string();
    let second = RedisCacheBackend::new(second_config).expect("second backend");

    let held = first.lock_commit("ns", "primary-a").await.unwrap().unwrap();
    let denied = second
        .lock_commit("ns", "primary-b")
        .await
        .err()
        .expect("second independent client cannot acquire the namespace");
    assert!(denied.to_string().contains("already has an active writer"));

    // A stale token cannot release another client's lease.
    release_redis_lease(
        first.client.clone(),
        "qpx:writer-lock:ns".to_string(),
        "stale-token".to_string(),
    )
    .await
    .unwrap();
    assert!(second.lock_commit("ns", "primary-b").await.is_err());

    held.release().await.unwrap();
    let acquired = second
        .lock_commit("ns", "primary-b")
        .await
        .expect("lock available after release")
        .unwrap();
    acquired.release().await.unwrap();
    drop(second);
    drop(first);
    server.abort();
}
