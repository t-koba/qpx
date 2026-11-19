use crate::types::{CacheBackend, CommitLease};
use bytes::BytesMut;
use qpx_core::config::CacheBackendConfig;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

use super::protocol::{read_bulk_string, read_integer};
use super::{
    RedisCacheBackend, RedisCommitLease, RedisConnection, RedisTransport, release_redis_lease,
};

fn cfg(endpoint: &str) -> CacheBackendConfig {
    cfg_with_ttl(endpoint, 5_000)
}

fn cfg_with_ttl(endpoint: &str, writer_lease_ttl_ms: u64) -> CacheBackendConfig {
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
        writer_lease_ttl_ms,
        allow_local_only_remote_coordination: false,
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

/// How the RESP server mishandles the first successful conditional create.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CreateFault {
    None,
    /// Apply SET NX, signal the token, then close without a reply.
    DropReply,
    /// Apply SET NX, signal the token, then never acknowledge it.
    HangReply,
}

/// Minimal RESP server whose SET NX and compare-and-delete are the only
/// atomic operations used by the writer lease. Each connection is independent,
/// like a separate qpx process.
async fn spawn_writer_lease_server() -> (
    String,
    Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
    tokio::task::JoinHandle<()>,
) {
    let (endpoint, locks, _applied, _deleted, server) =
        spawn_writer_lease_server_with(CreateFault::None).await;
    (endpoint, locks, server)
}

/// Same server, with a deterministic ambiguous-create fault and channels that
/// announce the applied token and each token-checked deletion.
#[allow(clippy::type_complexity)]
async fn spawn_writer_lease_server_with(
    fault: CreateFault,
) -> (
    String,
    Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    tokio::sync::mpsc::UnboundedReceiver<String>,
    tokio::task::JoinHandle<()>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
    use tokio::sync::mpsc;

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
    let expiries: Arc<tokio::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>> =
        Arc::new(Default::default());
    let server_locks = locks.clone();
    let server_expiries = expiries.clone();
    let (applied_tx, applied_rx) = mpsc::unbounded_channel();
    let (deleted_tx, deleted_rx) = mpsc::unbounded_channel();
    let fault = Arc::new(std::sync::Mutex::new(fault));
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let locks = server_locks.clone();
            let expiries = server_expiries.clone();
            let applied = applied_tx.clone();
            let deleted = deleted_tx.clone();
            let fault = fault.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                while let Some(parts) = command(&mut reader).await {
                    let reply = match parts.first().map(String::as_str) {
                        Some("SET")
                            if parts.get(3).map(String::as_str) == Some("NX")
                                && parts.get(4).map(String::as_str) == Some("PX") =>
                        {
                            let ttl_ms: u64 = parts[5].parse().expect("PX ttl");
                            let mut locks = locks.lock().await;
                            {
                                let mut expiries = expiries.lock().await;
                                if expiries
                                    .get(&parts[1])
                                    .is_some_and(|at| *at <= std::time::Instant::now())
                                {
                                    locks.remove(&parts[1]);
                                    expiries.remove(&parts[1]);
                                }
                            }
                            match locks.entry(parts[1].clone()) {
                                std::collections::hash_map::Entry::Vacant(entry) => {
                                    expiries.lock().await.insert(
                                        parts[1].clone(),
                                        std::time::Instant::now()
                                            + std::time::Duration::from_millis(ttl_ms),
                                    );
                                    entry.insert(parts[2].clone());
                                    let mode = {
                                        let mut fault = fault.lock().expect("fault");
                                        let mode = *fault;
                                        *fault = CreateFault::None;
                                        mode
                                    };
                                    if mode != CreateFault::None {
                                        let _ = applied.send(parts[2].clone());
                                        match mode {
                                            CreateFault::DropReply => return,
                                            CreateFault::HangReply => continue,
                                            CreateFault::None => {}
                                        }
                                    }
                                    "+OK\r\n".to_string()
                                }
                                std::collections::hash_map::Entry::Occupied(_) => {
                                    "$-1\r\n".to_string()
                                }
                            }
                        }
                        Some("GET") => {
                            let mut locks = locks.lock().await;
                            {
                                let mut expiries = expiries.lock().await;
                                if expiries
                                    .get(&parts[1])
                                    .is_some_and(|at| *at <= std::time::Instant::now())
                                {
                                    locks.remove(&parts[1]);
                                    expiries.remove(&parts[1]);
                                }
                            }
                            match locks.get(&parts[1]) {
                                Some(token) => format!("${}\r\n{}\r\n", token.len(), token),
                                None => "$-1\r\n".to_string(),
                            }
                        }
                        Some("SELECT") => "+OK\r\n".to_string(),
                        Some("EVAL") if parts.get(1).is_some_and(|s| s.contains("pexpire")) => {
                            let locks = locks.lock().await;
                            let ttl_ms: u64 = parts[5].parse().expect("PX ttl");
                            let held = locks.get(&parts[3]).map(String::as_str) == Some(&parts[4]);
                            if held {
                                expiries.lock().await.insert(
                                    parts[3].clone(),
                                    std::time::Instant::now()
                                        + std::time::Duration::from_millis(ttl_ms),
                                );
                            }
                            format!(":{}\r\n", u8::from(held))
                        }
                        Some("EVAL") => {
                            // The lease script is compare-and-delete on KEYS[1]/ARGV[1].
                            let mut locks = locks.lock().await;
                            {
                                let mut expiries = expiries.lock().await;
                                if expiries
                                    .get(&parts[3])
                                    .is_some_and(|at| *at <= std::time::Instant::now())
                                {
                                    locks.remove(&parts[3]);
                                    expiries.remove(&parts[3]);
                                }
                            }
                            let held = locks.get(&parts[3]).map(String::as_str) == Some(&parts[4]);
                            if held {
                                locks.remove(&parts[3]);
                                expiries.lock().await.remove(&parts[3]);
                                let _ = deleted.send(parts[4].clone());
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
    (
        format!("redis://{addr}/0"),
        locks,
        applied_rx,
        deleted_rx,
        server,
    )
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

#[tokio::test]
async fn redis_lost_create_reply_is_released_and_fences_the_stale_holder() {
    let (endpoint, locks, mut applied, mut deleted, server) =
        spawn_writer_lease_server_with(CreateFault::DropReply).await;
    let first = RedisCacheBackend::new(cfg(&endpoint)).expect("first backend");
    let mut second_config = cfg(&endpoint);
    second_config.name = "cache-b".to_string();
    let second = RedisCacheBackend::new(second_config).expect("second backend");
    let key = "qpx:writer-lock:ns".to_string();

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
    let cleaned = timeout(Duration::from_secs(2), deleted.recv())
        .await
        .expect("live client cleaned up")
        .expect("deleted signal");
    assert_eq!(cleaned, stale);
    assert!(locks.lock().await.is_empty());

    let held = second
        .lock_commit("ns", "primary-b")
        .await
        .expect("second client can acquire")
        .expect("lease");
    let current = {
        let locks = locks.lock().await;
        assert_eq!(locks.len(), 1);
        locks.get(&key).expect("second token").clone()
    };
    assert_ne!(current, stale);

    // The stale token cannot remove the lease held under the new token.
    release_redis_lease(second.client.clone(), key.clone(), stale)
        .await
        .expect("fenced release of a stale token is harmless");
    {
        let locks = locks.lock().await;
        assert_eq!(locks.get(&key).map(String::as_str), Some(current.as_str()));
    }

    held.release().await.expect("second client releases");
    assert!(locks.lock().await.is_empty());
    server.abort();
}

#[tokio::test]
async fn cancelled_redis_acquisition_releases_the_applied_lease() {
    let (endpoint, locks, mut applied, mut deleted, server) =
        spawn_writer_lease_server_with(CreateFault::HangReply).await;
    let backend = RedisCacheBackend::new(cfg(&endpoint)).expect("backend");
    let key = "qpx:writer-lock:ns".to_string();

    let acquire = tokio::spawn(async move { backend.lock_commit("ns", "primary-a").await });
    let token = timeout(Duration::from_secs(2), applied.recv())
        .await
        .expect("conditional create was applied")
        .expect("applied signal");
    assert_eq!(
        locks.lock().await.get(&key).map(String::as_str),
        Some(token.as_str())
    );
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
    assert!(locks.lock().await.is_empty());

    let second = RedisCacheBackend::new(cfg(&endpoint)).expect("second backend");
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
async fn expired_redis_lease_is_reclaimable_and_fences_the_old_holder() {
    let (endpoint, locks, server) = spawn_writer_lease_server().await;
    let first = RedisCacheBackend::new(cfg_with_ttl(&endpoint, 40)).expect("first backend");
    let second = RedisCacheBackend::new(cfg(&endpoint)).expect("second backend");
    let old = RedisCommitLease::acquire(first.client.clone(), "ns")
        .await
        .expect("first lease");
    old.stop.notify_one();
    tokio::time::sleep(Duration::from_millis(80)).await;
    let current = second
        .lock_commit("ns", "primary-b")
        .await
        .expect("second lease after expiry")
        .expect("backend lease");
    assert_eq!(locks.lock().await.len(), 1);

    let err = old
        .validate()
        .await
        .expect_err("the expired holder cannot publish");
    assert!(err.to_string().contains("no longer held"), "{err}");
    current.validate().await.expect("current holder is valid");

    current.release().await.expect("release current lease");
    assert!(locks.lock().await.is_empty());
    server.abort();
}

#[tokio::test]
async fn redis_heartbeat_keeps_a_live_writer_lease_past_its_initial_ttl() {
    let (endpoint, locks, server) = spawn_writer_lease_server().await;
    let first = RedisCacheBackend::new(cfg_with_ttl(&endpoint, 60)).expect("first backend");
    let second = RedisCacheBackend::new(cfg(&endpoint)).expect("second backend");
    let held = first
        .lock_commit("ns", "primary-a")
        .await
        .expect("first lease")
        .expect("backend lease");
    tokio::time::sleep(Duration::from_millis(150)).await;
    held.validate().await.expect("heartbeat renewed the lease");
    assert_eq!(locks.lock().await.len(), 1);
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
async fn redis_validate_rejects_a_lease_whose_heartbeat_was_revoked() {
    let (endpoint, _locks, _server) = spawn_writer_lease_server().await;
    let backend = RedisCacheBackend::new(cfg_with_ttl(&endpoint, 30)).expect("backend");
    let held = RedisCommitLease::acquire(backend.client.clone(), "ns")
        .await
        .expect("lease");
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

#[tokio::test]
async fn redis_lost_lease_revokes_on_renewal_result_zero() {
    let (endpoint, locks, server) = spawn_writer_lease_server().await;
    let backend = RedisCacheBackend::new(cfg_with_ttl(&endpoint, 40)).expect("backend");
    let held = RedisCommitLease::acquire(backend.client.clone(), "ns")
        .await
        .expect("lease");

    // Another actor reclaims the key. The next conditional renewal returns 0,
    // which must revoke the holder without manually setting the flag.
    locks
        .lock()
        .await
        .insert("qpx:writer-lock:ns".to_string(), "reclaimer".to_string());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let err = held
        .validate()
        .await
        .expect_err("lost lease cannot publish");
    assert!(err.to_string().contains("was not renewed"), "{err}");
    drop(held);
    server.abort();
}
