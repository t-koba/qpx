use bytes::BytesMut;
use qpx_core::config::CacheBackendConfig;
use tokio::io::AsyncWriteExt;
use tokio::time::Duration;

use super::protocol::{read_bulk_string, read_integer};
use super::{RedisCacheBackend, RedisConnection, RedisTransport};

fn cfg(endpoint: &str) -> CacheBackendConfig {
    CacheBackendConfig {
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
    assert!(matches!(backend.transport, RedisTransport::Tcp { .. }));
    assert_eq!(backend.db, Some(2));
    assert!(backend.tls_domain.is_none());
}

#[test]
fn parse_rediss_enables_tls() {
    let backend = RedisCacheBackend::new(cfg("rediss://cache.internal:6380/5")).expect("backend");
    assert!(matches!(backend.transport, RedisTransport::Tcp { .. }));
    assert_eq!(backend.db, Some(5));
    assert!(backend.tls_domain.is_some());
}

#[cfg(unix)]
#[test]
fn parse_redis_unix_socket_endpoint() {
    let backend =
        RedisCacheBackend::new(cfg("redis+unix:///tmp/redis.sock?db=1")).expect("backend");
    assert!(matches!(backend.transport, RedisTransport::Unix { .. }));
    assert_eq!(backend.db, Some(1));
    assert!(backend.tls_domain.is_none());
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
    backend.idle.lock().await.push(RedisConnection {
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
