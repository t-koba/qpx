use super::protocol::*;
use super::*;

fn cfg(endpoint: &str) -> CacheBackendConfig {
    CacheBackendConfig {
        name: "cache-a".to_string(),
        kind: "redis".to_string(),
        endpoint: endpoint.to_string(),
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
