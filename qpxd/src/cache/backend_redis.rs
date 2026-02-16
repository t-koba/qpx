use super::CacheBackend;
use crate::http::address::format_authority_host_port;
use crate::tls::client::{connect_tls_http1, IoStream};
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use qpx_core::config::CacheBackendConfig;
#[cfg(unix)]
use std::{path::PathBuf, str::FromStr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};
use url::Url;

type DynStream = crate::tls::client::BoxTlsStream;

#[derive(Debug, Clone)]
enum RedisTransport {
    Tcp {
        addr: String,
    },
    #[cfg(unix)]
    Unix {
        path: PathBuf,
    },
}

#[derive(Clone)]
struct RedisEndpointSpec {
    transport: RedisTransport,
    tls_domain: Option<String>,
    db: Option<u32>,
    password: Option<String>,
}

pub(super) struct RedisCacheBackend {
    transport: RedisTransport,
    tls_domain: Option<String>,
    db: Option<u32>,
    password: Option<String>,
    timeout: Duration,
    key_prefix: String,
    max_object_bytes: usize,
}

impl RedisCacheBackend {
    pub(super) fn new(cfg: CacheBackendConfig) -> Result<Self> {
        let endpoint = cfg.endpoint.trim();
        let spec = parse_endpoint(endpoint)?;

        Ok(Self {
            transport: spec.transport,
            tls_domain: spec.tls_domain,
            db: spec.db,
            password: spec.password,
            timeout: Duration::from_millis(cfg.timeout_ms),
            key_prefix: cfg.name,
            max_object_bytes: cfg.max_object_bytes,
        })
    }

    fn full_key(&self, namespace: &str, key: &str) -> String {
        format!("qpx:{}:{}:{}", self.key_prefix, namespace, key)
    }

    async fn open(&self) -> Result<DynStream> {
        let mut stream: DynStream = match &self.transport {
            RedisTransport::Tcp { addr } => {
                let tcp = timeout(self.timeout, TcpStream::connect(addr)).await??;
                if let Some(domain) = self.tls_domain.as_deref() {
                    timeout(self.timeout, connect_tls_http1(domain, tcp)).await??
                } else {
                    Box::new(tcp)
                }
            }
            #[cfg(unix)]
            RedisTransport::Unix { path } => {
                let unix = timeout(self.timeout, UnixStream::connect(path)).await??;
                Box::new(unix)
            }
        };

        if let Some(password) = self.password.as_deref() {
            let auth = encode_command(&[b"AUTH".to_vec(), password.as_bytes().to_vec()]);
            timeout(self.timeout, stream.write_all(&auth)).await??;
            read_simple_ok(stream.as_mut(), self.timeout).await?;
        }

        if let Some(db) = self.db {
            let select = encode_command(&[b"SELECT".to_vec(), db.to_string().into_bytes()]);
            timeout(self.timeout, stream.write_all(&select)).await??;
            read_simple_ok(stream.as_mut(), self.timeout).await?;
        }

        Ok(stream)
    }
}

#[async_trait]
impl CacheBackend for RedisCacheBackend {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let mut stream = self.open().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[b"GET".to_vec(), full_key.into_bytes()]);
        timeout(self.timeout, stream.write_all(&cmd)).await??;
        read_bulk_string(stream.as_mut(), self.timeout, self.max_object_bytes).await
    }

    async fn put(&self, namespace: &str, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        if value.len() > self.max_object_bytes {
            return Err(anyhow!(
                "redis cache put payload too large: {} > {}",
                value.len(),
                self.max_object_bytes
            ));
        }
        let mut stream = self.open().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[
            b"SET".to_vec(),
            full_key.into_bytes(),
            value.to_vec(),
            b"EX".to_vec(),
            ttl_secs.to_string().into_bytes(),
        ]);
        timeout(self.timeout, stream.write_all(&cmd)).await??;
        read_simple_ok(stream.as_mut(), self.timeout).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let mut stream = self.open().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[b"DEL".to_vec(), full_key.into_bytes()]);
        timeout(self.timeout, stream.write_all(&cmd)).await??;
        read_integer(stream.as_mut(), self.timeout).await?;
        Ok(())
    }
}

fn parse_endpoint(endpoint: &str) -> Result<RedisEndpointSpec> {
    if endpoint.is_empty() {
        return Err(anyhow!("redis cache endpoint must not be empty"));
    }
    if endpoint.starts_with("redis://") || endpoint.starts_with("rediss://") {
        let parsed = Url::parse(endpoint)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("redis endpoint missing host"))?;
        let port = parsed.port().unwrap_or(6379);
        let db = db_from_url(&parsed);
        let password = parsed.password().map(ToString::to_string);
        let transport = RedisTransport::Tcp {
            addr: format_authority_host_port(host, port),
        };
        let tls_domain = (parsed.scheme() == "rediss").then(|| host.to_string());
        return Ok(RedisEndpointSpec {
            transport,
            tls_domain,
            db,
            password,
        });
    }
    if endpoint.starts_with("redis+unix://") {
        #[cfg(not(unix))]
        {
            return Err(anyhow!(
                "redis+unix endpoint requires a unix host; use redis:// or rediss:// on this platform"
            ));
        }
        #[cfg(unix)]
        {
            let parsed = Url::parse(endpoint)?;
            let path = parsed.path().trim();
            if path.is_empty() || path == "/" {
                return Err(anyhow!("redis+unix endpoint missing socket path"));
            }
            let socket_path = percent_decode(path)?;
            let db = parsed
                .query_pairs()
                .find_map(|(k, v)| (k == "db").then(|| v.parse::<u32>().ok()).flatten());
            let password = parsed
                .query_pairs()
                .find_map(|(k, v)| (k == "password").then(|| v.to_string()));
            let transport = RedisTransport::Unix { path: socket_path };
            return Ok(RedisEndpointSpec {
                transport,
                tls_domain: None,
                db,
                password,
            });
        }
    }

    Err(anyhow!(
        "redis cache endpoint must be redis://, rediss://, or redis+unix://"
    ))
}

fn db_from_url(url: &Url) -> Option<u32> {
    let from_path = url.path().trim_start_matches('/').trim();
    if !from_path.is_empty() {
        if let Ok(db) = from_path.parse::<u32>() {
            return Some(db);
        }
    }
    url.query_pairs()
        .find_map(|(k, v)| (k == "db").then(|| v.parse::<u32>().ok()).flatten())
}

#[cfg(unix)]
fn percent_decode(path: &str) -> Result<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(path)
        .decode_utf8()
        .map_err(|_| anyhow!("invalid utf-8 in redis+unix path"))?;
    Ok(PathBuf::from_str(decoded.as_ref())?)
}

fn encode_command(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(format!("*{}\r\n", parts.len()).as_bytes());
    for part in parts {
        out.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        out.extend_from_slice(part);
        out.extend_from_slice(b"\r\n");
    }
    out
}

async fn read_simple_ok(stream: &mut (dyn IoStream + '_), timeout_dur: Duration) -> Result<()> {
    let line = read_line(stream, timeout_dur).await?;
    if line == b"+OK" {
        return Ok(());
    }
    if let Some(err) = line.strip_prefix(b"-") {
        return Err(anyhow!("redis error: {}", String::from_utf8_lossy(err)));
    }
    Err(anyhow!(
        "unexpected redis response: {}",
        String::from_utf8_lossy(&line)
    ))
}

async fn read_bulk_string(
    stream: &mut (dyn IoStream + '_),
    timeout_dur: Duration,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let line = read_line(stream, timeout_dur).await?;
    if line == b"$-1" {
        return Ok(None);
    }
    let len_str = line
        .strip_prefix(b"$")
        .ok_or_else(|| anyhow!("invalid redis bulk response"))?;
    let len: usize = std::str::from_utf8(len_str)?.parse()?;
    if len > max_bytes {
        return Err(anyhow!(
            "redis cache get payload too large: {} > {}",
            len,
            max_bytes
        ));
    }
    let mut payload = vec![0u8; len + 2];
    timeout(timeout_dur, stream.read_exact(&mut payload)).await??;
    if &payload[len..] != b"\r\n" {
        return Err(anyhow!("invalid redis bulk terminator"));
    }
    payload.truncate(len);
    Ok(Some(payload))
}

async fn read_line(stream: &mut (dyn IoStream + '_), timeout_dur: Duration) -> Result<Vec<u8>> {
    timeout(timeout_dur, async {
        let mut line = Vec::with_capacity(64);
        loop {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await?;
            line.push(b[0]);
            if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
                line.truncate(line.len() - 2);
                return Ok(line);
            }
            if line.len() > 8192 {
                return Err(anyhow!("redis line too long"));
            }
        }
    })
    .await?
}

async fn read_integer(stream: &mut (dyn IoStream + '_), timeout_dur: Duration) -> Result<i64> {
    let line = read_line(stream, timeout_dur).await?;
    if let Some(err) = line.strip_prefix(b"-") {
        return Err(anyhow!("redis error: {}", String::from_utf8_lossy(err)));
    }
    let value = line
        .strip_prefix(b":")
        .ok_or_else(|| anyhow!("invalid redis integer response"))?;
    Ok(std::str::from_utf8(value)?.parse::<i64>()?)
}

#[cfg(test)]
mod tests {
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
        let backend =
            RedisCacheBackend::new(cfg("redis://cache.internal:6380/2")).expect("backend");
        assert!(matches!(backend.transport, RedisTransport::Tcp { .. }));
        assert_eq!(backend.db, Some(2));
        assert!(backend.tls_domain.is_none());
    }

    #[test]
    fn parse_rediss_enables_tls() {
        let backend =
            RedisCacheBackend::new(cfg("rediss://cache.internal:6380/5")).expect("backend");
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
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = server.write_all(b"$5\r\nhello\r\n").await;
        });
        let err = read_bulk_string(&mut client, Duration::from_secs(1), 4)
            .await
            .expect_err("must fail");
        assert!(err.to_string().contains("payload too large"));
    }
}
