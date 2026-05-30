use super::types::CachedBodyStream;
use super::{CacheBackend, CachedBody};
use crate::http::body::Body;
use crate::http::protocol::address::format_authority_host_port;
use crate::tls::client::connect_tls_http1;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use qpx_core::config::CacheBackendConfig;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::{path::PathBuf, str::FromStr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::time::{Duration, timeout};
use url::Url;

type DynStream = crate::tls::client::BoxTlsStream;
const REDIS_CACHE_MAX_IDLE_CONNECTIONS: usize = 8;
const REDIS_CACHE_MAX_ACTIVE_OPERATIONS: usize = 32;
const REDIS_APPEND_PIPELINE_WINDOW: usize = 16;
static REDIS_STREAM_PUT_COUNTER: AtomicU64 = AtomicU64::new(1);

struct RedisConnection {
    stream: DynStream,
    read_buf: BytesMut,
}

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
    idle: Arc<AsyncMutex<Vec<RedisConnection>>>,
    active: Arc<Semaphore>,
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
            idle: Arc::new(AsyncMutex::new(Vec::new())),
            active: Arc::new(Semaphore::new(REDIS_CACHE_MAX_ACTIVE_OPERATIONS)),
        })
    }

    fn full_key(&self, namespace: &str, key: &str) -> String {
        format!("qpx:{}:{}:{}", self.key_prefix, namespace, key)
    }

    async fn open(&self) -> Result<RedisConnection> {
        let stream: DynStream = match &self.transport {
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

        let mut conn = RedisConnection {
            stream,
            read_buf: BytesMut::with_capacity(4096),
        };

        if let Some(password) = self.password.as_deref() {
            let auth = encode_command(&[b"AUTH".to_vec(), password.as_bytes().to_vec()]);
            timeout(self.timeout, conn.stream.write_all(&auth)).await??;
            read_simple_ok(&mut conn, self.timeout).await?;
        }

        if let Some(db) = self.db {
            let select = encode_command(&[b"SELECT".to_vec(), db.to_string().into_bytes()]);
            timeout(self.timeout, conn.stream.write_all(&select)).await??;
            read_simple_ok(&mut conn, self.timeout).await?;
        }

        Ok(conn)
    }

    async fn checkout(&self) -> Result<RedisConnection> {
        if let Some(stream) = self.idle.lock().await.pop() {
            return Ok(stream);
        }
        self.open().await
    }

    async fn recycle(&self, stream: RedisConnection) {
        recycle_stream(self.idle.clone(), stream).await;
    }
}

#[async_trait]
impl CacheBackend for RedisCacheBackend {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Bytes>> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        let mut stream = self.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[b"GET".to_vec(), full_key.into_bytes()]);
        let result = async {
            timeout(self.timeout, stream.stream.write_all(&cmd)).await??;
            read_bulk_string(&mut stream, self.timeout, self.max_object_bytes).await
        }
        .await;
        if result.is_ok() {
            self.recycle(stream).await;
        }
        result
    }

    async fn get_many(&self, namespace: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        let mut stream = self.checkout().await?;
        let mut parts = Vec::with_capacity(keys.len() + 1);
        parts.push(b"MGET".to_vec());
        parts.extend(
            keys.iter()
                .map(|key| self.full_key(namespace, key).into_bytes()),
        );
        let cmd = encode_command(&parts);
        let result = async {
            timeout(self.timeout, stream.stream.write_all(&cmd)).await??;
            read_bulk_string_array(&mut stream, self.timeout, keys.len(), self.max_object_bytes)
                .await
        }
        .await;
        if result.is_ok() {
            self.recycle(stream).await;
        }
        result
    }

    async fn get_object(&self, namespace: &str, key: &str) -> Result<Option<CachedBody>> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        let mut stream = self.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[b"GET".to_vec(), full_key.into_bytes()]);
        let result = async {
            timeout(self.timeout, stream.stream.write_all(&cmd)).await??;
            read_bulk_cached_body(&mut stream, self.timeout, self.max_object_bytes).await
        }
        .await;
        if result.is_ok() {
            self.recycle(stream).await;
        }
        result
    }

    async fn get_object_stream(
        &self,
        namespace: &str,
        key: &str,
        expected_len: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        let permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        let mut stream = self.checkout().await?;
        let full_key = self.full_key(namespace, key);
        match range {
            Some((start, end)) => {
                let start_arg = start.to_string();
                let end_arg = end.to_string();
                let cmd = encode_command(&[
                    b"GETRANGE".to_vec(),
                    full_key.into_bytes(),
                    start_arg.into_bytes(),
                    end_arg.into_bytes(),
                ]);
                timeout(self.timeout, stream.stream.write_all(&cmd)).await??;
            }
            None => {
                let cmd = encode_command(&[b"GET".to_vec(), full_key.into_bytes()]);
                timeout(self.timeout, stream.stream.write_all(&cmd)).await??;
            }
        }

        let Some(len) = read_bulk_len(&mut stream, self.timeout, self.max_object_bytes).await?
        else {
            return Ok(None);
        };
        let expected_stream_len = range
            .map(|(start, end)| end.saturating_sub(start).saturating_add(1))
            .unwrap_or(expected_len);
        if len as u64 != expected_stream_len {
            return Ok(None);
        }

        let (tx, body) = Body::channel_with_capacity(16);
        let idle = self.idle.clone();
        let timeout_dur = self.timeout;
        tokio::spawn(async move {
            let result = stream_redis_bulk_to_body(stream, timeout_dur, len, tx).await;
            if let Ok(stream) = result {
                recycle_stream(idle, stream).await;
            }
            drop(permit);
        });

        Ok(Some(CachedBodyStream {
            len: expected_stream_len,
            body,
        }))
    }

    async fn put(&self, namespace: &str, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        if value.len() > self.max_object_bytes {
            return Err(anyhow!(
                "redis cache put payload too large: {} > {}",
                value.len(),
                self.max_object_bytes
            ));
        }
        let mut stream = self.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[
            b"SET".to_vec(),
            full_key.into_bytes(),
            value.to_vec(),
            b"EX".to_vec(),
            ttl_secs.to_string().into_bytes(),
        ]);
        let result = async {
            timeout(self.timeout, stream.stream.write_all(&cmd)).await??;
            read_simple_ok(&mut stream, self.timeout).await
        }
        .await;
        if result.is_ok() {
            self.recycle(stream).await;
        }
        result
    }

    async fn put_object(
        &self,
        namespace: &str,
        key: &str,
        body: &CachedBody,
        ttl_secs: u64,
    ) -> Result<()> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        if body.len() > self.max_object_bytes as u64 {
            return Err(anyhow!(
                "redis cache put payload too large: {} > {}",
                body.len(),
                self.max_object_bytes
            ));
        }
        let mut stream = self.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let result = async {
            write_set_cached_body(
                &mut stream,
                self.timeout,
                full_key.as_bytes(),
                body,
                ttl_secs,
            )
            .await?;
            read_simple_ok(&mut stream, self.timeout).await
        }
        .await;
        if result.is_ok() {
            self.recycle(stream).await;
        }
        result
    }

    async fn put_object_stream(
        &self,
        namespace: &str,
        key: &str,
        mut body: crate::http::body::Body,
        max_body_bytes: usize,
        body_read_timeout: Duration,
        ttl_secs: u64,
    ) -> Result<u64> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        let max_body_bytes = max_body_bytes.min(self.max_object_bytes);
        let mut stream = self.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let tmp_id = REDIS_STREAM_PUT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_key = format!("{full_key}:tmp:{tmp_id}");
        let result = async {
            let init = encode_command(&[
                b"SET".to_vec(),
                tmp_key.as_bytes().to_vec(),
                Vec::new(),
                b"EX".to_vec(),
                ttl_secs.to_string().into_bytes(),
            ]);
            timeout(self.timeout, stream.stream.write_all(&init)).await??;
            read_simple_ok(&mut stream, self.timeout).await?;

            let mut size = 0usize;
            let mut pending_appends = VecDeque::new();
            while let Some(chunk) = timeout(body_read_timeout, body.data())
                .await
                .map_err(|_| anyhow!("cache object body read timed out"))?
            {
                let chunk = chunk?;
                let next = size
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow!("cache object length overflow"))?;
                if next > max_body_bytes {
                    return Err(anyhow!(
                        "cache object exceeds configured limit: {} bytes",
                        max_body_bytes
                    ));
                }
                size = next;
                if !chunk.is_empty() {
                    write_command3(
                        &mut stream,
                        self.timeout,
                        b"APPEND",
                        tmp_key.as_bytes(),
                        chunk.as_ref(),
                    )
                    .await?;
                    pending_appends.push_back(size);
                    if pending_appends.len() >= REDIS_APPEND_PIPELINE_WINDOW {
                        validate_next_append_reply(&mut stream, self.timeout, &mut pending_appends)
                            .await?;
                    }
                }
            }
            while !pending_appends.is_empty() {
                validate_next_append_reply(&mut stream, self.timeout, &mut pending_appends).await?;
            }

            let rename = encode_command(&[
                b"RENAME".to_vec(),
                tmp_key.as_bytes().to_vec(),
                full_key.as_bytes().to_vec(),
            ]);
            timeout(self.timeout, stream.stream.write_all(&rename)).await??;
            read_simple_ok(&mut stream, self.timeout).await?;
            Ok(size as u64)
        }
        .await;
        if result.is_ok() {
            self.recycle(stream).await;
        }
        result
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        let mut stream = self.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[b"DEL".to_vec(), full_key.into_bytes()]);
        let result = async {
            timeout(self.timeout, stream.stream.write_all(&cmd)).await??;
            read_integer(&mut stream, self.timeout).await?;
            Ok(())
        }
        .await;
        if result.is_ok() {
            self.recycle(stream).await;
        }
        result
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
    if !from_path.is_empty()
        && let Ok(db) = from_path.parse::<u32>()
    {
        return Some(db);
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

mod protocol;

use self::protocol::*;

#[cfg(test)]
mod tests;
