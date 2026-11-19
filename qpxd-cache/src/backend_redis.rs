use super::types::CachedBodyStream;
use super::{CacheBackend, CachedBody, CommitLease};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use qpx_core::config::CacheBackendConfig;
use qpx_http::body::Body;
use qpx_http::protocol::address::format_authority_host_port;
use qpx_http::tls::builder::connect_client_http1;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(unix)]
use std::{path::PathBuf, str::FromStr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore};
use tokio::time::{Duration, timeout};
use url::Url;

type DynStream = qpx_http::tls::builder::BoxTlsStream;
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

/// Shared connection/config state used by both data operations and leases.
pub(super) struct RedisClient {
    transport: RedisTransport,
    tls_domain: Option<String>,
    db: Option<u32>,
    password: Option<String>,
    timeout: Duration,
    writer_lease_ttl: Duration,
    idle: Arc<AsyncMutex<Vec<RedisConnection>>>,
}

pub struct RedisCacheBackend {
    client: Arc<RedisClient>,
    key_prefix: String,
    max_object_bytes: usize,
    active: Arc<Semaphore>,
}

impl RedisCacheBackend {
    pub fn new(cfg: CacheBackendConfig) -> Result<Self> {
        if cfg.writer_mode == qpx_core::config::CacheWriterMode::Shared {
            return Err(anyhow!(
                "writer_mode shared is supported only by the disk backend on Unix"
            ));
        }
        if cfg.writer_lease_ttl_ms == 0 {
            return Err(anyhow!("writer_lease_ttl_ms must be greater than zero"));
        }
        let endpoint = cfg.endpoint.trim();
        let spec = parse_endpoint(endpoint)?;

        Ok(Self {
            client: Arc::new(RedisClient {
                transport: spec.transport,
                tls_domain: spec.tls_domain,
                db: spec.db,
                password: spec.password,
                timeout: Duration::from_millis(cfg.timeout_ms),
                writer_lease_ttl: Duration::from_millis(cfg.writer_lease_ttl_ms),
                idle: Arc::new(AsyncMutex::new(Vec::new())),
            }),
            key_prefix: cfg.name,
            max_object_bytes: cfg.max_object_bytes,
            active: Arc::new(Semaphore::new(REDIS_CACHE_MAX_ACTIVE_OPERATIONS)),
        })
    }

    fn full_key(&self, namespace: &str, key: &str) -> String {
        format!("qpx:{}:{}:{}", self.key_prefix, namespace, key)
    }
}

impl RedisClient {
    fn max_object_bytes_for_lease(&self) -> usize {
        8 * 1024
    }

    async fn open(&self) -> Result<RedisConnection> {
        let stream: DynStream = match &self.transport {
            RedisTransport::Tcp { addr } => {
                let tcp = timeout(self.timeout, TcpStream::connect(addr)).await??;
                if let Some(domain) = self.tls_domain.as_deref() {
                    timeout(self.timeout, connect_client_http1(domain, tcp, true, None))
                        .await??
                        .0
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

/// A namespace-wide writer lease backed by Redis `SET NX PX` and an atomic
/// compare-and-delete. The bounded expiry prevents a crashed writer from
/// blocking the fleet forever; publication re-checks ownership before its
/// critical section, and release is always fenced by the holder token.
struct RedisCommitLease {
    client: Arc<RedisClient>,
    key: String,
    token: String,
    ttl: Duration,
    released: AtomicBool,
    revoked: Arc<AtomicBool>,
    stop: Arc<Notify>,
}

impl RedisCommitLease {
    async fn acquire(client: Arc<RedisClient>, namespace: &str) -> Result<Self> {
        let token = format!("{}:{}", std::process::id(), uuid::Uuid::new_v4());
        let key = format!("qpx:writer-lock:{}", namespace);
        // Own the cleanup token before sending the conditional create, so a
        // lost reply or a cancelled future can still release this exact lease.
        let candidate = Self {
            client: client.clone(),
            key: key.clone(),
            token: token.clone(),
            ttl: client.writer_lease_ttl,
            released: AtomicBool::new(false),
            revoked: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(Notify::new()),
        };
        // Process-local commits are already serialized by commit::lock. Only a
        // genuinely held cross-client lease should make an operation wait.
        let deadline = std::time::Instant::now() + client.timeout.max(Duration::from_millis(250));
        loop {
            let mut stream = client.checkout().await?;
            let cmd = encode_command(&[
                b"SET".to_vec(),
                key.clone().into_bytes(),
                token.clone().into_bytes(),
                b"NX".to_vec(),
                b"PX".to_vec(),
                client.writer_lease_ttl.as_millis().to_string().into_bytes(),
            ]);
            let result = async {
                timeout(client.timeout, stream.stream.write_all(&cmd)).await??;
                read_set_nx(&mut stream, client.timeout).await
            }
            .await;
            if result.is_ok() {
                client.recycle(stream).await;
            }
            let created = match result {
                Ok(created) => created,
                Err(err) => {
                    // SET NX may have succeeded before the reply was lost.
                    let _ = candidate.release().await;
                    return Err(err);
                }
            };
            if created {
                candidate.start_heartbeat();
                return Ok(candidate);
            }
            if std::time::Instant::now() >= deadline {
                let err = anyhow!(
                    "redis cache namespace {} already has an active writer (lock key {})",
                    namespace,
                    key
                );
                let _ = candidate.release().await;
                return Err(err);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

async fn release_redis_lease(client: Arc<RedisClient>, key: String, token: String) -> Result<()> {
    // Ownership is checked inside Redis: an expired/replaced token can never
    // release a lease belonging to a different client.
    const RELEASE: &[u8] = b"if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end";
    let cmd = encode_command(&[
        b"EVAL".to_vec(),
        RELEASE.to_vec(),
        b"1".to_vec(),
        key.into_bytes(),
        token.into_bytes(),
    ]);
    let mut stream = client.checkout().await?;
    let result = async {
        timeout(client.timeout, stream.stream.write_all(&cmd)).await??;
        read_integer(&mut stream, client.timeout).await?;
        Ok(())
    }
    .await;
    if result.is_ok() {
        client.recycle(stream).await;
    }
    result
}

impl RedisCommitLease {
    fn start_heartbeat(&self) {
        let client = self.client.clone();
        let key = self.key.clone();
        let token = self.token.clone();
        let ttl = self.ttl;
        let revoked = self.revoked.clone();
        let stop = self.stop.clone();
        tokio::spawn(async move {
            let interval = (ttl / 3).max(Duration::from_millis(10));
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        if renew_redis_lease(&client, &key, &token, ttl).await.is_err() {
                            revoked.store(true, Ordering::Release);
                            break;
                        }
                    }
                    _ = stop.notified() => break,
                }
            }
        });
    }
}

async fn renew_redis_lease(
    client: &Arc<RedisClient>,
    key: &str,
    token: &str,
    ttl: Duration,
) -> Result<()> {
    // A renewal can only extend the caller's own token. A reclaimed token
    // cannot be revived, so a lost lease is never silently resurrected.
    const RENEW: &[u8] = b"if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end";
    let cmd = encode_command(&[
        b"EVAL".to_vec(),
        RENEW.to_vec(),
        b"1".to_vec(),
        key.as_bytes().to_vec(),
        token.as_bytes().to_vec(),
        ttl.as_millis().to_string().into_bytes(),
    ]);
    let mut stream = client.checkout().await?;
    let result = async {
        timeout(client.timeout, stream.stream.write_all(&cmd)).await??;
        let renewed = read_integer(&mut stream, client.timeout).await?;
        if renewed == 1 {
            Ok(())
        } else {
            Err(anyhow!(
                "redis cache writer lease for {} was not renewed (script returned {})",
                token,
                renewed
            ))
        }
    }
    .await;
    if result.is_ok() {
        client.recycle(stream).await;
    }
    result
}

#[async_trait]
impl CommitLease for RedisCommitLease {
    fn fence_token(&self) -> Option<&str> {
        Some(&self.token)
    }

    fn fence_key(&self) -> Option<&str> {
        Some(&self.key)
    }

    async fn release(&self) -> Result<()> {
        self.stop.notify_one();
        release_redis_lease(self.client.clone(), self.key.clone(), self.token.clone()).await?;
        self.released.store(true, Ordering::Release);
        Ok(())
    }

    async fn validate(&self) -> Result<()> {
        if self.revoked.load(Ordering::Acquire) {
            return Err(anyhow!(
                "redis cache writer lease for {} was not renewed and is no longer held",
                self.token
            ));
        }
        let cmd = encode_command(&[b"GET".to_vec(), self.key.clone().into_bytes()]);
        let mut stream = self.client.checkout().await?;
        let result = async {
            timeout(self.client.timeout, stream.stream.write_all(&cmd)).await??;
            read_bulk_string(
                &mut stream,
                self.client.timeout,
                self.client.max_object_bytes_for_lease(),
            )
            .await
        }
        .await;
        if result.is_ok() {
            self.client.recycle(stream).await;
        }
        let current = result?;
        if current.as_deref() == Some(self.token.as_bytes()) {
            return Ok(());
        }
        Err(anyhow!(
            "redis cache writer lease for {} is no longer held (lock key {})",
            self.token,
            self.key
        ))
    }
}

impl Drop for RedisCommitLease {
    fn drop(&mut self) {
        if self.released.load(Ordering::Acquire) {
            return;
        }
        self.stop.notify_one();
        // Cancellation happens in an async context, so cannot block on I/O.
        // A detached compare-and-delete is safe and idempotent.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let client = self.client.clone();
            let key = self.key.clone();
            let token = self.token.clone();
            handle.spawn(async move {
                let _ = release_redis_lease(client, key, token).await;
            });
        }
    }
}

/// Atomically applies a mutation only while the writer-lease key still holds
/// the caller's token. Validation and publication are one Redis script, so a
/// lease lost between them cannot overwrite the successor's state.
struct FencedMutation<'a> {
    script: &'a [u8],
    namespace: &'a str,
    key: &'a str,
    token: &'a str,
    fence_key: &'a str,
    value: Option<&'a [u8]>,
    ttl_secs: Option<u64>,
}

async fn fenced_redis_mutation(
    backend: &RedisCacheBackend,
    mutation: FencedMutation<'_>,
) -> Result<()> {
    let _permit = backend
        .active
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
    let mut parts = vec![
        b"EVAL".to_vec(),
        mutation.script.to_vec(),
        b"2".to_vec(),
        mutation.fence_key.as_bytes().to_vec(),
        backend
            .full_key(mutation.namespace, mutation.key)
            .into_bytes(),
        mutation.token.as_bytes().to_vec(),
    ];
    if let Some(value) = mutation.value {
        parts.push(value.to_vec());
    }
    if let Some(ttl_secs) = mutation.ttl_secs {
        parts.push(ttl_secs.to_string().into_bytes());
    }
    let cmd = encode_command(&parts);
    let mut stream = backend.client.checkout().await?;
    let result = async {
        timeout(backend.client.timeout, stream.stream.write_all(&cmd)).await??;
        let applied = read_integer(&mut stream, backend.client.timeout).await?;
        if applied == 1 {
            Ok(())
        } else {
            Err(anyhow!(
                "redis cache writer lease {} was lost before the authoritative mutation (script returned {})",
                mutation.token,
                applied
            ))
        }
    }
    .await;
    if result.is_ok() {
        backend.client.recycle(stream).await;
    }
    result
}

#[async_trait]
impl CacheBackend for RedisCacheBackend {
    async fn lock_commit(
        &self,
        namespace: &str,
        _primary: &str,
    ) -> Result<Option<Arc<dyn CommitLease>>> {
        // The lease is namespace-wide: every writer of the same remote
        // namespace, including a differently named backend, must contend.
        Ok(Some(Arc::new(
            RedisCommitLease::acquire(self.client.clone(), namespace).await?,
        )))
    }

    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Bytes>> {
        let _permit = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("redis cache backend operation limiter closed"))?;
        let mut stream = self.client.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[b"GET".to_vec(), full_key.into_bytes()]);
        let result = async {
            timeout(self.client.timeout, stream.stream.write_all(&cmd)).await??;
            read_bulk_string(&mut stream, self.client.timeout, self.max_object_bytes).await
        }
        .await;
        if result.is_ok() {
            self.client.recycle(stream).await;
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
        let mut stream = self.client.checkout().await?;
        let mut parts = Vec::with_capacity(keys.len() + 1);
        parts.push(b"MGET".to_vec());
        parts.extend(
            keys.iter()
                .map(|key| self.full_key(namespace, key).into_bytes()),
        );
        let cmd = encode_command(&parts);
        let result = async {
            timeout(self.client.timeout, stream.stream.write_all(&cmd)).await??;
            read_bulk_string_array(
                &mut stream,
                self.client.timeout,
                keys.len(),
                self.max_object_bytes,
            )
            .await
        }
        .await;
        if result.is_ok() {
            self.client.recycle(stream).await;
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
        let mut stream = self.client.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[b"GET".to_vec(), full_key.into_bytes()]);
        let result = async {
            timeout(self.client.timeout, stream.stream.write_all(&cmd)).await??;
            read_bulk_cached_body(&mut stream, self.client.timeout, self.max_object_bytes).await
        }
        .await;
        if result.is_ok() {
            self.client.recycle(stream).await;
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
        let mut stream = self.client.checkout().await?;
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
                timeout(self.client.timeout, stream.stream.write_all(&cmd)).await??;
            }
            None => {
                let cmd = encode_command(&[b"GET".to_vec(), full_key.into_bytes()]);
                timeout(self.client.timeout, stream.stream.write_all(&cmd)).await??;
            }
        }

        let Some(len) =
            read_bulk_len(&mut stream, self.client.timeout, self.max_object_bytes).await?
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
        let idle = self.client.idle.clone();
        let timeout_dur = self.client.timeout;
        let (done, producer_done) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = stream_redis_bulk_to_body(stream, timeout_dur, len, tx).await;
            if let Ok(stream) = result {
                recycle_stream(idle, stream).await;
            }
            drop(permit);
            let _ = done.send(());
        });

        Ok(Some(CachedBodyStream::from_producer_for_backend(
            expected_stream_len,
            body,
            producer_done,
        )))
    }

    async fn put_fenced(
        &self,
        namespace: &str,
        key: &str,
        value: &[u8],
        ttl_secs: u64,
        token: Option<&str>,
        fence_key: Option<&str>,
    ) -> Result<()> {
        const SCRIPT: &[u8] = b"-- qpx:fenced-put\nif redis.call('get', KEYS[1]) == ARGV[1] then redis.call('set', KEYS[2], ARGV[2], 'EX', ARGV[3]) return 1 else return 0 end";
        let (token, fence_key) = match (token, fence_key) {
            (Some(token), Some(fence_key)) => (token, fence_key),
            _ => {
                return Err(anyhow!(
                    "redis cache fenced put requires the current writer lease"
                ));
            }
        };
        if value.len() > self.max_object_bytes {
            return Err(anyhow!(
                "redis cache put payload too large: {} > {}",
                value.len(),
                self.max_object_bytes
            ));
        }
        fenced_redis_mutation(
            self,
            FencedMutation {
                script: SCRIPT,
                namespace,
                key,
                token,
                fence_key,
                value: Some(value),
                ttl_secs: Some(ttl_secs),
            },
        )
        .await
    }

    async fn retire_fenced(
        &self,
        namespace: &str,
        key: &str,
        token: Option<&str>,
        fence_key: Option<&str>,
    ) -> Result<()> {
        self.delete_fenced(namespace, key, token, fence_key).await
    }

    async fn delete_fenced(
        &self,
        namespace: &str,
        key: &str,
        token: Option<&str>,
        fence_key: Option<&str>,
    ) -> Result<()> {
        const SCRIPT: &[u8] = b"-- qpx:fenced-delete\nif redis.call('get', KEYS[1]) == ARGV[1] then redis.call('del', KEYS[2]) return 1 else return 0 end";
        let (token, fence_key) = match (token, fence_key) {
            (Some(token), Some(fence_key)) => (token, fence_key),
            _ => {
                return Err(anyhow!(
                    "redis cache fenced delete requires the current writer lease"
                ));
            }
        };
        fenced_redis_mutation(
            self,
            FencedMutation {
                script: SCRIPT,
                namespace,
                key,
                token,
                fence_key,
                value: None,
                ttl_secs: None,
            },
        )
        .await
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
        let mut stream = self.client.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[
            b"SET".to_vec(),
            full_key.into_bytes(),
            value.to_vec(),
            b"EX".to_vec(),
            ttl_secs.to_string().into_bytes(),
        ]);
        let result = async {
            timeout(self.client.timeout, stream.stream.write_all(&cmd)).await??;
            read_simple_ok(&mut stream, self.client.timeout).await
        }
        .await;
        if result.is_ok() {
            self.client.recycle(stream).await;
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
        let mut stream = self.client.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let result = async {
            write_set_cached_body(
                &mut stream,
                self.client.timeout,
                full_key.as_bytes(),
                body,
                ttl_secs,
            )
            .await?;
            read_simple_ok(&mut stream, self.client.timeout).await
        }
        .await;
        if result.is_ok() {
            self.client.recycle(stream).await;
        }
        result
    }

    async fn put_object_stream(
        &self,
        namespace: &str,
        key: &str,
        mut body: qpx_http::body::Body,
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
        let mut stream = self.client.checkout().await?;
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
            timeout(self.client.timeout, stream.stream.write_all(&init)).await??;
            read_simple_ok(&mut stream, self.client.timeout).await?;

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
                        self.client.timeout,
                        b"APPEND",
                        tmp_key.as_bytes(),
                        chunk.as_ref(),
                    )
                    .await?;
                    pending_appends.push_back(size);
                    if pending_appends.len() >= REDIS_APPEND_PIPELINE_WINDOW {
                        validate_next_append_reply(
                            &mut stream,
                            self.client.timeout,
                            &mut pending_appends,
                        )
                        .await?;
                    }
                }
            }
            while !pending_appends.is_empty() {
                validate_next_append_reply(&mut stream, self.client.timeout, &mut pending_appends)
                    .await?;
            }

            let rename = encode_command(&[
                b"RENAME".to_vec(),
                tmp_key.as_bytes().to_vec(),
                full_key.as_bytes().to_vec(),
            ]);
            timeout(self.client.timeout, stream.stream.write_all(&rename)).await??;
            read_simple_ok(&mut stream, self.client.timeout).await?;
            Ok(size as u64)
        }
        .await;
        if result.is_ok() {
            self.client.recycle(stream).await;
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
        let mut stream = self.client.checkout().await?;
        let full_key = self.full_key(namespace, key);
        let cmd = encode_command(&[b"DEL".to_vec(), full_key.into_bytes()]);
        let result = async {
            timeout(self.client.timeout, stream.stream.write_all(&cmd)).await??;
            read_integer(&mut stream, self.client.timeout).await?;
            Ok(())
        }
        .await;
        if result.is_ok() {
            self.client.recycle(stream).await;
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
