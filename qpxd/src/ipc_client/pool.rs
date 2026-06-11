use super::backend::{IpcBackend, IpcStream};
use super::shm::IpcShmPair;
use anyhow::{Result, anyhow};
use qpx_http::sharding::AsyncShardMap;
use std::sync::Arc;
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Duration, timeout};

const MAX_IDLE_CONNS_PER_BACKEND: usize = 8;
const MAX_ACTIVE_CONNS_PER_BACKEND: usize = 64;
const IPC_POOL_SHARDS: usize = 64;

pub(super) struct PooledIpcConnection {
    pub(super) stream: IpcStream,
    pub(super) shm: Option<IpcShmPair>,
    pub(super) active_permit: Option<OwnedSemaphorePermit>,
}

/// Per-runtime IPC connection pool: idle connections plus per-backend active limiters.
/// Owned by [`crate::pool::PoolRegistry`] (formerly process-global `OnceLock`s).
pub(crate) struct IpcConnectionPool {
    idle: AsyncShardMap<String, Vec<PooledIpcConnection>>,
    limiters: AsyncShardMap<String, Arc<Semaphore>>,
}

impl Default for IpcConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcConnectionPool {
    pub(crate) fn new() -> Self {
        Self {
            idle: AsyncShardMap::new(IPC_POOL_SHARDS),
            limiters: AsyncShardMap::new(IPC_POOL_SHARDS),
        }
    }

    async fn pop(&self, key: &str) -> Option<PooledIpcConnection> {
        self.idle.lock(key).await.get_mut(key).and_then(|v| v.pop())
    }

    async fn push(&self, key: String, conn: PooledIpcConnection) {
        let mut guard = self.idle.lock(&key).await;
        let entry = guard.entry(key).or_insert_with(Vec::new);
        if entry.len() < MAX_IDLE_CONNS_PER_BACKEND {
            entry.push(conn);
        }
    }

    async fn limiter(&self, key: &str) -> Arc<Semaphore> {
        let mut guard = self.limiters.lock(key).await;
        if let Some(limiter) = guard.get(key) {
            return limiter.clone();
        }
        let limiter = Arc::new(Semaphore::new(MAX_ACTIVE_CONNS_PER_BACKEND));
        guard.insert(key.to_string(), limiter.clone());
        limiter
    }
}

async fn connect_backend(
    backend: &IpcBackend,
    timeout_dur: Duration,
) -> Result<PooledIpcConnection> {
    match backend {
        IpcBackend::Tcp { host, port } => {
            let addr = format!("{}:{}", host, port);
            let stream = timeout(timeout_dur, TcpStream::connect(&addr))
                .await
                .map_err(|_| anyhow!("IPC connect timeout: {}", addr))??;
            let _ = stream.set_nodelay(true);
            Ok(PooledIpcConnection {
                stream: IpcStream::Tcp(stream),
                shm: None,
                active_permit: None,
            })
        }
        #[cfg(unix)]
        IpcBackend::Unix { path } => {
            let stream = timeout(timeout_dur, UnixStream::connect(path))
                .await
                .map_err(|_| anyhow!("IPC unix connect timeout: {}", path.display()))??;
            Ok(PooledIpcConnection {
                stream: IpcStream::Unix(stream),
                shm: None,
                active_permit: None,
            })
        }
    }
}

pub(super) async fn checkout_stream(
    pool: &IpcConnectionPool,
    backend: &IpcBackend,
    timeout_dur: Duration,
) -> Result<(String, PooledIpcConnection)> {
    let key = backend.pool_key();
    let limiter = pool.limiter(&key).await;
    let permit = timeout(timeout_dur, limiter.acquire_owned())
        .await
        .map_err(|_| anyhow!("IPC active connection limit wait timed out"))?
        .map_err(|_| anyhow!("IPC active connection limiter closed"))?;
    if let Some(mut stream) = pool.pop(&key).await {
        stream.active_permit = Some(permit);
        return Ok((key, stream));
    }
    let mut stream = connect_backend(backend, timeout_dur).await?;
    stream.active_permit = Some(permit);
    Ok((key, stream))
}

pub(super) async fn checkin_stream(
    pool: &IpcConnectionPool,
    key: String,
    mut conn: PooledIpcConnection,
) {
    let _permit = conn.active_permit.take();
    pool.push(key, conn).await;
}
