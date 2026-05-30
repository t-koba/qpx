use super::backend::{IpcBackend, IpcStream};
use super::shm::IpcShmPair;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, OnceLock};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::{Duration, timeout};

const MAX_IDLE_CONNS_PER_BACKEND: usize = 8;
const MAX_ACTIVE_CONNS_PER_BACKEND: usize = 64;

pub(super) struct PooledIpcConnection {
    pub(super) stream: IpcStream,
    pub(super) shm: Option<IpcShmPair>,
    pub(super) active_permit: Option<OwnedSemaphorePermit>,
}

type PoolMap = HashMap<String, Vec<PooledIpcConnection>>;
struct Pool {
    shards: Vec<Mutex<PoolMap>>,
}
type ActiveLimiterMap = HashMap<String, Arc<Semaphore>>;
struct ActiveLimiters {
    shards: Vec<Mutex<ActiveLimiterMap>>,
}

fn ipc_pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(|| Pool::new(64))
}

fn ipc_active_limiters() -> &'static ActiveLimiters {
    static LIMITERS: OnceLock<ActiveLimiters> = OnceLock::new();
    LIMITERS.get_or_init(|| ActiveLimiters::new(64))
}

impl Pool {
    fn new(shards: usize) -> Self {
        let shards = shards.max(1);
        let mut out = Vec::with_capacity(shards);
        for _ in 0..shards {
            out.push(Mutex::new(HashMap::new()));
        }
        Self { shards: out }
    }

    fn shard_for(&self, key: &str) -> usize {
        shard_for_key(key, self.shards.len())
    }

    async fn pop(&self, key: &str) -> Option<PooledIpcConnection> {
        let mut guard = self.shards[self.shard_for(key)].lock().await;
        guard.get_mut(key).and_then(|v| v.pop())
    }

    async fn push(&self, key: String, conn: PooledIpcConnection) {
        let mut guard = self.shards[self.shard_for(&key)].lock().await;
        let entry = guard.entry(key).or_insert_with(Vec::new);
        if entry.len() < MAX_IDLE_CONNS_PER_BACKEND {
            entry.push(conn);
        }
    }
}

impl ActiveLimiters {
    fn new(shards: usize) -> Self {
        let shards = shards.max(1);
        let mut out = Vec::with_capacity(shards);
        for _ in 0..shards {
            out.push(Mutex::new(HashMap::new()));
        }
        Self { shards: out }
    }

    fn shard_for(&self, key: &str) -> usize {
        shard_for_key(key, self.shards.len())
    }

    async fn limiter(&self, key: &str) -> Arc<Semaphore> {
        let mut guard = self.shards[self.shard_for(key)].lock().await;
        guard
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_ACTIVE_CONNS_PER_BACKEND)))
            .clone()
    }
}

fn shard_for_key(key: &str, shards: usize) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % shards.max(1)
}

async fn ipc_active_limiter(key: &str) -> Arc<Semaphore> {
    ipc_active_limiters().limiter(key).await
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
    backend: &IpcBackend,
    timeout_dur: Duration,
) -> Result<(String, PooledIpcConnection)> {
    let key = backend.pool_key();
    let limiter = ipc_active_limiter(&key).await;
    let permit = timeout(timeout_dur, limiter.acquire_owned())
        .await
        .map_err(|_| anyhow!("IPC active connection limit wait timed out"))?
        .map_err(|_| anyhow!("IPC active connection limiter closed"))?;
    if let Some(mut stream) = ipc_pool().pop(&key).await {
        stream.active_permit = Some(permit);
        return Ok((key, stream));
    }
    let mut stream = connect_backend(backend, timeout_dur).await?;
    stream.active_permit = Some(permit);
    Ok((key, stream))
}

pub(super) async fn checkin_stream(key: String, mut conn: PooledIpcConnection) {
    let _permit = conn.active_permit.take();
    ipc_pool().push(key, conn).await;
}
