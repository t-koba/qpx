use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::sync::{Mutex, Semaphore};

pub(super) type UpstreamProxySender = crate::http::protocol::common::Http1SendRequest;

static UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT: AtomicUsize = AtomicUsize::new(8);

pub(crate) fn set_upstream_proxy_max_concurrent_per_endpoint(value: usize) {
    UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT.store(value.max(1), Ordering::Relaxed);
}

fn upstream_proxy_max_concurrent_per_endpoint() -> usize {
    UPSTREAM_PROXY_MAX_CONCURRENT_PER_ENDPOINT
        .load(Ordering::Relaxed)
        .max(1)
}

pub(super) struct UpstreamProxySlot {
    pub(super) senders: Mutex<Vec<UpstreamProxySender>>,
    pub(super) semaphore: Arc<Semaphore>,
}

type UpstreamProxySlotHandle = Arc<UpstreamProxySlot>;
type UpstreamProxyMap = HashMap<String, UpstreamProxySlotHandle>;
pub(super) struct UpstreamProxyPool {
    shards: Vec<Mutex<UpstreamProxyMap>>,
}

pub(super) fn upstream_proxy_pool() -> &'static UpstreamProxyPool {
    static POOL: OnceLock<UpstreamProxyPool> = OnceLock::new();
    POOL.get_or_init(|| UpstreamProxyPool::new(64))
}

impl UpstreamProxyPool {
    fn new(shards: usize) -> Self {
        let shards = shards.max(1);
        let mut out = Vec::with_capacity(shards);
        for _ in 0..shards {
            out.push(Mutex::new(HashMap::new()));
        }
        Self { shards: out }
    }

    fn shard_for(&self, key: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len().max(1)
    }

    pub(super) async fn slot_for(&self, key: &str) -> UpstreamProxySlotHandle {
        let shard = self.shard_for(key);
        let mut guard = self.shards[shard].lock().await;
        guard
            .entry(key.to_string())
            .or_insert_with(|| {
                Arc::new(UpstreamProxySlot {
                    senders: Mutex::new(Vec::new()),
                    semaphore: Arc::new(Semaphore::new(
                        upstream_proxy_max_concurrent_per_endpoint(),
                    )),
                })
            })
            .clone()
    }
}
