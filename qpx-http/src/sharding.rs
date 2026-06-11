//! Sharded keyed maps and hashing helpers shared across connection pools and caches.

use std::borrow::Borrow;
use std::collections::{HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::Mutex as StdMutex;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};

pub fn modulo<T: Hash + ?Sized>(key: &T, shards: usize) -> usize {
    hash_usize(key) % shards.max(1)
}

pub fn modulo_u64(key: u64, shards: usize) -> usize {
    (key as usize) % shards.max(1)
}

pub fn masked<T: Hash + ?Sized>(key: &T, mask: usize) -> usize {
    hash_usize(key) & mask
}

pub fn sync_mutex_shards<T>(shards: usize, mut init: impl FnMut() -> T) -> Vec<StdMutex<T>> {
    let shards = shards.max(1);
    (0..shards).map(|_| StdMutex::new(init())).collect()
}

pub fn async_mutex_shards<T>(shards: usize, mut init: impl FnMut() -> T) -> Vec<AsyncMutex<T>> {
    let shards = shards.max(1);
    (0..shards).map(|_| AsyncMutex::new(init())).collect()
}

pub struct AsyncShardMap<K, V> {
    shards: Vec<AsyncMutex<HashMap<K, V>>>,
}

impl<K, V> AsyncShardMap<K, V>
where
    K: Eq + Hash,
{
    pub fn new(shards: usize) -> Self {
        Self {
            shards: async_mutex_shards(shards, HashMap::new),
        }
    }

    pub async fn lock<Q>(&self, key: &Q) -> AsyncMutexGuard<'_, HashMap<K, V>>
    where
        K: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        let shard = modulo(key, self.shards.len());
        self.shards[shard].lock().await
    }

    #[cfg(test)]
    fn shard_count(&self) -> usize {
        self.shards.len()
    }
}

fn hash_usize<T: Hash + ?Sized>(key: &T) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish() as usize
}

#[cfg(test)]
mod tests {
    use super::{AsyncShardMap, async_mutex_shards, modulo_u64, sync_mutex_shards};

    #[test]
    fn modulo_u64_handles_empty_shard_count() {
        assert_eq!(modulo_u64(42, 0), 0);
    }

    #[test]
    fn modulo_u64_selects_expected_shard() {
        assert_eq!(modulo_u64(67, 64), 3);
    }

    #[test]
    fn mutex_shard_helpers_clamp_empty_counts() {
        assert_eq!(sync_mutex_shards(0, Vec::<u8>::new).len(), 1);
        assert_eq!(async_mutex_shards(0, Vec::<u8>::new).len(), 1);
    }

    #[tokio::test]
    async fn async_shard_map_clamps_and_locks_by_borrowed_key() {
        let map = AsyncShardMap::<String, usize>::new(0);
        assert_eq!(map.shard_count(), 1);
        map.lock("alpha").await.insert("alpha".to_string(), 7);
        assert_eq!(map.lock("alpha").await.get("alpha"), Some(&7));
    }
}
