use lru::LruCache;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "digest-auth")]
use super::digest::sha256_hex;

#[derive(Debug, Clone)]
pub(super) struct LdapCache {
    ttl: Duration,
    shards: Arc<[Mutex<LdapCacheInner>]>,
}

#[derive(Debug, Clone)]
struct LdapCacheInner {
    entries: LruCache<String, LdapCacheEntry>,
    last_prune: Instant,
}

#[derive(Debug, Clone)]
struct LdapCacheEntry {
    groups: Vec<String>,
    created: Instant,
}

impl LdapCache {
    const DEFAULT_MAX_ENTRIES: usize = 16_384;
    const SHARDS: usize = 16;

    pub(super) fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    #[cfg(test)]
    pub(super) fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        let shard_count = Self::SHARDS.min(max_entries.max(1));
        let per_shard = (max_entries.max(1) / shard_count).max(1);
        Self {
            ttl,
            shards: build_shards(shard_count, per_shard),
        }
    }

    #[cfg(not(test))]
    fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        let shard_count = Self::SHARDS.min(max_entries.max(1));
        let per_shard = (max_entries.max(1) / shard_count).max(1);
        Self {
            ttl,
            shards: build_shards(shard_count, per_shard),
        }
    }

    pub(super) fn get(&self, username: &str, password: &str) -> Option<Vec<String>> {
        let key = cache_key(username, password);
        let mut guard = self.shards[shard_for(&key, self.shards.len())]
            .lock()
            .ok()?;
        let now = Instant::now();
        guard.prune_if_due(now, self.ttl);
        let expired = guard
            .entries
            .get(&key)
            .map(|entry| now.duration_since(entry.created) >= self.ttl)?;
        if expired {
            guard.entries.pop(&key);
            return None;
        }
        guard.entries.get(&key).map(|entry| entry.groups.clone())
    }

    pub(super) fn put(&self, username: &str, password: &str, groups: Vec<String>) {
        let key = cache_key(username, password);
        if let Ok(mut guard) = self.shards[shard_for(&key, self.shards.len())].lock() {
            let now = Instant::now();
            guard.prune(now, self.ttl);
            guard.entries.put(
                key,
                LdapCacheEntry {
                    groups,
                    created: now,
                },
            );
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().expect("ldap cache mutex").entries.len())
            .sum()
    }
}

impl LdapCacheInner {
    fn prune_if_due(&mut self, now: Instant, ttl: Duration) {
        let interval = if ttl <= Duration::from_secs(1) {
            ttl
        } else {
            ttl.div_f64(4.0)
                .clamp(Duration::from_secs(1), Duration::from_secs(60))
        };
        if now.duration_since(self.last_prune) >= interval {
            self.prune(now, ttl);
        }
    }

    fn prune(&mut self, now: Instant, ttl: Duration) {
        while self
            .entries
            .peek_lru()
            .is_some_and(|(_, entry)| now.duration_since(entry.created) >= ttl)
        {
            let _ = self.entries.pop_lru();
        }
        self.last_prune = now;
    }
}

fn cache_key(username: &str, password: &str) -> String {
    format!(
        "{}:{}",
        username,
        password_cache_hash_hex(password.as_bytes())
    )
}

fn build_shards(shards: usize, per_shard: usize) -> Arc<[Mutex<LdapCacheInner>]> {
    let mut inners = Vec::with_capacity(shards.max(1));
    for _ in 0..shards.max(1) {
        inners.push(Mutex::new(LdapCacheInner {
            entries: LruCache::new(nonzero_capacity(per_shard)),
            last_prune: Instant::now(),
        }));
    }
    inners.into()
}

fn nonzero_capacity(value: usize) -> NonZeroUsize {
    match NonZeroUsize::new(value.max(1)) {
        Some(capacity) => capacity,
        None => unreachable!("usize::max(1) is always non-zero"),
    }
}

fn shard_for<T: Hash + ?Sized>(value: &T, shards: usize) -> usize {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % shards.max(1)
}

#[cfg(feature = "digest-auth")]
fn password_cache_hash_hex(input: &[u8]) -> String {
    sha256_hex(input)
}

#[cfg(not(feature = "digest-auth"))]
fn password_cache_hash_hex(input: &[u8]) -> String {
    use std::hash::{Hash as _, Hasher as _};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
