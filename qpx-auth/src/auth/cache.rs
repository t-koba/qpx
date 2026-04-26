use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "digest-auth")]
use super::digest::sha256_hex;

#[derive(Debug, Clone)]
pub(super) struct LdapCache {
    ttl: Duration,
    max_entries: usize,
    inner: Arc<Mutex<HashMap<String, LdapCacheEntry>>>,
}

#[derive(Debug, Clone)]
struct LdapCacheEntry {
    groups: Vec<String>,
    created: Instant,
}

impl LdapCache {
    const DEFAULT_MAX_ENTRIES: usize = 16_384;

    pub(super) fn new(ttl: Duration) -> Self {
        Self::with_max_entries(ttl, Self::DEFAULT_MAX_ENTRIES)
    }

    #[cfg(test)]
    pub(super) fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(not(test))]
    fn with_max_entries(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries: max_entries.max(1),
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(super) fn get(&self, username: &str, password: &str) -> Option<Vec<String>> {
        let key = cache_key(username, password);
        let mut guard = self.inner.lock().ok()?;
        let now = Instant::now();
        guard.retain(|_, e| now.duration_since(e.created) < self.ttl);
        guard.get(&key).map(|e| e.groups.clone())
    }

    pub(super) fn put(&self, username: &str, password: &str, groups: Vec<String>) {
        let key = cache_key(username, password);
        if let Ok(mut guard) = self.inner.lock() {
            let now = Instant::now();
            guard.retain(|_, entry| now.duration_since(entry.created) < self.ttl);
            while guard.len() >= self.max_entries {
                let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, entry)| entry.created)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                guard.remove(&oldest_key);
            }
            guard.insert(
                key,
                LdapCacheEntry {
                    groups,
                    created: Instant::now(),
                },
            );
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.inner.lock().expect("ldap cache mutex").len()
    }
}

fn cache_key(username: &str, password: &str) -> String {
    format!(
        "{}:{}",
        username,
        password_cache_hash_hex(password.as_bytes())
    )
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
