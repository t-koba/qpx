use super::types::{
    BodyStreamWriteOptions, CacheBackend, CachedBody, CachedBodyStream, CachedResponseCandidate,
    CachedResponseEnvelope, MetadataEncoder, VariantIndex, bounded_cache_body_stream,
    cache_body_storage_key, decode_cached_response_metadata, is_cache_body_storage_key,
};
use anyhow::{Context, Result, anyhow};
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use lru::LruCache;
use qpx_core::config::CacheBackendConfig;
use qpx_http::body::Body;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::warn;

const DISK_CACHE_MAGIC: &[u8] = b"QPX-DISK-CACHE\0\x01";
const DISK_CACHE_SCHEMA_VERSION: u16 = 2;
const DISK_CACHE_FILE_EXT: &str = "qpxc";
// File size overhead of the on-disk header: magic bytes + u32 header length.
const DISK_CACHE_HEADER_OVERHEAD_BYTES: u64 = DISK_CACHE_MAGIC.len() as u64 + 4;
const DISK_CACHE_CHUNK_BYTES: usize = 64 * 1024;
const DISK_CACHE_HOT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DISK_CACHE_HOT_MAX_OBJECT_BYTES: u64 = 2 * 1024 * 1024;
const DISK_CACHE_HOT_MAX_ENTRIES: usize = 8 * 1024;
// Keep the lock-free read index wider than the number of hot metadata/body
// objects commonly touched by one worker. A narrow table makes the metadata
// and body keys for unrelated cache entries collide frequently, forcing every
// hit through the LRU mutex that the read path is designed to avoid.
const DISK_CACHE_RECENT_ENTRIES: usize = 256;
const DISK_CACHE_RECENT_SHARDS: usize = 16;
const DISK_CACHE_RECENT_ENTRIES_PER_SHARD: usize =
    DISK_CACHE_RECENT_ENTRIES / DISK_CACHE_RECENT_SHARDS;
const DISK_CACHE_DECODED_SLOTS: usize = 256;
const DISK_CACHE_ZERO_COPY_MIN_BYTES: u64 = 64 * 1024;
const HOT_SLOT_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const HOT_SLOT_PRIME: u64 = 0x100000001b3;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DiskCacheFileId([u8; 32]);

#[derive(Clone)]
pub struct DiskCacheBackend {
    root: PathBuf,
    max_bytes: u64,
    sweep_interval: Duration,
    hot_max_bytes: u64,
    hot_max_object_bytes: u64,
    hot_recent: std::sync::Arc<ArcSwap<RecentHotCache>>,
    hot_recent_update: std::sync::Arc<std::sync::Mutex<()>>,
    hot_recent_generation: std::sync::Arc<AtomicU64>,
    decoded_variants: std::sync::Arc<Vec<ArcSwapOption<DecodedVariantIndexEntry>>>,
    decoded_metadata: std::sync::Arc<Vec<ArcSwapOption<DecodedMetadataEntry>>>,
    hot_responses: std::sync::Arc<Vec<ArcSwapOption<HotResponseEntry>>>,
    background_sweep_started: std::sync::Arc<AtomicBool>,
    indexed_flag: std::sync::Arc<AtomicBool>,
    state: std::sync::Arc<Mutex<DiskCacheState>>,
}

struct DiskCacheState {
    indexed: bool,
    total_bytes: u64,
    entries: HashMap<DiskCacheFileId, DiskCacheIndexEntry>,
    hot_bytes: u64,
    hot_entries: LruCache<PathBuf, HotCacheEntry>,
}

impl Default for DiskCacheState {
    fn default() -> Self {
        Self {
            indexed: false,
            total_bytes: 0,
            entries: HashMap::new(),
            hot_bytes: 0,
            hot_entries: LruCache::unbounded(),
        }
    }
}

#[derive(Clone)]
struct DiskCacheIndexEntry {
    total_len: u64,
    expires_at_ms: u64,
    touched_at_ms: u64,
}

struct HotCacheEntry {
    value: Bytes,
    expires_at_ms: u64,
    body_offset: u64,
}

#[derive(Clone)]
struct RecentHotCacheEntry {
    namespace: std::sync::Arc<str>,
    key: std::sync::Arc<str>,
    path: PathBuf,
    value: Bytes,
    expires_at_ms: u64,
    body_offset: u64,
    file: Option<std::sync::Arc<File>>,
}

#[derive(Clone)]
struct RecentHotCache {
    shards: Vec<std::sync::Arc<RecentHotCacheShard>>,
}

#[derive(Clone)]
struct RecentHotCacheShard {
    entries: Vec<Option<RecentHotCacheEntry>>,
}

impl Default for RecentHotCache {
    fn default() -> Self {
        Self {
            shards: (0..DISK_CACHE_RECENT_SHARDS)
                .map(|_| {
                    std::sync::Arc::new(RecentHotCacheShard {
                        entries: vec![None; DISK_CACHE_RECENT_ENTRIES_PER_SHARD],
                    })
                })
                .collect(),
        }
    }
}

struct DecodedVariantIndexEntry {
    namespace: std::sync::Arc<str>,
    key: std::sync::Arc<str>,
    raw: Bytes,
    value: std::sync::Arc<VariantIndex>,
}

struct DecodedMetadataEntry {
    namespace: std::sync::Arc<str>,
    key: std::sync::Arc<str>,
    raw: Bytes,
    value: std::sync::Arc<CachedResponseEnvelope>,
}

struct HotResponseEntry {
    namespace: std::sync::Arc<str>,
    index_key: std::sync::Arc<str>,
    envelope: std::sync::Arc<CachedResponseEnvelope>,
    body: Bytes,
    body_offset: u64,
    file: Option<std::sync::Arc<File>>,
    expires_at_ms: u64,
    source_generation: u64,
}

struct HotRecentUpdateGuard<'a> {
    _writer: std::sync::MutexGuard<'a, ()>,
    generation: &'a AtomicU64,
    next_stable_generation: u64,
}

impl<'a> HotRecentUpdateGuard<'a> {
    fn acquire(writer: &'a std::sync::Mutex<()>, generation: &'a AtomicU64) -> Self {
        let writer = writer.lock().expect("hot recent update lock poisoned");
        let stable_generation = generation.fetch_add(1, Ordering::AcqRel);
        debug_assert_eq!(stable_generation & 1, 0);
        Self {
            _writer: writer,
            generation,
            next_stable_generation: stable_generation.wrapping_add(2),
        }
    }
}

impl Drop for HotRecentUpdateGuard<'_> {
    fn drop(&mut self) {
        self.generation
            .store(self.next_stable_generation, Ordering::Release);
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskCacheHeader {
    schema_version: u16,
    expires_at_ms: u64,
    body_len: u64,
    // Co-located envelope metadata trailer length; zero for plain values.
    meta_len: u64,
}

impl DiskCacheHeader {
    fn trailer_len(&self) -> u64 {
        if self.meta_len == 0 {
            0
        } else {
            4 + self.meta_len
        }
    }
}

struct DiskCacheRead {
    path: PathBuf,
    header: DiskCacheHeader,
    body_offset: u64,
    total_len: u64,
}

struct DiskCacheWrite {
    body_offset: u64,
    expires_at_ms: u64,
    total_len: u64,
}

enum HotCacheLookup {
    Hit {
        value: Bytes,
        body_offset: u64,
        file: Option<std::sync::Arc<File>>,
    },
    Miss(PathBuf),
}

fn decoded_slots<T>() -> Vec<ArcSwapOption<T>> {
    (0..DISK_CACHE_DECODED_SLOTS)
        .map(|_| ArcSwapOption::empty())
        .collect()
}

fn same_bytes_allocation(left: &Bytes, right: &Bytes) -> bool {
    left.len() == right.len() && left.as_ptr() == right.as_ptr()
}

impl DiskCacheBackend {
    pub fn new(cfg: CacheBackendConfig) -> Result<Self> {
        let root = cfg
            .path
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("disk cache backend {} path must be set", cfg.name))?;
        let max_bytes = cfg
            .max_bytes
            .ok_or_else(|| anyhow!("disk cache backend {} max_bytes must be set", cfg.name))?;
        if max_bytes < 1024 * 1024 {
            return Err(anyhow!(
                "disk cache backend {} max_bytes must be >= 1048576",
                cfg.name
            ));
        }
        ensure_private_dir(&root)?;
        let backend = Self {
            root,
            max_bytes,
            sweep_interval: Duration::from_secs(cfg.sweep_interval_secs.max(1)),
            hot_max_bytes: max_bytes.min(DISK_CACHE_HOT_MAX_BYTES),
            hot_max_object_bytes: (cfg.max_object_bytes as u64)
                .min(DISK_CACHE_HOT_MAX_OBJECT_BYTES),
            hot_recent: std::sync::Arc::new(ArcSwap::from_pointee(RecentHotCache::default())),
            hot_recent_update: std::sync::Arc::new(std::sync::Mutex::new(())),
            hot_recent_generation: std::sync::Arc::new(AtomicU64::new(0)),
            decoded_variants: std::sync::Arc::new(decoded_slots()),
            decoded_metadata: std::sync::Arc::new(decoded_slots()),
            hot_responses: std::sync::Arc::new(decoded_slots()),
            background_sweep_started: std::sync::Arc::new(AtomicBool::new(false)),
            indexed_flag: std::sync::Arc::new(AtomicBool::new(false)),
            state: std::sync::Arc::new(Mutex::new(DiskCacheState::default())),
        };
        backend.ensure_background_sweep();
        Ok(backend)
    }

    fn ensure_background_sweep(&self) {
        if self.background_sweep_started.load(Ordering::Relaxed) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self
            .background_sweep_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let cloned = self.clone();
        handle.spawn(async move {
            // Index pre-existing files up front so the first sweep never
            // pays the directory scan while traffic is being served.
            let _ = cloned.ensure_indexed().await;
            cloned.background_sweep().await;
        });
    }

    fn path_for(&self, namespace: &str, key: &str) -> PathBuf {
        self.path_for_id(cache_file_id(namespace, key))
    }

    fn path_for_id(&self, id: DiskCacheFileId) -> PathBuf {
        let digest = cache_file_id_hex(id);
        self.root
            .join(&digest[0..2])
            .join(&digest[2..4])
            .join(format!("{digest}.{DISK_CACHE_FILE_EXT}"))
    }

    async fn ensure_indexed(&self) -> Result<()> {
        // Fast path: after the first successful scan, lookups must not pay for
        // a state mutex acquisition just to observe the indexed marker.
        if self.indexed_flag.load(Ordering::Acquire) {
            return Ok(());
        }
        // Scan without the state lock: the per-file header reads dominate,
        // and holding the lock would stall every cache write for the whole
        // scan. Writes concurrent with the scan re-register themselves, so
        // the merge below only fills gaps.
        let mut entries = HashMap::new();
        let mut total_bytes = 0u64;
        for path in collect_cache_files(&self.root)? {
            let Some(id) = cache_file_id_from_path(&self.root, &path) else {
                let _ = fs::remove_file(&path);
                continue;
            };
            match read_disk_cache_header_sync(&path) {
                Ok(read) => {
                    if read.header.expires_at_ms <= now_ms() {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    let touched_at_ms = file_touched_at_ms(&path).unwrap_or(0);
                    total_bytes = total_bytes.saturating_add(read.total_len);
                    entries.insert(
                        id,
                        DiskCacheIndexEntry {
                            total_len: read.total_len,
                            expires_at_ms: read.header.expires_at_ms,
                            touched_at_ms,
                        },
                    );
                }
                Err(_) => {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        let mut state = self.state.lock().await;
        if state.indexed {
            return Ok(());
        }
        for (id, entry) in entries {
            let entry_len = entry.total_len;
            let inserted = match state.entries.entry(id) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(entry);
                    true
                }
                std::collections::hash_map::Entry::Occupied(_) => false,
            };
            if inserted {
                state.total_bytes = state.total_bytes.saturating_add(entry_len);
            }
        }
        state.indexed = true;
        drop(state);
        self.indexed_flag.store(true, Ordering::Release);
        Ok(())
    }

    async fn open_valid(&self, path: PathBuf) -> Result<Option<DiskCacheRead>> {
        self.ensure_indexed().await?;
        let read = match read_disk_cache_header_sync(&path) {
            Ok(read) => read,
            Err(_) => return Ok(None),
        };
        if read.header.expires_at_ms <= now_ms() {
            self.delete_path(&path).await;
            return Ok(None);
        }
        let mut state = self.state.lock().await;
        if let Some(id) = cache_file_id_from_path(&self.root, &path)
            && let Some(entry) = state.entries.get_mut(&id)
        {
            entry.touched_at_ms = now_ms();
        }
        Ok(Some(read))
    }

    async fn hot_get(&self, namespace: &str, key: &str) -> HotCacheLookup {
        let now = now_ms();
        if let Some(result) = self.hot_recent_lookup(namespace, key, now) {
            if let HotCacheLookup::Miss(path) = &result {
                self.hot_remove(path).await;
            }
            return result;
        }
        let path = self.path_for(namespace, key);
        self.hot_get_from_lru(namespace, key, path, now).await
    }

    fn hot_recent_lookup(&self, namespace: &str, key: &str, now: u64) -> Option<HotCacheLookup> {
        let recent = self.hot_recent.load();
        let entry = recent_hot_entry_at(&recent, hot_slot(namespace, key))?;
        if entry.namespace.as_ref() != namespace || entry.key.as_ref() != key {
            return None;
        }
        if entry.expires_at_ms <= now {
            return Some(HotCacheLookup::Miss(entry.path.clone()));
        }
        Some(HotCacheLookup::Hit {
            value: entry.value.clone(),
            body_offset: entry.body_offset,
            file: entry.file.clone(),
        })
    }

    async fn hot_get_from_lru(
        &self,
        namespace: &str,
        key: &str,
        path: PathBuf,
        now: u64,
    ) -> HotCacheLookup {
        let mut state = self.state.lock().await;
        let expired = state
            .hot_entries
            .peek(&path)
            .is_some_and(|entry| entry.expires_at_ms <= now);
        if expired {
            if let Some(entry) = state.hot_entries.pop(&path) {
                state.hot_bytes = state.hot_bytes.saturating_sub(entry.value.len() as u64);
            }
            return HotCacheLookup::Miss(path);
        }
        let value = state
            .hot_entries
            .get(&path)
            .map(|entry| (entry.value.clone(), entry.expires_at_ms, entry.body_offset));
        drop(state);
        if let Some((value, expires_at_ms, body_offset)) = value {
            let file = open_zero_copy_source(key, &path, value.len() as u64);
            self.hot_recent_upsert(
                RecentHotCacheEntry {
                    namespace: std::sync::Arc::from(namespace),
                    key: std::sync::Arc::from(key),
                    path,
                    value: value.clone(),
                    expires_at_ms,
                    body_offset,
                    file: file.clone(),
                },
                &[],
            );
            return HotCacheLookup::Hit {
                value,
                body_offset,
                file,
            };
        }
        HotCacheLookup::Miss(path)
    }

    fn decode_variant_index(
        &self,
        namespace: &str,
        key: &str,
        raw: Bytes,
    ) -> Result<std::sync::Arc<VariantIndex>> {
        let slot = qpx_http::sharding::modulo(&(namespace, key), self.decoded_variants.len());
        if let Some(entry) = self.decoded_variants[slot].load_full()
            && entry.namespace.as_ref() == namespace
            && entry.key.as_ref() == key
            && same_bytes_allocation(&entry.raw, &raw)
        {
            return Ok(entry.value.clone());
        }
        let value: std::sync::Arc<VariantIndex> =
            std::sync::Arc::new(serde_json::from_slice(&raw)?);
        self.decoded_variants[slot].store(Some(std::sync::Arc::new(DecodedVariantIndexEntry {
            namespace: std::sync::Arc::from(namespace),
            key: std::sync::Arc::from(key),
            raw,
            value: value.clone(),
        })));
        Ok(value)
    }

    fn decode_response_metadata(
        &self,
        namespace: &str,
        key: &str,
        raw: Bytes,
    ) -> Result<std::sync::Arc<CachedResponseEnvelope>> {
        let slot = qpx_http::sharding::modulo(&(namespace, key), self.decoded_metadata.len());
        if let Some(entry) = self.decoded_metadata[slot].load_full()
            && entry.namespace.as_ref() == namespace
            && entry.key.as_ref() == key
            && same_bytes_allocation(&entry.raw, &raw)
        {
            return Ok(entry.value.clone());
        }
        let value = std::sync::Arc::new(decode_cached_response_metadata(raw.clone())?);
        self.decoded_metadata[slot].store(Some(std::sync::Arc::new(DecodedMetadataEntry {
            namespace: std::sync::Arc::from(namespace),
            key: std::sync::Arc::from(key),
            raw,
            value: value.clone(),
        })));
        Ok(value)
    }

    async fn hot_insert(
        &self,
        namespace: &str,
        key: &str,
        path: PathBuf,
        value: Bytes,
        expires_at_ms: u64,
        body_offset: u64,
    ) {
        let value_len = value.len() as u64;
        if self.hot_max_bytes == 0
            || value_len > self.hot_max_object_bytes
            || value_len > self.hot_max_bytes
            || expires_at_ms <= now_ms()
        {
            return;
        }
        let recent = RecentHotCacheEntry {
            namespace: std::sync::Arc::from(namespace),
            key: std::sync::Arc::from(key),
            path: path.clone(),
            value: value.clone(),
            expires_at_ms,
            body_offset,
            file: open_zero_copy_source(key, &path, value_len),
        };
        let mut state = self.state.lock().await;
        if let Some(previous) = state.hot_entries.pop(&path) {
            state.hot_bytes = state.hot_bytes.saturating_sub(previous.value.len() as u64);
        }
        state.hot_bytes = state.hot_bytes.saturating_add(value_len);
        state.hot_entries.put(
            path,
            HotCacheEntry {
                value,
                expires_at_ms,
                body_offset,
            },
        );
        let mut evicted_paths = Vec::new();
        while state.hot_bytes > self.hot_max_bytes
            || state.hot_entries.len() > DISK_CACHE_HOT_MAX_ENTRIES
        {
            let Some((evicted_path, evicted)) = state.hot_entries.pop_lru() else {
                state.hot_bytes = 0;
                break;
            };
            evicted_paths.push(evicted_path);
            state.hot_bytes = state.hot_bytes.saturating_sub(evicted.value.len() as u64);
        }
        drop(state);
        self.hot_recent_upsert(recent, &evicted_paths);
    }

    async fn hot_remove(&self, path: &Path) {
        self.hot_recent_remove(path);
        let mut state = self.state.lock().await;
        if let Some(entry) = state.hot_entries.pop(path) {
            state.hot_bytes = state.hot_bytes.saturating_sub(entry.value.len() as u64);
        }
    }

    async fn delete_path(&self, path: &Path) {
        let _ = tokio::fs::remove_file(path).await;
        self.hot_recent_remove(path);
        let mut state = self.state.lock().await;
        if let Some(entry) = state.hot_entries.pop(path) {
            state.hot_bytes = state.hot_bytes.saturating_sub(entry.value.len() as u64);
        }
        if let Some(id) = cache_file_id_from_path(&self.root, path)
            && let Some(entry) = state.entries.remove(&id)
        {
            state.total_bytes = state.total_bytes.saturating_sub(entry.total_len);
        }
    }

    fn hot_recent_upsert(&self, entry: RecentHotCacheEntry, removed: &[PathBuf]) {
        let _update =
            HotRecentUpdateGuard::acquire(&self.hot_recent_update, &self.hot_recent_generation);
        self.hot_recent.rcu(|current| {
            let mut shards = current.shards.clone();
            if !removed.is_empty() {
                for slot in 0..DISK_CACHE_RECENT_ENTRIES {
                    if recent_hot_entry_at(current, slot)
                        .is_some_and(|candidate| removed.iter().any(|path| path == &candidate.path))
                    {
                        *recent_hot_entry_mut(&mut shards, slot) = None;
                    }
                }
            }
            let slot = hot_slot(entry.namespace.as_ref(), entry.key.as_ref());
            *recent_hot_entry_mut(&mut shards, slot) = Some(entry.clone());
            RecentHotCache { shards }
        });
    }

    fn hot_recent_remove(&self, path: &Path) {
        if !self
            .hot_recent
            .load()
            .shards
            .iter()
            .flat_map(|shard| shard.entries.iter().flatten())
            .any(|entry| entry.path == path)
        {
            return;
        }
        let _update =
            HotRecentUpdateGuard::acquire(&self.hot_recent_update, &self.hot_recent_generation);
        self.hot_recent.rcu(|current| {
            let mut shards = current.shards.clone();
            for slot in 0..DISK_CACHE_RECENT_ENTRIES {
                if recent_hot_entry_at(current, slot).is_some_and(|entry| entry.path == path) {
                    *recent_hot_entry_mut(&mut shards, slot) = None;
                }
            }
            RecentHotCache { shards }
        });
    }

    async fn remember_write(
        &self,
        path: PathBuf,
        total_len: u64,
        expires_at_ms: u64,
    ) -> Result<()> {
        self.ensure_indexed().await?;
        let id = cache_file_id_from_path(&self.root, &path)
            .ok_or_else(|| anyhow!("invalid disk cache object path: {}", path.display()))?;
        {
            let mut state = self.state.lock().await;
            if let Some(old) = state.entries.insert(
                id,
                DiskCacheIndexEntry {
                    total_len,
                    expires_at_ms,
                    touched_at_ms: now_ms(),
                },
            ) {
                state.total_bytes = state.total_bytes.saturating_sub(old.total_len);
            }
            state.total_bytes = state.total_bytes.saturating_add(total_len);
        }
        self.evict_if_needed().await
    }

    async fn sweep_expired(&self) {
        if self.ensure_indexed().await.is_err() {
            return;
        }
        let now = now_ms();
        let expired = {
            let state = self.state.lock().await;
            state
                .entries
                .iter()
                .filter(|(_, entry)| entry.expires_at_ms <= now)
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
        };
        for id in expired {
            let path = self.path_for_id(id);
            self.delete_path(&path).await;
        }
    }

    async fn evict_if_needed(&self) -> Result<()> {
        loop {
            let victim = {
                let state = self.state.lock().await;
                if state.total_bytes <= self.max_bytes {
                    return Ok(());
                }
                state
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.touched_at_ms)
                    .map(|(id, _)| *id)
            };
            let Some(id) = victim else {
                return Ok(());
            };
            let path = self.path_for_id(id);
            self.delete_path(&path).await;
        }
    }

    async fn write_bytes(
        &self,
        namespace: &str,
        key: &str,
        path: &Path,
        value: &[u8],
        ttl_secs: u64,
    ) -> Result<()> {
        let write_path = path.to_path_buf();
        let value = Bytes::copy_from_slice(value);
        let (write, value) = tokio::task::spawn_blocking(move || {
            write_cached_bytes_sync(write_path.as_path(), value, ttl_secs)
        })
        .await
        .context("disk cache writer task failed")??;
        self.remember_write(path.to_path_buf(), write.total_len, write.expires_at_ms)
            .await?;
        self.hot_insert(
            namespace,
            key,
            path.to_path_buf(),
            value,
            write.expires_at_ms,
            write.body_offset,
        )
        .await;
        Ok(())
    }

    async fn write_body_stream(
        &self,
        namespace: &str,
        key: &str,
        path: &Path,
        body: Body,
        options: BodyStreamWriteOptions,
        metadata: Option<(String, MetadataEncoder)>,
    ) -> Result<u64> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("disk cache path missing parent: {}", path.display()))?;
        ensure_private_dir(parent)?;
        let (body, len_rx) =
            bounded_cache_body_stream(body, options.max_body_bytes, options.body_read_timeout);
        let cached =
            CachedBody::from_body_limited(body, options.max_body_bytes, options.body_read_timeout)
                .await?;
        let len = len_rx
            .await
            .map_err(|_| anyhow!("disk cache body writer closed"))??;
        let metadata = match metadata {
            Some((meta_key, encode)) => Some((meta_key, Bytes::from(encode(len)?))),
            None => None,
        };
        self.put_object_path(namespace, key, path, &cached, metadata, options.ttl_secs)
            .await?;
        Ok(len)
    }

    async fn read_response_metadata(&self, namespace: &str, key: &str) -> Result<Option<Bytes>> {
        let now = now_ms();
        let recent = self.hot_recent.load();
        if let Some(entry) = recent_hot_entry(&recent, namespace, key, now) {
            return Ok(Some(entry.value.clone()));
        }
        let body_key = cache_body_storage_key(key);
        let path = self.path_for(namespace, body_key.as_str());
        // Inline like open_valid: the header and trailer reads are two small
        // preads, far cheaper than a blocking-pool dispatch per lookup.
        read_metadata_trailer_sync(&path)
    }

    async fn put_object_path(
        &self,
        namespace: &str,
        key: &str,
        path: &Path,
        body: &CachedBody,
        metadata: Option<(String, Bytes)>,
        ttl_secs: u64,
    ) -> Result<()> {
        if let CachedBody::Memory(value) = body {
            let write_path = path.to_path_buf();
            let value = value.clone();
            let meta_key = metadata.as_ref().map(|(meta_key, _)| meta_key.clone());
            let meta_bytes = metadata.as_ref().map(|(_, meta)| meta.clone());
            let (write, value, written_meta) = tokio::task::spawn_blocking(move || {
                write_cached_object_sync(write_path.as_path(), value, meta_bytes, ttl_secs)
            })
            .await
            .context("disk cache body writer task failed")??;
            self.remember_write(path.to_path_buf(), write.total_len, write.expires_at_ms)
                .await?;
            self.hot_insert(
                namespace,
                key,
                path.to_path_buf(),
                value,
                write.expires_at_ms,
                write.body_offset,
            )
            .await;
            if let (Some(meta_key), Some(meta)) = (meta_key, written_meta) {
                self.hot_insert(
                    namespace,
                    meta_key.as_str(),
                    path.to_path_buf(),
                    meta,
                    write.expires_at_ms,
                    write.body_offset,
                )
                .await;
            }
            return Ok(());
        }

        let mut source = body.to_body();
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("disk cache path missing parent: {}", path.display()))?;
        ensure_private_dir(parent)?;
        let expires_at_ms = now_ms().saturating_add(ttl_secs.saturating_mul(1000));
        let header = DiskCacheHeader {
            schema_version: DISK_CACHE_SCHEMA_VERSION,
            expires_at_ms,
            body_len: body.len(),
            meta_len: metadata.as_ref().map_or(0, |(_, meta)| meta.len() as u64),
        };
        let tmp_path = temp_path(parent);
        let streamed: std::result::Result<u64, anyhow::Error> = async {
            let mut file = TokioFile::from_std(create_secure_new_file(&tmp_path)?);
            write_header_async(&mut file, &header).await?;
            while let Some(chunk) = source.data().await {
                file.write_all(chunk?.as_ref()).await?;
            }
            if let Some((_, meta)) = metadata.as_ref() {
                file.write_all(&(meta.len() as u32).to_be_bytes()).await?;
                file.write_all(meta.as_ref()).await?;
            }
            // Cache objects are re-fetchable, so commit to the page cache and
            // publish atomically via rename instead of paying for an fsync.
            let body_len = header.body_len;
            drop(file);
            fs::rename(&tmp_path, path).with_context(|| {
                format!("failed to commit disk cache object {}", path.display())
            })?;
            Ok(body_len)
        }
        .await;
        if streamed.is_err() {
            let _ = fs::remove_file(&tmp_path);
            invalidate_ensured_dir(parent);
        }
        let body_len = streamed?;
        let total_len = DISK_CACHE_HEADER_OVERHEAD_BYTES + body_len + header.trailer_len();
        self.remember_write(path.to_path_buf(), total_len, expires_at_ms)
            .await?;
        self.hot_remove(path).await;
        Ok(())
    }

    async fn background_sweep(self) {
        let start = tokio::time::Instant::now() + self.sweep_interval;
        let mut interval = tokio::time::interval_at(start, self.sweep_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.sweep_expired().await;
            let _ = self.evict_if_needed().await;
        }
    }
}

#[async_trait]
impl CacheBackend for DiskCacheBackend {
    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Bytes>> {
        self.ensure_background_sweep();
        let path = match self.hot_get(namespace, key).await {
            HotCacheLookup::Hit { value, .. } => return Ok(Some(value)),
            HotCacheLookup::Miss(path) => path,
        };
        let Some(read) = self.open_valid(path).await? else {
            return Ok(None);
        };
        let mut file = TokioFile::open(&read.path).await?;
        file.seek(std::io::SeekFrom::Start(read.body_offset))
            .await?;
        let mut out = Vec::with_capacity(read.header.body_len.min(usize::MAX as u64) as usize);
        file.take(read.header.body_len)
            .read_to_end(&mut out)
            .await?;
        let value = Bytes::from(out);
        self.hot_insert(
            namespace,
            key,
            read.path,
            value.clone(),
            read.header.expires_at_ms,
            read.body_offset,
        )
        .await;
        Ok(Some(value))
    }

    async fn get_many(&self, namespace: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_background_sweep();
        let now = now_ms();
        let mut out = vec![None; keys.len()];
        let mut misses = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            match self.hot_recent_lookup(namespace, key, now) {
                Some(HotCacheLookup::Hit { value, .. }) => out[index] = Some(value),
                Some(HotCacheLookup::Miss(path)) => {
                    self.hot_remove(&path).await;
                    misses.push((index, key));
                }
                None => misses.push((index, key)),
            }
        }
        for (index, key) in misses {
            out[index] = self.get(namespace, key).await?;
        }
        Ok(out)
    }

    async fn get_decoded_variant_index(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<std::sync::Arc<VariantIndex>>> {
        let Some(raw) = self.get(namespace, key).await? else {
            return Ok(None);
        };
        self.decode_variant_index(namespace, key, raw).map(Some)
    }

    async fn get_decoded_response_metadata_many(
        &self,
        namespace: &str,
        keys: &[String],
    ) -> Result<Vec<Option<std::sync::Arc<CachedResponseEnvelope>>>> {
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let raw = self.read_response_metadata(namespace, key).await?;
            let decoded = match raw {
                Some(raw) => Some(self.decode_response_metadata(namespace, key, raw)?),
                None => None,
            };
            out.push(decoded);
        }
        Ok(out)
    }

    fn get_response_candidate(
        &self,
        namespace: &str,
        index_key: &str,
        default_variant_key: &str,
        now: u64,
    ) -> Result<Option<CachedResponseCandidate>> {
        let slot_index = hot_slot(namespace, index_key);
        let slot = &self.hot_responses[slot_index];
        let generation = self.hot_recent_generation.load(Ordering::Acquire);
        if generation & 1 != 0 {
            return Ok(None);
        }
        let cached = slot.load();
        if let Some(entry) = cached.as_ref()
            && entry.namespace.as_ref() == namespace
            && entry.index_key.as_ref() == index_key
            && entry.source_generation == generation
            && entry.expires_at_ms > now
            && self.hot_recent_generation.load(Ordering::Acquire) == generation
        {
            return Ok(hot_response_candidate(entry.as_ref()));
        }
        drop(cached);
        if self.hot_recent_generation.load(Ordering::Acquire) != generation {
            return Ok(None);
        }
        if slot.load().is_some() {
            slot.store(None);
        }

        let recent = self.hot_recent.load();
        // Vary-less responses publish no variant index; when the index is
        // missing or holds no single variant, the canonical default variant
        // is probed directly.
        let resolved = match recent_hot_entry(&recent, namespace, index_key, now) {
            Some(index_entry) => {
                let variants =
                    self.decode_variant_index(namespace, index_key, index_entry.value.clone())?;
                match variants.variants.first() {
                    Some(only) if variants.variants.len() == 1 => {
                        Some((only.clone(), index_entry.expires_at_ms))
                    }
                    _ => None,
                }
            }
            None => None,
        };
        let (variant_key, index_expires_at_ms) =
            resolved.unwrap_or((default_variant_key.to_string(), u64::MAX));
        let Some(metadata_entry) = recent_hot_entry(&recent, namespace, variant_key.as_str(), now)
        else {
            return Ok(None);
        };
        let envelope = self.decode_response_metadata(
            namespace,
            variant_key.as_str(),
            metadata_entry.value.clone(),
        )?;
        let body_key = cache_body_storage_key(variant_key.as_str());
        let Some(body_entry) = recent_hot_entry(&recent, namespace, body_key.as_str(), now) else {
            return Ok(None);
        };
        if body_entry.value.len() as u64 != envelope.body_len {
            return Ok(None);
        }
        let entry = std::sync::Arc::new(HotResponseEntry {
            namespace: std::sync::Arc::from(namespace),
            index_key: std::sync::Arc::from(index_key),
            envelope,
            body: body_entry.value.clone(),
            body_offset: body_entry.body_offset,
            file: body_entry.file.clone(),
            expires_at_ms: index_expires_at_ms
                .min(metadata_entry.expires_at_ms)
                .min(body_entry.expires_at_ms),
            source_generation: generation,
        });
        let candidate = hot_response_candidate(entry.as_ref());
        if self.hot_recent_generation.load(Ordering::Acquire) != generation {
            return Ok(None);
        }
        if candidate.is_some() {
            slot.store(Some(entry));
        }
        Ok(candidate)
    }

    async fn get_object(&self, namespace: &str, key: &str) -> Result<Option<CachedBody>> {
        Ok(self.get(namespace, key).await?.map(CachedBody::from_bytes))
    }

    async fn get_object_stream(
        &self,
        namespace: &str,
        key: &str,
        expected_len: u64,
        range: Option<(u64, u64)>,
    ) -> Result<Option<CachedBodyStream>> {
        self.ensure_background_sweep();
        let path = match self.hot_get(namespace, key).await {
            HotCacheLookup::Hit {
                value,
                body_offset,
                file,
            } => {
                return Ok(hot_body_stream(
                    value,
                    expected_len,
                    range,
                    file,
                    body_offset,
                ));
            }
            HotCacheLookup::Miss(path) => path,
        };
        let Some(read) = self.open_valid(path).await? else {
            return Ok(None);
        };
        if read.header.body_len != expected_len {
            return Ok(None);
        }
        if read.header.body_len <= self.hot_max_object_bytes {
            let mut file = TokioFile::open(&read.path).await?;
            file.seek(std::io::SeekFrom::Start(read.body_offset))
                .await?;
            let mut out = Vec::with_capacity(read.header.body_len as usize);
            file.take(read.header.body_len)
                .read_to_end(&mut out)
                .await?;
            if out.len() as u64 != read.header.body_len {
                return Ok(None);
            }
            let value = Bytes::from(out);
            self.hot_insert(
                namespace,
                key,
                read.path.clone(),
                value.clone(),
                read.header.expires_at_ms,
                read.body_offset,
            )
            .await;
            return Ok(hot_body_stream(
                value,
                expected_len,
                range,
                open_zero_copy_source(key, &read.path, read.header.body_len),
                read.body_offset,
            ));
        }
        let body_len = range
            .map(|(start, end)| end.saturating_sub(start).saturating_add(1))
            .unwrap_or(read.header.body_len);
        let start_offset = read
            .body_offset
            .saturating_add(range.map(|(start, _)| start).unwrap_or(0));
        let (mut sender, body) = Body::channel_with_capacity(16);
        tokio::spawn(async move {
            let result = async {
                let mut file = TokioFile::open(&read.path).await?;
                file.seek(std::io::SeekFrom::Start(start_offset)).await?;
                let mut remaining = body_len;
                let mut buf = BytesMut::with_capacity(DISK_CACHE_CHUNK_BYTES);
                while remaining > 0 {
                    let want = remaining.min(DISK_CACHE_CHUNK_BYTES as u64) as usize;
                    buf.clear();
                    buf.reserve(want);
                    let read_len = (&mut file).take(want as u64).read_buf(&mut buf).await?;
                    if read_len == 0 {
                        return Err(anyhow!("disk cache object length mismatch"));
                    }
                    remaining = remaining.saturating_sub(read_len as u64);
                    if sender.send_data(buf.split().freeze()).await.is_err() {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
                Ok(())
            }
            .await;
            if result.is_err() {
                sender.abort();
            }
        });
        Ok(Some(CachedBodyStream::from_body_for_backend(
            body_len, body,
        )))
    }

    async fn put(&self, namespace: &str, key: &str, value: &[u8], ttl_secs: u64) -> Result<()> {
        if value.len() as u64 > self.max_bytes {
            return Err(anyhow!("disk cache object exceeds backend max_bytes"));
        }
        self.ensure_background_sweep();
        let path = self.path_for(namespace, key);
        self.write_bytes(namespace, key, &path, value, ttl_secs)
            .await
    }

    async fn put_object(
        &self,
        namespace: &str,
        key: &str,
        body: &CachedBody,
        ttl_secs: u64,
    ) -> Result<()> {
        if body.len() > self.max_bytes {
            return Err(anyhow!("disk cache object exceeds backend max_bytes"));
        }
        self.ensure_background_sweep();
        let path = self.path_for(namespace, key);
        self.put_object_path(namespace, key, &path, body, None, ttl_secs)
            .await
    }

    async fn put_object_stream(
        &self,
        namespace: &str,
        key: &str,
        body: Body,
        max_body_bytes: usize,
        body_read_timeout: Duration,
        ttl_secs: u64,
    ) -> Result<u64> {
        if max_body_bytes as u64 > self.max_bytes {
            return Err(anyhow!(
                "disk cache max_body_bytes exceeds backend max_bytes"
            ));
        }
        self.ensure_background_sweep();
        let path = self.path_for(namespace, key);
        timeout(
            body_read_timeout,
            self.write_body_stream(
                namespace,
                key,
                &path,
                body,
                BodyStreamWriteOptions {
                    max_body_bytes,
                    body_read_timeout,
                    ttl_secs,
                },
                None,
            ),
        )
        .await?
    }

    async fn put_response(
        &self,
        namespace: &str,
        key: &str,
        body: Body,
        options: BodyStreamWriteOptions,
        encode_metadata: MetadataEncoder,
    ) -> Result<u64> {
        if options.max_body_bytes as u64 > self.max_bytes {
            return Err(anyhow!(
                "disk cache max_body_bytes exceeds backend max_bytes"
            ));
        }
        self.ensure_background_sweep();
        // The response is one file: the envelope metadata rides in a trailer
        // after the body, so a cache miss creates a single file and a cache
        // hit opens one file instead of two.
        let body_key = cache_body_storage_key(key);
        let path = self.path_for(namespace, body_key.as_str());
        timeout(
            options.body_read_timeout,
            self.write_body_stream(
                namespace,
                body_key.as_str(),
                &path,
                body,
                options,
                Some((key.to_string(), encode_metadata)),
            ),
        )
        .await?
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let path = self.path_for(namespace, key);
        self.delete_path(&path).await;
        Ok(())
    }
}

fn hot_body_stream(
    value: Bytes,
    expected_len: u64,
    range: Option<(u64, u64)>,
    file: Option<std::sync::Arc<File>>,
    body_offset: u64,
) -> Option<CachedBodyStream> {
    if value.len() as u64 != expected_len {
        return None;
    }
    let range_start = range.map(|(start, _)| start).unwrap_or(0);
    let value = match range {
        Some((start, end)) => {
            let start = usize::try_from(start).ok()?;
            let end = usize::try_from(end).ok()?.checked_add(1)?;
            if start >= end || end > value.len() {
                return None;
            }
            value.slice(start..end)
        }
        None => value,
    };
    let len = value.len() as u64;
    let mut body = Body::from(value).mark_trailers_sanitized();
    if len >= DISK_CACHE_ZERO_COPY_MIN_BYTES
        && let Some(file) = file
    {
        body = body.with_file_region(file, body_offset.saturating_add(range_start), len);
    }
    Some(CachedBodyStream::from_body_for_backend(len, body))
}

fn recent_hot_entry<'a>(
    recent: &'a RecentHotCache,
    namespace: &str,
    key: &str,
    now: u64,
) -> Option<&'a RecentHotCacheEntry> {
    let entry = recent_hot_entry_at(recent, hot_slot(namespace, key))?;
    (entry.namespace.as_ref() == namespace
        && entry.key.as_ref() == key
        && entry.expires_at_ms > now)
        .then_some(entry)
}

fn recent_hot_entry_at(recent: &RecentHotCache, slot: usize) -> Option<&RecentHotCacheEntry> {
    let shard = recent
        .shards
        .get(slot / DISK_CACHE_RECENT_ENTRIES_PER_SHARD)?;
    shard
        .entries
        .get(slot % DISK_CACHE_RECENT_ENTRIES_PER_SHARD)?
        .as_ref()
}

fn recent_hot_entry_mut(
    shards: &mut [std::sync::Arc<RecentHotCacheShard>],
    slot: usize,
) -> &mut Option<RecentHotCacheEntry> {
    let shard = std::sync::Arc::make_mut(&mut shards[slot / DISK_CACHE_RECENT_ENTRIES_PER_SHARD]);
    &mut shard.entries[slot % DISK_CACHE_RECENT_ENTRIES_PER_SHARD]
}

fn hot_response_candidate(entry: &HotResponseEntry) -> Option<CachedResponseCandidate> {
    let body = hot_body_stream(
        entry.body.clone(),
        entry.envelope.body_len,
        None,
        entry.file.clone(),
        entry.body_offset,
    )?;
    Some(CachedResponseCandidate::new(entry.envelope.clone(), body))
}

fn hot_slot(namespace: &str, key: &str) -> usize {
    let mut hash = HOT_SLOT_OFFSET_BASIS;
    for byte in namespace
        .as_bytes()
        .iter()
        .copied()
        .chain(std::iter::once(0))
        .chain(key.as_bytes().iter().copied())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(HOT_SLOT_PRIME);
    }
    (hash as usize) % DISK_CACHE_RECENT_ENTRIES
}

fn open_zero_copy_source(key: &str, path: &Path, body_len: u64) -> Option<std::sync::Arc<File>> {
    if !is_cache_body_storage_key(key) || body_len < DISK_CACHE_ZERO_COPY_MIN_BYTES {
        return None;
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    match options.open(path) {
        Ok(file) => Some(std::sync::Arc::new(file)),
        Err(err) => {
            warn!(
                error = ?err,
                path = %path.display(),
                "cache zero-copy source open failed; using the verified memory body"
            );
            None
        }
    }
}

fn cache_file_id(namespace: &str, key: &str) -> DiskCacheFileId {
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0]);
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    DiskCacheFileId(digest.into())
}

fn cache_file_id_hex(id: DiskCacheFileId) -> String {
    super::hash::hex_lower(id.0.as_slice())
}

fn cache_file_id_from_path(root: &Path, path: &Path) -> Option<DiskCacheFileId> {
    if path.extension().and_then(|extension| extension.to_str()) != Some(DISK_CACHE_FILE_EXT) {
        return None;
    }
    let encoded = path.file_stem()?.to_str()?;
    if encoded.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest[index] = decode_hex_nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_hex_nibble(pair[1])?)?;
    }
    let id = DiskCacheFileId(digest);
    let expected = cache_file_id_hex(id);
    let expected_path = root
        .join(&expected[0..2])
        .join(&expected[2..4])
        .join(format!("{expected}.{DISK_CACHE_FILE_EXT}"));
    (expected_path == path).then_some(id)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn file_touched_at_ms(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()
        .and_then(|meta| meta.modified().ok())
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
}

fn collect_cache_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_cache_files_inner(root, &mut out)?;
    Ok(out)
}

fn collect_cache_files_inner(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_cache_files_inner(&path, out)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some(DISK_CACHE_FILE_EXT) {
            out.push(path);
        }
    }
    Ok(())
}

fn read_disk_cache_header_sync(path: &Path) -> Result<DiskCacheRead> {
    reject_symlink(path)?;
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    let mut magic = vec![0; DISK_CACHE_MAGIC.len()];
    file.read_exact(&mut magic)?;
    if magic != DISK_CACHE_MAGIC {
        return Err(anyhow!("invalid disk cache object magic"));
    }
    let mut len = [0u8; 4];
    file.read_exact(&mut len)?;
    let header_len = u32::from_be_bytes(len) as usize;
    if header_len == 0 || header_len > 16 * 1024 {
        return Err(anyhow!("invalid disk cache header length"));
    }
    let mut raw = vec![0; header_len];
    file.read_exact(&mut raw)?;
    let header: DiskCacheHeader = serde_json::from_slice(&raw)?;
    if header.schema_version != DISK_CACHE_SCHEMA_VERSION {
        return Err(anyhow!("unsupported disk cache schema version"));
    }
    let body_offset = DISK_CACHE_MAGIC.len() as u64 + 4 + header_len as u64;
    if meta.len().saturating_sub(body_offset) != header.body_len + header.trailer_len() {
        return Err(anyhow!(
            "disk cache object length mismatch: file {} body_offset {} body_len {} meta_len {}",
            meta.len(),
            body_offset,
            header.body_len,
            header.meta_len
        ));
    }
    Ok(DiskCacheRead {
        path: path.to_path_buf(),
        header,
        body_offset,
        total_len: meta.len(),
    })
}

fn read_metadata_trailer_sync(path: &Path) -> Result<Option<Bytes>> {
    // Same semantics as open_valid: an unreadable object is a miss, not a
    // lookup failure; the entry is re-fetchable from the origin.
    let Ok(read) = read_disk_cache_header_sync(path) else {
        return Ok(None);
    };
    if read.header.meta_len == 0 {
        return Ok(None);
    }
    if read.header.expires_at_ms <= now_ms() {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    let trailer_start = read.total_len - 4 - read.header.meta_len;
    file.seek(std::io::SeekFrom::Start(trailer_start))?;
    let mut len = [0u8; 4];
    file.read_exact(&mut len)?;
    let meta_len = u32::from_be_bytes(len) as u64;
    if meta_len != read.header.meta_len {
        return Err(anyhow!("disk cache metadata trailer length mismatch"));
    }
    let mut meta = vec![0u8; meta_len as usize];
    file.read_exact(&mut meta)?;
    Ok(Some(Bytes::from(meta)))
}

fn write_header(file: &mut File, header: &DiskCacheHeader) -> Result<u64> {
    let raw = serde_json::to_vec(header)?;
    file.write_all(DISK_CACHE_MAGIC)?;
    file.write_all(&(raw.len() as u32).to_be_bytes())?;
    file.write_all(&raw)?;
    Ok(DISK_CACHE_MAGIC.len() as u64 + 4 + raw.len() as u64)
}

fn write_cached_bytes_sync(
    path: &Path,
    value: Bytes,
    ttl_secs: u64,
) -> Result<(DiskCacheWrite, Bytes)> {
    write_cached_object_sync(path, value, None, ttl_secs).map(|(write, value, _)| (write, value))
}

/// Writes one disk cache object: `[magic][header][body][meta trailer]`. The
/// optional envelope metadata trailer keeps a response to a single file so a
/// cache miss creates one file instead of two.
fn write_cached_object_sync(
    path: &Path,
    value: Bytes,
    metadata: Option<Bytes>,
    ttl_secs: u64,
) -> Result<(DiskCacheWrite, Bytes, Option<Bytes>)> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("disk cache path missing parent: {}", path.display()))?;
    ensure_private_dir(parent)?;
    let expires_at_ms = now_ms().saturating_add(ttl_secs.saturating_mul(1000));
    let header = DiskCacheHeader {
        schema_version: DISK_CACHE_SCHEMA_VERSION,
        expires_at_ms,
        body_len: value.len() as u64,
        meta_len: metadata.as_ref().map_or(0, |meta| meta.len() as u64),
    };
    let tmp_path = temp_path(parent);
    let result = (|| {
        let mut file = create_secure_new_file(&tmp_path)?;
        let body_offset = write_header(&mut file, &header)?;
        file.write_all(value.as_ref())?;
        if let Some(meta) = metadata.as_ref() {
            file.write_all(&(meta.len() as u32).to_be_bytes())?;
            file.write_all(meta.as_ref())?;
        }
        // Durability note: cache objects are re-fetchable from the origin, so
        // writes are committed to the page cache and published atomically via
        // rename without an fsync. This matches the behavior of other HTTP
        // caches and keeps write-heavy miss workloads off the disk sync path.
        let total_len = DISK_CACHE_HEADER_OVERHEAD_BYTES + header.body_len + header.trailer_len();
        drop(file);
        fs::rename(&tmp_path, path)
            .with_context(|| format!("failed to commit disk cache object {}", path.display()))?;
        Ok(DiskCacheWrite {
            body_offset,
            expires_at_ms,
            total_len,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
        if let Some(parent) = path.parent() {
            invalidate_ensured_dir(parent);
        }
    }
    result.map(|write| (write, value, metadata))
}

async fn write_header_async(file: &mut TokioFile, header: &DiskCacheHeader) -> Result<u64> {
    let raw = serde_json::to_vec(header)?;
    file.write_all(DISK_CACHE_MAGIC).await?;
    file.write_all(&(raw.len() as u32).to_be_bytes()).await?;
    file.write_all(&raw).await?;
    Ok(DISK_CACHE_MAGIC.len() as u64 + 4 + raw.len() as u64)
}

fn temp_path(parent: &Path) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".qpx-cache-{}-{counter}-{}.tmp",
        std::process::id(),
        now_ms()
    ))
}

fn create_secure_new_file(path: &Path) -> Result<File> {
    reject_symlink(path)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to create disk cache file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(anyhow!(
            "disk cache path must not contain parent traversal: {}",
            path.display()
        ));
    }
    // Cache-miss writebacks rebuild the directory chain on every store; a
    // process-wide memo of verified parents keeps repeat writes off the
    // mkdir/stat path. The walk itself is the security boundary (symlink and
    // type checks), so only full successful walks are memoized.
    if let Some(ensured) = ENSURED_PRIVATE_DIRS.get()
        && ensured.lock().expect("ensured dir lock").contains(path)
    {
        return Ok(());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match fs::create_dir(&current) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let meta = fs::symlink_metadata(&current)?;
                if meta.file_type().is_symlink() {
                    return Err(anyhow!(
                        "refusing symlinked disk cache path component {}",
                        current.display()
                    ));
                }
                if !meta.is_dir() {
                    return Err(anyhow!(
                        "disk cache path component is not a directory: {}",
                        current.display()
                    ));
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to create disk cache directory {}",
                        current.display()
                    )
                });
            }
        }
    }
    if let Some(ensured) = ENSURED_PRIVATE_DIRS.get()
        && let Ok(mut set) = ensured.lock()
        && set.len() < ENSURED_PRIVATE_DIR_LIMIT
    {
        set.insert(path.to_path_buf());
    }
    Ok(())
}

/// Verified private disk-cache parents. The guard walks directories afresh on
/// first use, so entries are trusted for the lifetime of the process only.
static ENSURED_PRIVATE_DIRS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<PathBuf>>,
> = std::sync::OnceLock::new();
const ENSURED_PRIVATE_DIR_LIMIT: usize = 4096;

/// Drops the memoized entry for `dir` so the next write re-runs the directory
/// guard. Write paths call this when the parent stops accepting files.
fn invalidate_ensured_dir(dir: &Path) {
    if let Some(ensured) = ENSURED_PRIVATE_DIRS.get()
        && let Ok(mut set) = ensured.lock()
    {
        set.remove(dir);
    }
}

fn reject_symlink(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(anyhow!(
            "refusing symlinked disk cache path {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(name: &str) -> PathBuf {
        let base = if Path::new("/private/tmp").is_dir() {
            PathBuf::from("/private/tmp")
        } else {
            std::env::temp_dir()
        };
        let path = base.join(format!(
            "qpx-disk-cache-{name}-{}-{}",
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn cfg(path: PathBuf, max_bytes: u64) -> CacheBackendConfig {
        CacheBackendConfig {
            name: "disk".to_string(),
            kind: "disk".to_string(),
            endpoint: String::new(),
            path: Some(path.display().to_string()),
            max_bytes: Some(max_bytes),
            sweep_interval_secs: 1,
            timeout_ms: 500,
            max_object_bytes: 1024 * 1024,
            auth_header_env: None,
        }
    }

    #[test]
    fn private_directory_creation_is_concurrent_safe() {
        const WORKERS: usize = 16;
        let root = temp_dir("concurrent-directory");
        let target = root.join("objects").join("ab").join("cd");
        let barrier = Arc::new(Barrier::new(WORKERS));
        let mut workers = Vec::with_capacity(WORKERS);
        for _ in 0..WORKERS {
            let barrier = Arc::clone(&barrier);
            let target = target.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                ensure_private_dir(&target)
            }));
        }

        for worker in workers {
            worker
                .join()
                .expect("directory creation worker")
                .expect("create private directory");
        }
        assert!(target.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn private_directory_creation_accepts_an_absolute_path_anchor() {
        let root = temp_dir("absolute-path-anchor");
        let target = root.join("objects");
        ensure_private_dir(&target).expect("create directory below absolute path anchor");
        assert!(target.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn private_directory_creation_rejects_parent_traversal_before_mutation() {
        let root = temp_dir("parent-traversal");
        let child = root.join("untrusted");
        let target = child.join("..").join("objects");
        let error = ensure_private_dir(&target).expect_err("reject parent traversal");
        assert!(error.to_string().contains("parent traversal"));
        assert!(!child.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn disk_backend_reads_after_restart() {
        let dir = temp_dir("restart");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend.put("ns", "key", b"value", 60).await.expect("put");
        drop(backend);

        let restarted = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("restart");
        let value = restarted
            .get("ns", "key")
            .await
            .expect("get")
            .expect("value");
        assert_eq!(value.as_ref(), b"value");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_serves_hot_small_objects_without_disk_io() {
        let dir = temp_dir("hot-object");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend
            .put("ns", "key", b"hot-value", 60)
            .await
            .expect("put");
        let path = backend.path_for("ns", "key");
        fs::remove_file(&path).expect("remove persisted object");

        let value = backend
            .get("ns", "key")
            .await
            .expect("get")
            .expect("hot value");
        assert_eq!(value.as_ref(), b"hot-value");

        backend.delete("ns", "key").await.expect("delete");
        assert!(
            backend
                .get("ns", "key")
                .await
                .expect("get deleted")
                .is_none()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_put_response_serves_metadata_after_hot_expiry() {
        let dir = temp_dir("put-response-file-body");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 64 * 1024 * 1024)).expect("backend");
        let big = vec![7u8; 1024 * 1024];
        let body = Body::from(big.clone());
        let len = backend
            .put_response(
                "ns",
                "variant",
                body,
                BodyStreamWriteOptions {
                    max_body_bytes: 2 * 1024 * 1024,
                    body_read_timeout: Duration::from_secs(5),
                    ttl_secs: 600,
                },
                Box::new(|body_len: u64| Ok(format!(r#"{{"body_len":{body_len}}}"#).into_bytes())),
            )
            .await
            .expect("put response");
        assert_eq!(len, big.len() as u64);
        let raw = backend
            .read_response_metadata("ns", "variant")
            .await
            .expect("read metadata")
            .expect("metadata present");
        assert!(String::from_utf8_lossy(&raw).contains(r#""body_len":1048576"#));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_keeps_multiple_recent_keys_lock_free() {
        let dir = temp_dir("recent-keys");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        for (key, value) in [("index", b"i"), ("metadata", b"m"), ("body", b"b")] {
            backend.put("ns", key, value, 60).await.expect("put");
            fs::remove_file(backend.path_for("ns", key)).expect("remove persisted object");
        }

        for (key, expected) in [("index", b"i"), ("metadata", b"m"), ("body", b"b")] {
            let value = backend
                .get("ns", key)
                .await
                .expect("get")
                .expect("recent value");
            assert_eq!(value.as_ref(), expected);
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_reuses_decoded_cache_records_and_invalidates_on_write() {
        let dir = temp_dir("decoded-records");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let first_index = VariantIndex {
            variants: vec!["v1".to_string()],
        };
        backend
            .put(
                "ns",
                "index",
                &serde_json::to_vec(&first_index).expect("encode index"),
                60,
            )
            .await
            .expect("put index");

        let first = backend
            .get_decoded_variant_index("ns", "index")
            .await
            .expect("decode first index")
            .expect("first index");
        let repeated = backend
            .get_decoded_variant_index("ns", "index")
            .await
            .expect("decode repeated index")
            .expect("repeated index");
        assert!(std::sync::Arc::ptr_eq(&first, &repeated));

        let second_index = VariantIndex {
            variants: vec!["v2".to_string()],
        };
        backend
            .put(
                "ns",
                "index",
                &serde_json::to_vec(&second_index).expect("encode replacement index"),
                60,
            )
            .await
            .expect("replace index");
        let replaced = backend
            .get_decoded_variant_index("ns", "index")
            .await
            .expect("decode replacement index")
            .expect("replacement index");
        assert!(!std::sync::Arc::ptr_eq(&first, &replaced));
        assert_eq!(replaced.variants, vec!["v2"]);

        let envelope = CachedResponseEnvelope {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: CachedBody::default(),
            body_len: 7,
            stored_at_ms: 1,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            header_map: Default::default(),
            response_directives: Default::default(),
            response_header_values: Default::default(),
        };
        backend
            .put(
                "ns",
                "metadata",
                &super::super::types::encode_cached_response_metadata(&envelope)
                    .expect("encode metadata"),
                60,
            )
            .await
            .expect("put metadata");
        let keys = vec!["metadata".to_string()];
        let first = backend
            .get_decoded_response_metadata_many("ns", &keys)
            .await
            .expect("decode first metadata")
            .pop()
            .flatten()
            .expect("first metadata");
        let repeated = backend
            .get_decoded_response_metadata_many("ns", &keys)
            .await
            .expect("decode repeated metadata")
            .pop()
            .flatten()
            .expect("repeated metadata");
        assert!(std::sync::Arc::ptr_eq(&first, &repeated));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_hot_response_candidate_is_coherent_across_replacement_and_delete() {
        let dir = temp_dir("hot-response-candidate");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let variant_key = "obj:primary:variant";
        let body_key = cache_body_storage_key(variant_key);
        let mut envelope = CachedResponseEnvelope {
            status: 200,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: CachedBody::default(),
            body_len: 7,
            stored_at_ms: 1,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            header_map: Default::default(),
            response_directives: Default::default(),
            response_header_values: Default::default(),
        };
        backend
            .put_object(
                "ns",
                body_key.as_str(),
                &CachedBody::from_bytes(Bytes::from_static(b"payload")),
                60,
            )
            .await
            .expect("put body");
        backend
            .put(
                "ns",
                variant_key,
                &super::super::types::encode_cached_response_metadata(&envelope)
                    .expect("encode metadata"),
                60,
            )
            .await
            .expect("put metadata");
        backend
            .put(
                "ns",
                "index",
                &serde_json::to_vec(&VariantIndex {
                    variants: vec![variant_key.to_string()],
                })
                .expect("encode index"),
                60,
            )
            .await
            .expect("put index");

        let mut first = backend
            .get_response_candidate("ns", "index", "obj:default", now_ms())
            .expect("get candidate")
            .expect("candidate");
        assert_eq!(first.envelope.status, 200);
        assert_eq!(
            first.body.body.data().await.expect("body").expect("bytes"),
            Bytes::from_static(b"payload")
        );

        envelope.status = 201;
        let updated_metadata = Bytes::from(
            super::super::types::encode_cached_response_metadata(&envelope)
                .expect("encode concurrently replaced metadata"),
        );
        let mut updated_recent = (**backend.hot_recent.load()).clone();
        let updated_entry =
            recent_hot_entry_mut(&mut updated_recent.shards, hot_slot("ns", variant_key))
                .as_mut()
                .expect("hot metadata");
        updated_entry.value = updated_metadata;
        {
            let _update = HotRecentUpdateGuard::acquire(
                &backend.hot_recent_update,
                &backend.hot_recent_generation,
            );
            backend
                .hot_recent
                .store(std::sync::Arc::new(updated_recent));
            assert!(
                backend
                    .get_response_candidate("ns", "index", "obj:default", now_ms())
                    .expect("get candidate during replacement")
                    .is_none()
            );
        }
        let raced_replacement = backend
            .get_response_candidate("ns", "index", "obj:default", now_ms())
            .expect("get concurrently replaced candidate")
            .expect("concurrently replaced candidate");
        assert_eq!(raced_replacement.envelope.status, 201);

        envelope.status = 202;
        backend
            .put(
                "ns",
                variant_key,
                &super::super::types::encode_cached_response_metadata(&envelope)
                    .expect("encode replacement metadata"),
                60,
            )
            .await
            .expect("replace metadata");
        let replaced = backend
            .get_response_candidate("ns", "index", "obj:default", now_ms())
            .expect("get replaced candidate")
            .expect("replaced candidate");
        assert_eq!(replaced.envelope.status, 202);

        backend
            .delete("ns", body_key.as_str())
            .await
            .expect("delete body");
        assert!(
            backend
                .get_response_candidate("ns", "index", "obj:default", now_ms())
                .expect("get deleted candidate")
                .is_none()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_slices_hot_stream_objects_without_spawning_file_io() {
        let dir = temp_dir("hot-stream");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let body = CachedBody::from_bytes(Bytes::from_static(b"0123456789"));
        backend
            .put_object("ns", "body", &body, 60)
            .await
            .expect("put object");
        fs::remove_file(backend.path_for("ns", "body")).expect("remove persisted object");

        let mut stream = backend
            .get_object_stream("ns", "body", 10, Some((2, 5)))
            .await
            .expect("get stream")
            .expect("hot stream")
            .body;
        assert!(stream.take_file_region_without_trailers().is_none());
        let mut received = Vec::new();
        while let Some(chunk) = stream.data().await {
            received.extend_from_slice(&chunk.expect("chunk"));
        }
        assert_eq!(received, b"2345");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn canonical_small_bodies_do_not_retain_zero_copy_files() {
        let dir = temp_dir("canonical-small-body");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let key = super::super::types::cache_body_storage_key("small-variant");
        let body = CachedBody::from_bytes(Bytes::from(vec![b'x'; 1024]));
        backend
            .put_object("ns", &key, &body, 60)
            .await
            .expect("put object");

        let recent = backend.hot_recent.load();
        let entry = recent_hot_entry(&recent, "ns", &key, now_ms()).expect("recent body");
        assert!(entry.file.is_none());
        drop(recent);

        let mut stream = backend
            .get_object_stream("ns", &key, 1024, None)
            .await
            .expect("get stream")
            .expect("cached stream");
        assert!(stream.body.take_file_region_without_trailers().is_none());
        assert_eq!(
            stream.body.data().await.expect("body").expect("bytes"),
            Bytes::from(vec![b'x'; 1024])
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn canonical_body_keys_receive_file_regions_independent_of_route_names() {
        let dir = temp_dir("canonical-body-region");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let key = super::super::types::cache_body_storage_key("ordinary-route-variant");
        let body = CachedBody::from_bytes(Bytes::from(vec![b'x'; 64 * 1024]));
        backend
            .put_object("ordinary-namespace", &key, &body, 60)
            .await
            .expect("put object");

        let mut stream = backend
            .get_object_stream("ordinary-namespace", &key, 64 * 1024, None)
            .await
            .expect("get stream")
            .expect("cached stream");
        let region = stream
            .body
            .take_file_region_without_trailers()
            .expect("canonical cache body file region");
        assert_eq!(region.len(), 64 * 1024);
        assert!(region.offset() > 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn disk_cache_file_ids_round_trip_only_canonical_paths() {
        let dir = temp_dir("file-id-round-trip");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let id = cache_file_id("ordinary-namespace", "ordinary-key");
        let path = backend.path_for_id(id);
        assert_eq!(cache_file_id_from_path(&dir, &path), Some(id));

        let encoded = cache_file_id_hex(id);
        let misplaced = dir
            .join("ff")
            .join(&encoded[2..4])
            .join(format!("{encoded}.{DISK_CACHE_FILE_EXT}"));
        assert_eq!(cache_file_id_from_path(&dir, &misplaced), None);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_purges_expired_on_read() {
        let dir = temp_dir("expired");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend.put("ns", "key", b"value", 0).await.expect("put");
        let value = backend.get("ns", "key").await.expect("get");
        assert!(value.is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_evicts_oldest_past_budget() {
        let dir = temp_dir("evict");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let first = vec![b'a'; 600 * 1024];
        let second = vec![b'b'; 600 * 1024];
        backend.put("ns", "a", &first, 60).await.expect("put first");
        tokio::time::sleep(Duration::from_millis(2)).await;
        backend
            .put("ns", "b", &second, 60)
            .await
            .expect("put second");
        assert!(backend.get("ns", "a").await.expect("get first").is_none());
        assert!(backend.get("ns", "b").await.expect("get second").is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn disk_backend_rejects_symlink_root() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlink-target");
        let link = dir.with_extension("link");
        symlink(&dir, &link).expect("symlink");
        let err = match DiskCacheBackend::new(cfg(link.clone(), 1024 * 1024)) {
            Ok(_) => panic!("symlink root must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("symlinked disk cache path"),
            "unexpected error: {err}"
        );
        let _ = fs::remove_file(link);
        let _ = fs::remove_dir_all(dir);
    }
}
