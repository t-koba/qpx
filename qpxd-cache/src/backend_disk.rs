use super::types::{
    BodyStreamWriteOptions, CacheBackend, CachedBody, CachedBodyStream, CachedResponseCandidate,
    CachedResponseEnvelope, MetadataEncoder, VariantIndex, cache_body_storage_key,
    decode_cached_response_metadata, is_cache_body_storage_key,
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
use std::io::{IoSlice, Read, Seek, Write};
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
    hot_entries: LruCache<DiskCacheFileId, HotCacheEntry>,
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
    value: Option<Bytes>,
    metadata: Option<Bytes>,
    expires_at_ms: u64,
    body_offset: u64,
}

impl HotCacheEntry {
    fn memory_len(&self) -> u64 {
        self.value.as_ref().map_or(0, |value| value.len() as u64)
            + self.metadata.as_ref().map_or(0, |value| value.len() as u64)
    }
}

struct HotCacheValue {
    body: Bytes,
    metadata: Option<(String, Bytes)>,
}

impl From<Bytes> for HotCacheValue {
    fn from(body: Bytes) -> Self {
        Self {
            body,
            metadata: None,
        }
    }
}

#[derive(Clone)]
struct RecentHotCacheEntry {
    file_id: DiskCacheFileId,
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
    entries: Vec<Option<std::sync::Arc<RecentHotCacheEntry>>>,
    file_filter: u64,
}

impl Default for RecentHotCache {
    fn default() -> Self {
        Self {
            shards: (0..DISK_CACHE_RECENT_SHARDS)
                .map(|_| {
                    std::sync::Arc::new(RecentHotCacheShard {
                        entries: vec![None; DISK_CACHE_RECENT_ENTRIES_PER_SHARD],
                        file_filter: 0,
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
    file: File,
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
            if let Err(error) = cloned.ensure_indexed().await {
                warn!(error = ?error, "failed to initialize disk cache index");
            }
            cloned.background_sweep().await;
        });
    }

    fn path_for(&self, namespace: &str, key: &str) -> PathBuf {
        self.path_for_id(cache_file_id(namespace, key))
    }

    fn path_for_id(&self, id: DiskCacheFileId) -> PathBuf {
        let digest = cache_file_id_hex(id);
        let capacity = self.root.as_os_str().as_encoded_bytes().len()
            + digest.len()
            + DISK_CACHE_FILE_EXT.len()
            + 8;
        let mut path = PathBuf::with_capacity(capacity);
        path.push(&self.root);
        path.push(&digest[0..2]);
        path.push(&digest[2..4]);
        path.push(&digest);
        path.set_extension(DISK_CACHE_FILE_EXT);
        path
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
        for path in collect_cache_files(&self.root)? {
            let Some(id) = cache_file_id_from_path(&self.root, &path) else {
                remove_cache_file_sync(&path)?;
                continue;
            };
            match read_disk_cache_header_sync(&path) {
                Ok(read) => {
                    if read.header.expires_at_ms <= now_ms() {
                        remove_cache_file_sync(&path)?;
                        continue;
                    }
                    let touched_at_ms = read
                        .file
                        .metadata()?
                        .modified()?
                        .duration_since(UNIX_EPOCH)?
                        .as_millis() as u64;
                    entries.insert(
                        id,
                        DiskCacheIndexEntry {
                            total_len: read.total_len,
                            expires_at_ms: read.header.expires_at_ms,
                            touched_at_ms,
                        },
                    );
                }
                Err(error) if cache_file_not_found(&error) => continue,
                Err(error) => return Err(error),
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
            Err(error) if cache_file_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        if read.header.expires_at_ms <= now_ms() {
            self.delete_path(&path).await?;
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
        let file_id = cache_file_id(namespace, key);
        let path = self.path_for_id(file_id);
        self.hot_get_from_lru(namespace, key, file_id, path, now)
            .await
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
        file_id: DiskCacheFileId,
        path: PathBuf,
        now: u64,
    ) -> HotCacheLookup {
        let mut state = self.state.lock().await;
        let expired = state
            .hot_entries
            .peek(&file_id)
            .is_some_and(|entry| entry.expires_at_ms <= now);
        if expired {
            if let Some(entry) = state.hot_entries.pop(&file_id) {
                state.hot_bytes = state.hot_bytes.saturating_sub(entry.memory_len());
            }
            return HotCacheLookup::Miss(path);
        }
        let value = state.hot_entries.get(&file_id).and_then(|entry| {
            entry
                .value
                .as_ref()
                .map(|value| (value.clone(), entry.expires_at_ms, entry.body_offset))
        });
        drop(state);
        if let Some((value, expires_at_ms, body_offset)) = value {
            let file = open_zero_copy_source(key, &path, value.len() as u64);
            self.hot_recent_upsert(
                [
                    Some(RecentHotCacheEntry {
                        file_id,
                        namespace: std::sync::Arc::from(namespace),
                        key: std::sync::Arc::from(key),
                        path,
                        value: value.clone(),
                        expires_at_ms,
                        body_offset,
                        file: file.clone(),
                    }),
                    None,
                ],
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
        value: HotCacheValue,
        expires_at_ms: u64,
        body_offset: u64,
    ) {
        if self.hot_max_bytes == 0 || expires_at_ms <= now_ms() {
            return;
        }
        let eligible = |bytes: &Bytes| {
            bytes.len() as u64 <= self.hot_max_object_bytes
                && bytes.len() as u64 <= self.hot_max_bytes
        };
        let body = eligible(&value.body).then_some(value.body);
        let metadata = value.metadata.filter(|(_, bytes)| eligible(bytes));
        if body.is_none() && metadata.is_none() {
            return;
        }
        let file_id = cache_file_id_from_path(&self.root, &path)
            .expect("hot cache entry must reference a canonical disk object");
        let namespace = std::sync::Arc::<str>::from(namespace);
        let body_recent = body.as_ref().map(|value| RecentHotCacheEntry {
            file_id,
            namespace: namespace.clone(),
            key: std::sync::Arc::from(key),
            path: path.clone(),
            value: value.clone(),
            expires_at_ms,
            body_offset,
            file: open_zero_copy_source(key, &path, value.len() as u64),
        });
        let metadata_recent = metadata.as_ref().map(|(key, value)| RecentHotCacheEntry {
            file_id,
            namespace: namespace.clone(),
            key: std::sync::Arc::from(key.as_str()),
            path,
            value: value.clone(),
            expires_at_ms,
            body_offset,
            file: None,
        });
        let entry = HotCacheEntry {
            value: body,
            metadata: metadata.map(|(_, bytes)| bytes),
            expires_at_ms,
            body_offset,
        };
        let mut state = self.state.lock().await;
        if let Some(previous) = state.hot_entries.pop(&file_id) {
            state.hot_bytes = state.hot_bytes.saturating_sub(previous.memory_len());
        }
        state.hot_bytes = state.hot_bytes.saturating_add(entry.memory_len());
        state.hot_entries.put(file_id, entry);
        let mut evicted_ids = Vec::new();
        while state.hot_bytes > self.hot_max_bytes
            || state.hot_entries.len() > DISK_CACHE_HOT_MAX_ENTRIES
        {
            let Some((evicted_id, evicted)) = state.hot_entries.pop_lru() else {
                state.hot_bytes = 0;
                break;
            };
            evicted_ids.push(evicted_id);
            state.hot_bytes = state.hot_bytes.saturating_sub(evicted.memory_len());
        }
        drop(state);
        let retained = !evicted_ids.contains(&file_id);
        // Publish the completed file's eligible views together and remove
        // obsolete views from this publication snapshot.
        evicted_ids.push(file_id);
        self.hot_recent_upsert(
            if retained {
                [body_recent, metadata_recent]
            } else {
                [None, None]
            },
            &evicted_ids,
        );
    }

    async fn hot_remove(&self, path: &Path) {
        let file_id = cache_file_id_from_path(&self.root, path)
            .expect("hot cache removal must reference a canonical disk object");
        self.hot_recent_remove(file_id);
        let mut state = self.state.lock().await;
        if let Some(entry) = state.hot_entries.pop(&file_id) {
            state.hot_bytes = state.hot_bytes.saturating_sub(entry.memory_len());
        }
    }

    async fn delete_path(&self, path: &Path) -> Result<()> {
        let file_id = cache_file_id_from_path(&self.root, path)
            .ok_or_else(|| anyhow!("invalid disk cache object path: {}", path.display()))?;
        match tokio::fs::remove_file(path).await {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to remove disk cache object {}", path.display())
                });
            }
        }
        self.hot_recent_remove(file_id);
        let mut state = self.state.lock().await;
        if let Some(entry) = state.hot_entries.pop(&file_id) {
            state.hot_bytes = state.hot_bytes.saturating_sub(entry.memory_len());
        }
        if let Some(entry) = state.entries.remove(&file_id) {
            state.total_bytes = state.total_bytes.saturating_sub(entry.total_len);
        }
        Ok(())
    }

    fn hot_recent_upsert(
        &self,
        entries: [Option<RecentHotCacheEntry>; 2],
        removed: &[DiskCacheFileId],
    ) {
        // Snapshot updates share immutable records instead of copying every
        // retained path, payload handle, and key in the affected shard.
        let entries = entries.map(|entry| entry.map(std::sync::Arc::new));
        let _update =
            HotRecentUpdateGuard::acquire(&self.hot_recent_update, &self.hot_recent_generation);
        self.hot_recent.rcu(|current| {
            let mut shards = current.shards.clone();
            if !removed.is_empty() {
                let filter = removed
                    .iter()
                    .fold(0, |bits, id| bits | recent_file_bit(*id));
                for (index, shard) in current.shards.iter().enumerate() {
                    if shard.file_filter & filter == 0 {
                        continue;
                    }
                    for (offset, entry) in shard.entries.iter().enumerate() {
                        if entry
                            .as_ref()
                            .is_some_and(|entry| removed.contains(&entry.file_id))
                        {
                            let slot = index * DISK_CACHE_RECENT_ENTRIES_PER_SHARD + offset;
                            *recent_hot_entry_mut(&mut shards, slot) = None;
                        }
                    }
                }
            }
            for entry in entries.iter().flatten() {
                let slot = hot_slot(entry.namespace.as_ref(), entry.key.as_ref());
                *recent_hot_entry_mut(&mut shards, slot) = Some(entry.clone());
            }
            refresh_recent_file_filters(current, &mut shards);
            RecentHotCache { shards }
        });
    }

    fn hot_recent_remove(&self, file_id: DiskCacheFileId) {
        if !self
            .hot_recent
            .load()
            .shards
            .iter()
            .filter(|shard| shard.file_filter & recent_file_bit(file_id) != 0)
            .flat_map(|shard| shard.entries.iter().flatten())
            .any(|entry| entry.file_id == file_id)
        {
            return;
        }
        let _update =
            HotRecentUpdateGuard::acquire(&self.hot_recent_update, &self.hot_recent_generation);
        self.hot_recent.rcu(|current| {
            let mut shards = current.shards.clone();
            for (index, shard) in current.shards.iter().enumerate() {
                if shard.file_filter & recent_file_bit(file_id) == 0 {
                    continue;
                }
                for (offset, entry) in shard.entries.iter().enumerate() {
                    if entry.as_ref().is_some_and(|entry| entry.file_id == file_id) {
                        let slot = index * DISK_CACHE_RECENT_ENTRIES_PER_SHARD + offset;
                        *recent_hot_entry_mut(&mut shards, slot) = None;
                    }
                }
            }
            refresh_recent_file_filters(current, &mut shards);
            RecentHotCache { shards }
        });
    }

    async fn remember_write(
        &self,
        path: PathBuf,
        total_len: u64,
        expires_at_ms: u64,
    ) -> Result<()> {
        let _phase = crate::perf_diagnostics::phase_timer!("cache_index_update");
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

    async fn sweep_expired(&self) -> Result<()> {
        self.ensure_indexed().await?;
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
            self.delete_path(&path).await?;
        }
        Ok(())
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
                return Err(anyhow!(
                    "disk cache capacity accounting has no eviction candidate"
                ));
            };
            let path = self.path_for_id(id);
            self.delete_path(&path).await?;
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
            value.into(),
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
        // The collector already enforces size and read deadlines. Passing the
        // source through another bounded channel duplicates tasks and checks
        // on every miss without changing the storage boundary.
        let transfer_phase = crate::perf_diagnostics::phase_timer!("cache_body_transfer");
        let cached =
            CachedBody::from_body_limited(body, options.max_body_bytes, options.body_read_timeout)
                .await?;
        drop(transfer_phase);
        let len = cached.len();
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
        let _phase = crate::perf_diagnostics::phase_timer!("cache_persistence");
        if let CachedBody::Memory(value) = body {
            let write_path = path.to_path_buf();
            let value = value.clone();
            let (meta_key, meta_bytes) = metadata.unzip();
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
                HotCacheValue {
                    body: value,
                    metadata: meta_key.zip(written_meta),
                },
                write.expires_at_ms,
                write.body_offset,
            )
            .await;
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
            let body_offset = write_header_async(&mut file, &header).await?;
            while let Some(chunk) = source.data().await {
                file.write_all(chunk?.as_ref()).await?;
            }
            if let Some((_, meta)) = metadata.as_ref() {
                file.write_all(&(meta.len() as u32).to_be_bytes()).await?;
                file.write_all(meta.as_ref()).await?;
            }
            // Tokio file writes can complete before their blocking I/O has
            // drained. Finish those writes before publishing the object.
            file.flush().await?;
            // Cache objects are re-fetchable, so commit to the page cache and
            // publish atomically via rename instead of paying for an fsync.
            let body_len = header.body_len;
            drop(file);
            fs::rename(&tmp_path, path).with_context(|| {
                format!("failed to commit disk cache object {}", path.display())
            })?;
            Ok(body_offset + body_len + header.trailer_len())
        }
        .await;
        if streamed.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        let total_len = streamed?;
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
            if let Err(error) = self.sweep_expired().await {
                warn!(error = ?error, "failed to expire disk cache objects");
            }
            if let Err(error) = self.evict_if_needed().await {
                warn!(error = ?error, "failed to enforce disk cache capacity");
            }
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
        let file = TokioFile::from_std(read.file);
        let mut out = Vec::with_capacity(read.header.body_len.min(usize::MAX as u64) as usize);
        file.take(read.header.body_len)
            .read_to_end(&mut out)
            .await?;
        let value = Bytes::from(out);
        self.hot_insert(
            namespace,
            key,
            read.path,
            value.clone().into(),
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
                if variants.variants.len() == 1 {
                    Some((variants, index_entry.expires_at_ms))
                } else {
                    None
                }
            }
            None => None,
        };
        // Neither an absent object nor a decoded variant needs an owned key copy.
        let (variant_key, index_expires_at_ms) = match &resolved {
            Some((variants, expires_at_ms)) => (variants.variants[0].as_str(), *expires_at_ms),
            None => (default_variant_key, u64::MAX),
        };
        let Some(metadata_entry) = recent_hot_entry(&recent, namespace, variant_key, now) else {
            return Ok(None);
        };
        let envelope =
            self.decode_response_metadata(namespace, variant_key, metadata_entry.value.clone())?;
        let body_key = cache_body_storage_key(variant_key);
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
            let file = TokioFile::from_std(read.file);
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
                value.clone().into(),
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
                let mut file = TokioFile::from_std(read.file);
                if start_offset != read.body_offset {
                    file.seek(std::io::SeekFrom::Start(start_offset)).await?;
                }
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
        self.delete_path(&path).await
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
        .as_deref()
}

fn recent_file_bit(id: DiskCacheFileId) -> u64 {
    1_u64 << (id.0[0] & 63)
}

fn refresh_recent_file_filters(
    previous: &RecentHotCache,
    shards: &mut [std::sync::Arc<RecentHotCacheShard>],
) {
    for (previous, shard) in previous.shards.iter().zip(shards) {
        if std::sync::Arc::ptr_eq(previous, shard) {
            continue;
        }
        let shard = std::sync::Arc::make_mut(shard);
        // The filter only skips impossible matches; removal still compares
        // complete file identities, including when filter bits collide.
        shard.file_filter = shard
            .entries
            .iter()
            .flatten()
            .fold(0, |bits, entry| bits | recent_file_bit(entry.file_id));
    }
}

fn recent_hot_entry_mut(
    shards: &mut [std::sync::Arc<RecentHotCacheShard>],
    slot: usize,
) -> &mut Option<std::sync::Arc<RecentHotCacheEntry>> {
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
    let relative = path.strip_prefix(root).ok()?;
    let mut components = relative.components();
    let first = components.next()?.as_os_str().to_str()?;
    let second = components.next()?.as_os_str().to_str()?;
    let filename = components.next()?.as_os_str();
    if components.next().is_some() || path.file_name()? != filename {
        return None;
    }
    if path.extension().and_then(|extension| extension.to_str()) != Some(DISK_CACHE_FILE_EXT) {
        return None;
    }
    let encoded = path.file_stem()?.to_str()?;
    if encoded.len() != 64 {
        return None;
    }
    if first.as_bytes() != &encoded.as_bytes()[0..2]
        || second.as_bytes() != &encoded.as_bytes()[2..4]
    {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest[index] = decode_hex_nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_hex_nibble(pair[1])?)?;
    }
    Some(DiskCacheFileId(digest))
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

fn remove_cache_file_sync(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to remove disk cache object {}", path.display())),
    }
}

fn collect_cache_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    collect_cache_files_inner(root, &mut out)?;
    Ok(out)
}

fn collect_cache_files_inner(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
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

fn cache_file_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

fn read_disk_cache_header_sync(path: &Path) -> Result<DiskCacheRead> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Validate and open the same object; a separate lstat both duplicates
        // miss I/O and leaves a symlink replacement window before open.
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    reject_symlink(path)?;
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open disk cache object {}", path.display()))?;
    let meta = file.metadata()?;
    let mut magic = [0; DISK_CACHE_MAGIC.len()];
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
        file,
        path: path.to_path_buf(),
        header,
        body_offset,
        total_len: meta.len(),
    })
}

fn read_metadata_trailer_sync(path: &Path) -> Result<Option<Bytes>> {
    let read = match read_disk_cache_header_sync(path) {
        Ok(read) => read,
        Err(error) if cache_file_not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    if read.header.meta_len == 0 {
        return Ok(None);
    }
    if read.header.expires_at_ms <= now_ms() {
        return Ok(None);
    }
    let mut file = read.file;
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
        let raw_header = serde_json::to_vec(&header)?;
        let header_length = u32::try_from(raw_header.len())
            .context("disk cache header exceeds framing limit")?
            .to_be_bytes();
        let metadata_length = u32::try_from(metadata.as_ref().map_or(0, |meta| meta.len()))
            .context("disk cache metadata exceeds framing limit")?
            .to_be_bytes();
        let metadata_prefix = if metadata.is_some() {
            metadata_length.as_slice()
        } else {
            &[]
        };
        let mut buffers = [
            IoSlice::new(DISK_CACHE_MAGIC),
            IoSlice::new(&header_length),
            IoSlice::new(&raw_header),
            IoSlice::new(&value),
            IoSlice::new(metadata_prefix),
            IoSlice::new(metadata.as_deref().unwrap_or(&[])),
        ];
        let mut remaining = buffers.as_mut_slice();
        while !remaining.is_empty() {
            match file.write_vectored(remaining) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "disk cache object write made no progress",
                    )
                    .into());
                }
                Ok(written) => IoSlice::advance_slices(&mut remaining, written),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let body_offset = DISK_CACHE_MAGIC.len() as u64 + 4 + raw_header.len() as u64;
        // Durability note: cache objects are re-fetchable from the origin, so
        // writes are committed to the page cache and published atomically via
        // rename without an fsync. This matches the behavior of other HTTP
        // caches and keeps write-heavy miss workloads off the disk sync path.
        let total_len = body_offset + header.body_len + header.trailer_len();
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
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                validate_directory_metadata(&current, metadata)?;
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect disk cache directory {}",
                        current.display()
                    )
                });
            }
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
                validate_directory_metadata(&current, fs::symlink_metadata(&current)?)?;
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
    Ok(())
}

fn validate_directory_metadata(path: &Path, metadata: fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(anyhow!(
            "refusing symlinked disk cache path component {}",
            path.display()
        ));
    }
    if !metadata.is_dir() {
        return Err(anyhow!(
            "disk cache path component is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn private_directory_guard_rechecks_replaced_parents() {
        let root = temp_dir("replaced-directory-parent");
        let outside = temp_dir("outside-directory-parent");
        let parent = root.join("objects");
        let target = parent.join("ab");
        ensure_private_dir(&target).expect("create private object directory");
        fs::rename(&parent, root.join("saved-objects")).expect("replace verified parent");
        std::os::unix::fs::symlink(&outside, &parent).expect("install replacement symlink");
        let error = ensure_private_dir(&target).expect_err("reject replaced symlink parent");
        assert!(
            error
                .to_string()
                .contains("symlinked disk cache path component")
        );
        assert!(!outside.join("ab").exists());
        fs::remove_dir_all(root).expect("remove cache fixture");
        fs::remove_dir_all(outside).expect("remove outside fixture");
    }

    #[tokio::test]
    async fn disk_backend_reads_after_restart() {
        let dir = temp_dir("restart");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend.put("ns", "key", b"value", 60).await.expect("put");
        backend
            .put("ns", "empty", b"", 60)
            .await
            .expect("put empty object");
        drop(backend);

        let restarted = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("restart");
        let value = restarted
            .get("ns", "key")
            .await
            .expect("get")
            .expect("value");
        assert_eq!(value.as_ref(), b"value");
        assert!(
            restarted
                .get("ns", "empty")
                .await
                .expect("read empty object")
                .expect("persisted empty object")
                .is_empty()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_budget_accounts_for_complete_object_files() {
        let dir = temp_dir("physical-file-budget");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let objects: &[(&str, usize)] = if cfg!(unix) {
            &[("memory", 1024), ("spooled", 128 * 1024)]
        } else {
            &[("memory", 1024)]
        };
        for &(key, size) in objects {
            let body = CachedBody::from_body_limited(
                Body::from(vec![b'x'; size]),
                256 * 1024,
                Duration::from_secs(5),
            )
            .await
            .expect("collect real cache body");
            backend
                .put_object("ns", key, &body, 60)
                .await
                .expect("write cache object");
        }
        let mut physical_bytes = 0;
        for &(key, _) in objects {
            let path = backend.path_for("ns", key);
            let size = fs::metadata(&path).expect("persisted cache file").len();
            physical_bytes += size;
            let id = cache_file_id("ns", key);
            assert_eq!(backend.state.lock().await.entries[&id].total_len, size);
        }
        assert_eq!(backend.state.lock().await.total_bytes, physical_bytes);
        for &(key, size) in objects {
            let stored = backend
                .get_object_stream("ns", key, size as u64, None)
                .await
                .expect("read persisted cache object")
                .expect("complete cache object");
            assert_eq!(
                qpx_http::body::to_bytes(stored.body)
                    .await
                    .expect("read persisted body"),
                vec![b'x'; size]
            );
        }
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

    // The streamed-file body path spills through qpx-core secure temp files,
    // which only implement owner-only semantics on Unix today.
    #[cfg(unix)]
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
        // Verify the on-disk object directly first, so a failing metadata
        // read below can be told apart from a bad write.
        let stored_path = backend.path_for("ns", cache_body_storage_key("variant").as_str());
        let bytes = fs::read(&stored_path).expect("read stored object");
        let header_len =
            u32::from_be_bytes(bytes[16..20].try_into().expect("header length")) as usize;
        let header: DiskCacheHeader =
            serde_json::from_slice(&bytes[20..20 + header_len]).expect("parse header");
        assert_eq!(header.body_len, big.len() as u64, "stored body length");
        assert!(
            header.meta_len > 0,
            "stored object must carry a metadata trailer"
        );
        assert_eq!(
            bytes.len() as u64,
            20 + header_len as u64 + header.body_len + header.trailer_len(),
            "stored object length accounting"
        );
        let raw = backend
            .read_response_metadata("ns", "variant")
            .await
            .expect("read metadata")
            .unwrap_or_else(|| {
                panic!(
                    "metadata present (stored {} bytes, header body_len {} meta_len {})",
                    bytes.len(),
                    header.body_len,
                    header.meta_len
                )
            });
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
            response_base_headers: Default::default(),
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
            response_base_headers: Default::default(),
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
        std::sync::Arc::make_mut(updated_entry).value = updated_metadata;
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
    async fn recent_file_filter_collision_preserves_unrelated_cache_objects() {
        let dir = temp_dir("recent-file-filter-collision");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let first = "first";
        let first_id = cache_file_id("ns", first);
        let second = (0..10_000)
            .map(|index| format!("second-{index}"))
            .find(|key| {
                let id = cache_file_id("ns", key);
                id != first_id
                    && recent_file_bit(id) == recent_file_bit(first_id)
                    && hot_slot("ns", key) != hot_slot("ns", first)
            })
            .expect("find distinct real keys sharing a filter bit");
        backend
            .put("ns", first, b"original", 60)
            .await
            .expect("put first");
        backend
            .put("ns", &second, b"unrelated", 60)
            .await
            .expect("put second");
        backend
            .put("ns", first, b"replacement", 60)
            .await
            .expect("replace first");
        backend.delete("ns", first).await.expect("delete first");
        assert!(backend.hot_recent_lookup("ns", first, now_ms()).is_none());
        assert!(matches!(
            backend.hot_recent_lookup("ns", &second, now_ms()),
            Some(HotCacheLookup::Hit { value, .. }) if value == b"unrelated"[..]
        ));
        assert_eq!(
            backend.get("ns", &second).await.expect("read unrelated"),
            Some(Bytes::from_static(b"unrelated"))
        );
        assert!(
            backend
                .get("ns", first)
                .await
                .expect("read deleted")
                .is_none()
        );
        fs::remove_dir_all(dir).expect("remove cache directory");
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
        let non_ascii = format!("{}x", "€".repeat(21));
        assert_eq!(non_ascii.len(), 64);
        assert_eq!(
            cache_file_id_from_path(
                &dir,
                &dir.join("00")
                    .join("00")
                    .join(format!("{non_ascii}.{DISK_CACHE_FILE_EXT}"))
            ),
            None
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_cache_delete_rejects_noncanonical_paths_before_io() {
        let dir = temp_dir("delete-path-validation");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let path = dir.join("unrelated-file");
        fs::write(&path, b"preserved").expect("write unrelated file");

        let error = backend
            .delete_path(&path)
            .await
            .expect_err("noncanonical object path must be rejected");
        assert!(error.to_string().contains("invalid disk cache object path"));
        assert_eq!(
            fs::read(&path).expect("read preserved unrelated file"),
            b"preserved"
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn inline_metadata_does_not_replace_lru_body_after_recent_collision() {
        let dir = temp_dir("inline-metadata-lru-collision");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let metadata_key = "obj:collision:default";
        let body_key = cache_body_storage_key(metadata_key);
        let path = backend.path_for("ns", &body_key);
        backend
            .put_object_path(
                "ns",
                &body_key,
                &path,
                &CachedBody::from_bytes(Bytes::from_static(b"original")),
                Some((metadata_key.to_string(), Bytes::from_static(b"metadata"))),
                60,
            )
            .await
            .expect("persist body and inline metadata");
        let collision = (0..10_000)
            .map(|index| format!("collision-{index}"))
            .find(|key| hot_slot("ns", key) == hot_slot("ns", &body_key))
            .expect("find a real recent-cache slot collision");
        backend
            .put("ns", &collision, b"x", 60)
            .await
            .expect("put collision");
        assert!(
            backend
                .hot_recent_lookup("ns", &body_key, now_ms())
                .is_none()
        );
        assert_eq!(
            backend
                .get("ns", &body_key)
                .await
                .expect("read body through LRU"),
            Some(Bytes::from_static(b"original"))
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn inline_metadata_and_body_both_count_toward_hot_capacity() {
        let dir = temp_dir("inline-metadata-hot-capacity");
        let mut backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend.hot_max_bytes = 16;
        let metadata_key = "obj:capacity:default";
        let body_key = cache_body_storage_key(metadata_key);
        let path = backend.path_for("ns", &body_key);
        backend
            .put_object_path(
                "ns",
                &body_key,
                &path,
                &CachedBody::from_bytes(Bytes::from_static(b"original")),
                Some((metadata_key.to_string(), Bytes::from_static(b"metadata"))),
                60,
            )
            .await
            .expect("persist body and metadata within hot capacity");
        assert_eq!(backend.state.lock().await.hot_bytes, 16);
        backend
            .put("ns", "other", b"replaced", 60)
            .await
            .expect("evict combined object");
        assert!(
            backend
                .hot_recent_lookup("ns", &body_key, now_ms())
                .is_none()
        );
        assert!(
            backend
                .hot_recent_lookup("ns", metadata_key, now_ms())
                .is_none()
        );
        assert!(backend.state.lock().await.hot_bytes <= 16);
        assert_eq!(
            backend
                .get("ns", &body_key)
                .await
                .expect("read persistent body"),
            Some(Bytes::from_static(b"original"))
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn inline_metadata_remains_hot_when_body_exceeds_object_limit() {
        let dir = temp_dir("inline-metadata-large-body");
        let mut backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend.hot_max_object_bytes = 8;
        let metadata_key = "obj:large-body:default";
        let body_key = cache_body_storage_key(metadata_key);
        let path = backend.path_for("ns", &body_key);
        backend
            .put_object_path(
                "ns",
                &body_key,
                &path,
                &CachedBody::from_bytes(Bytes::from_static(b"large-body")),
                Some((metadata_key.to_string(), Bytes::from_static(b"metadata"))),
                60,
            )
            .await
            .expect("persist large body and small metadata");
        assert!(
            backend
                .hot_recent_lookup("ns", &body_key, now_ms())
                .is_none()
        );
        assert!(matches!(
            backend.hot_recent_lookup("ns", metadata_key, now_ms()),
            Some(HotCacheLookup::Hit { .. })
        ));
        assert_eq!(backend.state.lock().await.hot_bytes, 8);
        assert_eq!(
            backend
                .get("ns", &body_key)
                .await
                .expect("read large disk body"),
            Some(Bytes::from_static(b"large-body"))
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn combined_hot_file_over_capacity_leaves_no_recent_views() {
        let dir = temp_dir("inline-metadata-combined-capacity");
        let mut backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend.hot_max_bytes = 8;
        let metadata_key = "obj:combined-capacity:default";
        let body_key = cache_body_storage_key(metadata_key);
        let path = backend.path_for("ns", &body_key);
        backend
            .put_object_path(
                "ns",
                &body_key,
                &path,
                &CachedBody::from_bytes(Bytes::from_static(b"original")),
                Some((metadata_key.to_string(), Bytes::from_static(b"metadata"))),
                60,
            )
            .await
            .expect("persist object exceeding combined hot capacity");
        assert_eq!(backend.state.lock().await.hot_bytes, 0);
        assert!(
            backend
                .hot_recent_lookup("ns", &body_key, now_ms())
                .is_none()
        );
        assert!(
            backend
                .hot_recent_lookup("ns", metadata_key, now_ms())
                .is_none()
        );
        assert_eq!(
            backend
                .read_response_metadata("ns", metadata_key)
                .await
                .expect("read disk metadata"),
            Some(Bytes::from_static(b"metadata"))
        );
        assert_eq!(
            backend.get("ns", &body_key).await.expect("read disk body"),
            Some(Bytes::from_static(b"original"))
        );
        fs::remove_dir_all(dir).expect("remove test directory");
    }

    #[tokio::test]
    async fn disk_hot_eviction_invalidates_body_and_metadata_by_file_identity() {
        let dir = temp_dir("hot-file-identity-eviction");
        let mut backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend.hot_max_bytes = 16;
        let body_key = cache_body_storage_key("obj:eviction:default");
        let metadata_key = "obj:eviction:default";
        assert_ne!(hot_slot("ns", &body_key), hot_slot("ns", metadata_key));
        let path = backend.path_for("ns", &body_key);
        backend
            .put_object_path(
                "ns",
                &body_key,
                &path,
                &CachedBody::from_bytes(Bytes::from_static(b"original")),
                Some((metadata_key.to_string(), Bytes::from_static(b"metadata"))),
                60,
            )
            .await
            .expect("persist source body and metadata");
        assert!(matches!(
            backend.hot_recent_lookup("ns", &body_key, now_ms()),
            Some(HotCacheLookup::Hit { .. })
        ));
        assert!(matches!(
            backend.hot_recent_lookup("ns", metadata_key, now_ms()),
            Some(HotCacheLookup::Hit { .. })
        ));
        backend
            .put("ns", "other", b"replaced-content", 60)
            .await
            .expect("evict source hot entry");
        assert!(
            backend
                .hot_recent_lookup("ns", &body_key, now_ms())
                .is_none()
        );
        assert!(
            backend
                .hot_recent_lookup("ns", metadata_key, now_ms())
                .is_none()
        );
        assert!(
            path.is_file(),
            "hot eviction must retain the persistent object"
        );
        assert_eq!(
            backend
                .get("ns", &body_key)
                .await
                .expect("read persistent source"),
            Some(Bytes::from_static(b"original"))
        );
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

    #[tokio::test]
    async fn disk_backend_preserves_validated_file_snapshot_after_replacement() {
        let dir = temp_dir("validated-file-snapshot");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend
            .put("ns", "key", b"original", 60)
            .await
            .expect("put original");
        let path = backend.path_for("ns", "key");
        let mut read = read_disk_cache_header_sync(&path).expect("validated original file");
        write_cached_bytes_sync(&path, Bytes::from_static(b"replaced"), 60)
            .expect("replace object atomically");
        let mut snapshot = Vec::new();
        read.file
            .read_to_end(&mut snapshot)
            .expect("read validated descriptor");
        assert_eq!(snapshot, b"original");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_reports_read_errors_instead_of_cache_misses() {
        let dir = temp_dir("read-error-propagation");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend
            .ensure_indexed()
            .await
            .expect("initialize cache index");
        assert!(
            backend
                .get("ns", "absent")
                .await
                .expect("absent object")
                .is_none()
        );
        let path = backend.path_for("ns", "directory");
        ensure_private_dir(path.parent().expect("object parent")).expect("create object parent");
        fs::create_dir(&path).expect("create invalid object directory");
        assert!(backend.get("ns", "directory").await.is_err());
        assert!(read_metadata_trailer_sync(&path).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_rejects_invalid_initial_objects_without_deleting_evidence() {
        let dir = temp_dir("initial-index-error");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let path = backend.path_for("ns", "invalid");
        ensure_private_dir(path.parent().expect("object parent")).expect("create object parent");
        fs::write(&path, b"invalid cache object").expect("write invalid object");
        assert!(backend.ensure_indexed().await.is_err());
        assert!(!backend.indexed_flag.load(Ordering::Acquire));
        assert_eq!(
            fs::read(&path).expect("preserved invalid object"),
            b"invalid cache object"
        );
        assert!(backend.get("ns", "absent").await.is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_preserves_capacity_accounting_after_failed_eviction() {
        let dir = temp_dir("failed-eviction-accounting");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let value = vec![b'a'; 600 * 1024];
        backend
            .put("ns", "first", &value, 60)
            .await
            .expect("put first");
        let path = backend.path_for("ns", "first");
        let id = cache_file_id("ns", "first");
        let first_len = backend.state.lock().await.total_bytes;
        fs::remove_file(&path).expect("remove first object");
        fs::create_dir(&path).expect("replace first object with directory");
        assert!(backend.delete("ns", "first").await.is_err());
        {
            let state = backend.state.lock().await;
            assert_eq!(state.total_bytes, first_len);
            assert!(state.entries.contains_key(&id));
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(backend.put("ns", "second", &value, 60).await.is_err());
        {
            let state = backend.state.lock().await;
            assert!(state.total_bytes > backend.max_bytes);
            assert!(state.entries.contains_key(&id));
        }
        fs::remove_dir(&path).expect("remove invalid object directory");
        backend
            .evict_if_needed()
            .await
            .expect("reconcile absent object");
        assert!(backend.state.lock().await.total_bytes <= backend.max_bytes);
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn disk_backend_rejects_symlinked_object_reads() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("symlinked-object-read");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend
            .put("ns", "source", b"protected", 60)
            .await
            .expect("put source");
        let source = backend.path_for("ns", "source");
        let path = backend.path_for("ns", "link");
        ensure_private_dir(path.parent().expect("object parent")).expect("create object parent");
        symlink(&source, &path).expect("create object symlink");
        assert!(backend.get("ns", "link").await.is_err());
        assert!(read_metadata_trailer_sync(&path).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
