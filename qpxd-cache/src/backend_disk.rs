#[cfg(unix)]
mod commit;

use super::types::{
    BodyStreamWriteOptions, CacheBackend, CachedBody, CachedBodyStream, CachedResponseCandidate,
    CachedResponseEnvelope, CommitLease, MetadataEncoder, VariantIndex, bounded_cache_body_stream,
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
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
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
// Each slot is a small set-associative bucket so co-published objects (index,
// metadata, body) survive hash collisions. Total bound: 16 * 16 * 4 = 1024.
const DISK_CACHE_RECENT_WAYS: usize = 4;
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
    shared: bool,
    #[cfg(unix)]
    commit_locks: Option<std::sync::Arc<commit::CommitLocks>>,
    max_bytes: u64,
    sweep_interval: Duration,
    hot_max_bytes: u64,
    hot_max_object_bytes: u64,
    hot_recent: std::sync::Arc<ArcSwap<RecentHotCache>>,
    hot_recent_update: std::sync::Arc<std::sync::Mutex<()>>,
    hot_recent_generation: std::sync::Arc<AtomicU64>,
    decoded_generation: std::sync::Arc<AtomicU64>,
    decoded_lifecycle: std::sync::Arc<std::sync::Mutex<()>>,
    decoded_variants: std::sync::Arc<Vec<ArcSwapOption<DecodedVariantIndexEntry>>>,
    decoded_metadata: std::sync::Arc<Vec<ArcSwapOption<DecodedMetadataEntry>>>,
    hot_responses: std::sync::Arc<Vec<ArcSwapOption<HotResponseEntry>>>,
    background_sweep_started: std::sync::Arc<AtomicBool>,
    indexed_flag: std::sync::Arc<AtomicBool>,
    state: std::sync::Arc<Mutex<DiskCacheState>>,
    #[cfg(test)]
    bookkeeping_waiters: std::sync::Arc<AtomicUsize>,
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
    #[cfg(unix)]
    identity: Option<commit::FileIdentity>,
    total_len: u64,
    expires_at_ms: u64,
    touched_at_ms: u64,
}

struct HotCacheEntry {
    // Co-located metadata and body share a path, but never logical identity.
    key: std::sync::Arc<str>,
    value: Bytes,
    expires_at_ms: u64,
    body_offset: u64,
}

#[derive(Clone)]
struct RecentHotCacheEntry {
    namespace: std::sync::Arc<str>,
    key: std::sync::Arc<str>,
    id: DiskCacheFileId,
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

type RecentHotBucket = [Option<RecentHotCacheEntry>; DISK_CACHE_RECENT_WAYS];

#[derive(Clone)]
struct RecentHotCacheShard {
    entries: Vec<RecentHotBucket>,
}

impl Default for RecentHotCache {
    fn default() -> Self {
        Self {
            shards: (0..DISK_CACHE_RECENT_SHARDS)
                .map(|_| {
                    std::sync::Arc::new(RecentHotCacheShard {
                        entries: (0..DISK_CACHE_RECENT_ENTRIES_PER_SHARD)
                            .map(|_| std::array::from_fn(|_| None))
                            .collect(),
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

fn same_arc_option<T>(left: Option<&std::sync::Arc<T>>, right: &Option<std::sync::Arc<T>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => std::sync::Arc::ptr_eq(left, right),
        _ => false,
    }
}

impl DiskCacheBackend {
    pub fn new(cfg: CacheBackendConfig) -> Result<Self> {
        let shared = cfg.writer_mode == qpx_core::config::CacheWriterMode::Shared;
        if shared && !cfg!(unix) {
            return Err(anyhow!("writer_mode shared requires disk OS locks on Unix"));
        }
        if cfg.commit_lock_stripes == 0 || cfg.timeout_ms == 0 {
            return Err(anyhow!(
                "disk commit_lock_stripes and timeout_ms must be > 0"
            ));
        }
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
        #[cfg(unix)]
        let commit_locks = if shared {
            Some(std::sync::Arc::new(commit::CommitLocks::new(
                &root,
                cfg.commit_lock_stripes,
                Duration::from_millis(cfg.timeout_ms),
            )?))
        } else {
            None
        };
        let backend = Self {
            root,
            shared,
            #[cfg(unix)]
            commit_locks,
            max_bytes,
            sweep_interval: Duration::from_secs(cfg.sweep_interval_secs.max(1)),
            hot_max_bytes: max_bytes.min(DISK_CACHE_HOT_MAX_BYTES),
            hot_max_object_bytes: (cfg.max_object_bytes as u64)
                .min(DISK_CACHE_HOT_MAX_OBJECT_BYTES),
            hot_recent: std::sync::Arc::new(ArcSwap::from_pointee(RecentHotCache::default())),
            hot_recent_update: std::sync::Arc::new(std::sync::Mutex::new(())),
            hot_recent_generation: std::sync::Arc::new(AtomicU64::new(0)),
            decoded_generation: std::sync::Arc::new(AtomicU64::new(0)),
            decoded_lifecycle: std::sync::Arc::new(std::sync::Mutex::new(())),
            decoded_variants: std::sync::Arc::new(decoded_slots()),
            decoded_metadata: std::sync::Arc::new(decoded_slots()),
            hot_responses: std::sync::Arc::new(decoded_slots()),
            background_sweep_started: std::sync::Arc::new(AtomicBool::new(false)),
            indexed_flag: std::sync::Arc::new(AtomicBool::new(false)),
            state: std::sync::Arc::new(Mutex::new(DiskCacheState::default())),
            #[cfg(test)]
            bookkeeping_waiters: std::sync::Arc::new(AtomicUsize::new(0)),
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
                if !self.shared {
                    let _ = fs::remove_file(&path);
                }
                continue;
            };
            // Re-read only after acquiring the object stripe: the directory
            // listing and all per-instance state may predate a replacement.
            let _object = self.lock_object(&path).await?;
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
                            #[cfg(unix)]
                            identity: Some(commit::FileIdentity::of(&read.file.metadata()?)),
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
        let _object = self.lock_object(&path).await?;
        let read = match read_disk_cache_header_sync(&path) {
            Ok(read) => read,
            Err(_) => return Ok(None),
        };
        if read.header.expires_at_ms <= now_ms() {
            let _ = self.delete_path_locked(&path).await;
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
        if self.shared {
            return HotCacheLookup::Miss(self.path_for(namespace, key));
        }
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
        if self.shared {
            return None;
        }
        let recent = self.hot_recent.load();
        let entry = recent_hot_entry_by_key(&recent, namespace, key)?;
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
        let Some(id) = cache_file_id_from_path(&self.root, &path) else {
            return HotCacheLookup::Miss(path);
        };
        let mut state = self.state.lock().await;
        let expired = state
            .hot_entries
            .peek(&id)
            .is_some_and(|entry| entry.expires_at_ms <= now);
        if expired {
            if let Some(entry) = state.hot_entries.pop(&id) {
                state.hot_bytes = state.hot_bytes.saturating_sub(entry.value.len() as u64);
            }
            return HotCacheLookup::Miss(path);
        }
        let value = state
            .hot_entries
            .get(&id)
            .filter(|entry| entry.key.as_ref() == key)
            .map(|entry| (entry.value.clone(), entry.expires_at_ms, entry.body_offset));
        drop(state);
        if let Some((value, expires_at_ms, body_offset)) = value {
            let file = open_zero_copy_source(key, &path, value.len() as u64);
            self.hot_recent_upsert(
                RecentHotCacheEntry {
                    namespace: std::sync::Arc::from(namespace),
                    key: std::sync::Arc::from(key),
                    id,
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

    fn decoded_generation(&self) -> u64 {
        self.decoded_generation.load(Ordering::Acquire)
    }

    fn decode_variant_index(
        &self,
        namespace: &str,
        key: &str,
        raw: Bytes,
        source_generation: u64,
    ) -> Result<std::sync::Arc<VariantIndex>> {
        if self.shared {
            return Ok(std::sync::Arc::new(serde_json::from_slice(&raw)?));
        }
        let slot = qpx_http::sharding::modulo(&(namespace, key), self.decoded_variants.len());
        let observed = self.decoded_variants[slot].load_full();
        if let Some(entry) = observed.as_ref()
            && entry.namespace.as_ref() == namespace
            && entry.key.as_ref() == key
            && same_bytes_allocation(&entry.raw, &raw)
        {
            return Ok(entry.value.clone());
        }
        let value: std::sync::Arc<VariantIndex> =
            std::sync::Arc::new(serde_json::from_slice(&raw)?);
        let entry = std::sync::Arc::new(DecodedVariantIndexEntry {
            namespace: std::sync::Arc::from(namespace),
            key: std::sync::Arc::from(key),
            raw,
            value: value.clone(),
        });
        self.publish_decoded_variant(slot, observed, entry, source_generation);
        Ok(value)
    }

    fn publish_decoded_variant(
        &self,
        slot: usize,
        observed: Option<std::sync::Arc<DecodedVariantIndexEntry>>,
        entry: std::sync::Arc<DecodedVariantIndexEntry>,
        source_generation: u64,
    ) {
        let _guard = self
            .decoded_lifecycle
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if self.decoded_generation.load(Ordering::Acquire) != source_generation {
            return;
        }
        self.decoded_variants[slot].rcu(|current| {
            if same_arc_option(observed.as_ref(), current) {
                Some(entry.clone())
            } else {
                current.clone()
            }
        });
    }

    fn publish_decoded_metadata(
        &self,
        slot: usize,
        observed: Option<std::sync::Arc<DecodedMetadataEntry>>,
        entry: std::sync::Arc<DecodedMetadataEntry>,
        source_generation: u64,
    ) {
        let _guard = self
            .decoded_lifecycle
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if self.decoded_generation.load(Ordering::Acquire) != source_generation {
            return;
        }
        self.decoded_metadata[slot].rcu(|current| {
            if same_arc_option(observed.as_ref(), current) {
                Some(entry.clone())
            } else {
                current.clone()
            }
        });
    }

    fn release_decoded_records(&self, namespace: &str, key: &str) {
        if self.shared {
            return;
        }
        let _guard = self
            .decoded_lifecycle
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        self.decoded_generation.fetch_add(1, Ordering::AcqRel);
        let variant_slot =
            qpx_http::sharding::modulo(&(namespace, key), self.decoded_variants.len());
        self.decoded_variants[variant_slot].rcu(|current| {
            if current.as_ref().is_some_and(|entry| {
                entry.namespace.as_ref() == namespace && entry.key.as_ref() == key
            }) {
                None
            } else {
                current.clone()
            }
        });
        let metadata_slot =
            qpx_http::sharding::modulo(&(namespace, key), self.decoded_metadata.len());
        self.decoded_metadata[metadata_slot].rcu(|current| {
            if current.as_ref().is_some_and(|entry| {
                entry.namespace.as_ref() == namespace && entry.key.as_ref() == key
            }) {
                None
            } else {
                current.clone()
            }
        });
    }

    fn decode_response_metadata(
        &self,
        namespace: &str,
        key: &str,
        raw: Bytes,
        source_generation: u64,
    ) -> Result<std::sync::Arc<CachedResponseEnvelope>> {
        if self.shared {
            return Ok(std::sync::Arc::new(decode_cached_response_metadata(raw)?));
        }
        let slot = qpx_http::sharding::modulo(&(namespace, key), self.decoded_metadata.len());
        let observed = self.decoded_metadata[slot].load_full();
        if let Some(entry) = observed.as_ref()
            && entry.namespace.as_ref() == namespace
            && entry.key.as_ref() == key
            && same_bytes_allocation(&entry.raw, &raw)
        {
            return Ok(entry.value.clone());
        }
        let value = std::sync::Arc::new(decode_cached_response_metadata(raw.clone())?);
        let entry = std::sync::Arc::new(DecodedMetadataEntry {
            namespace: std::sync::Arc::from(namespace),
            key: std::sync::Arc::from(key),
            raw,
            value: value.clone(),
        });
        self.publish_decoded_metadata(slot, observed, entry, source_generation);
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
        if self.shared
            || self.hot_max_bytes == 0
            || value_len > self.hot_max_object_bytes
            || value_len > self.hot_max_bytes
            || expires_at_ms <= now_ms()
        {
            return;
        }
        let Some(id) = cache_file_id_from_path(&self.root, &path) else {
            return;
        };
        let recent = RecentHotCacheEntry {
            namespace: std::sync::Arc::from(namespace),
            key: std::sync::Arc::from(key),
            id,
            path: path.clone(),
            value: value.clone(),
            expires_at_ms,
            body_offset,
            file: open_zero_copy_source(key, &path, value_len),
        };
        let mut state = self.state.lock().await;
        if let Some(previous) = state.hot_entries.pop(&id) {
            state.hot_bytes = state.hot_bytes.saturating_sub(previous.value.len() as u64);
        }
        state.hot_bytes = state.hot_bytes.saturating_add(value_len);
        state.hot_entries.put(
            id,
            HotCacheEntry {
                key: std::sync::Arc::from(key),
                value,
                expires_at_ms,
                body_offset,
            },
        );
        let mut evicted_ids = Vec::new();
        while state.hot_bytes > self.hot_max_bytes
            || state.hot_entries.len() > DISK_CACHE_HOT_MAX_ENTRIES
        {
            let Some((evicted_id, evicted)) = state.hot_entries.pop_lru() else {
                state.hot_bytes = 0;
                break;
            };
            evicted_ids.push(evicted_id);
            state.hot_bytes = state.hot_bytes.saturating_sub(evicted.value.len() as u64);
        }
        drop(state);
        self.hot_recent_upsert(recent, &evicted_ids);
    }

    async fn hot_remove(&self, path: &Path) {
        self.hot_recent_remove(path);
        let Some(id) = cache_file_id_from_path(&self.root, path) else {
            return;
        };
        let mut state = self.state.lock().await;
        if let Some(entry) = state.hot_entries.pop(&id) {
            state.hot_bytes = state.hot_bytes.saturating_sub(entry.value.len() as u64);
        }
    }

    // Optional guard keeps the default single-instance path free of OS locks.
    async fn lock_object(&self, path: &Path) -> Result<Option<File>> {
        #[cfg(unix)]
        if let Some(locks) = &self.commit_locks {
            let id = cache_file_id_from_path(&self.root, path)
                .ok_or_else(|| anyhow!("invalid shared disk object path"))?;
            return Ok(Some(locks.lock_object(id).await?));
        }
        let _ = path;
        Ok(None)
    }

    async fn delete_path(&self, path: &Path) -> Result<()> {
        let _object = self.lock_object(path).await?;
        self.delete_path_locked(path).await
    }

    // Caller holds the object stripe in shared mode. The unlink must complete
    // before cancellation can drop that guard (no detached tokio filesystem op).
    async fn delete_path_locked(&self, path: &Path) -> Result<()> {
        let result = if self.shared {
            fs::remove_file(path)
        } else {
            tokio::fs::remove_file(path).await
        };
        if let Err(error) = result
            && self.shared
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error.into());
        }
        self.hot_recent_remove(path);
        let mut state = self.state.lock().await;
        if let Some(id) = cache_file_id_from_path(&self.root, path) {
            if let Some(entry) = state.hot_entries.pop(&id) {
                state.hot_bytes = state.hot_bytes.saturating_sub(entry.value.len() as u64);
            }
            if let Some(entry) = state.entries.remove(&id) {
                state.total_bytes = state.total_bytes.saturating_sub(entry.total_len);
            }
        }
        Ok(())
    }

    fn hot_recent_upsert(&self, entry: RecentHotCacheEntry, removed: &[DiskCacheFileId]) {
        let _update =
            HotRecentUpdateGuard::acquire(&self.hot_recent_update, &self.hot_recent_generation);
        self.hot_recent.rcu(|current| {
            let mut shards = current.shards.clone();
            if !removed.is_empty() {
                for slot in 0..DISK_CACHE_RECENT_ENTRIES {
                    for way in recent_hot_bucket_mut(&mut shards, slot).iter_mut() {
                        if way
                            .as_ref()
                            .is_some_and(|candidate| removed.contains(&candidate.id))
                        {
                            *way = None;
                        }
                    }
                }
            }
            let slot = hot_slot(entry.namespace.as_ref(), entry.key.as_ref());
            recent_hot_upsert(recent_hot_bucket_mut(&mut shards, slot), entry.clone());
            RecentHotCache { shards }
        });
    }

    fn hot_recent_remove(&self, path: &Path) {
        let Some(id) = cache_file_id_from_path(&self.root, path) else {
            return;
        };
        if !self
            .hot_recent
            .load()
            .shards
            .iter()
            .flat_map(|shard| shard.entries.iter().flatten().flatten())
            .any(|entry| entry.id == id)
        {
            return;
        }
        let _update =
            HotRecentUpdateGuard::acquire(&self.hot_recent_update, &self.hot_recent_generation);
        self.hot_recent.rcu(|current| {
            let mut shards = current.shards.clone();
            for slot in 0..DISK_CACHE_RECENT_ENTRIES {
                for way in recent_hot_bucket_mut(&mut shards, slot).iter_mut() {
                    if way.as_ref().is_some_and(|entry| entry.id == id) {
                        *way = None;
                    }
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
        let object = self.lock_object(&path).await?;
        let current = if self.shared {
            // Publication may have been replaced/deleted before bookkeeping.
            let Ok(read) = read_disk_cache_header_sync(&path) else {
                return Ok(());
            };
            Some(read)
        } else {
            None
        };
        let (total_len, expires_at_ms) =
            current.as_ref().map_or((total_len, expires_at_ms), |read| {
                (read.total_len, read.header.expires_at_ms)
            });
        #[cfg(test)]
        self.bookkeeping_waiters.fetch_add(1, Ordering::SeqCst);
        {
            let mut state = self.state.lock().await;
            #[cfg(test)]
            self.bookkeeping_waiters.fetch_sub(1, Ordering::SeqCst);
            if let Some(old) = state.entries.insert(
                id,
                DiskCacheIndexEntry {
                    #[cfg(unix)]
                    identity: current
                        .as_ref()
                        .map(|read| {
                            read.file
                                .metadata()
                                .map(|meta| commit::FileIdentity::of(&meta))
                        })
                        .transpose()?,
                    total_len,
                    expires_at_ms,
                    touched_at_ms: now_ms(),
                },
            ) {
                state.total_bytes = state.total_bytes.saturating_sub(old.total_len);
            }
            state.total_bytes = state.total_bytes.saturating_add(total_len);
        }
        drop(object);
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
            let _ = self.cleanup_expired(&path).await;
        }
    }

    async fn cleanup_expired(&self, path: &Path) -> Result<()> {
        let _object = self.lock_object(path).await?;
        if self.shared
            && read_disk_cache_header_sync(path)
                .is_ok_and(|read| read.header.expires_at_ms > now_ms())
        {
            return Ok(());
        }
        self.delete_path_locked(path).await
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
                    .map(|(id, entry)| (*id, entry.clone()))
            };
            let Some((id, candidate)) = victim else {
                return Ok(());
            };
            let path = self.path_for_id(id);
            let _object = self.lock_object(&path).await?;
            #[cfg(unix)]
            if self.shared {
                let identity = fs::symlink_metadata(&path)
                    .ok()
                    .map(|meta| commit::FileIdentity::of(&meta));
                if identity != candidate.identity {
                    // Forget stale capacity data, not the replacement. Capacity
                    // is per-instance best effort, not a shared-root quota.
                    let mut state = self.state.lock().await;
                    if let Some(old) = state.entries.remove(&id) {
                        state.total_bytes = state.total_bytes.saturating_sub(old.total_len);
                    }
                    continue;
                }
            }
            #[cfg(not(unix))]
            let _ = candidate;
            self.delete_path_locked(&path).await?;
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
        let object = self.lock_object(path).await?;
        let (write, value) = tokio::task::spawn_blocking(move || {
            // A cancelled async caller must not unlock a still-running rename.
            let _object = object;
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
        self.release_decoded_records(namespace, key);
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
        if !self.shared
            && let Some(entry) = recent_hot_entry(&recent, namespace, key, now)
        {
            return Ok(Some(entry.value.clone()));
        }
        // Revalidated metadata is published as a standalone object. It must
        // win over the response trailer: the trailer still carries the
        // pre-revalidation envelope, and a missing hot-recent entry must not
        // resurrect it.
        if let Some(value) = self.get(namespace, key).await? {
            return Ok(Some(value));
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
            let object = self.lock_object(path).await?;
            let (write, value, written_meta) = tokio::task::spawn_blocking(move || {
                let _object = object;
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
        let streamed: std::result::Result<(u64, u64), anyhow::Error> = async {
            let mut file = TokioFile::from_std(create_secure_new_file(&tmp_path)?);
            let body_offset = write_header_async(&mut file, &header).await?;
            while let Some(chunk) = source.data().await {
                file.write_all(chunk?.as_ref()).await?;
            }
            if let Some((_, meta)) = metadata.as_ref() {
                file.write_all(&(meta.len() as u32).to_be_bytes()).await?;
                file.write_all(meta.as_ref()).await?;
            }
            // Await a real close before publishing: drop() only schedules the
            // close on the blocking pool, so rename could otherwise win over
            // the still-queued tail bytes and commit a truncated object.
            // Cache objects stay re-fetchable, so no fsync, but a short object
            // must fail closed here instead of being indexed as valid.
            file.flush().await?;
            tokio::io::AsyncWriteExt::shutdown(&mut file).await?;
            let expected_len = body_offset + header.body_len + header.trailer_len();
            let actual_len = file.metadata().await?.len();
            if actual_len != expected_len {
                return Err(anyhow!(
                    "disk cache object length mismatch: file {} expected {}",
                    actual_len,
                    expected_len
                ));
            }
            // Cache objects are re-fetchable, so commit to the page cache and
            // publish atomically via rename instead of paying for an fsync.
            drop(file);
            let _object = self.lock_object(path).await?;
            fs::rename(&tmp_path, path).with_context(|| {
                format!("failed to commit disk cache object {}", path.display())
            })?;
            Ok((header.body_len, expected_len))
        }
        .await;
        if streamed.is_err() {
            let _ = fs::remove_file(&tmp_path);
            invalidate_ensured_dir(parent);
        }
        let (_body_len, total_len) = streamed?;
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

/// OS advisory lock fd: dropping the file is the release, including on cancel.
#[cfg(unix)]
struct DiskCommitLease {
    _file: std::fs::File,
}

#[cfg(unix)]
#[async_trait]
impl CommitLease for DiskCommitLease {
    async fn release(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl CacheBackend for DiskCacheBackend {
    async fn lock_commit(
        &self,
        namespace: &str,
        primary: &str,
    ) -> Result<Option<std::sync::Arc<dyn CommitLease>>> {
        #[cfg(unix)]
        if let Some(locks) = &self.commit_locks {
            return Ok(Some(std::sync::Arc::new(DiskCommitLease {
                _file: locks.lock(namespace, primary).await?,
            })));
        }
        let _ = (namespace, primary);
        Ok(None)
    }

    async fn get(&self, namespace: &str, key: &str) -> Result<Option<Bytes>> {
        self.ensure_background_sweep();
        let path = match self.hot_get(namespace, key).await {
            HotCacheLookup::Hit { value, .. } => return Ok(Some(value)),
            HotCacheLookup::Miss(path) => path,
        };
        let Some(read) = self.open_valid(path).await? else {
            return Ok(None);
        };
        let mut file = TokioFile::from_std(read.file);
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
        let source_generation = self.decoded_generation();
        let Some(raw) = self.get(namespace, key).await? else {
            return Ok(None);
        };
        self.decode_variant_index(namespace, key, raw, source_generation)
            .map(Some)
    }

    async fn get_decoded_response_metadata_many(
        &self,
        namespace: &str,
        keys: &[String],
    ) -> Result<Vec<Option<std::sync::Arc<CachedResponseEnvelope>>>> {
        let mut out = Vec::with_capacity(keys.len());
        let source_generation = self.decoded_generation();
        for key in keys {
            let raw = self.read_response_metadata(namespace, key).await?;
            let decoded = match raw {
                Some(raw) => {
                    Some(self.decode_response_metadata(namespace, key, raw, source_generation)?)
                }
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
        _default_variant_key: &str,
        now: u64,
    ) -> Result<Option<CachedResponseCandidate>> {
        if self.shared {
            return Ok(None);
        }
        let slot_index = hot_slot(namespace, index_key);
        let slot = &self.hot_responses[slot_index];
        let decoded_generation = self.decoded_generation();
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
        // New responses always publish a generation through the index. If it
        // is cold or not a single variant, use full lookup/negotiation instead
        // of probing an older canonical object that replacement left behind.
        let Some(index_entry) = recent_hot_entry(&recent, namespace, index_key, now) else {
            return Ok(None);
        };
        let variants = self.decode_variant_index(
            namespace,
            index_key,
            index_entry.value.clone(),
            decoded_generation,
        )?;
        let [variant_key] = variants.variants.as_slice() else {
            return Ok(None);
        };
        let index_expires_at_ms = index_entry.expires_at_ms;
        let Some(metadata_entry) = recent_hot_entry(&recent, namespace, variant_key.as_str(), now)
        else {
            return Ok(None);
        };
        let envelope = self.decode_response_metadata(
            namespace,
            variant_key.as_str(),
            metadata_entry.value.clone(),
            decoded_generation,
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
            // Pin the validated inode for zero-copy too; reopening the pathname
            // after reading could attach a replacement's bytes to this body.
            let source_file = if is_cache_body_storage_key(key)
                && read.header.body_len >= DISK_CACHE_ZERO_COPY_MIN_BYTES
            {
                read.file.try_clone().ok().map(std::sync::Arc::new)
            } else {
                None
            };
            let mut file = TokioFile::from_std(read.file);
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
                source_file,
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
        let (done, producer_done) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = async {
                let mut file = TokioFile::from_std(read.file);
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
            let _ = done.send(());
        });
        Ok(Some(CachedBodyStream::from_producer_for_backend(
            body_len,
            body,
            producer_done,
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
        let written = timeout(
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
        .await?;
        self.release_decoded_records(namespace, key);
        written
    }

    async fn retire_response_metadata(&self, namespace: &str, key: &str) -> Result<()> {
        let path = self.path_for(namespace, cache_body_storage_key(key).as_str());
        // Drop metadata and compound response candidates before changing the
        // trailer; body producers retain the unchanged body bytes and offset.
        self.hot_remove(&path).await;
        let _object = self.lock_object(&path).await?;
        let _update =
            HotRecentUpdateGuard::acquire(&self.hot_recent_update, &self.hot_recent_generation);
        let result = retire_metadata_trailer_sync(&path);
        drop(_update);
        if result.is_ok() {
            self.release_decoded_records(namespace, key);
        }
        result
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let path = self.path_for(namespace, key);
        self.delete_path(&path).await?;
        self.release_decoded_records(namespace, key);
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

fn recent_hot_matches(entry: &RecentHotCacheEntry, namespace: &str, key: &str) -> bool {
    entry.namespace.as_ref() == namespace && entry.key.as_ref() == key
}

fn recent_hot_entry<'a>(
    recent: &'a RecentHotCache,
    namespace: &str,
    key: &str,
    now: u64,
) -> Option<&'a RecentHotCacheEntry> {
    recent_hot_entry_by_key(recent, namespace, key).filter(|entry| entry.expires_at_ms > now)
}

fn recent_hot_entry_by_key<'a>(
    recent: &'a RecentHotCache,
    namespace: &str,
    key: &str,
) -> Option<&'a RecentHotCacheEntry> {
    recent_hot_bucket_at(recent, hot_slot(namespace, key))?
        .iter()
        .flatten()
        .find(|entry| recent_hot_matches(entry, namespace, key))
}

fn recent_hot_bucket_at(recent: &RecentHotCache, slot: usize) -> Option<&RecentHotBucket> {
    let shard = recent
        .shards
        .get(slot / DISK_CACHE_RECENT_ENTRIES_PER_SHARD)?;
    shard
        .entries
        .get(slot % DISK_CACHE_RECENT_ENTRIES_PER_SHARD)
}

fn recent_hot_bucket_mut(
    shards: &mut [std::sync::Arc<RecentHotCacheShard>],
    slot: usize,
) -> &mut RecentHotBucket {
    let shard = std::sync::Arc::make_mut(&mut shards[slot / DISK_CACHE_RECENT_ENTRIES_PER_SHARD]);
    &mut shard.entries[slot % DISK_CACHE_RECENT_ENTRIES_PER_SHARD]
}

fn recent_hot_upsert(bucket: &mut RecentHotBucket, entry: RecentHotCacheEntry) {
    if let Some(way) = bucket.iter().position(|candidate| {
        candidate
            .as_ref()
            .is_some_and(|candidate| recent_hot_matches(candidate, &entry.namespace, &entry.key))
    }) {
        bucket[way] = Some(entry);
        return;
    }
    if let Some(way) = bucket.iter().position(Option::is_none) {
        bucket[way] = Some(entry);
        return;
    }
    // Bucket full: distribute evictions with the upper hash bits instead of
    // keeping per-way state in the RCU snapshot.
    let hash = hot_hash(entry.namespace.as_ref(), entry.key.as_ref());
    bucket[(hash >> 32) as usize % DISK_CACHE_RECENT_WAYS] = Some(entry);
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

fn hot_hash(namespace: &str, key: &str) -> u64 {
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
    hash
}

fn hot_slot(namespace: &str, key: &str) -> usize {
    hot_hash(namespace, key) as usize % DISK_CACHE_RECENT_ENTRIES
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
        file,
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
    // NUL cannot begin a serialized JSON envelope. Retirement overwrites the
    // payload with NULs, retaining its length and all header/body framing.
    if meta.first() == Some(&0) {
        return Ok(None);
    }
    Ok(Some(Bytes::from(meta)))
}

fn retire_metadata_trailer_sync(path: &Path) -> Result<()> {
    let read = match read_disk_cache_header_sync(path) {
        Ok(read) => read,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if read.header.meta_len == 0 {
        return Ok(());
    }
    reject_symlink(path)?;
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(std::io::SeekFrom::Start(
        read.total_len - read.header.meta_len,
    ))?;
    let zeros = [0u8; DISK_CACHE_CHUNK_BYTES];
    let mut remaining = read.header.meta_len;
    while remaining > 0 {
        let len = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..len])?;
        remaining -= len as u64;
    }
    Ok(())
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
    let ensured = ENSURED_PRIVATE_DIRS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    if ensured
        .lock()
        .expect("ensured dir lock")
        .contains(path.as_os_str().as_encoded_bytes())
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
    if let Ok(mut set) = ensured.lock()
        && set.len() < ENSURED_PRIVATE_DIR_LIMIT
    {
        set.insert(path.as_os_str().as_encoded_bytes().to_vec());
    }
    Ok(())
}

/// Verified private disk-cache parents. The guard walks directories afresh on
/// first use, so entries are trusted for the lifetime of the process only.
static ENSURED_PRIVATE_DIRS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashSet<Vec<u8>>>,
> = std::sync::OnceLock::new();
const ENSURED_PRIVATE_DIR_LIMIT: usize = 4096;

/// Drops the memoized entry for `dir` so the next write re-runs the directory
/// guard. Write paths call this when the parent stops accepting files.
fn invalidate_ensured_dir(dir: &Path) {
    if let Some(ensured) = ENSURED_PRIVATE_DIRS.get()
        && let Ok(mut set) = ensured.lock()
    {
        set.remove(dir.as_os_str().as_encoded_bytes());
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
            writer_mode: Default::default(),
            commit_lock_stripes: 64,
            name: "disk".to_string(),
            kind: "disk".to_string(),
            endpoint: String::new(),
            path: Some(path.display().to_string()),
            max_bytes: Some(max_bytes),
            sweep_interval_secs: 1,
            timeout_ms: 500,
            writer_lease_ttl_ms: 5_000,
            allow_local_only_remote_coordination: false,
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

    #[test]
    fn private_directory_memo_recognizes_ensured_path_bytes() {
        let root = temp_dir("memo-encoded-bytes");
        let target = root.join("objects").join("ab");

        ensure_private_dir(&target).expect("create private directory");
        assert!(
            ENSURED_PRIVATE_DIRS
                .get()
                .expect("memo initialized")
                .lock()
                .expect("memo lock")
                .contains(target.as_os_str().as_encoded_bytes()),
            "ensured path must be memoized as encoded bytes"
        );

        // A memo hit skips the directory walk: removing the ensured directory
        // must not be silently repaired by a second ensure call.
        fs::remove_dir_all(&target).expect("remove ensured directory");
        ensure_private_dir(&target).expect("memoized path must be accepted");
        assert!(
            !target.exists(),
            "memo hit must not re-run the directory guard"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn invalidate_ensured_dir_forces_a_fresh_directory_walk() {
        let root = temp_dir("memo-invalidation");
        let target = root.join("objects").join("ab");
        let key = target.as_os_str().as_encoded_bytes().to_vec();

        ensure_private_dir(&target).expect("create private directory");
        assert!(
            ENSURED_PRIVATE_DIRS
                .get()
                .expect("memo initialized")
                .lock()
                .expect("memo lock")
                .contains(&key)
        );
        invalidate_ensured_dir(&target);
        assert!(
            !ENSURED_PRIVATE_DIRS
                .get()
                .expect("memo initialized")
                .lock()
                .expect("memo lock")
                .contains(&key),
            "invalidation must drop the memoized path bytes"
        );

        // With the entry gone, the next call must walk and rebuild the tree.
        fs::remove_dir_all(&target).expect("remove ensured directory");
        ensure_private_dir(&target).expect("re-walk after invalidation");
        assert!(
            target.is_dir(),
            "fresh walk must recreate the removed directory"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_creation_still_rejects_symlink_components_and_traversal() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("symlink-component");
        let real = root.join("real");
        fs::create_dir(&real).expect("create symlink target");
        let link = root.join("link");
        symlink(&real, &link).expect("create symlink component");
        let target = link.join("objects");

        let error = ensure_private_dir(&target).expect_err("reject symlinked component");
        assert!(
            error
                .to_string()
                .contains("refusing symlinked disk cache path component")
        );
        assert!(!target.exists());
        assert!(
            !ENSURED_PRIVATE_DIRS
                .get()
                .expect("memo initialized")
                .lock()
                .expect("memo lock")
                .contains(target.as_os_str().as_encoded_bytes()),
            "a rejected path must never be memoized"
        );

        let traversal = link.join("..").join("objects");
        let error = ensure_private_dir(&traversal).expect_err("reject parent traversal");
        assert!(error.to_string().contains("parent traversal"));
        assert!(!root.join("objects").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn disk_response_stream_error_publishes_no_object_or_metadata() {
        let dir = temp_dir("response-stream-error");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let (mut sender, body) = Body::channel();
        sender
            .send_data(Bytes::from_static(b"partial"))
            .await
            .expect("send data");
        sender.abort();
        backend
            .put_response(
                "ns",
                "variant",
                body,
                BodyStreamWriteOptions {
                    max_body_bytes: 1024,
                    body_read_timeout: Duration::from_secs(1),
                    ttl_secs: 60,
                },
                Box::new(|_| panic!("metadata must not be encoded after a stream error")),
            )
            .await
            .expect_err("reject body stream error");
        let body_key = cache_body_storage_key("variant");
        assert!(
            backend
                .get("ns", &body_key)
                .await
                .expect("get body")
                .is_none()
        );
        assert!(
            backend
                .read_response_metadata("ns", "variant")
                .await
                .expect("metadata")
                .is_none()
        );
        assert!(collect_cache_files(&dir).expect("cache files").is_empty());
        let _ = fs::remove_dir_all(dir);
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
    async fn metadata_retirement_preserves_body_and_framing_across_restart() {
        let dir = temp_dir("retired-metadata");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).unwrap();
        let key = "obj:primary:default";
        let envelope = CachedResponseEnvelope {
            status: 200,
            headers: crate::types::CachedHeaders::from_pairs(Vec::new()),
            body: CachedBody::default(),
            body_len: 4,
            stored_at_ms: now_ms(),
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 600,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            response_directives: Default::default(),
            response_header_values: Default::default(),
        };
        backend
            .put_response(
                "ns",
                key,
                Body::from("body"),
                BodyStreamWriteOptions {
                    max_body_bytes: 1024,
                    body_read_timeout: Duration::from_secs(1),
                    ttl_secs: 600,
                },
                Box::new(move |_| super::super::types::encode_cached_response_metadata(&envelope)),
            )
            .await
            .unwrap();
        backend
            .put(
                "ns",
                "index",
                &serde_json::to_vec(&VariantIndex {
                    variants: vec![key.to_string()],
                })
                .unwrap(),
                600,
            )
            .await
            .unwrap();
        let held = backend
            .get_response_candidate("ns", "index", key, now_ms())
            .unwrap()
            .expect("hot candidate");
        let path = backend.path_for("ns", &cache_body_storage_key(key));
        let before = fs::read(&path).unwrap();
        let header = read_disk_cache_header_sync(&path).unwrap();
        let payload_offset = (header.total_len - header.header.meta_len) as usize;
        backend.retire_response_metadata("ns", key).await.unwrap();
        backend.retire_response_metadata("ns", key).await.unwrap(); // idempotent
        let after = fs::read(&path).unwrap();
        assert_eq!(before.len(), after.len());
        assert_eq!(before[..payload_offset], after[..payload_offset]);
        assert!(after[payload_offset..].iter().all(|byte| *byte == 0));
        assert!(
            backend
                .get_response_candidate("ns", "index", key, now_ms())
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .read_response_metadata("ns", key)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            qpx_http::body::to_bytes(held.body.body).await.unwrap(),
            "body"
        );
        let restarted = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).unwrap();
        assert!(
            restarted
                .read_response_metadata("ns", key)
                .await
                .unwrap()
                .is_none()
        );
        let body = restarted
            .get_object_stream("ns", &cache_body_storage_key(key), 4, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(qpx_http::body::to_bytes(body.body).await.unwrap(), "body");
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn co_located_metadata_never_aliases_body_after_recent_slot_eviction() {
        let dir = temp_dir("generation-lru-identity");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).unwrap();
        let key = super::super::vary::representation_storage_key("obj:primary:default");
        backend
            .put_response(
                "ns",
                &key,
                Body::from("body"),
                BodyStreamWriteOptions {
                    max_body_bytes: 1024,
                    body_read_timeout: Duration::from_secs(1),
                    ttl_secs: 60,
                },
                // Equal sizes deliberately defeat length-only identity checking.
                Box::new(|_| Ok(b"meta".to_vec())),
            )
            .await
            .unwrap();
        // A slot collision/eviction must fall back to the correct logical LRU
        // object, even though metadata and body share the same physical file.
        backend
            .hot_recent
            .store(std::sync::Arc::new(RecentHotCache::default()));
        let stream = backend
            .get_object_stream("ns", &cache_body_storage_key(&key), 4, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(qpx_http::body::to_bytes(stream.body).await.unwrap(), "body");
        std::fs::remove_dir_all(dir).unwrap();
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
    async fn hot_lru_hits_by_file_id_without_recent_entry() {
        let dir = temp_dir("hot-lru-file-id");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let path = backend.path_for("ns", "body-key");
        backend
            .hot_insert(
                "ns",
                "body-key",
                path.clone(),
                Bytes::from_static(b"body"),
                now_ms() + 60_000,
                0,
            )
            .await;
        // Force the lookup through the LRU rather than the lock-free index.
        backend
            .hot_recent
            .store(std::sync::Arc::new(RecentHotCache::default()));
        {
            let state = backend.state.lock().await;
            let id = cache_file_id("ns", "body-key");
            assert_eq!(state.hot_entries.len(), 1);
            assert!(state.hot_entries.contains(&id));
        }
        match backend
            .hot_get_from_lru("ns", "body-key", path.clone(), now_ms())
            .await
        {
            HotCacheLookup::Hit { value, .. } => assert_eq!(value.as_ref(), b"body"),
            HotCacheLookup::Miss(_) => panic!("expected a hit keyed by the file id"),
        }

        // A non-canonical path cannot derive an id and must miss without
        // touching the stored entry.
        let misplaced = dir.join("wrong.qpxc");
        match backend
            .hot_get_from_lru("ns", "body-key", misplaced.clone(), now_ms())
            .await
        {
            HotCacheLookup::Miss(missed) => assert_eq!(missed, misplaced),
            HotCacheLookup::Hit { .. } => panic!("invalid path must miss"),
        }
        assert_eq!(backend.state.lock().await.hot_entries.len(), 1);

        backend.hot_remove(&path).await;
        assert_eq!(backend.state.lock().await.hot_bytes, 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn co_located_metadata_replaces_body_in_one_file_id_slot() {
        let dir = temp_dir("hot-lru-co-located");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let path = backend.path_for("ns", "body-key");
        let expires_at_ms = now_ms() + 60_000;
        backend
            .hot_insert(
                "ns",
                "body-key",
                path.clone(),
                Bytes::from(vec![b'b'; 32]),
                expires_at_ms,
                0,
            )
            .await;
        backend
            .hot_insert(
                "ns",
                "meta-key",
                path.clone(),
                Bytes::from(vec![b'm'; 8]),
                expires_at_ms,
                0,
            )
            .await;
        {
            let state = backend.state.lock().await;
            assert_eq!(state.hot_entries.len(), 1);
            assert_eq!(state.hot_bytes, 8);
            let entry = state
                .hot_entries
                .peek(&cache_file_id("ns", "body-key"))
                .expect("single slot for the shared path");
            assert_eq!(entry.key.as_ref(), "meta-key");
            assert_eq!(entry.value.as_ref(), b"mmmmmmmm");
        }
        assert_eq!(
            recent_hot_entry_by_key(&backend.hot_recent.load(), "ns", "meta-key")
                .map(|entry| entry.id),
            Some(cache_file_id("ns", "body-key"))
        );
        match backend
            .hot_get_from_lru("ns", "meta-key", path.clone(), now_ms())
            .await
        {
            HotCacheLookup::Hit { value, .. } => assert_eq!(value.len(), 8),
            HotCacheLookup::Miss(_) => panic!("metadata must remain hot"),
        }
        match backend
            .hot_get_from_lru("ns", "body-key", path, now_ms())
            .await
        {
            HotCacheLookup::Miss(_) => {}
            HotCacheLookup::Hit { .. } => panic!("body must not alias the metadata entry"),
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn hot_lru_eviction_invalidates_recent_entry_by_file_id() {
        let dir = temp_dir("hot-lru-eviction");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let first = backend.path_for("ns", "first");
        let second = backend.path_for("ns", "second");
        let value = Bytes::from(vec![b'x'; 600 * 1024]);
        let expires_at_ms = now_ms() + 60_000;
        backend
            .hot_insert("ns", "first", first, value.clone(), expires_at_ms, 0)
            .await;
        backend
            .hot_insert("ns", "second", second.clone(), value, expires_at_ms, 0)
            .await;

        let now = now_ms();
        let recent = backend.hot_recent.load();
        assert!(recent_hot_entry(&recent, "ns", "first", now).is_none());
        assert!(recent_hot_entry(&recent, "ns", "second", now).is_some());
        {
            let state = backend.state.lock().await;
            assert_eq!(state.hot_entries.len(), 1);
            assert_eq!(state.hot_bytes, 600 * 1024);
            assert!(state.hot_entries.contains(&cache_file_id("ns", "second")));
            assert!(!state.hot_entries.contains(&cache_file_id("ns", "first")));
        }
        assert_eq!(
            recent_hot_entry(&recent, "ns", "second", now).map(|entry| entry.id),
            Some(cache_file_id("ns", "second"))
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn hot_recent_remove_only_invalidates_the_target_file_id() {
        let dir = temp_dir("hot-recent-remove-by-id");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let first_key = "remove-target";
        let target_slot = hot_slot("ns", first_key);
        let neighbor_key = (0..4096)
            .map(|index| format!("remove-neighbor-{index}"))
            .find(|key| hot_slot("ns", key) == target_slot)
            .expect("two keys must share a recent-hot slot");
        let first_path = backend.path_for("ns", first_key);
        let neighbor_path = backend.path_for("ns", &neighbor_key);
        let first_id = cache_file_id("ns", first_key);
        let neighbor_id = cache_file_id("ns", &neighbor_key);
        assert_ne!(first_id, neighbor_id);
        let expires_at_ms = now_ms() + 60_000;
        for (key, path) in [
            (first_key, &first_path),
            (neighbor_key.as_str(), &neighbor_path),
        ] {
            backend
                .hot_insert(
                    "ns",
                    key,
                    path.clone(),
                    Bytes::from_static(b"value"),
                    expires_at_ms,
                    0,
                )
                .await;
        }
        let recent = backend.hot_recent.load();
        assert_eq!(
            recent_hot_entry(&recent, "ns", first_key, now_ms()).map(|entry| entry.id),
            Some(first_id)
        );
        assert_eq!(
            recent_hot_entry(&recent, "ns", &neighbor_key, now_ms()).map(|entry| entry.id),
            Some(neighbor_id)
        );
        drop(recent);

        backend.hot_recent_remove(&first_path);
        let recent = backend.hot_recent.load();
        assert!(recent_hot_entry(&recent, "ns", first_key, now_ms()).is_none());
        assert_eq!(
            recent_hot_entry(&recent, "ns", &neighbor_key, now_ms()).map(|entry| entry.id),
            Some(neighbor_id)
        );
        match backend
            .hot_get_from_lru("ns", &neighbor_key, neighbor_path, now_ms())
            .await
        {
            HotCacheLookup::Hit { value, .. } => assert_eq!(value.as_ref(), b"value"),
            HotCacheLookup::Miss(_) => panic!("neighbor must stay hot in the LRU"),
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shared_mode_keeps_hot_lru_empty() {
        let dir = temp_dir("hot-lru-shared");
        let mut config = cfg(dir.clone(), 1024 * 1024);
        config.writer_mode = qpx_core::config::CacheWriterMode::Shared;
        let backend = DiskCacheBackend::new(config).expect("shared backend");
        let path = backend.path_for("ns", "key");
        backend
            .hot_insert(
                "ns",
                "key",
                path.clone(),
                Bytes::from_static(b"shared"),
                now_ms() + 60_000,
                0,
            )
            .await;
        {
            let state = backend.state.lock().await;
            assert!(state.hot_entries.is_empty());
            assert_eq!(state.hot_bytes, 0);
        }
        assert!(
            !backend
                .hot_recent
                .load()
                .shards
                .iter()
                .flat_map(|shard| shard.entries.iter().flatten().flatten())
                .any(|entry| entry.id == cache_file_id("ns", "key"))
        );
        match backend.hot_get("ns", "key").await {
            HotCacheLookup::Miss(missed) => assert_eq!(missed, path),
            HotCacheLookup::Hit { .. } => panic!("shared mode must bypass hot caches"),
        }
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
            headers: crate::types::CachedHeaders::from_pairs(vec![(
                "content-type".to_string(),
                "text/plain".to_string(),
            )]),
            body: CachedBody::default(),
            body_len: 7,
            stored_at_ms: 1,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
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
    async fn disk_backend_write_invalidates_decoded_records_after_hot_replacement() {
        let dir = temp_dir("decoded-invalidation-order");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let old = serde_json::to_vec(&VariantIndex {
            variants: vec!["v1".to_string()],
        })
        .expect("encode old index");
        let replacement = serde_json::to_vec(&VariantIndex {
            variants: vec!["v2".to_string()],
        })
        .expect("encode replacement index");
        backend
            .put("ns", "index", &old, 60)
            .await
            .expect("put old index");
        let old_raw = backend
            .get("ns", "index")
            .await
            .expect("get old index")
            .expect("old index");
        // Hold the state lock while the writer waits for it. The waiter
        // counter is incremented immediately before that wait, so decoding
        // after observing it cannot race ahead of the writer's bookkeeping.
        let state = backend.state.lock().await;
        let writer = tokio::spawn({
            let backend = backend.clone();
            let replacement = replacement.clone();
            async move { backend.put("ns", "index", &replacement, 60).await }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while backend.bookkeeping_waiters.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("writer reached the bookkeeping state lock");

        let decoded = backend
            .get_decoded_variant_index("ns", "index")
            .await
            .expect("decode old index while write is in flight")
            .expect("old index");
        assert_eq!(decoded.variants, vec!["v1"]);
        drop(decoded);
        drop(state);
        writer.await.expect("writer task").expect("replace index");

        let slot = qpx_http::sharding::modulo(&("ns", "index"), backend.decoded_variants.len());
        let retained = backend.decoded_variants[slot].load_full();
        assert!(
            retained
                .as_ref()
                .is_none_or(|entry| !same_bytes_allocation(&entry.raw, &old_raw)),
            "decoded slot still retains the superseded raw allocation"
        );
        let latest = backend
            .get_decoded_variant_index("ns", "index")
            .await
            .expect("decode replacement index")
            .expect("replacement index");
        assert_eq!(latest.variants, vec!["v2"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_replacement_releases_decoded_records() {
        let dir = temp_dir("decoded-record-release");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");

        let index = VariantIndex {
            variants: vec!["v1".to_string()],
        };
        backend
            .put(
                "ns",
                "index",
                &serde_json::to_vec(&index).expect("encode index"),
                60,
            )
            .await
            .expect("put index");
        let first = backend
            .get_decoded_variant_index("ns", "index")
            .await
            .expect("decode index")
            .expect("index");
        let old_index = std::sync::Arc::downgrade(&first);
        drop(first);

        let envelope = CachedResponseEnvelope {
            status: 200,
            headers: crate::types::CachedHeaders::from_pairs(vec![(
                "content-type".to_string(),
                "text/plain".to_string(),
            )]),
            body: CachedBody::default(),
            body_len: 7,
            stored_at_ms: 1,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            response_directives: Default::default(),
            response_header_values: Default::default(),
        };
        let encode_envelope = |value: &CachedResponseEnvelope| {
            super::super::types::encode_cached_response_metadata(value).expect("encode metadata")
        };
        backend
            .put("ns", "metadata", &encode_envelope(&envelope), 60)
            .await
            .expect("put metadata");
        let first = backend
            .get_decoded_response_metadata_many("ns", &["metadata".to_string()])
            .await
            .expect("decode metadata")
            .pop()
            .flatten()
            .expect("metadata");
        let old_metadata = std::sync::Arc::downgrade(&first);
        drop(first);

        let replacement = VariantIndex {
            variants: vec!["v2".to_string()],
        };
        backend
            .put(
                "ns",
                "index",
                &serde_json::to_vec(&replacement).expect("encode replacement index"),
                60,
            )
            .await
            .expect("replace index");
        let replacement_envelope = CachedResponseEnvelope {
            body_len: 8,
            ..envelope
        };
        backend
            .put(
                "ns",
                "metadata",
                &encode_envelope(&replacement_envelope),
                60,
            )
            .await
            .expect("replace metadata");

        assert!(old_index.upgrade().is_none(), "old index is still retained");
        assert!(
            old_metadata.upgrade().is_none(),
            "old metadata is still retained"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn disk_backend_put_response_replacement_releases_decoded_metadata() {
        let dir = temp_dir("response-decoded-record-release");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let envelope = |body_len| CachedResponseEnvelope {
            status: 200,
            headers: crate::types::CachedHeaders::from_pairs(Vec::new()),
            body: CachedBody::default(),
            body_len,
            stored_at_ms: 1,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            response_directives: Default::default(),
            response_header_values: Default::default(),
        };
        let options = || BodyStreamWriteOptions {
            max_body_bytes: 1024,
            body_read_timeout: Duration::from_secs(1),
            ttl_secs: 60,
        };
        let first = envelope(4);
        backend
            .put_response(
                "ns",
                "variant",
                Body::from("body"),
                options(),
                Box::new(move |_| super::super::types::encode_cached_response_metadata(&first)),
            )
            .await
            .expect("put response");
        let decoded = backend
            .get_decoded_response_metadata_many("ns", &["variant".to_string()])
            .await
            .expect("decode response metadata")
            .pop()
            .flatten()
            .expect("response metadata");
        let old = std::sync::Arc::downgrade(&decoded);
        drop(decoded);

        let replacement = envelope(5);
        backend
            .put_response(
                "ns",
                "variant",
                Body::from("body2"),
                options(),
                Box::new(move |_| {
                    super::super::types::encode_cached_response_metadata(&replacement)
                }),
            )
            .await
            .expect("replace response");
        assert!(
            old.upgrade().is_none(),
            "old decoded metadata retained after put_response replacement"
        );

        let decoded = backend
            .get_decoded_response_metadata_many("ns", &["variant".to_string()])
            .await
            .expect("decode replacement metadata")
            .pop()
            .flatten()
            .expect("replacement metadata");
        let old = std::sync::Arc::downgrade(&decoded);
        drop(decoded);
        backend
            .retire_response_metadata("ns", "variant")
            .await
            .expect("retire metadata");
        assert!(
            old.upgrade().is_none(),
            "decoded metadata retained after retire_response_metadata"
        );

        let retired = envelope(6);
        backend
            .put_response(
                "ns",
                "variant",
                Body::from("body3"),
                options(),
                Box::new(move |_| super::super::types::encode_cached_response_metadata(&retired)),
            )
            .await
            .expect("replace retired response");
        let decoded = backend
            .get_decoded_response_metadata_many("ns", &["variant".to_string()])
            .await
            .expect("decode metadata before delete")
            .pop()
            .flatten()
            .expect("metadata before delete");
        let old = std::sync::Arc::downgrade(&decoded);
        drop(decoded);
        backend
            .delete("ns", "variant")
            .await
            .expect("delete response key");
        assert!(
            old.upgrade().is_none(),
            "decoded metadata retained after delete"
        );
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
            headers: crate::types::CachedHeaders::from_pairs(vec![(
                "content-type".to_string(),
                "text/plain".to_string(),
            )]),
            body: CachedBody::default(),
            body_len: 7,
            stored_at_ms: 1,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
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
            recent_hot_bucket_mut(&mut updated_recent.shards, hot_slot("ns", variant_key))
                .iter_mut()
                .find_map(|way| {
                    way.as_mut()
                        .filter(|entry| recent_hot_matches(entry, "ns", variant_key))
                })
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
    async fn disk_backend_hot_response_candidate_survives_recent_slot_collision() {
        let dir = temp_dir("hot-response-slot-collision");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let index_key = "index";
        let variant_key = "obj:primary:cf";
        let body_key = cache_body_storage_key(variant_key);
        assert_eq!(hot_slot("ns", index_key), hot_slot("ns", variant_key));
        assert_ne!(hot_slot("ns", index_key), hot_slot("ns", body_key.as_str()));
        let envelope = CachedResponseEnvelope {
            status: 200,
            headers: crate::types::CachedHeaders::from_pairs(Vec::new()),
            body: CachedBody::default(),
            body_len: 7,
            stored_at_ms: 1,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
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
                index_key,
                &serde_json::to_vec(&VariantIndex {
                    variants: vec![variant_key.to_string()],
                })
                .expect("encode index"),
                60,
            )
            .await
            .expect("put index");

        let mut candidate = backend
            .get_response_candidate("ns", index_key, "obj:default", now_ms())
            .expect("get candidate")
            .expect("candidate must survive colliding index and metadata keys");
        assert_eq!(
            candidate
                .body
                .body
                .data()
                .await
                .expect("body")
                .expect("bytes"),
            Bytes::from_static(b"payload")
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

    fn variant_raw() -> Bytes {
        Bytes::from(
            serde_json::to_vec(&VariantIndex {
                variants: vec!["v1".to_string()],
            })
            .expect("encode index"),
        )
    }

    fn metadata_raw(body_len: u64) -> Bytes {
        super::super::types::encode_cached_response_metadata(&CachedResponseEnvelope {
            status: 200,
            headers: crate::types::CachedHeaders::from_pairs(Vec::new()),
            body: CachedBody::default(),
            body_len,
            stored_at_ms: 1,
            initial_age_secs: 0,
            response_delay_secs: 0,
            freshness_lifetime_secs: 60,
            vary_headers: Vec::new(),
            vary_values: Vec::new(),
            response_directives: Default::default(),
            response_header_values: Default::default(),
        })
        .expect("encode metadata")
        .into()
    }

    #[tokio::test]
    async fn revalidated_metadata_object_wins_over_stale_trailer() {
        let dir = temp_dir("revalidated-metadata-object");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        backend
            .put_response(
                "ns",
                "variant",
                Body::from(Bytes::from_static(b"0123456789")),
                BodyStreamWriteOptions {
                    max_body_bytes: 1024,
                    body_read_timeout: Duration::from_secs(1),
                    ttl_secs: 60,
                },
                Box::new(|_| Ok(metadata_raw(4).to_vec())),
            )
            .await
            .expect("store response with trailer metadata");
        backend
            .put("ns", "variant", &metadata_raw(9), 60)
            .await
            .expect("publish revalidated metadata");
        backend.hot_recent_remove(&backend.path_for("ns", "variant"));

        let raw = backend
            .read_response_metadata("ns", "variant")
            .await
            .expect("read metadata")
            .expect("revalidated metadata must remain readable");
        assert_eq!(
            decode_cached_response_metadata(raw)
                .expect("decode metadata")
                .body_len,
            9
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn in_flight_decoded_reader_cannot_reinstall_invalidated_records() {
        let dir = temp_dir("decoded-slot-in-flight");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let variant_slot =
            qpx_http::sharding::modulo(&("ns", "index"), backend.decoded_variants.len());
        let metadata_slot =
            qpx_http::sharding::modulo(&("ns", "v1"), backend.decoded_metadata.len());

        backend
            .decode_variant_index("ns", "index", variant_raw(), backend.decoded_generation())
            .expect("decode index");
        backend
            .decode_response_metadata("ns", "v1", metadata_raw(4), backend.decoded_generation())
            .expect("decode metadata");
        let observed_variant = backend.decoded_variants[variant_slot].load_full().unwrap();
        let observed_metadata = backend.decoded_metadata[metadata_slot].load_full().unwrap();

        backend.release_decoded_records("ns", "index");
        backend.release_decoded_records("ns", "v1");
        backend.publish_decoded_variant(
            variant_slot,
            Some(observed_variant.clone()),
            observed_variant,
            backend.decoded_generation(),
        );
        backend.publish_decoded_metadata(
            metadata_slot,
            Some(observed_metadata.clone()),
            observed_metadata,
            backend.decoded_generation(),
        );

        assert!(backend.decoded_variants[variant_slot].load_full().is_none());
        assert!(
            backend.decoded_metadata[metadata_slot]
                .load_full()
                .is_none()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn decoded_release_preserves_colliding_slot_entries() {
        let dir = temp_dir("decoded-slot-collision");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let variant_slot =
            qpx_http::sharding::modulo(&("ns", "index"), backend.decoded_variants.len());
        let metadata_slot =
            qpx_http::sharding::modulo(&("ns", "v1"), backend.decoded_metadata.len());
        let colliding_variant = Arc::new(DecodedVariantIndexEntry {
            namespace: Arc::from("other"),
            key: Arc::from("other-index"),
            raw: variant_raw(),
            value: Arc::new(VariantIndex {
                variants: Vec::new(),
            }),
        });
        let colliding_metadata = Arc::new(DecodedMetadataEntry {
            namespace: Arc::from("other"),
            key: Arc::from("other-v1"),
            raw: metadata_raw(9),
            value: Arc::new(CachedResponseEnvelope {
                status: 204,
                headers: crate::types::CachedHeaders::from_pairs(Vec::new()),
                body: CachedBody::default(),
                body_len: 9,
                stored_at_ms: 1,
                initial_age_secs: 0,
                response_delay_secs: 0,
                freshness_lifetime_secs: 60,
                vary_headers: Vec::new(),
                vary_values: Vec::new(),
                response_directives: Default::default(),
                response_header_values: Default::default(),
            }),
        });
        backend.decoded_variants[variant_slot].store(Some(colliding_variant.clone()));
        backend.decoded_metadata[metadata_slot].store(Some(colliding_metadata.clone()));

        backend.release_decoded_records("ns", "index");
        backend.release_decoded_records("ns", "v1");

        assert!(Arc::ptr_eq(
            &backend.decoded_variants[variant_slot].load_full().unwrap(),
            &colliding_variant
        ));
        assert!(Arc::ptr_eq(
            &backend.decoded_metadata[metadata_slot].load_full().unwrap(),
            &colliding_metadata
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_decoded_reader_does_not_publish_after_replacement() {
        let dir = temp_dir("decoded-stale-reader-empty-slot");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let variant_slot =
            qpx_http::sharding::modulo(&("ns", "index"), backend.decoded_variants.len());
        let metadata_slot =
            qpx_http::sharding::modulo(&("ns", "v1"), backend.decoded_metadata.len());
        let source_generation = backend.decoded_generation();

        backend.release_decoded_records("ns", "index");
        backend.release_decoded_records("ns", "v1");
        backend
            .decode_variant_index("ns", "index", variant_raw(), source_generation)
            .expect("decode index");
        backend
            .decode_response_metadata("ns", "v1", metadata_raw(4), source_generation)
            .expect("decode metadata");

        assert!(backend.decoded_variants[variant_slot].load_full().is_none());
        assert!(
            backend.decoded_metadata[metadata_slot]
                .load_full()
                .is_none()
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_decoded_publication_is_rejected_after_replacement() {
        let dir = temp_dir("decoded-stale-publication");
        let backend = DiskCacheBackend::new(cfg(dir.clone(), 1024 * 1024)).expect("backend");
        let variant_slot =
            qpx_http::sharding::modulo(&("ns", "index"), backend.decoded_variants.len());
        let metadata_slot =
            qpx_http::sharding::modulo(&("ns", "v1"), backend.decoded_metadata.len());
        let stale_generation = backend.decoded_generation();
        let variant = Arc::new(DecodedVariantIndexEntry {
            namespace: Arc::from("ns"),
            key: Arc::from("index"),
            raw: variant_raw(),
            value: Arc::new(VariantIndex {
                variants: Vec::new(),
            }),
        });
        let metadata = Arc::new(DecodedMetadataEntry {
            namespace: Arc::from("ns"),
            key: Arc::from("v1"),
            raw: metadata_raw(4),
            value: Arc::new(CachedResponseEnvelope {
                status: 204,
                headers: crate::types::CachedHeaders::from_pairs(Vec::new()),
                body: CachedBody::default(),
                body_len: 4,
                stored_at_ms: 1,
                initial_age_secs: 0,
                response_delay_secs: 0,
                freshness_lifetime_secs: 60,
                vary_headers: Vec::new(),
                vary_values: Vec::new(),
                response_directives: Default::default(),
                response_header_values: Default::default(),
            }),
        });

        backend.release_decoded_records("ns", "index");
        backend.release_decoded_records("ns", "v1");
        backend.publish_decoded_variant(variant_slot, None, variant, stale_generation);
        backend.publish_decoded_metadata(metadata_slot, None, metadata, stale_generation);

        assert!(backend.decoded_variants[variant_slot].load_full().is_none());
        assert!(
            backend.decoded_metadata[metadata_slot]
                .load_full()
                .is_none()
        );
        let _ = fs::remove_dir_all(dir);
    }
}
