use super::types::{CacheBackend, CachedBody, CachedBodyStream, bounded_cache_body_stream};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use qpx_core::config::CacheBackendConfig;
use qpx_http::body::Body;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::timeout;

const DISK_CACHE_MAGIC: &[u8] = b"QPX-DISK-CACHE\0\x01";
const DISK_CACHE_SCHEMA_VERSION: u16 = 1;
const DISK_CACHE_FILE_EXT: &str = "qpxc";
const DISK_CACHE_CHUNK_BYTES: usize = 64 * 1024;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct DiskCacheBackend {
    root: PathBuf,
    max_bytes: u64,
    sweep_interval: Duration,
    state: std::sync::Arc<Mutex<DiskCacheState>>,
}

#[derive(Default)]
struct DiskCacheState {
    indexed: bool,
    total_bytes: u64,
    entries: HashMap<PathBuf, DiskCacheIndexEntry>,
    last_sweep_ms: u64,
}

#[derive(Clone)]
struct DiskCacheIndexEntry {
    total_len: u64,
    expires_at_ms: u64,
    touched_at_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct DiskCacheHeader {
    schema_version: u16,
    expires_at_ms: u64,
    body_len: u64,
}

struct DiskCacheRead {
    path: PathBuf,
    header: DiskCacheHeader,
    body_offset: u64,
    total_len: u64,
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
            state: std::sync::Arc::new(Mutex::new(DiskCacheState::default())),
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let cloned = backend.clone();
            handle.spawn(async move {
                cloned.background_sweep().await;
            });
        }
        Ok(backend)
    }

    fn path_for(&self, namespace: &str, key: &str) -> PathBuf {
        let digest = cache_hash(namespace, key);
        self.root
            .join(&digest[0..2])
            .join(&digest[2..4])
            .join(format!("{digest}.{DISK_CACHE_FILE_EXT}"))
    }

    async fn ensure_indexed(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.indexed {
            return Ok(());
        }
        let mut entries = HashMap::new();
        let mut total_bytes = 0u64;
        for path in collect_cache_files(&self.root)? {
            match read_disk_cache_header_sync(&path) {
                Ok(read) => {
                    if read.header.expires_at_ms <= now_ms() {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    let touched_at_ms = file_touched_at_ms(&path).unwrap_or(0);
                    total_bytes = total_bytes.saturating_add(read.total_len);
                    entries.insert(
                        path,
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
        state.entries = entries;
        state.total_bytes = total_bytes;
        state.indexed = true;
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
        if let Some(entry) = state.entries.get_mut(&path) {
            entry.touched_at_ms = now_ms();
        }
        Ok(Some(read))
    }

    async fn delete_path(&self, path: &Path) {
        let _ = tokio::fs::remove_file(path).await;
        let mut state = self.state.lock().await;
        if let Some(entry) = state.entries.remove(path) {
            state.total_bytes = state.total_bytes.saturating_sub(entry.total_len);
        }
    }

    async fn remember_write(
        &self,
        path: PathBuf,
        total_len: u64,
        expires_at_ms: u64,
    ) -> Result<()> {
        self.ensure_indexed().await?;
        {
            let mut state = self.state.lock().await;
            if let Some(old) = state.entries.insert(
                path,
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

    async fn maybe_sweep(&self) {
        let now = now_ms();
        let should_sweep = {
            let mut state = self.state.lock().await;
            let due =
                now.saturating_sub(state.last_sweep_ms) >= self.sweep_interval.as_millis() as u64;
            if due {
                state.last_sweep_ms = now;
            }
            due
        };
        if should_sweep {
            self.sweep_expired().await;
        }
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
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>()
        };
        for path in expired {
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
                    .map(|(path, _)| path.clone())
            };
            let Some(path) = victim else {
                return Ok(());
            };
            self.delete_path(&path).await;
        }
    }

    async fn write_bytes(&self, path: &Path, value: &[u8], ttl_secs: u64) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("disk cache path missing parent: {}", path.display()))?;
        ensure_private_dir(parent)?;
        let expires_at_ms = now_ms().saturating_add(ttl_secs.saturating_mul(1000));
        let header = DiskCacheHeader {
            schema_version: DISK_CACHE_SCHEMA_VERSION,
            expires_at_ms,
            body_len: value.len() as u64,
        };
        let tmp_path = temp_path(parent);
        let mut file = create_secure_new_file(&tmp_path)?;
        write_header(&mut file, &header)?;
        file.write_all(value)?;
        file.sync_all()?;
        let total_len = file.metadata()?.len();
        drop(file);
        fs::rename(&tmp_path, path)
            .with_context(|| format!("failed to commit disk cache object {}", path.display()))?;
        self.remember_write(path.to_path_buf(), total_len, expires_at_ms)
            .await?;
        Ok(())
    }

    async fn write_body_stream(
        &self,
        path: &Path,
        body: Body,
        max_body_bytes: usize,
        body_read_timeout: Duration,
        ttl_secs: u64,
    ) -> Result<u64> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("disk cache path missing parent: {}", path.display()))?;
        ensure_private_dir(parent)?;
        let (body, len_rx) = bounded_cache_body_stream(body, max_body_bytes, body_read_timeout);
        let cached = CachedBody::from_body_limited(body, max_body_bytes, body_read_timeout).await?;
        let len = len_rx
            .await
            .map_err(|_| anyhow!("disk cache body writer closed"))??;
        self.put_object_path(path, &cached, ttl_secs).await?;
        Ok(len)
    }

    async fn put_object_path(&self, path: &Path, body: &CachedBody, ttl_secs: u64) -> Result<()> {
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
        };
        let tmp_path = temp_path(parent);
        let mut file = TokioFile::from_std(create_secure_new_file(&tmp_path)?);
        write_header_async(&mut file, &header).await?;
        while let Some(chunk) = source.data().await {
            file.write_all(chunk?.as_ref()).await?;
        }
        file.sync_all().await?;
        let total_len = file.metadata().await?.len();
        drop(file);
        fs::rename(&tmp_path, path)
            .with_context(|| format!("failed to commit disk cache object {}", path.display()))?;
        self.remember_write(path.to_path_buf(), total_len, expires_at_ms)
            .await?;
        Ok(())
    }

    async fn background_sweep(self) {
        let mut interval = tokio::time::interval(self.sweep_interval);
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
        self.maybe_sweep().await;
        let path = self.path_for(namespace, key);
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
        Ok(Some(Bytes::from(out)))
    }

    async fn get_many(&self, namespace: &str, keys: &[String]) -> Result<Vec<Option<Bytes>>> {
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            out.push(self.get(namespace, key).await?);
        }
        Ok(out)
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
        self.maybe_sweep().await;
        let path = self.path_for(namespace, key);
        let Some(read) = self.open_valid(path).await? else {
            return Ok(None);
        };
        if read.header.body_len != expected_len {
            return Ok(None);
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
        self.maybe_sweep().await;
        let path = self.path_for(namespace, key);
        self.write_bytes(&path, value, ttl_secs).await
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
        self.maybe_sweep().await;
        let path = self.path_for(namespace, key);
        self.put_object_path(&path, body, ttl_secs).await
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
        self.maybe_sweep().await;
        let path = self.path_for(namespace, key);
        timeout(
            body_read_timeout,
            self.write_body_stream(&path, body, max_body_bytes, body_read_timeout, ttl_secs),
        )
        .await?
    }

    async fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let path = self.path_for(namespace, key);
        self.delete_path(&path).await;
        Ok(())
    }
}

fn cache_hash(namespace: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0]);
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
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
    if meta.len().saturating_sub(body_offset) != header.body_len {
        return Err(anyhow!("disk cache object length mismatch"));
    }
    Ok(DiskCacheRead {
        path: path.to_path_buf(),
        header,
        body_offset,
        total_len: meta.len(),
    })
}

fn write_header(file: &mut File, header: &DiskCacheHeader) -> Result<()> {
    let raw = serde_json::to_vec(header)?;
    file.write_all(DISK_CACHE_MAGIC)?;
    file.write_all(&(raw.len() as u32).to_be_bytes())?;
    file.write_all(&raw)?;
    Ok(())
}

async fn write_header_async(file: &mut TokioFile, header: &DiskCacheHeader) -> Result<()> {
    let raw = serde_json::to_vec(header)?;
    file.write_all(DISK_CACHE_MAGIC).await?;
    file.write_all(&(raw.len() as u32).to_be_bytes()).await?;
    file.write_all(&raw).await?;
    Ok(())
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
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.exists() {
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
            continue;
        }
        fs::create_dir(&current)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
        }
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
