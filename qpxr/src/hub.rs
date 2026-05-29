use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use qpx_core::exporter::{CaptureDirection, CapturePlane};
use std::collections::{HashMap, VecDeque};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, broadcast, mpsc};
use tokio::task::spawn_blocking;
use tracing::warn;

const MAX_SEQUENCE_KEYS: usize = 100_000;
const SEQUENCE_GC_INTERVAL_NANOS: u64 = 5_000_000_000;

#[derive(Clone)]
pub(crate) struct ExporterHub {
    pub(super) sequences: Arc<Mutex<SequencesState>>,
    pub(super) history: Arc<RwLock<HistoryState>>,
    file_sink: Option<mpsc::Sender<Bytes>>,
    pub(super) live_tx: broadcast::Sender<Bytes>,
    history_limit_bytes: usize,
    history_limit_age: Duration,
    pub(super) pcap_preface: Arc<Vec<u8>>,
    pub(super) max_payload_bytes: usize,
}

pub(super) struct SequencesState {
    pub(super) sequences: HashMap<SequenceKey, SequenceState>,
    sequences_last_gc_unix_nanos: u64,
}

pub(super) struct HistoryState {
    history: VecDeque<HistoryItem>,
    history_bytes: usize,
}

struct HistoryItem {
    ts_unix_nanos: u64,
    bytes: Bytes,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct SequenceKey {
    pub(super) session_id: String,
    pub(super) plane: CapturePlane,
    pub(super) direction: CaptureDirection,
}

#[derive(Clone, Copy)]
pub(super) struct SequenceState {
    pub(super) next: u32,
    pub(super) last_seen_unix_nanos: u64,
}

struct RotatingFileSink {
    dir: PathBuf,
    rotate_bytes: u64,
    current_size: u64,
    index: u64,
    file: File,
    preface: Arc<Vec<u8>>,
    blocks_since_flush: usize,
}

impl ExporterHub {
    pub(crate) fn new(
        save_dir: Option<PathBuf>,
        rotate_bytes: u64,
        history_limit_bytes: usize,
        history_limit_age: Duration,
        pcap_preface: Arc<Vec<u8>>,
        max_payload_bytes: usize,
    ) -> Result<Self> {
        let file_sink = match save_dir {
            Some(dir) => {
                const FILE_SINK_QUEUE: usize = 4096;
                let sink = RotatingFileSink::new(dir, rotate_bytes.max(1), pcap_preface.clone())?;
                let (tx, mut rx) = mpsc::channel::<Bytes>(FILE_SINK_QUEUE);
                spawn_blocking(move || {
                    let mut sink = sink;
                    while let Some(block) = rx.blocking_recv() {
                        if let Err(err) = sink.write_block(block.as_ref()) {
                            warn!(error = ?err, "failed to persist pcapng block");
                        }
                    }
                });
                Some(tx)
            }
            None => None,
        };
        let (live_tx, _) = broadcast::channel::<Bytes>(4096);
        Ok(Self {
            sequences: Arc::new(Mutex::new(SequencesState {
                sequences: HashMap::new(),
                sequences_last_gc_unix_nanos: 0,
            })),
            history: Arc::new(RwLock::new(HistoryState {
                history: VecDeque::new(),
                history_bytes: 0,
            })),
            file_sink,
            live_tx,
            history_limit_bytes,
            history_limit_age,
            pcap_preface,
            max_payload_bytes,
        })
    }

    pub(super) async fn publish_encoded_block(&self, ts_unix_nanos: u64, encoded: Bytes) {
        if let Some(tx) = self.file_sink.as_ref()
            && let Err(err) = tx.send(encoded.clone()).await
        {
            warn!(error = ?err, "pcapng file sink disconnected");
        }
        {
            let mut history = self.history.write().await;
            self.push_history_locked(&mut history, ts_unix_nanos, encoded.clone());
        }
        let _ = self.live_tx.send(encoded);
    }

    fn push_history_locked(&self, state: &mut HistoryState, ts_unix_nanos: u64, bytes: Bytes) {
        if self.history_limit_bytes == 0 {
            return;
        }
        state.history_bytes += bytes.len();
        state.history.push_back(HistoryItem {
            ts_unix_nanos,
            bytes,
        });
        self.evict_history_locked(state, ts_unix_nanos);
    }

    fn evict_history_locked(&self, state: &mut HistoryState, now_unix_nanos: u64) {
        let min_ts = now_unix_nanos.saturating_sub(self.history_limit_age.as_nanos() as u64);
        while let Some(front) = state.history.front() {
            if front.ts_unix_nanos >= min_ts {
                break;
            }
            if let Some(old) = state.history.pop_front() {
                state.history_bytes = state.history_bytes.saturating_sub(old.bytes.len());
            }
        }
        while state.history_bytes > self.history_limit_bytes {
            if let Some(old) = state.history.pop_front() {
                state.history_bytes = state.history_bytes.saturating_sub(old.bytes.len());
            } else {
                break;
            }
        }
    }

    pub(super) async fn history_snapshot(&self) -> Vec<Bytes> {
        let state = self.history.read().await;
        state.history.iter().map(|h| h.bytes.clone()).collect()
    }

    pub(super) fn gc_sequences_locked(&self, state: &mut SequencesState, now_unix_nanos: u64) {
        if state.sequences.len() <= MAX_SEQUENCE_KEYS
            && now_unix_nanos.saturating_sub(state.sequences_last_gc_unix_nanos)
                < SEQUENCE_GC_INTERVAL_NANOS
        {
            return;
        }
        state.sequences_last_gc_unix_nanos = now_unix_nanos;

        let cutoff = now_unix_nanos
            .saturating_sub(self.history_limit_age.as_nanos().min(u64::MAX as u128) as u64);
        state
            .sequences
            .retain(|_, v| v.last_seen_unix_nanos >= cutoff);

        if state.sequences.len() > MAX_SEQUENCE_KEYS {
            warn!(
                sequences = state.sequences.len(),
                max = MAX_SEQUENCE_KEYS,
                "sequence state too large; clearing"
            );
            state.sequences.clear();
        }
    }
}

impl RotatingFileSink {
    fn new(dir: PathBuf, rotate_bytes: u64, preface: Arc<Vec<u8>>) -> Result<Self> {
        ensure_dir_secure(&dir)?;
        let tmp = dir.join(".bootstrap.tmp");
        let file = open_secure_file(&tmp)?;
        let mut sink = Self {
            dir,
            rotate_bytes,
            current_size: 0,
            index: 0,
            file,
            preface,
            blocks_since_flush: 0,
        };
        sink.rotate()?;
        let _ = fs::remove_file(tmp);
        Ok(sink)
    }

    fn write_block(&mut self, block: &[u8]) -> Result<()> {
        const FLUSH_EVERY_BLOCKS: usize = 128;
        if self.current_size > 0 && self.current_size + block.len() as u64 > self.rotate_bytes {
            self.rotate()?;
        }
        self.file.write_all(block)?;
        self.current_size += block.len() as u64;
        self.blocks_since_flush = self.blocks_since_flush.saturating_add(1);
        if self.blocks_since_flush >= FLUSH_EVERY_BLOCKS {
            self.file.flush()?;
            self.blocks_since_flush = 0;
        }
        Ok(())
    }

    fn rotate(&mut self) -> Result<()> {
        self.index = self.index.saturating_add(1);
        let filename = format!(
            "capture-{}-{:06}.pcapng",
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            self.index
        );
        let path = self.dir.join(filename);
        self.file = open_secure_file(&path)?;
        self.current_size = 0;
        self.file.write_all(&self.preface)?;
        self.file.flush()?;
        self.current_size = self.preface.len() as u64;
        self.blocks_since_flush = 0;
        Ok(())
    }
}

fn ensure_dir_secure(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure_secure_dir_components(dir, "save dir")?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to chmod {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        ensure_not_symlink(dir, "save dir")?;
        fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_secure_dir_components(dir: &Path, label: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut current = PathBuf::new();
    for component in dir.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    current = resolve_trusted_symlink_component(&current, &meta, label)?;
                    continue;
                }
                if !meta.is_dir() {
                    return Err(anyhow!(
                        "{label} component is not a directory: {}",
                        current.display()
                    ));
                }
                reject_untrusted_dir_component(&current, &meta, label)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .with_context(|| format!("failed to create {}", current.display()))?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("failed to chmod {}", current.display()))?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn resolve_trusted_symlink_component(
    path: &Path,
    meta: &fs::Metadata,
    label: &str,
) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "{label} path must not contain untrusted symlink component: {}",
            path.display()
        ));
    }
    let resolved =
        fs::canonicalize(path).with_context(|| format!("failed to resolve {}", path.display()))?;
    let resolved_meta = fs::metadata(&resolved)?;
    if !resolved_meta.is_dir() {
        return Err(anyhow!(
            "{label} symlink target is not a directory: {}",
            resolved.display()
        ));
    }
    reject_untrusted_dir_component(&resolved, &resolved_meta, label)?;
    Ok(resolved)
}

#[cfg(unix)]
fn reject_untrusted_dir_component(path: &Path, meta: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = meta.mode();
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let sticky_bit = u32::from(libc::S_ISVTX);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let sticky_bit = libc::S_ISVTX;
    let sticky = mode & sticky_bit != 0;
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing {label} ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing sticky writable {label} ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable {label} ancestor directory {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable {label} ancestor directory not owned by current user: {}",
            path.display()
        ));
    }
    Ok(())
}

fn open_secure_file(path: &Path) -> Result<File> {
    ensure_not_symlink(path, "pcapng file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .with_context(|| format!("failed to open {}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(anyhow!(
            "secure pcapng file creation is not supported on this platform without owner-only file permissions"
        ))
    }
}

fn ensure_not_symlink(path: &Path, label: &str) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(anyhow!("{label} must not be a symlink: {}", path.display()));
    }
    Ok(())
}
