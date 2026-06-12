use crate::shm_ring::ShmRingBuffer;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

type Result<T> = std::result::Result<T, IpcShmError>;

#[derive(Debug, Error)]
pub enum IpcShmError {
    #[error("path is not a directory: {path}")]
    NotDirectory { path: PathBuf },
    #[error("failed to create directory {path}")]
    CreateDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect directory {path}")]
    InspectPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(unix)]
    #[error("refusing IPC SHM symlink component not owned by root or current user: {path}")]
    UntrustedSymlinkOwner { path: PathBuf },
    #[cfg(unix)]
    #[error("failed to resolve directory {path}")]
    ResolveSymlink {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(unix)]
    #[error("failed to inspect resolved directory {path}")]
    InspectResolvedPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[cfg(unix)]
    #[error("IPC SHM symlink target is not a directory: {path}")]
    SymlinkTargetNotDirectory { path: PathBuf },
    #[cfg(not(unix))]
    #[error("refusing IPC SHM symlink component: {path}")]
    SymlinkUnsupported { path: PathBuf },
    #[cfg(unix)]
    #[error("refusing IPC SHM ancestor directory not owned by root or current user: {path}")]
    UntrustedAncestorOwner { path: PathBuf },
    #[cfg(unix)]
    #[error("refusing attacker-writable IPC SHM ancestor directory: {path}")]
    AttackerWritableAncestor { path: PathBuf },
    #[cfg(unix)]
    #[error("refusing group-writable IPC SHM ancestor directory not owned by current user: {path}")]
    GroupWritableAncestor { path: PathBuf },
    #[cfg(unix)]
    #[error("failed to set permissions on directory {path}")]
    SetPermissions {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("IPC SHM token is too long")]
    TokenTooLong,
    #[error("IPC SHM token must be ASCII")]
    TokenNotAscii,
    #[error("IPC SHM token contains forbidden path characters")]
    TokenForbiddenPathChars,
    #[error("IPC SHM token has unexpected format")]
    TokenUnexpectedFormat,
    #[error("IPC SHM token contains invalid characters")]
    TokenInvalidChars,
    #[error("failed to create or open IPC SHM ring {path}")]
    Ring {
        path: PathBuf,
        #[source]
        source: anyhow::Error,
    },
}

static ACTIVE_IPC_SHM_TOKENS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn active_ipc_shm_tokens() -> &'static Mutex<HashSet<String>> {
    ACTIVE_IPC_SHM_TOKENS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn register_active_ipc_shm_token(token: &str) {
    if let Ok(mut active) = active_ipc_shm_tokens().lock() {
        active.insert(token.to_string());
    }
}

fn is_active_ipc_shm_token(token: &str) -> bool {
    active_ipc_shm_tokens()
        .lock()
        .map(|active| active.contains(token))
        .unwrap_or(false)
}

pub fn unregister_ipc_shm_token(token: &str) {
    if let Ok(mut active) = active_ipc_shm_tokens().lock() {
        active.remove(token);
    }
}

pub fn unregister_ipc_shm_path(path: &Path) {
    if let Some(token) = path.file_name().and_then(|value| value.to_str()) {
        unregister_ipc_shm_token(token);
    }
}

pub fn ensure_secure_dir(dir: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in dir.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    current = resolve_trusted_symlink_component(&current, &meta)?;
                    continue;
                }
                if !meta.is_dir() {
                    return Err(IpcShmError::NotDirectory {
                        path: current.clone(),
                    });
                }
                reject_untrusted_dir_component(&current, &meta)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|source| IpcShmError::CreateDir {
                    path: current.clone(),
                    source,
                })?;
                set_private_dir_permissions(&current)?;
            }
            Err(source) => {
                return Err(IpcShmError::InspectPath {
                    path: current.clone(),
                    source,
                });
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn resolve_trusted_symlink_component(path: &Path, meta: &fs::Metadata) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions and only reads the current process credentials.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(IpcShmError::UntrustedSymlinkOwner {
            path: path.to_path_buf(),
        });
    }
    let resolved = fs::canonicalize(path).map_err(|source| IpcShmError::ResolveSymlink {
        path: path.to_path_buf(),
        source,
    })?;
    let resolved_meta =
        fs::metadata(&resolved).map_err(|source| IpcShmError::InspectResolvedPath {
            path: resolved.clone(),
            source,
        })?;
    if !resolved_meta.is_dir() {
        return Err(IpcShmError::SymlinkTargetNotDirectory { path: resolved });
    }
    reject_untrusted_dir_component(&resolved, &resolved_meta)?;
    Ok(resolved)
}

#[cfg(not(unix))]
fn resolve_trusted_symlink_component(path: &Path, _meta: &fs::Metadata) -> Result<PathBuf> {
    Err(IpcShmError::SymlinkUnsupported {
        path: path.to_path_buf(),
    })
}

#[cfg(unix)]
fn reject_untrusted_dir_component(path: &Path, meta: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mode = meta.mode();
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let sticky_bit = u32::from(libc::S_ISVTX);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let sticky_bit = libc::S_ISVTX;
    let sticky = mode & sticky_bit != 0;
    // SAFETY: geteuid has no preconditions and only reads the current process credentials.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(IpcShmError::UntrustedAncestorOwner {
            path: path.to_path_buf(),
        });
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(IpcShmError::AttackerWritableAncestor {
            path: path.to_path_buf(),
        });
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(IpcShmError::GroupWritableAncestor {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_untrusted_dir_component(_path: &Path, _meta: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        IpcShmError::SetPermissions {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn ipc_shm_dir() -> Result<PathBuf> {
    let base = ShmRingBuffer::default_shm_dir();
    ensure_secure_dir(&base)?;
    let ipc = base.join("ipc");
    ensure_secure_dir(&ipc)?;
    Ok(ipc)
}

pub fn validate_ipc_shm_token(token: &str, expected_prefix: &str) -> Result<()> {
    if token.len() > 255 {
        return Err(IpcShmError::TokenTooLong);
    }
    if !token.is_ascii() {
        return Err(IpcShmError::TokenNotAscii);
    }
    if token.contains('/') || token.contains('\\') || token.contains("..") {
        return Err(IpcShmError::TokenForbiddenPathChars);
    }
    if !token.starts_with(expected_prefix) || !token.ends_with(".shm") {
        return Err(IpcShmError::TokenUnexpectedFormat);
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(IpcShmError::TokenInvalidChars);
    }
    Ok(())
}

pub fn ipc_shm_path(token: &str, expected_prefix: &str) -> Result<PathBuf> {
    validate_ipc_shm_token(token, expected_prefix)?;
    Ok(ipc_shm_dir()?.join(token))
}

pub fn create_or_open_ipc_ring(
    token: &str,
    expected_prefix: &str,
    size_bytes: usize,
) -> Result<(PathBuf, ShmRingBuffer)> {
    let path = ipc_shm_path(token, expected_prefix)?;
    let ring =
        ShmRingBuffer::create_or_open(&path, size_bytes).map_err(|source| IpcShmError::Ring {
            path: path.clone(),
            source: source.into(),
        })?;
    register_active_ipc_shm_token(token);
    Ok((path, ring))
}

pub fn maybe_cleanup_stale_ipc_shm_files(
    dir: &Path,
    last_cleanup_unix_secs: &AtomicU64,
    cleanup_interval_secs: u64,
    stale_after_secs: u64,
) {
    let now = SystemTime::now();
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let last = last_cleanup_unix_secs.load(Ordering::Relaxed);
    if now_secs.saturating_sub(last) < cleanup_interval_secs {
        return;
    }
    if last_cleanup_unix_secs
        .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("ipc_req_") && !name.starts_with("ipc_res_") {
            continue;
        }
        if is_active_ipc_shm_token(name) {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("shm") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let Ok(age) = now.duration_since(modified) else {
            continue;
        };
        if age.as_secs() < stale_after_secs {
            continue;
        }
        let _ = std::fs::remove_file(path);
    }
}
