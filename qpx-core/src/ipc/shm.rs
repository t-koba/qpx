use crate::shm_ring::ShmRingBuffer;
use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
                    return Err(anyhow!("path is not a directory: {}", current.display()));
                }
                reject_untrusted_dir_component(&current, &meta)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|err| {
                    anyhow!("failed to create directory {}: {err}", current.display())
                })?;
                set_private_dir_permissions(&current)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn resolve_trusted_symlink_component(path: &Path, meta: &fs::Metadata) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing IPC SHM symlink component not owned by root or current user: {}",
            path.display()
        ));
    }
    let resolved = fs::canonicalize(path)
        .map_err(|err| anyhow!("failed to resolve directory {}: {err}", path.display()))?;
    let resolved_meta = fs::metadata(&resolved).map_err(|err| {
        anyhow!(
            "failed to inspect resolved directory {}: {err}",
            resolved.display()
        )
    })?;
    if !resolved_meta.is_dir() {
        return Err(anyhow!(
            "IPC SHM symlink target is not a directory: {}",
            resolved.display()
        ));
    }
    reject_untrusted_dir_component(&resolved, &resolved_meta)?;
    Ok(resolved)
}

#[cfg(not(unix))]
fn resolve_trusted_symlink_component(path: &Path, _meta: &fs::Metadata) -> Result<PathBuf> {
    Err(anyhow!(
        "refusing IPC SHM symlink component: {}",
        path.display()
    ))
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
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing IPC SHM ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable IPC SHM ancestor directory: {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable IPC SHM ancestor directory not owned by current user: {}",
            path.display()
        ));
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
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|err| {
        anyhow!(
            "failed to set permissions on directory {}: {err}",
            path.display()
        )
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
        return Err(anyhow!("IPC SHM token is too long"));
    }
    if !token.is_ascii() {
        return Err(anyhow!("IPC SHM token must be ASCII"));
    }
    if token.contains('/') || token.contains('\\') || token.contains("..") {
        return Err(anyhow!("IPC SHM token contains forbidden path characters"));
    }
    if !token.starts_with(expected_prefix) || !token.ends_with(".shm") {
        return Err(anyhow!("IPC SHM token has unexpected format"));
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(anyhow!("IPC SHM token contains invalid characters"));
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
    let ring = ShmRingBuffer::create_or_open(&path, size_bytes)?;
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
