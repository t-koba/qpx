use anyhow::{Context, Result, anyhow};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use super::PersistedUdpSessionHandoff;

#[cfg(unix)]
pub(super) fn ensure_secure_handoff_dir(dir: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in dir.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    current = resolve_trusted_handoff_symlink(&current, &meta)?;
                    continue;
                }
                if !meta.is_dir() {
                    return Err(anyhow!(
                        "udp handoff path component is not a directory: {}",
                        current.display()
                    ));
                }
                reject_untrusted_handoff_ancestor(&current, &meta)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| {
                    format!(
                        "failed to create udp handoff directory component {}",
                        current.display()
                    )
                })?;
                set_private_handoff_dir_permissions(&current)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    set_private_handoff_dir_permissions(dir)?;
    Ok(())
}

#[cfg(unix)]
fn resolve_trusted_handoff_symlink(path: &Path, meta: &fs::Metadata) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing untrusted symlinked udp handoff path component {}",
            path.display()
        ));
    }
    let resolved = fs::canonicalize(path).with_context(|| {
        format!(
            "failed to resolve udp handoff symlink component {}",
            path.display()
        )
    })?;
    let resolved_meta = fs::metadata(&resolved)?;
    if !resolved_meta.is_dir() {
        return Err(anyhow!(
            "udp handoff symlink target is not a directory: {}",
            resolved.display()
        ));
    }
    reject_untrusted_handoff_ancestor(&resolved, &resolved_meta)?;
    Ok(resolved)
}

#[cfg(unix)]
fn set_private_handoff_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "failed to set private permissions on udp handoff directory {}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn reject_untrusted_handoff_ancestor(path: &Path, meta: &fs::Metadata) -> Result<()> {
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
            "refusing udp handoff ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing sticky writable udp handoff ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable udp handoff ancestor directory {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable udp handoff ancestor directory not owned by current user: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn write_handoff_file(path: &Path, handoff: &PersistedUdpSessionHandoff) -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let serialized =
        serde_json::to_vec(handoff).context("failed to serialize udp session handoff")?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to create udp session handoff {}", path.display()))?;
    file.write_all(&serialized)
        .with_context(|| format!("failed to write udp session handoff {}", path.display()))?;
    file.flush().ok();
    Ok(())
}

#[cfg(unix)]
pub(super) fn read_handoff_file(path: &Path) -> Result<PersistedUdpSessionHandoff> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open udp session handoff {}", path.display()))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .with_context(|| format!("failed to read udp session handoff {}", path.display()))?;
    serde_json::from_slice(&buf).context("invalid udp session handoff")
}

pub(super) fn validate_connected_socket(
    socket: &std::net::UdpSocket,
    expected_local_addr: SocketAddr,
    expected_peer_addr: SocketAddr,
) -> Result<()> {
    let local_addr = socket
        .local_addr()
        .context("failed to resolve restored udp local addr")?;
    let peer_addr = socket
        .peer_addr()
        .context("failed to resolve restored udp peer addr")?;
    if local_addr != expected_local_addr {
        return Err(anyhow!(
            "restored udp local addr mismatch: expected {}, got {}",
            expected_local_addr,
            local_addr
        ));
    }
    if peer_addr != expected_peer_addr {
        return Err(anyhow!(
            "restored udp peer addr mismatch: expected {}, got {}",
            expected_peer_addr,
            peer_addr
        ));
    }
    Ok(())
}
