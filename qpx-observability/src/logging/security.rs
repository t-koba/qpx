use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

pub(super) fn ensure_private_log_dir(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(anyhow!(
                        "refusing to use symlinked log path component {}",
                        current.display()
                    ));
                }
                if !meta.is_dir() {
                    return Err(anyhow!(
                        "log path component is not a directory: {}",
                        current.display()
                    ));
                }
                reject_untrusted_log_ancestor(&current, &meta)?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                set_private_directory_permissions(&current)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(anyhow!(
            "refusing file logging on this platform: private ACL and reparse-point protection is not implemented"
        ))
    }
}

#[cfg(unix)]
fn reject_untrusted_log_ancestor(path: &Path, meta: &fs::Metadata) -> Result<()> {
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
            "refusing log ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if sticky && mode & 0o022 != 0 && meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing sticky writable log ancestor directory not owned by root or current user: {}",
            path.display()
        ));
    }
    if mode & 0o002 != 0 && !sticky {
        return Err(anyhow!(
            "refusing attacker-writable log ancestor directory {}",
            path.display()
        ));
    }
    if !sticky && mode & 0o020 != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing group-writable log ancestor directory not owned by current user: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_untrusted_log_ancestor(_path: &Path, _meta: &fs::Metadata) -> Result<()> {
    Err(anyhow!(
        "refusing file logging on this platform: private ACL and reparse-point protection is not implemented"
    ))
}

pub(super) fn reject_symlink_path(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(anyhow!(
            "refusing to write logs through symlink path {}",
            path.display()
        ));
    }
    Ok(())
}
