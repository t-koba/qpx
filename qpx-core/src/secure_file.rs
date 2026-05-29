#[cfg(unix)]
use anyhow::Context;
use anyhow::{Result, anyhow};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn create_secure_temp_file(prefix: &str, suffix: &str) -> Result<(File, PathBuf)> {
    let dir = std::env::temp_dir();
    for _ in 0..128 {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = dir.join(format!(
            "{prefix}-{}-{counter}-{nanos}{suffix}",
            std::process::id()
        ));
        match open_secure_new_file(path.as_path()) {
            Ok(file) => return Ok((file, path)),
            Err(err) if already_exists(&err) => continue,
            Err(err) => return Err(err),
        }
    }
    Err(anyhow!(
        "failed to allocate a unique secure temp file after repeated attempts"
    ))
}

pub fn open_secure_output_file(path: &Path) -> Result<File> {
    ensure_not_symlink(path)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    open_secure_options(&mut options, path)
}

fn open_secure_new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true).read(true);
    open_secure_options(&mut options, path)
}

fn open_secure_options(options: &mut OpenOptions, path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options
            .open(path)
            .with_context(|| format!("failed to open secure file {}", path.display()))?;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set secure file mode on {}", path.display()))?;
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        let _ = options;
        Err(anyhow!(
            "secure file creation is not supported on this platform without owner-only file permissions: {}",
            path.display()
        ))
    }
}

fn ensure_not_symlink(path: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(anyhow!("refusing to open symlink: {}", path.display()));
    }
    Ok(())
}

fn already_exists(err: &anyhow::Error) -> bool {
    err.downcast_ref::<std::io::Error>()
        .is_some_and(|err| err.kind() == std::io::ErrorKind::AlreadyExists)
}
