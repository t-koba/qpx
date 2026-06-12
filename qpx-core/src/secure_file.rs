use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

type Result<T> = std::result::Result<T, SecureFileError>;

/// Error returned when a secure file cannot be created, opened, or validated.
#[derive(Debug, Error)]
pub enum SecureFileError {
    /// A unique temporary name could not be allocated after bounded retries.
    #[error("failed to allocate a unique secure temp file after repeated attempts")]
    UniqueTempExhausted,
    /// The current platform lacks the owner-only file semantics required here.
    #[error(
        "secure file creation is not supported on this platform without owner-only file permissions: {path}"
    )]
    UnsupportedPlatform {
        /// Path that required secure handling.
        path: PathBuf,
    },
    /// The target path is a symlink.
    #[error("refusing to open symlink: {path}")]
    Symlink {
        /// Rejected symlink path.
        path: PathBuf,
    },
    /// The opened handle is not a regular file.
    #[error("refusing to open non-regular secure file: {path}")]
    NonRegular {
        /// Rejected non-regular file path.
        path: PathBuf,
    },
    /// The opened file has more than one hard link.
    #[error("refusing to open hard-linked secure file: {path}")]
    HardLinked {
        /// Rejected hard-linked file path.
        path: PathBuf,
    },
    /// The opened file is not owned by the current effective user.
    #[error("refusing to open secure file owned by another user: {path}")]
    WrongOwner {
        /// Rejected file path owned by another user.
        path: PathBuf,
    },
    /// Opening the target path failed.
    #[error("failed to open secure file {path}")]
    Open {
        /// Path being opened.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// Reading file metadata failed.
    #[error("failed to stat secure file {path}")]
    Stat {
        /// Path whose metadata was inspected.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// Applying owner-only file permissions failed.
    #[error("failed to set secure file mode on {path}")]
    Chmod {
        /// Path whose permissions were updated.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// Truncating the validated output file failed.
    #[error("failed to truncate secure file {path}")]
    Truncate {
        /// Path being truncated.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Creates a unique owner-only temporary file in the process temp directory.
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
    Err(SecureFileError::UniqueTempExhausted)
}

/// Opens `path` for secure output and truncates it after handle validation.
pub fn open_secure_output_file(path: &Path) -> Result<File> {
    ensure_not_symlink(path)?;
    let mut options = OpenOptions::new();
    options.create(true).write(true).read(true);
    let file = open_secure_options(&mut options, path)?;
    file.set_len(0)
        .map_err(|source| SecureFileError::Truncate {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(file)
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
        let file = options.open(path).map_err(|source| SecureFileError::Open {
            path: path.to_path_buf(),
            source,
        })?;
        validate_secure_file_handle(&file, path)?;
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| SecureFileError::Chmod {
                path: path.to_path_buf(),
                source,
            })?;
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        let _ = options;
        Err(SecureFileError::UnsupportedPlatform {
            path: path.to_path_buf(),
        })
    }
}

#[cfg(unix)]
/// Validates that `file` is a private regular file owned by this process user.
pub fn validate_secure_file_handle(file: &File, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().map_err(|source| SecureFileError::Stat {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.file_type().is_file() {
        return Err(SecureFileError::NonRegular {
            path: path.to_path_buf(),
        });
    }
    if meta.nlink() != 1 {
        return Err(SecureFileError::HardLinked {
            path: path.to_path_buf(),
        });
    }
    // SAFETY: geteuid has no preconditions and only reads the current process credentials.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(SecureFileError::WrongOwner {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn ensure_not_symlink(path: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(SecureFileError::Symlink {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn already_exists(err: &SecureFileError) -> bool {
    match err {
        SecureFileError::Open { source, .. } => source.kind() == std::io::ErrorKind::AlreadyExists,
        _ => false,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn open_secure_output_file_rejects_hard_link_before_truncate() {
        let base = std::env::temp_dir().join(format!(
            "qpx-secure-output-hardlink-{}-{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let link = base.with_extension("link");
        {
            let mut file = File::create(&base).expect("create base");
            file.write_all(b"keep").expect("write base");
        }
        std::fs::hard_link(&base, &link).expect("hard link");
        let err = match open_secure_output_file(&link) {
            Ok(_) => panic!("hard link must be rejected"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("hard-linked"),
            "unexpected error: {err}"
        );
        let contents = std::fs::read(&base).expect("read base");
        assert_eq!(contents, b"keep");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&base);
    }
}
