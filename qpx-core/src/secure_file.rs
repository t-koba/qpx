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
    let dir = secure_temp_dir()?;
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

/// The directory that holds the secure temporary files.
///
/// On Unix a file is created with the owner-only mode, so the file never
/// exists with a wider mode and the directory needs no protection of its
/// own. On Windows a file inherits the access control list of the directory
/// it is created in, so the directory itself is restricted to its owner
/// before any file is created inside it.
#[cfg(unix)]
fn secure_temp_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
}

#[cfg(not(any(unix, windows)))]
fn secure_temp_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir())
}

#[cfg(windows)]
fn secure_temp_dir() -> Result<PathBuf> {
    owner_only_temp_dir()
}

/// The per-process directory that holds the secure temporary files.
///
/// The directory is created once and restricted to its owner, so a file
/// created inside it inherits an owner-only access control list from its
/// first instant. The file is therefore never readable by another local
/// user, not even in the window between its creation and the application of
/// its own access control list.
#[cfg(windows)]
fn owner_only_temp_dir() -> Result<PathBuf> {
    use std::sync::OnceLock;

    static DIR: OnceLock<PathBuf> = OnceLock::new();
    if let Some(dir) = DIR.get() {
        return Ok(dir.clone());
    }
    let path = std::env::temp_dir().join(format!("qpx-secure-{}", std::process::id()));
    match std::fs::create_dir(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(SecureFileError::Open {
                path: path.clone(),
                source,
            });
        }
    }
    apply_owner_only_directory_acl(&path)?;
    let _ = DIR.set(path.clone());
    Ok(path)
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

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC,
        };

        // The file is created new, so it cannot be a pre-existing link, and
        // the handle is opened for writing so that the owner-only access
        // control list can be applied to it before anything is written.
        options.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC);
        let file = options.open(path).map_err(|source| SecureFileError::Open {
            path: path.to_path_buf(),
            source,
        })?;
        validate_windows_secure_file_handle(&file, path)?;
        apply_owner_only_acl(&file, path)?;
        Ok(file)
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = options;
        Err(SecureFileError::UnsupportedPlatform {
            path: path.to_path_buf(),
        })
    }
}

/// Applies the owner-only access control list to an open file.
///
/// The descriptor grants full access to the local system, the administrators
/// and the file's owner, and nothing to anyone else. It is the same
/// descriptor the MITM CA material uses, so both kinds of private file get
/// the same protection on Windows.
#[cfg(windows)]
pub(crate) fn apply_owner_only_acl(file: &File, path: &Path) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    // Protected DACL: LocalSystem, Administrators and the current owner get
    // full access. This keeps private file material out of inherited
    // temp-directory ACLs.
    let sddl_text = concat!("D:P(A;;FA;;;SY)(A;;FA;;;", "\x42", "\x41", ")(A;;FA;;;OW)");
    let sddl: Vec<u16> = sddl_text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and `descriptor` is an out pointer freed with LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(SecureFileError::Chmod {
            path: path.to_path_buf(),
            source: std::io::Error::other(format!(
                "failed to build owner-only security descriptor: {}",
                std::io::Error::last_os_error()
            )),
        });
    }
    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: descriptor is a valid security descriptor produced by the Win32 conversion API.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(descriptor.cast());
        }
        return Err(SecureFileError::Chmod {
            path: path.to_path_buf(),
            source: std::io::Error::other(format!(
                "failed to extract the owner-only DACL: {}",
                std::io::Error::last_os_error()
            )),
        });
    }
    if dacl_present == 0 || dacl.is_null() {
        // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(descriptor.cast());
        }
        return Err(SecureFileError::Chmod {
            path: path.to_path_buf(),
            source: std::io::Error::other("the owner-only security descriptor has no DACL"),
        });
    }
    // SAFETY: the file handle is open and validated by the caller; DACL belongs to the live descriptor.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        let _ = LocalFree(descriptor.cast());
    }
    if status != 0 {
        return Err(SecureFileError::Chmod {
            path: path.to_path_buf(),
            source: std::io::Error::from_raw_os_error(status as i32),
        });
    }
    Ok(())
}

/// Restricts a directory to its owner.
///
/// The descriptor grants full access to the local system, the administrators
/// and the directory's owner, and nothing to anyone else. A file created
/// inside the directory inherits that access control list, so the file is
/// private from its first instant.
#[cfg(windows)]
pub(crate) fn apply_owner_only_directory_acl(path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
    };

    let sddl_text = concat!("D:P(A;;FA;;;SY)(A;;FA;;;", "\x42", "\x41", ")(A;;FA;;;OW)");
    let sddl: Vec<u16> = sddl_text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and `descriptor` is an out pointer freed with LocalFree.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(SecureFileError::Chmod {
            path: path.to_path_buf(),
            source: std::io::Error::other(format!(
                "failed to build the owner-only directory security descriptor: {}",
                std::io::Error::last_os_error()
            )),
        });
    }

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: both pointers are valid NUL-terminated/Windows-owned buffers for the call.
    let ok = unsafe { SetFileSecurityW(path_wide.as_ptr(), DACL_SECURITY_INFORMATION, descriptor) };
    // SAFETY: descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        let _ = LocalFree(descriptor.cast());
    }
    if ok == 0 {
        return Err(SecureFileError::Chmod {
            path: path.to_path_buf(),
            source: std::io::Error::other(format!(
                "failed to set the owner-only ACL on the directory: {}",
                std::io::Error::last_os_error()
            )),
        });
    }
    Ok(())
}

/// Checks that an open handle refers to a private regular file.
///
/// The file must not be a reparse point, a directory, or a file with more than
/// one hard link, so that the owner-only access control list protects exactly
/// the file the caller opened.
#[cfg(windows)]
pub(crate) fn validate_windows_secure_file_handle(file: &File, path: &Path) -> Result<()> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };

    let metadata = file.metadata().map_err(|source| SecureFileError::Stat {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(SecureFileError::NonRegular {
            path: path.to_path_buf(),
        });
    }
    let mut info = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` is an open file handle and `info` points to writable storage.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(SecureFileError::Stat {
            path: path.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: the API succeeded and initialized the structure.
    let info = unsafe { info.assume_init() };
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(SecureFileError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(SecureFileError::NonRegular {
            path: path.to_path_buf(),
        });
    }
    if info.nNumberOfLinks != 1 {
        return Err(SecureFileError::HardLinked {
            path: path.to_path_buf(),
        });
    }
    Ok(())
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn create_secure_temp_file_creates_a_private_file() {
        let (file, path) =
            create_secure_temp_file("qpx-secure-temp-test", ".body").expect("secure temp file");
        assert!(path.exists(), "the secure temp file must exist");
        assert!(file.metadata().expect("metadata").is_file());
        assert!(
            dacl_is_protected(&file),
            "the file's access control list must be set on the file, not inherited"
        );
        drop(file);
        let _ = std::fs::remove_file(&path);
    }

    /// Whether the file's access control list is protected, that is, set on
    /// the file itself instead of inherited from its directory.
    fn dacl_is_protected(file: &File) -> bool {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, PSECURITY_DESCRIPTOR,
            SE_DACL_PROTECTED,
        };

        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: the handle is open and every out pointer is valid.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return false;
        }
        let mut control = 0u32;
        let mut revision = 0u32;
        // SAFETY: descriptor is a valid security descriptor.
        let ok = unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        if ok == 0 {
            return false;
        }
        control & SE_DACL_PROTECTED != 0
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn create_secure_temp_file_creates_an_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        let (file, path) =
            create_secure_temp_file("qpx-secure-temp-test", ".body").expect("secure temp file");
        let mode = file.metadata().expect("metadata").permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the secure temp file must be private to its owner"
        );
        drop(file);
        let _ = std::fs::remove_file(&path);
    }

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
