use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

pub(super) fn open(path: &Path) -> io::Result<File> {
    if path.components().any(|part| part == Component::ParentDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "disk cache path must not contain parent traversal",
        ));
    }
    open_path(path)
}

#[cfg(target_os = "linux")]
fn open_path(path: &Path) -> io::Result<File> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: open_how contains integer fields for which zero is valid. Zero
    // initialization also leaves any future extension fields disabled.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS;
    // Validate every component in the same operation that opens the file.
    // O_NOFOLLOW alone protects only the final component. Unsupported or
    // restricted openat2 must fail rather than fall back to weaker checks.
    // SAFETY: name and how remain live for this synchronous syscall and their
    // pointers and structure size match the openat2 ABI.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            name.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat2 returned a new owned descriptor, transferred exactly once.
    Ok(unsafe { File::from_raw_fd(descriptor as libc::c_int) })
}

#[cfg(not(target_os = "linux"))]
fn open_path(path: &Path) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(if path.is_absolute() { "/" } else { "." })?;
    let mut parts = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .peekable();
    while let Some(part) = parts.next() {
        let name = CString::new(part.as_bytes())?;
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        let flags = if parts.peek().is_some() {
            flags | libc::O_DIRECTORY
        } else {
            flags
        };
        // SAFETY: parent owns a live directory descriptor and name is a live
        // NUL-terminated component. Each successful result is owned below.
        let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor, transferred exactly once.
        parent = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(parent)
}
