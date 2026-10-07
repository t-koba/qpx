use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

pub(super) fn open(path: &Path) -> io::Result<File> {
    open_checked(path, libc::O_NONBLOCK)
}

fn open_checked(path: &Path, extra_flags: libc::c_int) -> io::Result<File> {
    if path.components().any(|part| part == Component::ParentDir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "disk cache path must not contain parent traversal",
        ));
    }
    open_path(path, extra_flags)
}

pub(super) struct Directory(File);

impl Directory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        open_checked(path, libc::O_DIRECTORY).map(Self)
    }

    pub(super) fn create_all(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        if path.components().any(|part| part == Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "disk cache path must not contain parent traversal",
            ));
        }
        let mut remaining = path;
        let mut missing = Vec::new();
        // Locate an existing prefix, then verify every component before creating anything.
        // Metadata is only a search hint; the owned no-follow descriptor is authoritative.
        let mut parent = loop {
            let candidate = if remaining.as_os_str().is_empty() {
                Path::new(".")
            } else {
                remaining
            };
            match std::fs::symlink_metadata(candidate) {
                Ok(_) => break Self::open(candidate)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let part = remaining.file_name().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "disk cache directory missing name",
                        )
                    })?;
                    missing.push(part);
                    remaining = remaining.parent().ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "disk cache directory missing parent",
                        )
                    })?;
                }
                Err(error) => return Err(error),
            }
        };
        for part in missing.into_iter().rev() {
            let name = component_name(part)?;
            let mut created = false;
            // SAFETY: the name and owned directory descriptor remain live;
            // mkdirat receives a valid permission mode.
            let result = unsafe { libc::mkdirat(parent.0.as_raw_fd(), name.as_ptr(), 0o700) };
            if result == 0 {
                created = true;
            } else {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::AlreadyExists {
                    return Err(error);
                }
            }
            // SAFETY: name is a validated component relative to an owned parent.
            // O_NOFOLLOW rejects a replacement symlink, including after mkdirat.
            let descriptor = unsafe {
                libc::openat(
                    parent.0.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: openat returned a new owned descriptor, transferred once.
            parent = Self(unsafe { File::from_raw_fd(descriptor) });
            if created {
                parent
                    .0
                    .set_permissions(std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(parent)
    }

    pub(super) fn create(&self, name: &OsStr) -> io::Result<File> {
        use std::os::unix::fs::PermissionsExt;
        let name = component_name(name)?;
        let flags =
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: the parent descriptor is owned, name is a validated live
        // component, and O_CREAT receives a valid mode argument.
        let descriptor = unsafe { libc::openat(self.0.as_raw_fd(), name.as_ptr(), flags, 0o600) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor, transferred exactly once.
        let file = unsafe { File::from_raw_fd(descriptor) };
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }

    pub(super) fn rename(&self, source: &OsStr, destination: &OsStr) -> io::Result<()> {
        let source = component_name(source)?;
        let destination = component_name(destination)?;
        // SAFETY: both names are validated live components in the same owned
        // directory. renameat atomically replaces the destination entry.
        let result = unsafe {
            libc::renameat(
                self.0.as_raw_fd(),
                source.as_ptr(),
                self.0.as_raw_fd(),
                destination.as_ptr(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn remove(&self, name: &OsStr) -> io::Result<()> {
        let name = component_name(name)?;
        // SAFETY: name is a validated live component relative to the owned
        // directory; flags zero removes a file entry rather than a directory.
        let result = unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn component_name(name: &OsStr) -> io::Result<CString> {
    let mut parts = Path::new(name).components();
    if !matches!(parts.next(), Some(Component::Normal(_))) || parts.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "disk cache entry name must be one normal component",
        ));
    }
    Ok(CString::new(name.as_bytes())?)
}

#[cfg(target_os = "linux")]
fn open_path(path: &Path, extra_flags: libc::c_int) -> io::Result<File> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: open_how contains integer fields for which zero is valid. Zero
    // initialization also leaves any future extension fields disabled.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | extra_flags) as u64;
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
fn open_path(path: &Path, extra_flags: libc::c_int) -> io::Result<File> {
    use std::fs::OpenOptions;
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
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let flags = if parts.peek().is_some() {
            flags | libc::O_DIRECTORY
        } else {
            flags | extra_flags
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn create_all_preserves_existing_prefix_permissions() {
        let root = super::super::tests::temp_dir("missing-directory-prefix");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o750)).unwrap();
        let first = root.join("first");
        let leaf = first.join("second");
        let directory = Directory::create_all(&leaf).expect("create missing descendants");
        assert!(directory.0.metadata().unwrap().is_dir());
        for path in [&first, &leaf] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o750
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn create_all_rejects_symlink_prefix_before_creating_descendants() {
        let root = super::super::tests::temp_dir("symlink-directory-prefix");
        let outside = super::super::tests::temp_dir("outside-directory-prefix");
        let link = root.join("link");
        symlink(&outside, &link).expect("install outside directory alias");
        assert!(Directory::create_all(&link.join("missing/leaf")).is_err());
        assert!(!outside.join("missing").exists());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
