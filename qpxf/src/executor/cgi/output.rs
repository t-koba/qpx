use anyhow::{Result, anyhow};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub(super) struct PreparedCgiScript {
    command_path: PathBuf,
    command_args: Vec<OsString>,
    label_path: PathBuf,
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly"
    ))]
    _file: std::fs::File,
}

impl PreparedCgiScript {
    pub(super) fn command_path(&self) -> &Path {
        &self.command_path
    }

    pub(super) fn command_args(&self) -> &[OsString] {
        &self.command_args
    }

    pub(super) fn label_path(&self) -> &Path {
        &self.label_path
    }
}

#[cfg(unix)]
pub(super) fn validate_secure_cgi_root(root: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(root)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(anyhow!(
            "CGI root is not a secure directory: {}",
            root.display()
        ));
    }
    reject_untrusted_cgi_path(root, &meta, "CGI root")
}

#[cfg(not(unix))]
pub(super) fn validate_secure_cgi_root(_root: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
pub(super) fn validate_secure_cgi_script(root: &Path, script: &Path) -> Result<()> {
    validate_secure_cgi_root(root)?;
    let parent = script
        .parent()
        .ok_or_else(|| anyhow!("CGI script has no parent: {}", script.display()))?;
    let relative_parent = parent.strip_prefix(root).map_err(|_| {
        anyhow!(
            "CGI script parent escapes root: {} is not under {}",
            parent.display(),
            root.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative_parent.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(anyhow!(
                "CGI script parent contains unsupported path component: {}",
                parent.display()
            ));
        };
        current.push(name);
        let meta = std::fs::symlink_metadata(&current)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(anyhow!(
                "CGI script parent component is not a secure directory: {}",
                current.display()
            ));
        }
        reject_untrusted_cgi_path(&current, &meta, "CGI script parent")?;
    }

    let meta = std::fs::symlink_metadata(script)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(anyhow!(
            "CGI script is not a regular file: {}",
            script.display()
        ));
    }
    reject_untrusted_cgi_path(script, &meta, "CGI script")
}

#[cfg(not(unix))]
pub(super) fn validate_secure_cgi_script(_root: &Path, _script: &Path) -> Result<()> {
    Ok(())
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
pub(super) fn prepare_cgi_script_for_spawn(
    root: &Path,
    script: &Path,
) -> Result<PreparedCgiScript> {
    use std::os::fd::AsRawFd;

    validate_secure_cgi_script(root, script)?;
    let file = open_cgi_script_fd(script)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(anyhow!(
            "CGI script fd is not a regular file: {}",
            script.display()
        ));
    }
    reject_untrusted_cgi_path(script, &meta, "CGI script fd")?;
    clear_close_on_exec(file.as_raw_fd())?;
    let fd_path = cgi_fd_exec_path(file.as_raw_fd());
    if !fd_path.exists() {
        return Err(anyhow!(
            "CGI fd execution path is unavailable: {}",
            fd_path.display()
        ));
    }
    let (command_path, command_args) = cgi_fd_command_for_spawn(&file, &fd_path)?;
    Ok(PreparedCgiScript {
        command_path,
        command_args,
        label_path: script.to_path_buf(),
        _file: file,
    })
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "dragonfly"
)))]
pub(super) fn prepare_cgi_script_for_spawn(
    _root: &Path,
    _script: &Path,
) -> Result<PreparedCgiScript> {
    Err(anyhow!(
        "CGI execution requires fd-based script spawn support on this platform"
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn cgi_fd_exec_path(fd: std::os::fd::RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
fn cgi_fd_exec_path(fd: std::os::fd::RawFd) -> PathBuf {
    PathBuf::from(format!("/dev/fd/{fd}"))
}

#[cfg(target_os = "macos")]
fn cgi_fd_exec_path(fd: std::os::fd::RawFd) -> PathBuf {
    PathBuf::from(format!("/dev/fd/{fd}"))
}

#[cfg(target_os = "macos")]
fn cgi_fd_command_for_spawn(
    file: &std::fs::File,
    fd_path: &Path,
) -> Result<(PathBuf, Vec<OsString>)> {
    if let Some(mut shebang) = read_cgi_shebang(file)? {
        let command = PathBuf::from(shebang.remove(0));
        shebang.push(fd_path.as_os_str().to_os_string());
        return Ok((command, shebang));
    }
    Ok((fd_path.to_path_buf(), Vec::new()))
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
fn cgi_fd_command_for_spawn(
    _file: &std::fs::File,
    fd_path: &Path,
) -> Result<(PathBuf, Vec<OsString>)> {
    Ok((fd_path.to_path_buf(), Vec::new()))
}

#[cfg(target_os = "macos")]
fn read_cgi_shebang(file: &std::fs::File) -> Result<Option<Vec<OsString>>> {
    use std::os::unix::fs::FileExt;

    let mut buf = [0u8; 512];
    let n = file
        .read_at(&mut buf, 0)
        .map_err(|err| anyhow!("failed to read CGI script shebang: {err}"))?;
    if n < 2 || &buf[..2] != b"#!" {
        return Ok(None);
    }
    let line_end = buf[2..n]
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .map(|pos| pos + 2)
        .unwrap_or(n);
    let line = std::str::from_utf8(&buf[2..line_end])
        .map_err(|err| anyhow!("CGI script shebang is not UTF-8: {err}"))?
        .trim();
    if line.is_empty() {
        return Ok(None);
    }
    let parts = line.split_whitespace().map(OsString::from).collect();
    Ok(Some(parts))
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
fn open_cgi_script_fd(script: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(script)
        .map_err(|err| anyhow!("failed to open CGI script '{}': {err}", script.display()))
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
fn open_cgi_script_fd(script: &Path) -> Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(script.as_os_str().as_bytes())
        .map_err(|_| anyhow!("CGI script path contains NUL byte: {}", script.display()))?;
    // SAFETY: c_path is a valid NUL-terminated path. open returns either a valid owned fd
    // or -1 with errno set; File::from_raw_fd takes ownership only after success.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_EXEC | libc::O_NOFOLLOW) };
    if fd < 0 {
        return Err(anyhow!(
            "failed to open CGI script '{}': {}",
            script.display(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fd was returned by open above and is uniquely owned here.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "dragonfly"
))]
fn clear_close_on_exec(fd: std::os::fd::RawFd) -> Result<()> {
    // SAFETY: fcntl with F_GETFD only reads descriptor flags for a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fcntl with F_SETFD updates descriptor flags for the same valid fd.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(unix)]
fn reject_untrusted_cgi_path(path: &Path, meta: &std::fs::Metadata, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions and only reads the current process credentials.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(anyhow!(
            "refusing {label} not owned by root or current user: {}",
            path.display()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "refusing group/world-writable {label}: {}",
            path.display()
        ));
    }
    Ok(())
}
