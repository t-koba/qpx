use anyhow::{Result, anyhow};

pub(crate) fn set_cloexec(fd: i32, enabled: bool) -> Result<()> {
    // SAFETY: F_GETFD reads descriptor flags and does not access memory.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(anyhow!(
            "failed to read fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    let next = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: F_SETFD updates only flags for the descriptor supplied by the caller.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
        return Err(anyhow!(
            "failed to set fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::set_cloexec;
    use std::os::fd::AsRawFd;

    #[test]
    fn cloexec_toggle_preserves_other_descriptor_flags() {
        let (stream, _peer) = std::os::unix::net::UnixStream::pair().expect("unix stream pair");
        let fd = stream.as_raw_fd();
        // SAFETY: `fd` is borrowed from the live UnixStream above.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "failed to read descriptor flags");
        let preserved = flags & !libc::FD_CLOEXEC;

        set_cloexec(fd, false).expect("clear close-on-exec");
        // SAFETY: `fd` remains borrowed from the live UnixStream above.
        let cleared_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(cleared_flags, preserved);
        set_cloexec(fd, true).expect("set close-on-exec");
        // SAFETY: `fd` remains borrowed from the live UnixStream above.
        let enabled_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(enabled_flags, preserved | libc::FD_CLOEXEC);
    }
}
