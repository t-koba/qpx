#[cfg(unix)]
mod unix {
    use anyhow::{Context, Result, anyhow};
    #[cfg(any(feature = "http3", test))]
    use std::os::fd::IntoRawFd;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    fn set_cloexec(fd: i32, enabled: bool) -> Result<()> {
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
        if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
            return Err(anyhow!(
                "failed to set fd flags: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn duplicate_raw_fd(fd: i32, cloexec: bool) -> Result<OwnedFd> {
        let duplicated = unsafe { libc::dup(fd) };
        if duplicated < 0 {
            return Err(anyhow!(
                "failed to duplicate inherited udp socket fd: {}",
                std::io::Error::last_os_error()
            ));
        }
        set_cloexec(duplicated, cloexec)?;
        Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
    }

    pub(crate) fn adopt_inherited_udp_socket(fd: i32) -> Result<std::net::UdpSocket> {
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        socket
            .set_nonblocking(true)
            .context("failed to set inherited udp socket nonblocking")?;
        set_cloexec(socket.as_raw_fd(), true)?;
        Ok(socket)
    }

    #[cfg(test)]
    pub(crate) fn duplicate_std_udp_socket(
        socket: &std::net::UdpSocket,
    ) -> Result<std::net::UdpSocket> {
        let duplicated = duplicate_raw_fd(socket.as_raw_fd(), true)?;
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(duplicated.into_raw_fd()) };
        socket
            .set_nonblocking(true)
            .context("failed to set duplicated udp socket nonblocking")?;
        Ok(socket)
    }

    #[cfg(feature = "http3")]
    pub(crate) fn duplicate_tokio_udp_socket(
        socket: &tokio::net::UdpSocket,
    ) -> Result<std::net::UdpSocket> {
        let duplicated = duplicate_raw_fd(socket.as_raw_fd(), true)?;
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(duplicated.into_raw_fd()) };
        socket
            .set_nonblocking(true)
            .context("failed to set duplicated udp socket nonblocking")?;
        Ok(socket)
    }

    pub(crate) fn duplicate_std_udp_socket_for_handoff(
        socket: &std::net::UdpSocket,
        kept_fds: &mut Vec<OwnedFd>,
    ) -> Result<i32> {
        let duplicated = duplicate_raw_fd(socket.as_raw_fd(), false)?;
        let raw = duplicated.as_raw_fd();
        kept_fds.push(duplicated);
        Ok(raw)
    }
}

#[cfg(windows)]
mod windows {
    use anyhow::Result;

    pub(crate) fn adopt_inherited_udp_socket_windows(socket: &[u8]) -> Result<std::net::UdpSocket> {
        crate::windows_handoff::adopt_udp_socket(socket)
    }

    pub(crate) fn duplicate_std_udp_socket_for_child(
        socket: &std::net::UdpSocket,
        child_pid: u32,
    ) -> Result<Vec<u8>> {
        crate::windows_handoff::duplicate_socket_for_child(socket, child_pid)
    }
}

#[cfg(all(feature = "http3", not(unix)))]
mod non_unix_http3 {
    use anyhow::{Result, anyhow};

    pub(crate) fn duplicate_tokio_udp_socket(
        socket: &tokio::net::UdpSocket,
    ) -> Result<std::net::UdpSocket> {
        let _ = socket;
        Err(anyhow!("udp socket duplication is only supported on unix"))
    }
}

#[cfg(all(feature = "http3", not(unix)))]
pub(crate) use non_unix_http3::duplicate_tokio_udp_socket;
#[cfg(unix)]
pub(crate) use unix::*;
#[cfg(windows)]
pub(crate) use windows::*;
