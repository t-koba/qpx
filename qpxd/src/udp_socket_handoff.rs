#[cfg(unix)]
use anyhow::Context;
use anyhow::{anyhow, Result};

#[cfg(any(feature = "http3", test))]
#[cfg(unix)]
use std::os::fd::IntoRawFd;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
pub(crate) fn adopt_inherited_udp_socket(fd: i32) -> Result<std::net::UdpSocket> {
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    socket
        .set_nonblocking(true)
        .context("failed to set inherited udp socket nonblocking")?;
    set_cloexec(socket.as_raw_fd(), true)?;
    Ok(socket)
}

#[cfg(windows)]
pub(crate) fn adopt_inherited_udp_socket_windows(socket: &[u8]) -> Result<std::net::UdpSocket> {
    crate::windows_handoff::adopt_udp_socket(socket)
}

#[cfg(test)]
pub(crate) fn duplicate_std_udp_socket(
    socket: &std::net::UdpSocket,
) -> Result<std::net::UdpSocket> {
    #[cfg(unix)]
    {
        let duplicated = duplicate_raw_fd(socket.as_raw_fd(), true)?;
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(duplicated.into_raw_fd()) };
        socket
            .set_nonblocking(true)
            .context("failed to set duplicated udp socket nonblocking")?;
        Ok(socket)
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        Err(anyhow!("udp socket duplication is only supported on unix"))
    }
}

#[cfg(feature = "http3")]
pub(crate) fn duplicate_tokio_udp_socket(
    socket: &tokio::net::UdpSocket,
) -> Result<std::net::UdpSocket> {
    #[cfg(unix)]
    {
        let duplicated = duplicate_raw_fd(socket.as_raw_fd(), true)?;
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(duplicated.into_raw_fd()) };
        socket
            .set_nonblocking(true)
            .context("failed to set duplicated udp socket nonblocking")?;
        Ok(socket)
    }

    #[cfg(not(unix))]
    {
        let _ = socket;
        Err(anyhow!("udp socket duplication is only supported on unix"))
    }
}

#[cfg(unix)]
pub(crate) fn duplicate_std_udp_socket_for_handoff(
    socket: &std::net::UdpSocket,
    kept_fds: &mut Vec<OwnedFd>,
) -> Result<i32> {
    let duplicated = duplicate_raw_fd(socket.as_raw_fd(), false)?;
    let raw = duplicated.as_raw_fd();
    kept_fds.push(duplicated);
    Ok(raw)
}

#[cfg(windows)]
pub(crate) fn duplicate_std_udp_socket_for_child(
    socket: &std::net::UdpSocket,
    child_pid: u32,
) -> Result<Vec<u8>> {
    crate::windows_handoff::duplicate_socket_for_child(socket, child_pid)
}

#[cfg(windows)]
pub(crate) fn duplicate_tokio_udp_socket_for_child(
    socket: &tokio::net::UdpSocket,
    child_pid: u32,
) -> Result<Vec<u8>> {
    crate::windows_handoff::duplicate_socket_for_child(socket, child_pid)
}
