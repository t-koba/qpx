#[cfg(target_os = "linux")]
use anyhow::anyhow;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub(super) fn bind_udp_listener(
    addr: SocketAddr,
    runtime: &qpx_core::config::RuntimeConfig,
) -> Result<UdpSocket> {
    let std_socket = bind_udp_std_listener(addr, runtime)?;
    UdpSocket::from_std(std_socket).context("tokio UDP socket conversion failed")
}

pub(crate) fn bind_udp_std_listener(
    addr: SocketAddr,
    runtime: &qpx_core::config::RuntimeConfig,
) -> Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("failed to create transparent UDP socket")?;
    socket
        .set_reuse_address(true)
        .context("failed to set transparent UDP SO_REUSEADDR")?;
    #[cfg(unix)]
    if runtime.reuse_port {
        let _ = socket.set_reuse_port(true);
    }
    socket
        .set_nonblocking(true)
        .context("failed to set transparent UDP socket nonblocking")?;
    #[cfg(target_os = "linux")]
    enable_original_dst_cmsgs(&socket, addr)?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("transparent UDP bind failed on {}", addr))?;
    Ok(socket.into())
}

#[cfg(target_os = "linux")]
fn enable_original_dst_cmsgs(socket: &Socket, addr: SocketAddr) -> Result<()> {
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let value: libc::c_int = 1;
    let (level, ty) = if addr.is_ipv4() {
        (libc::SOL_IP, libc::IP_RECVORIGDSTADDR)
    } else {
        (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR)
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            ty,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(anyhow!(
            "failed to enable transparent UDP original-dst ancillary data: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(super) async fn recv_transparent_datagram(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    #[cfg(target_os = "linux")]
    {
        use tokio::io::Interest;

        let local_addr = socket.local_addr().ok();
        return socket
            .async_io(Interest::READABLE, || {
                recvmsg_with_original_dst(socket, buf, local_addr)
            })
            .await;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let (n, src) = socket.recv_from(buf).await?;
        Ok((n, src, None))
    }
}

#[cfg(target_os = "linux")]
fn recvmsg_with_original_dst(
    socket: &UdpSocket,
    buf: &mut [u8],
    local_addr: Option<SocketAddr>,
) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
    use std::mem::{size_of, zeroed};
    use std::os::fd::AsRawFd;

    let mut src_storage: libc::sockaddr_storage = unsafe { zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = [0u8; unsafe {
        libc::CMSG_SPACE(size_of::<libc::sockaddr_in6>() as libc::c_uint) as usize
    }];
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_name = (&mut src_storage as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = (&mut iov as *mut libc::iovec).cast();
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let src = socket_addr_from_storage(&src_storage, msg.msg_namelen).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid UDP source address",
        )
    })?;
    let mut original_dst = None;
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr) };
    while !cmsg.is_null() {
        let cmsg_ref = unsafe { &*cmsg };
        if cmsg_ref.cmsg_level == libc::SOL_IP && cmsg_ref.cmsg_type == libc::IP_ORIGDSTADDR {
            let addr = unsafe { &*(libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in>()) };
            original_dst = Some(SocketAddr::from(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                u16::from_be(addr.sin_port),
            )));
            break;
        }
        if cmsg_ref.cmsg_level == libc::SOL_IPV6 && cmsg_ref.cmsg_type == libc::IPV6_ORIGDSTADDR {
            let addr = unsafe { &*(libc::CMSG_DATA(cmsg).cast::<libc::sockaddr_in6>()) };
            original_dst = Some(SocketAddr::from(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
                u16::from_be(addr.sin6_port),
                addr.sin6_flowinfo,
                addr.sin6_scope_id,
            )));
            break;
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg as *const libc::msghdr, cmsg) };
    }
    if original_dst == local_addr {
        original_dst = None;
    }
    Ok((n as usize, src, original_dst))
}

#[cfg(target_os = "linux")]
fn socket_addr_from_storage(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    if len as usize >= std::mem::size_of::<libc::sockaddr_in>()
        && storage.ss_family == libc::AF_INET as libc::sa_family_t
    {
        let addr =
            unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
        return Some(SocketAddr::from(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
            u16::from_be(addr.sin_port),
        )));
    }
    if len as usize >= std::mem::size_of::<libc::sockaddr_in6>()
        && storage.ss_family == libc::AF_INET6 as libc::sa_family_t
    {
        let addr =
            unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
        return Some(SocketAddr::from(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
            u16::from_be(addr.sin6_port),
            addr.sin6_flowinfo,
            addr.sin6_scope_id,
        )));
    }
    None
}
