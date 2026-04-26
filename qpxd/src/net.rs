use anyhow::{Context, Result};
use qpx_core::config::RuntimeConfig;
use socket2::{Domain, Protocol, Socket, Type};
#[cfg(feature = "http3")]
use std::net::UdpSocket as StdUdpSocket;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use tokio::net::TcpListener;
use tracing::warn;

pub fn worker_threads(cfg: &RuntimeConfig) -> usize {
    cfg.worker_threads.unwrap_or_else(default_parallelism)
}

pub fn max_blocking_threads(cfg: &RuntimeConfig) -> usize {
    cfg.max_blocking_threads
        .unwrap_or_else(|| worker_threads(cfg).saturating_mul(32).max(128))
}

pub fn acceptor_tasks_per_listener(cfg: &RuntimeConfig) -> usize {
    cfg.acceptor_tasks_per_listener
        .unwrap_or_else(|| worker_threads(cfg))
        .max(1)
}

pub fn bind_tcp_std_listeners(
    addr: SocketAddr,
    runtime: &RuntimeConfig,
) -> Result<Vec<StdTcpListener>> {
    let requested = acceptor_tasks_per_listener(runtime);
    let allow_reuse_port = runtime.reuse_port;

    let effective = if requested <= 1 {
        1
    } else if allow_reuse_port {
        if reuse_port_supported() {
            requested
        } else {
            warn!(
                requested,
                "SO_REUSEPORT is unsupported on this platform; falling back to single acceptor"
            );
            1
        }
    } else {
        1
    };

    let mut listeners = Vec::with_capacity(effective);
    for _ in 0..effective {
        listeners.push(bind_single_std(addr, runtime, effective > 1)?);
    }
    Ok(listeners)
}

pub fn tokio_listener_from_std(listener: StdTcpListener) -> Result<TcpListener> {
    TcpListener::from_std(listener).context("tokio listener conversion failed")
}

#[cfg(feature = "http3")]
pub fn bind_udp_std_socket(addr: SocketAddr, runtime: &RuntimeConfig) -> Result<StdUdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .with_context(|| format!("failed to create UDP socket for {addr}"))?;
    socket
        .set_reuse_address(true)
        .context("failed to set UDP SO_REUSEADDR")?;
    #[cfg(unix)]
    if runtime.reuse_port {
        let _ = socket.set_reuse_port(true);
    }
    socket
        .set_nonblocking(true)
        .context("failed to set UDP nonblocking mode")?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("udp bind failed on {addr}"))?;
    Ok(socket.into())
}

fn bind_single_std(
    addr: SocketAddr,
    runtime: &RuntimeConfig,
    use_reuse_port: bool,
) -> Result<StdTcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).with_context(|| {
        format!(
            "failed to create listening socket for {}",
            if addr.is_ipv4() { "IPv4" } else { "IPv6" }
        )
    })?;

    socket
        .set_reuse_address(true)
        .context("failed to set SO_REUSEADDR")?;

    #[cfg(not(unix))]
    {
        // This should not be reachable because bind_tcp_listeners() falls back to a single acceptor
        // when SO_REUSEPORT isn't supported, but keep behavior explicit and avoid unused warnings.
        if use_reuse_port {
            warn!("SO_REUSEPORT requested but unsupported on this platform");
        }
    }

    #[cfg(unix)]
    {
        if use_reuse_port {
            socket
                .set_reuse_port(true)
                .context("failed to set SO_REUSEPORT")?;
        }
    }

    socket
        .set_nonblocking(true)
        .context("failed to set nonblocking mode")?;
    socket
        .bind(&addr.into())
        .with_context(|| format!("bind failed on {}", addr))?;
    socket
        .listen(runtime.tcp_backlog)
        .with_context(|| format!("listen failed on {}", addr))?;

    let std_listener: StdTcpListener = socket.into();
    Ok(std_listener)
}

#[cfg(unix)]
fn reuse_port_supported() -> bool {
    true
}

#[cfg(not(unix))]
fn reuse_port_supported() -> bool {
    false
}

fn default_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|v| v.get())
        .unwrap_or(1)
}
