use crate::http::address::parse_authority_host_port;
use crate::http::common::resolve_named_upstream;
use crate::upstream::connect::{connect_tunnel_target, ConnectedTunnel};
use crate::xdp;
use anyhow::{anyhow, Result};
use hyper::{Body, Request};
use qpx_core::config::{ActionConfig, ListenerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::time::Duration;
#[derive(Clone, Debug)]
pub(super) enum ConnectTarget {
    Socket(SocketAddr),
    HostPort(String, u16),
}

impl ConnectTarget {
    pub(super) fn port(&self) -> u16 {
        match self {
            Self::Socket(addr) => addr.port(),
            Self::HostPort(_, port) => *port,
        }
    }

    pub(super) fn host_for_connect(&self) -> String {
        match self {
            Self::Socket(addr) => addr.ip().to_string(),
            Self::HostPort(host, _) => host.clone(),
        }
    }

    pub(super) fn authority(&self) -> String {
        match self {
            Self::Socket(addr) => addr.to_string(),
            Self::HostPort(host, port) => {
                if host.contains(':') && !host.starts_with('[') {
                    format!("[{}]:{}", host, port)
                } else {
                    format!("{}:{}", host, port)
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum DestinationResolver {
    Kernel,
    XdpProxyV1 {
        metadata_mode: xdp::ProxyMetadataMode,
        require_metadata: bool,
        trusted_peers: Vec<cidr::IpCidr>,
    },
}

impl DestinationResolver {
    pub(super) async fn resolve_original_target(
        &self,
        stream: &mut TcpStream,
        remote_addr: SocketAddr,
        metadata_timeout: Duration,
    ) -> Result<Option<ConnectTarget>> {
        match self {
            Self::Kernel => Ok(original_dst_socket(stream).ok().map(ConnectTarget::Socket)),
            Self::XdpProxyV1 {
                metadata_mode,
                require_metadata,
                trusted_peers,
            } => {
                let trusted = xdp::peer_is_trusted(remote_addr.ip(), trusted_peers);
                if !trusted {
                    if *require_metadata {
                        return Err(anyhow!(
                            "proxy metadata required but peer is not trusted: {}",
                            remote_addr
                        ));
                    }
                    return Ok(original_dst_socket(stream).ok().map(ConnectTarget::Socket));
                }
                let meta = match tokio::time::timeout(
                    metadata_timeout,
                    xdp::consume_proxy_metadata(stream, *require_metadata, metadata_mode.clone()),
                )
                .await
                {
                    Ok(result) => result?,
                    Err(_) => {
                        if *require_metadata {
                            return Err(anyhow!(
                                "proxy metadata required but read timed out: {}",
                                remote_addr
                            ));
                        }
                        return Ok(original_dst_socket(stream).ok().map(ConnectTarget::Socket));
                    }
                };
                if let Some(meta) = meta {
                    if let Some(dst) = meta.dst {
                        return Ok(Some(ConnectTarget::Socket(dst)));
                    }
                }
                Ok(original_dst_socket(stream).ok().map(ConnectTarget::Socket))
            }
        }
    }
}

pub(super) fn resolve_upstream(
    action: &ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener: &ListenerConfig,
) -> Result<Option<String>> {
    resolve_named_upstream(action, state, listener.upstream_proxy.as_deref())
}

pub(super) fn resolve_http_target(
    req: &Request<Body>,
    fallback: Option<&ConnectTarget>,
) -> Result<(ConnectTarget, Option<String>)> {
    let host_from_request = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
        .and_then(|v| parse_authority_host_port(v, 80));

    let target = match fallback {
        Some(target) => target.clone(),
        None => {
            if let Some((host, port)) = host_from_request.clone() {
                ConnectTarget::HostPort(host, port)
            } else {
                return Err(anyhow!("transparent HTTP on this OS requires Host header when original destination is unavailable"));
            }
        }
    };

    let host_for_match = host_from_request
        .map(|(host, _)| host)
        .or_else(|| match &target {
            ConnectTarget::HostPort(host, _) => Some(host.clone()),
            ConnectTarget::Socket(addr) => Some(addr.ip().to_string()),
        });

    Ok((target, host_for_match))
}

pub(super) async fn connect_target_stream(
    target: &ConnectTarget,
    upstream_proxy: Option<&str>,
    timeout_dur: Duration,
) -> Result<ConnectedTunnel> {
    let host = target.host_for_connect();
    connect_tunnel_target(host.as_str(), target.port(), upstream_proxy, timeout_dur).await
}

pub(super) fn destination_resolver_for_listener(
    listener: &ListenerConfig,
) -> Result<DestinationResolver> {
    if let Some(xdp_cfg) = xdp::compile_xdp_config(listener.xdp.as_ref())? {
        return Ok(DestinationResolver::XdpProxyV1 {
            metadata_mode: xdp_cfg.metadata_mode,
            require_metadata: xdp_cfg.require_metadata,
            trusted_peers: xdp_cfg.trusted_peers,
        });
    }
    Ok(DestinationResolver::Kernel)
}

#[cfg(target_os = "linux")]
fn original_dst_socket(stream: &tokio::net::TcpStream) -> Result<SocketAddr> {
    use libc::{getsockopt, sockaddr_in, socklen_t, SOL_IP};
    use std::mem::MaybeUninit;
    use std::os::unix::io::AsRawFd;

    const SO_ORIGINAL_DST: i32 = 80;
    let fd = stream.as_raw_fd();
    let mut addr: MaybeUninit<sockaddr_in> = MaybeUninit::uninit();
    let mut len = std::mem::size_of::<sockaddr_in>() as socklen_t;
    let ret = unsafe {
        getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            addr.as_mut_ptr() as *mut _,
            &mut len as *mut _,
        )
    };
    if ret != 0 {
        return Err(anyhow!("getsockopt failed"));
    }
    if len < std::mem::size_of::<sockaddr_in>() as socklen_t {
        return Err(anyhow!(
            "getsockopt returned short sockaddr_in length: {}",
            len
        ));
    }
    let addr = unsafe { addr.assume_init() };
    let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
    let port = u16::from_be(addr.sin_port);
    Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
}

#[cfg(not(target_os = "linux"))]
fn original_dst_socket(_stream: &tokio::net::TcpStream) -> Result<SocketAddr> {
    Err(anyhow!(
        "original destination lookup unavailable on this OS"
    ))
}
