use crate::http::address::parse_authority_host_port;
use crate::http::body::Body;
use crate::http::common::resolve_named_upstream;
use crate::upstream::connect::{connect_tunnel_target, ConnectedTunnel};
use crate::xdp;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use hyper::Request;
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
    XdpProxyV2 {
        require_metadata: bool,
        trusted_peers: Vec<cidr::IpCidr>,
    },
}

impl DestinationResolver {
    pub(super) async fn resolve_original_target(
        &self,
        stream: TcpStream,
        remote_addr: SocketAddr,
        metadata_timeout: Duration,
    ) -> Result<(
        crate::io_prefix::PrefixedIo<TcpStream>,
        SocketAddr,
        Option<ConnectTarget>,
    )> {
        let mut stream = stream;
        let local_addr = stream.local_addr().ok();
        match self {
            Self::Kernel => {
                let target = original_dst_socket(&stream)
                    .ok()
                    // When a connection is made directly to the transparent listener (no NAT),
                    // SO_ORIGINAL_DST can be equal to the listener address. Treat that as
                    // "unavailable" to avoid proxying back into ourselves.
                    .filter(|dst| local_addr != Some(*dst))
                    .map(ConnectTarget::Socket);
                Ok((
                    crate::io_prefix::PrefixedIo::new(stream, Bytes::new()),
                    remote_addr,
                    target,
                ))
            }
            Self::XdpProxyV2 {
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
                    let target = original_dst_socket(&stream)
                        .ok()
                        .filter(|dst| local_addr != Some(*dst))
                        .map(ConnectTarget::Socket);
                    return Ok((
                        crate::io_prefix::PrefixedIo::new(stream, Bytes::new()),
                        remote_addr,
                        target,
                    ));
                }
                let result =
                    xdp::consume_proxy_metadata(&mut stream, *require_metadata, metadata_timeout)
                        .await?;
                let (src, dst) = match result.meta {
                    Some(meta) => (meta.src, meta.dst),
                    None => (None, None),
                };
                let effective_remote = src.unwrap_or(remote_addr);
                let target = dst
                    .filter(|dst| local_addr != Some(*dst))
                    .map(ConnectTarget::Socket)
                    .or_else(|| {
                        original_dst_socket(&stream)
                            .ok()
                            .filter(|dst| local_addr != Some(*dst))
                            .map(ConnectTarget::Socket)
                    });
                Ok((
                    crate::io_prefix::PrefixedIo::new(stream, result.prefix),
                    effective_remote,
                    target,
                ))
            }
        }
    }
}

pub(super) fn resolve_upstream(
    action: &ActionConfig,
    state: &Arc<crate::runtime::RuntimeState>,
    listener: &ListenerConfig,
) -> Result<Option<crate::upstream::pool::ResolvedUpstreamProxy>> {
    resolve_named_upstream(action, state, listener.upstream_proxy.as_deref())
}

pub(super) fn resolve_http_target(
    req: &Request<Body>,
    fallback: Option<&ConnectTarget>,
) -> Result<(ConnectTarget, Option<String>)> {
    let target = match fallback {
        Some(target) => target.clone(),
        None => {
            let host_from_request = req
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .or_else(|| req.uri().authority().map(|a| a.as_str()))
                .and_then(|v| parse_authority_host_port(v, 80));
            if let Some((host, port)) = host_from_request {
                ConnectTarget::HostPort(host, port)
            } else {
                return Err(anyhow!(
                    "transparent HTTP on this OS requires Host header when original destination is unavailable"
                ));
            }
        }
    };

    let host_for_match = match &target {
        ConnectTarget::HostPort(host, _) => Some(host.clone()),
        ConnectTarget::Socket(addr) => Some(addr.ip().to_string()),
    };

    Ok((target, host_for_match))
}

pub(super) async fn connect_target_stream(
    target: &ConnectTarget,
    upstream_proxy: Option<&crate::upstream::pool::ResolvedUpstreamProxy>,
    proxy_name: &str,
    timeout_dur: Duration,
) -> Result<ConnectedTunnel> {
    let host = target.host_for_connect();
    connect_tunnel_target(
        host.as_str(),
        target.port(),
        upstream_proxy,
        proxy_name,
        timeout_dur,
    )
    .await
}

pub(super) fn destination_resolver_for_listener(
    listener: &ListenerConfig,
) -> Result<DestinationResolver> {
    if let Some(xdp_cfg) = xdp::compile_xdp_config(listener.xdp.as_ref())? {
        return Ok(DestinationResolver::XdpProxyV2 {
            require_metadata: xdp_cfg.require_metadata,
            trusted_peers: xdp_cfg.trusted_peers,
        });
    }
    Ok(DestinationResolver::Kernel)
}

#[cfg(target_os = "linux")]
fn original_dst_socket(stream: &tokio::net::TcpStream) -> Result<SocketAddr> {
    use libc::{getsockopt, sockaddr_in, sockaddr_in6, socklen_t, SOL_IP, SOL_IPV6};
    use std::mem::MaybeUninit;
    use std::os::unix::io::AsRawFd;

    const SO_ORIGINAL_DST: i32 = 80;
    let fd = stream.as_raw_fd();

    // IPv4 (iptables / SO_ORIGINAL_DST).
    let mut addr4: MaybeUninit<sockaddr_in> = MaybeUninit::uninit();
    let mut len4 = std::mem::size_of::<sockaddr_in>() as socklen_t;
    let ret4 = unsafe {
        getsockopt(
            fd,
            SOL_IP,
            SO_ORIGINAL_DST,
            addr4.as_mut_ptr() as *mut _,
            &mut len4 as *mut _,
        )
    };
    if ret4 == 0 {
        if len4 < std::mem::size_of::<sockaddr_in>() as socklen_t {
            return Err(anyhow!(
                "getsockopt returned short sockaddr_in length: {}",
                len4
            ));
        }
        let addr = unsafe { addr4.assume_init() };
        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        return Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port));
    }
    let err4 = std::io::Error::last_os_error();

    // IPv6 (ip6tables / IP6T_SO_ORIGINAL_DST).
    const IP6T_SO_ORIGINAL_DST: i32 = 80;
    let mut addr6: MaybeUninit<sockaddr_in6> = MaybeUninit::uninit();
    let mut len6 = std::mem::size_of::<sockaddr_in6>() as socklen_t;
    let ret6 = unsafe {
        getsockopt(
            fd,
            SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            addr6.as_mut_ptr() as *mut _,
            &mut len6 as *mut _,
        )
    };
    if ret6 != 0 {
        let err6 = std::io::Error::last_os_error();
        return Err(anyhow!(
            "getsockopt SO_ORIGINAL_DST failed: {}; IP6T_SO_ORIGINAL_DST failed: {}",
            err4,
            err6
        ));
    }
    if len6 < std::mem::size_of::<sockaddr_in6>() as socklen_t {
        return Err(anyhow!(
            "getsockopt returned short sockaddr_in6 length: {}",
            len6
        ));
    }
    let addr = unsafe { addr6.assume_init() };
    let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
    let port = u16::from_be(addr.sin6_port);
    Ok(SocketAddr::new(std::net::IpAddr::V6(ip), port))
}

#[cfg(not(target_os = "linux"))]
fn original_dst_socket(_stream: &tokio::net::TcpStream) -> Result<SocketAddr> {
    Err(anyhow!(
        "original destination lookup unavailable on this OS"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cidr::IpCidr;
    use hyper::Request;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn resolve_http_target_prefers_original_target_over_host_fallback() {
        let request = Request::builder()
            .uri("/resource")
            .header(http::header::HOST, "ignored.example:8080")
            .body(Body::empty())
            .expect("request");
        let fallback = ConnectTarget::Socket("127.0.0.1:18080".parse().expect("socket"));

        let (target, host_for_match) =
            resolve_http_target(&request, Some(&fallback)).expect("target");
        assert!(matches!(target, ConnectTarget::Socket(addr) if addr.port() == 18080));
        assert_eq!(host_for_match.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn resolve_http_target_uses_host_header_when_original_target_is_unavailable() {
        let request = Request::builder()
            .uri("/resource")
            .header(http::header::HOST, "example.com:8443")
            .body(Body::empty())
            .expect("request");

        let (target, host_for_match) = resolve_http_target(&request, None).expect("target");
        assert!(matches!(target, ConnectTarget::HostPort(ref host, 8443) if host == "example.com"));
        assert_eq!(host_for_match.as_deref(), Some("example.com"));
    }

    fn proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
        let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (src, dst) else {
            panic!("test helper only supports ipv4");
        };
        let mut bytes = vec![
            0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11,
            0x00, 0x0c,
        ];
        bytes.extend_from_slice(&src.ip().octets());
        bytes.extend_from_slice(&dst.ip().octets());
        bytes.extend_from_slice(&src.port().to_be_bytes());
        bytes.extend_from_slice(&dst.port().to_be_bytes());
        bytes
    }

    #[tokio::test]
    async fn xdp_proxy_v2_destination_resolver_uses_proxy_metadata_for_target() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let payload = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n".to_vec();
        let client_payload = payload.clone();
        let proxy = proxy_v2_header(
            "10.2.3.4:41234".parse().expect("src"),
            "203.0.113.8:8443".parse().expect("dst"),
        );

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(listen_addr).await.expect("connect");
            stream.write_all(&proxy).await.expect("write proxy");
            stream
                .write_all(&client_payload)
                .await
                .expect("write payload");
        });

        let (stream, remote_addr) = listener.accept().await.expect("accept");
        let resolver = DestinationResolver::XdpProxyV2 {
            require_metadata: true,
            trusted_peers: vec!["127.0.0.0/8".parse::<IpCidr>().expect("cidr")],
        };
        let (mut prefixed, effective_remote, target) = resolver
            .resolve_original_target(stream, remote_addr, Duration::from_secs(1))
            .await
            .expect("resolve");

        assert_eq!(effective_remote, "10.2.3.4:41234".parse().unwrap());
        assert!(matches!(
            target,
            Some(ConnectTarget::Socket(addr)) if addr == "203.0.113.8:8443".parse().unwrap()
        ));
        let mut buf = vec![0u8; payload.len()];
        prefixed.read_exact(&mut buf).await.expect("read prefixed");
        assert_eq!(buf, payload);
        client.await.expect("client");
    }
}
