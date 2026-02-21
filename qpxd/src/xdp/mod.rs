use anyhow::{anyhow, Result};
use bytes::Bytes;
use cidr::IpCidr;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};

pub mod remote;

#[derive(Clone, Debug)]
pub struct CompiledXdpConfig {
    pub require_metadata: bool,
    pub trusted_peers: Vec<IpCidr>,
}

#[derive(Clone, Debug)]
pub struct ProxyMeta {
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
}

pub struct ProxyReadResult {
    pub meta: Option<ProxyMeta>,
    /// Bytes read from the socket that must be "unread" (re-injected) to preserve the stream.
    pub prefix: Bytes,
}

const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
const MAX_PROXY_V2_HEADER_BYTES: usize = 4096;

pub async fn consume_proxy_metadata(
    stream: &mut TcpStream,
    require_metadata: bool,
    metadata_timeout: Duration,
) -> Result<ProxyReadResult> {
    consume_proxy_v2(stream, require_metadata, metadata_timeout).await
}

pub fn compile_xdp_config(
    cfg: Option<&qpx_core::config::XdpConfig>,
) -> Result<Option<CompiledXdpConfig>> {
    let Some(cfg) = cfg.filter(|cfg| cfg.enabled) else {
        return Ok(None);
    };
    if cfg.metadata_mode != "proxy-v2" {
        return Err(anyhow!(
            "unsupported xdp metadata_mode: {} (only proxy-v2 is supported)",
            cfg.metadata_mode
        ));
    }
    let trusted_peers = compile_trusted_peers(&cfg.trusted_peers)?;
    Ok(Some(CompiledXdpConfig {
        require_metadata: cfg.require_metadata,
        trusted_peers,
    }))
}

pub fn compile_trusted_peers(trusted_peers: &[String]) -> Result<Vec<IpCidr>> {
    let mut out = Vec::with_capacity(trusted_peers.len());
    for peer in trusted_peers {
        let cidr: IpCidr = peer
            .parse()
            .map_err(|_| anyhow!("invalid trusted peer CIDR: {}", peer))?;
        out.push(cidr);
    }
    Ok(out)
}

pub fn peer_is_trusted(remote_ip: IpAddr, trusted_peers: &[IpCidr]) -> bool {
    trusted_peers.iter().any(|cidr| cidr.contains(&remote_ip))
}

async fn consume_proxy_v2(
    stream: &mut TcpStream,
    require_metadata: bool,
    metadata_timeout: Duration,
) -> Result<ProxyReadResult> {
    let deadline = Instant::now() + metadata_timeout;
    if require_metadata {
        let meta = read_proxy_v2(stream, true, deadline).await?;
        return Ok(ProxyReadResult {
            meta,
            prefix: Bytes::new(),
        });
    }

    // Optional mode: consume only when the signature is present, otherwise return any bytes read
    // so the caller can re-inject them.
    let mut prefix = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if prefix.len() >= PROXY_V2_SIGNATURE.len() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let n = match timeout(remaining, stream.read(&mut one)).await {
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => {
                if !prefix.is_empty() && PROXY_V2_SIGNATURE.starts_with(&prefix) {
                    return Err(anyhow!("proxy metadata read timed out"));
                }
                return Ok(ProxyReadResult {
                    meta: None,
                    prefix: Bytes::from(prefix),
                });
            }
        };
        if n == 0 {
            return Ok(ProxyReadResult {
                meta: None,
                prefix: Bytes::from(prefix),
            });
        }
        prefix.push(one[0]);
        if !PROXY_V2_SIGNATURE.starts_with(&prefix) {
            return Ok(ProxyReadResult {
                meta: None,
                prefix: Bytes::from(prefix),
            });
        }
    }

    // We already consumed the full signature; now read the rest of the fixed header and payload.
    let mut hdr = [0u8; 16];
    hdr[..PROXY_V2_SIGNATURE.len()].copy_from_slice(&PROXY_V2_SIGNATURE);
    let remaining = deadline.saturating_duration_since(Instant::now());
    timeout(
        remaining,
        stream.read_exact(&mut hdr[PROXY_V2_SIGNATURE.len()..]),
    )
    .await
    .map_err(|_| anyhow!("proxy metadata read timed out"))??;
    let addr_len = u16::from_be_bytes([hdr[14], hdr[15]]) as usize;
    let total_len = 16 + addr_len;
    if total_len > MAX_PROXY_V2_HEADER_BYTES {
        return Err(anyhow!("proxy-v2 header too large"));
    }
    let mut payload = vec![0u8; addr_len];
    if addr_len > 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        timeout(remaining, stream.read_exact(&mut payload))
            .await
            .map_err(|_| anyhow!("proxy metadata read timed out"))??;
    }
    let meta = parse_proxy_v2_header_and_payload(hdr, &payload, false)?;
    Ok(ProxyReadResult {
        meta,
        prefix: Bytes::new(),
    })
}

async fn read_proxy_v2(
    stream: &mut TcpStream,
    require_metadata: bool,
    deadline: Instant,
) -> Result<Option<ProxyMeta>> {
    let mut hdr = [0u8; 16];
    let remaining = deadline.saturating_duration_since(Instant::now());
    timeout(remaining, stream.read_exact(&mut hdr))
        .await
        .map_err(|_| anyhow!("proxy metadata read timed out"))??;
    if !hdr.starts_with(&PROXY_V2_SIGNATURE) {
        return Err(anyhow!(
            "proxy metadata required but stream does not start with PROXY header"
        ));
    }

    let addr_len = u16::from_be_bytes([hdr[14], hdr[15]]) as usize;
    let total_len = 16 + addr_len;
    if total_len > MAX_PROXY_V2_HEADER_BYTES {
        return Err(anyhow!("proxy-v2 header too large"));
    }

    let mut payload = vec![0u8; addr_len];
    if addr_len > 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        timeout(remaining, stream.read_exact(&mut payload))
            .await
            .map_err(|_| anyhow!("proxy metadata read timed out"))??;
    }

    let meta = parse_proxy_v2_header_and_payload(hdr, &payload, require_metadata)?;
    Ok(meta)
}

fn parse_proxy_v2_header_and_payload(
    hdr: [u8; 16],
    payload: &[u8],
    require_metadata: bool,
) -> Result<Option<ProxyMeta>> {
    let ver_cmd = hdr[12];
    if (ver_cmd & 0xF0) != 0x20 {
        return Err(anyhow!("invalid proxy-v2 version"));
    }
    let command = ver_cmd & 0x0F;
    if command == 0x00 {
        if require_metadata {
            return Err(anyhow!(
                "proxy-v2 LOCAL command provided while metadata is required"
            ));
        }
        return Ok(None);
    }
    if command != 0x01 {
        return Err(anyhow!("unsupported proxy-v2 command {}", command));
    }

    let fam_proto = hdr[13];
    let meta = parse_proxy_v2_payload(fam_proto, payload)?;
    if require_metadata && meta.src.is_none() && meta.dst.is_none() {
        return Err(anyhow!(
            "proxy metadata required but proxy-v2 payload is empty"
        ));
    }
    Ok(Some(meta))
}

fn parse_proxy_v2_payload(fam_proto: u8, payload: &[u8]) -> Result<ProxyMeta> {
    let family = fam_proto & 0xF0;
    match family {
        0x10 => {
            if payload.len() < 12 {
                return Err(anyhow!("proxy-v2 IPv4 payload too short"));
            }
            let src = std::net::Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let dst = std::net::Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let src_port = u16::from_be_bytes([payload[8], payload[9]]);
            let dst_port = u16::from_be_bytes([payload[10], payload[11]]);
            Ok(ProxyMeta {
                src: Some(SocketAddr::new(std::net::IpAddr::V4(src), src_port)),
                dst: Some(SocketAddr::new(std::net::IpAddr::V4(dst), dst_port)),
            })
        }
        0x20 => {
            if payload.len() < 36 {
                return Err(anyhow!("proxy-v2 IPv6 payload too short"));
            }
            let src = std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[0..16])
                    .map_err(|_| anyhow!("invalid proxy-v2 source IPv6"))?,
            );
            let dst = std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&payload[16..32])
                    .map_err(|_| anyhow!("invalid proxy-v2 destination IPv6"))?,
            );
            let src_port = u16::from_be_bytes([payload[32], payload[33]]);
            let dst_port = u16::from_be_bytes([payload[34], payload[35]]);
            Ok(ProxyMeta {
                src: Some(SocketAddr::new(std::net::IpAddr::V6(src), src_port)),
                dst: Some(SocketAddr::new(std::net::IpAddr::V6(dst), dst_port)),
            })
        }
        0x00 => Ok(ProxyMeta {
            src: None,
            dst: None,
        }),
        other => Err(anyhow!("unsupported proxy-v2 address family 0x{:x}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proxy_v2_ipv4_payload() {
        let payload = [
            10, 0, 0, 1, // src ip
            203, 0, 113, 7, // dst ip
            0x86, 0xA7, // src port 34471
            0x1F, 0x90, // dst port 8080
        ];
        let meta = parse_proxy_v2_payload(0x11, &payload).expect("ok");
        assert_eq!(meta.src.unwrap().to_string(), "10.0.0.1:34471");
        assert_eq!(meta.dst.unwrap().to_string(), "203.0.113.7:8080");
    }
}
