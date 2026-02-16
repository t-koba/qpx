use anyhow::{anyhow, Context, Result};
use cidr::IpCidr;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

pub mod remote;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyMetadataMode {
    ProxyV1,
    ProxyV2,
}

#[derive(Clone, Debug)]
pub struct CompiledXdpConfig {
    pub metadata_mode: ProxyMetadataMode,
    pub require_metadata: bool,
    pub trusted_peers: Vec<IpCidr>,
}

#[derive(Clone, Debug)]
pub struct ProxyMeta {
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
}

const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
const PROXY_V1_PREFIX: &[u8] = b"PROXY ";
const MAX_PROXY_V1_HEADER_BYTES: usize = 1024;
const MAX_PROXY_V2_HEADER_BYTES: usize = 4096;

pub async fn consume_proxy_metadata(
    stream: &mut TcpStream,
    require_metadata: bool,
    mode: ProxyMetadataMode,
) -> Result<Option<ProxyMeta>> {
    match mode {
        ProxyMetadataMode::ProxyV1 => consume_proxy_v1(stream, require_metadata).await,
        ProxyMetadataMode::ProxyV2 => consume_proxy_v2(stream, require_metadata).await,
    }
}

pub fn compile_xdp_config(
    cfg: Option<&qpx_core::config::XdpConfig>,
) -> Result<Option<CompiledXdpConfig>> {
    let Some(cfg) = cfg.filter(|cfg| cfg.enabled) else {
        return Ok(None);
    };
    let metadata_mode = match cfg.metadata_mode.as_str() {
        "proxy-v1" => ProxyMetadataMode::ProxyV1,
        "proxy-v2" => ProxyMetadataMode::ProxyV2,
        other => return Err(anyhow!("unsupported xdp metadata_mode: {}", other)),
    };
    let trusted_peers = compile_trusted_peers(&cfg.trusted_peers)?;
    Ok(Some(CompiledXdpConfig {
        metadata_mode,
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

pub(crate) fn looks_like_proxy_header_prefix(mode: ProxyMetadataMode, data: &[u8]) -> bool {
    match mode {
        ProxyMetadataMode::ProxyV1 => {
            if data.len() <= PROXY_V1_PREFIX.len() {
                PROXY_V1_PREFIX.starts_with(data)
            } else {
                data.starts_with(PROXY_V1_PREFIX)
            }
        }
        ProxyMetadataMode::ProxyV2 => {
            if data.len() <= PROXY_V2_SIGNATURE.len() {
                PROXY_V2_SIGNATURE.starts_with(data)
            } else {
                data.starts_with(&PROXY_V2_SIGNATURE)
            }
        }
    }
}

async fn consume_proxy_v1(
    stream: &mut TcpStream,
    require_metadata: bool,
) -> Result<Option<ProxyMeta>> {
    if let Some(data) = peek_for_prefix(stream, PROXY_V1_PREFIX, require_metadata).await? {
        if !data.starts_with(PROXY_V1_PREFIX) {
            if require_metadata {
                return Err(anyhow!(
                    "proxy metadata required but stream does not start with PROXY header"
                ));
            }
            return Ok(None);
        }
    } else {
        if require_metadata {
            return Err(anyhow!("proxy metadata required but no bytes received"));
        }
        return Ok(None);
    }

    let mut buf = vec![0u8; 128];
    let mut last_n = 0usize;
    loop {
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("proxy-v1 header closed before completion"));
        }
        let data = &buf[..n];
        if let Some(eol) = data.windows(2).position(|w| w == b"\r\n") {
            let line =
                std::str::from_utf8(&data[..eol]).context("invalid proxy-v1 header encoding")?;
            let meta = parse_proxy_v1_line(line)?;

            let mut discard = vec![0u8; eol + 2];
            stream.read_exact(&mut discard).await?;
            if require_metadata && meta.src.is_none() && meta.dst.is_none() {
                return Err(anyhow!("proxy-v1 metadata required but payload is UNKNOWN"));
            }
            return Ok(Some(meta));
        }

        if n == buf.len() {
            if buf.len() >= MAX_PROXY_V1_HEADER_BYTES {
                return Err(anyhow!("proxy-v1 header too large"));
            }
            let next = (buf.len() * 2).min(MAX_PROXY_V1_HEADER_BYTES);
            buf.resize(next, 0);
            continue;
        }

        // Wait for more bytes (bounded by caller timeout).
        if n == last_n {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        last_n = n;
    }
}

async fn consume_proxy_v2(
    stream: &mut TcpStream,
    require_metadata: bool,
) -> Result<Option<ProxyMeta>> {
    if let Some(data) = peek_for_prefix(stream, &PROXY_V2_SIGNATURE, require_metadata).await? {
        if !data.starts_with(&PROXY_V2_SIGNATURE) {
            if require_metadata {
                return Err(anyhow!(
                    "proxy metadata required but stream does not start with PROXY header"
                ));
            }
            return Ok(None);
        }
    } else {
        if require_metadata {
            return Err(anyhow!("proxy metadata required but no bytes received"));
        }
        return Ok(None);
    }

    let mut buf = vec![0u8; 16];
    let mut last_n = 0usize;
    loop {
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            return Err(anyhow!("proxy-v2 header closed before completion"));
        }
        if n < 16 {
            if n == last_n {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            last_n = n;
            continue;
        }
        if !buf[..n].starts_with(&PROXY_V2_SIGNATURE) {
            if require_metadata {
                return Err(anyhow!(
                    "proxy metadata required but stream does not start with PROXY header"
                ));
            }
            return Ok(None);
        }

        let ver_cmd = buf[12];
        if (ver_cmd & 0xF0) != 0x20 {
            return Err(anyhow!("invalid proxy-v2 version"));
        }
        let command = ver_cmd & 0x0F;
        let fam_proto = buf[13];
        let addr_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        let total_len = 16 + addr_len;
        if total_len > MAX_PROXY_V2_HEADER_BYTES {
            return Err(anyhow!("proxy-v2 header too large"));
        }
        if buf.len() < total_len {
            buf.resize(total_len, 0);
            continue;
        }
        if n < total_len {
            if n == last_n {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            last_n = n;
            continue;
        }

        if command == 0x00 {
            if require_metadata {
                return Err(anyhow!(
                    "proxy-v2 LOCAL command provided while metadata is required"
                ));
            }
            let mut discard = vec![0u8; total_len];
            stream.read_exact(&mut discard).await?;
            return Ok(None);
        }
        if command != 0x01 {
            return Err(anyhow!("unsupported proxy-v2 command {}", command));
        }

        let payload = &buf[16..total_len];
        let meta = parse_proxy_v2_payload(fam_proto, payload)?;
        let mut discard = vec![0u8; total_len];
        stream.read_exact(&mut discard).await?;
        return Ok(Some(meta));
    }
}

async fn peek_for_prefix(
    stream: &TcpStream,
    prefix: &[u8],
    require_metadata: bool,
) -> Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; prefix.len()];
    let mut last_n = 0usize;
    loop {
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        let data = &buf[..n];
        if n < prefix.len() {
            if prefix.starts_with(data) {
                if n == last_n {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                last_n = n;
                continue;
            }
            if require_metadata {
                return Ok(Some(data.to_vec()));
            }
            return Ok(Some(data.to_vec()));
        }
        return Ok(Some(data.to_vec()));
    }
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

pub fn parse_proxy_v1_line(line: &str) -> Result<ProxyMeta> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "PROXY" {
        return Err(anyhow!("invalid proxy-v1 header"));
    }
    if parts[1] == "UNKNOWN" {
        return Ok(ProxyMeta {
            src: None,
            dst: None,
        });
    }
    if parts.len() != 6 {
        return Err(anyhow!("invalid proxy-v1 field count"));
    }

    let src_port: u16 = parts[4]
        .parse()
        .map_err(|_| anyhow!("invalid proxy-v1 source port"))?;
    let dst_port: u16 = parts[5]
        .parse()
        .map_err(|_| anyhow!("invalid proxy-v1 destination port"))?;

    let (src, dst) = match parts[1] {
        "TCP4" => (
            SocketAddr::new(
                std::net::IpAddr::V4(
                    std::net::Ipv4Addr::from_str(parts[2])
                        .map_err(|_| anyhow!("invalid proxy-v1 source IPv4"))?,
                ),
                src_port,
            ),
            SocketAddr::new(
                std::net::IpAddr::V4(
                    std::net::Ipv4Addr::from_str(parts[3])
                        .map_err(|_| anyhow!("invalid proxy-v1 destination IPv4"))?,
                ),
                dst_port,
            ),
        ),
        "TCP6" => (
            SocketAddr::new(
                std::net::IpAddr::V6(
                    std::net::Ipv6Addr::from_str(parts[2])
                        .map_err(|_| anyhow!("invalid proxy-v1 source IPv6"))?,
                ),
                src_port,
            ),
            SocketAddr::new(
                std::net::IpAddr::V6(
                    std::net::Ipv6Addr::from_str(parts[3])
                        .map_err(|_| anyhow!("invalid proxy-v1 destination IPv6"))?,
                ),
                dst_port,
            ),
        ),
        other => {
            return Err(anyhow!("unsupported proxy-v1 protocol {}", other));
        }
    };

    Ok(ProxyMeta {
        src: Some(src),
        dst: Some(dst),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proxy_v1_tcp4() {
        let meta = parse_proxy_v1_line("PROXY TCP4 10.0.0.1 203.0.113.7 34567 8080").expect("ok");
        assert_eq!(meta.src.unwrap().to_string(), "10.0.0.1:34567");
        assert_eq!(meta.dst.unwrap().to_string(), "203.0.113.7:8080");
    }

    #[test]
    fn parse_proxy_v1_unknown() {
        let meta = parse_proxy_v1_line("PROXY UNKNOWN").expect("ok");
        assert!(meta.src.is_none());
        assert!(meta.dst.is_none());
    }

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
