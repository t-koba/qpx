use anyhow::{Result, anyhow};
use bytes::Bytes;
use cidr::IpCidr;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

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

pub(crate) async fn consume_proxy_metadata(
    stream: &mut TcpStream,
    require_metadata: bool,
    metadata_timeout: Duration,
) -> Result<ProxyReadResult> {
    consume_proxy_v2(stream, require_metadata, metadata_timeout).await
}

pub(crate) fn compile_xdp_config(
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

pub(crate) fn compile_trusted_peers(trusted_peers: &[String]) -> Result<Vec<IpCidr>> {
    let mut out = Vec::with_capacity(trusted_peers.len());
    for peer in trusted_peers {
        let cidr: IpCidr = peer
            .parse()
            .map_err(|_| anyhow!("invalid trusted peer CIDR: {}", peer))?;
        out.push(cidr);
    }
    Ok(out)
}

pub(crate) fn peer_is_trusted(remote_ip: IpAddr, trusted_peers: &[IpCidr]) -> bool {
    trusted_peers.iter().any(|cidr| cidr.contains(&remote_ip))
}

async fn consume_proxy_v2(
    stream: &mut TcpStream,
    require_metadata: bool,
    metadata_timeout: Duration,
) -> Result<ProxyReadResult> {
    let deadline = crate::runtime::tokio_deadline_after(metadata_timeout);
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
    if !matches!(family, 0x00 | 0x10 | 0x20 | 0x30) {
        return Err(anyhow!(
            "unsupported proxy-v2 address family 0x{:x}",
            family
        ));
    }
    let no_address = ProxyMeta {
        src: None,
        dst: None,
    };
    match fam_proto & 0x0F {
        // These consumers use TCP: UNSPEC ignores addresses, and unsupported DGRAM
        // must fall back to UNSPEC rather than trusting its address block.
        0x00 | 0x02 => {
            return Ok(no_address);
        }
        0x01 => {} // STREAM
        other => return Err(anyhow!("unsupported proxy-v2 transport 0x{:x}", other)),
    }
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
        0x00 => Ok(no_address),
        other => Err(anyhow!("unsupported proxy-v2 address family 0x{:x}", other)),
    }
}

pub(crate) fn fuzz_parse_proxy_v2_frame(frame: &[u8]) {
    if frame.len() < 16 {
        return;
    }
    let mut hdr = [0u8; 16];
    hdr.copy_from_slice(&frame[..16]);
    let _ = parse_proxy_v2_header_and_payload(hdr, &frame[16..], false);
}

#[cfg(test)]
mod tests {
    use crate::xdp::*;

    fn proxy_header(command: u8, fam_proto: u8, payload_len: usize) -> [u8; 16] {
        let mut hdr = [0u8; 16];
        hdr[..12].copy_from_slice(&PROXY_V2_SIGNATURE);
        hdr[12] = 0x20 | command;
        hdr[13] = fam_proto;
        hdr[14..16].copy_from_slice(&(payload_len as u16).to_be_bytes());
        hdr
    }

    #[test]
    fn parse_proxy_v2_transport_table() {
        let cases = [
            (0x10, "10.0.0.1:34471", "203.0.113.7:8080"),
            (0x20, "[2001:db8::1]:34471", "[2001:db8::2]:8080"),
        ];
        for (family, src, dst) in cases {
            let src: SocketAddr = src.parse().unwrap();
            let dst: SocketAddr = dst.parse().unwrap();
            let mut payload = Vec::new();
            for addr in [src, dst] {
                match addr.ip() {
                    IpAddr::V4(ip) => payload.extend_from_slice(&ip.octets()),
                    IpAddr::V6(ip) => payload.extend_from_slice(&ip.octets()),
                }
            }
            payload.extend_from_slice(&src.port().to_be_bytes());
            payload.extend_from_slice(&dst.port().to_be_bytes());

            for transport in 0..=15 {
                let fam_proto = family | transport;
                let hdr = proxy_header(1, fam_proto, payload.len());
                let optional = parse_proxy_v2_header_and_payload(hdr, &payload, false);
                let required = parse_proxy_v2_header_and_payload(hdr, &payload, true);
                match transport {
                    1 => {
                        for result in [optional, required] {
                            let meta = result.expect("STREAM accepted").expect("metadata");
                            assert_eq!(meta.src, Some(src));
                            assert_eq!(meta.dst, Some(dst));
                        }
                    }
                    0 | 2 => {
                        let meta = optional.expect("UNSPEC fallback").expect("metadata");
                        assert_eq!(meta.src, None, "fam_proto={fam_proto:#x}");
                        assert_eq!(meta.dst, None, "fam_proto={fam_proto:#x}");
                        assert!(required.is_err(), "fam_proto={fam_proto:#x}");
                        // Ignored address data must not require a full address block either.
                        let empty = parse_proxy_v2_payload(fam_proto, &[]).unwrap();
                        assert!(empty.src.is_none() && empty.dst.is_none());
                    }
                    _ => {
                        assert!(optional.is_err(), "reserved fam_proto={fam_proto:#x}");
                        assert!(required.is_err(), "reserved fam_proto={fam_proto:#x}");
                    }
                }
            }
        }
    }

    #[test]
    fn parse_proxy_v2_local_ignores_family_and_transport() {
        for fam_proto in 0..=u8::MAX {
            let hdr = proxy_header(0, fam_proto, 3);
            assert!(
                parse_proxy_v2_header_and_payload(hdr, &[1, 2, 3], false)
                    .unwrap()
                    .is_none(),
                "LOCAL fam_proto={fam_proto:#x}"
            );
            let err = parse_proxy_v2_header_and_payload(hdr, &[1, 2, 3], true).unwrap_err();
            assert!(err.to_string().contains("LOCAL command"));
        }
    }

    #[test]
    fn parse_proxy_v2_family_validation_and_unsupported_fallback() {
        let meta = parse_proxy_v2_payload(0x01, &[]).unwrap();
        assert!(meta.src.is_none() && meta.dst.is_none());
        assert!(parse_proxy_v2_payload(0x11, &[0; 11]).is_err());
        assert!(parse_proxy_v2_payload(0x21, &[0; 35]).is_err());
        assert!(parse_proxy_v2_payload(0x31, &[0; 36]).is_err());
        for family in 4..=15 {
            for transport in [0, 1, 2] {
                assert!(parse_proxy_v2_payload((family << 4) | transport, &[0; 36]).is_err());
            }
        }
        for fam_proto in [0x30, 0x32] {
            let meta = parse_proxy_v2_payload(fam_proto, &[]).expect("valid unsupported fallback");
            assert!(meta.src.is_none() && meta.dst.is_none());
        }
    }
}
