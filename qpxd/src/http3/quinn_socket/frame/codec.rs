use anyhow::{Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(super) fn encode_socket_addr(addr: SocketAddr, out: &mut Vec<u8>) {
    match addr {
        SocketAddr::V4(addr) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            out.push(6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}

pub(super) fn decode_socket_addr(buf: &mut &[u8]) -> Result<SocketAddr> {
    let family = take_u8(buf).ok_or_else(|| anyhow!("missing socket addr family"))?;
    match family {
        4 => {
            let ip = take_array::<4>(buf).ok_or_else(|| anyhow!("missing ipv4 addr"))?;
            let port = take_u16(buf).ok_or_else(|| anyhow!("missing ipv4 port"))?;
            Ok(SocketAddr::new(Ipv4Addr::from(ip).into(), port))
        }
        6 => {
            let ip = take_array::<16>(buf).ok_or_else(|| anyhow!("missing ipv6 addr"))?;
            let port = take_u16(buf).ok_or_else(|| anyhow!("missing ipv6 port"))?;
            Ok(SocketAddr::new(Ipv6Addr::from(ip).into(), port))
        }
        _ => Err(anyhow!("unknown socket addr family {}", family)),
    }
}

pub(super) fn encode_optional_ip(ip: Option<IpAddr>, out: &mut Vec<u8>) {
    match ip {
        Some(IpAddr::V4(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
        None => out.push(0),
    }
}

pub(super) fn decode_optional_ip(buf: &mut &[u8]) -> Result<Option<IpAddr>> {
    let family = take_u8(buf).ok_or_else(|| anyhow!("missing optional ip family"))?;
    Ok(match family {
        0 => None,
        4 => Some(IpAddr::V4(Ipv4Addr::from(
            take_array::<4>(buf).ok_or_else(|| anyhow!("missing optional ipv4"))?,
        ))),
        6 => Some(IpAddr::V6(Ipv6Addr::from(
            take_array::<16>(buf).ok_or_else(|| anyhow!("missing optional ipv6"))?,
        ))),
        _ => return Err(anyhow!("unknown optional ip family {}", family)),
    })
}

pub(super) fn encode_optional_ecn(ecn: Option<quinn::udp::EcnCodepoint>, out: &mut Vec<u8>) {
    out.push(ecn.map(|value| value as u8).unwrap_or(0xff));
}

pub(super) fn decode_optional_ecn(buf: &mut &[u8]) -> Result<Option<quinn::udp::EcnCodepoint>> {
    let value = take_u8(buf).ok_or_else(|| anyhow!("missing ecn"))?;
    if value == 0xff {
        return Ok(None);
    }
    quinn::udp::EcnCodepoint::from_bits(value)
        .map(Some)
        .ok_or_else(|| anyhow!("invalid ecn bits {}", value))
}

pub(super) fn take_u8(buf: &mut &[u8]) -> Option<u8> {
    let value = *buf.first()?;
    *buf = &buf[1..];
    Some(value)
}

pub(super) fn take_u16(buf: &mut &[u8]) -> Option<u16> {
    let bytes = take_array::<2>(buf)?;
    Some(u16::from_be_bytes(bytes))
}

pub(super) fn take_u32(buf: &mut &[u8]) -> Option<u32> {
    let bytes = take_array::<4>(buf)?;
    Some(u32::from_be_bytes(bytes))
}

fn take_array<const N: usize>(buf: &mut &[u8]) -> Option<[u8; N]> {
    let bytes = buf.get(..N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    *buf = &buf[N..];
    Some(out)
}
