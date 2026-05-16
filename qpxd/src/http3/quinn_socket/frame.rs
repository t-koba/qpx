use anyhow::{Result, anyhow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone)]
pub(super) struct InjectedPacket {
    pub(super) addr: SocketAddr,
    pub(super) ecn: Option<quinn::udp::EcnCodepoint>,
    pub(super) dst_ip: Option<IpAddr>,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct OwnedTransmit {
    pub(super) destination: SocketAddr,
    pub(super) ecn: Option<quinn::udp::EcnCodepoint>,
    pub(super) contents: Vec<u8>,
    pub(super) segment_size: Option<usize>,
    pub(super) src_ip: Option<IpAddr>,
}

impl OwnedTransmit {
    pub(super) fn borrowed(&self) -> quinn::udp::Transmit<'_> {
        quinn::udp::Transmit {
            destination: self.destination,
            ecn: self.ecn,
            contents: self.contents.as_slice(),
            segment_size: self.segment_size,
            src_ip: self.src_ip,
        }
    }

    pub(super) fn datagrams(&self) -> impl Iterator<Item = &[u8]> {
        let segment = self.segment_size.unwrap_or(self.contents.len()).max(1);
        self.contents.chunks(segment)
    }
}

#[derive(Debug)]
pub(super) enum BrokerFrame {
    InboundDatagram(InjectedPacket),
    OutboundTransmit(OwnedTransmit),
}

pub(super) fn encode_frame(frame: &BrokerFrame) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match frame {
        BrokerFrame::InboundDatagram(packet) => {
            out.push(1);
            encode_socket_addr(packet.addr, &mut out);
            encode_optional_ecn(packet.ecn, &mut out);
            encode_optional_ip(packet.dst_ip, &mut out);
            out.extend_from_slice(&(packet.payload.len() as u32).to_be_bytes());
            out.extend_from_slice(packet.payload.as_slice());
        }
        BrokerFrame::OutboundTransmit(transmit) => {
            out.push(2);
            encode_socket_addr(transmit.destination, &mut out);
            encode_optional_ecn(transmit.ecn, &mut out);
            encode_optional_ip(transmit.src_ip, &mut out);
            out.extend_from_slice(
                &(transmit.segment_size.unwrap_or(0).min(u32::MAX as usize) as u32).to_be_bytes(),
            );
            out.extend_from_slice(&(transmit.contents.len() as u32).to_be_bytes());
            out.extend_from_slice(transmit.contents.as_slice());
        }
    }
    Ok(out)
}

pub(super) fn decode_frame(mut buf: &[u8]) -> Result<BrokerFrame> {
    let Some(kind) = take_u8(&mut buf) else {
        return Err(anyhow!("broker frame missing kind"));
    };
    match kind {
        1 => {
            let addr = decode_socket_addr(&mut buf)?;
            let ecn = decode_optional_ecn(&mut buf)?;
            let dst_ip = decode_optional_ip(&mut buf)?;
            let len = take_u32(&mut buf).ok_or_else(|| anyhow!("broker frame missing len"))?;
            if buf.len() != len as usize {
                return Err(anyhow!("invalid broker inbound datagram length"));
            }
            Ok(BrokerFrame::InboundDatagram(InjectedPacket {
                addr,
                ecn,
                dst_ip,
                payload: buf.to_vec(),
            }))
        }
        2 => {
            let destination = decode_socket_addr(&mut buf)?;
            let ecn = decode_optional_ecn(&mut buf)?;
            let src_ip = decode_optional_ip(&mut buf)?;
            let segment_size =
                take_u32(&mut buf).ok_or_else(|| anyhow!("broker frame missing segment size"))?;
            let len = take_u32(&mut buf).ok_or_else(|| anyhow!("broker frame missing len"))?;
            if buf.len() != len as usize {
                return Err(anyhow!("invalid broker outbound transmit length"));
            }
            Ok(BrokerFrame::OutboundTransmit(OwnedTransmit {
                destination,
                ecn,
                contents: buf.to_vec(),
                segment_size: (segment_size != 0).then_some(segment_size as usize),
                src_ip,
            }))
        }
        _ => Err(anyhow!("unknown broker frame kind {}", kind)),
    }
}

fn encode_socket_addr(addr: SocketAddr, out: &mut Vec<u8>) {
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

fn decode_socket_addr(buf: &mut &[u8]) -> Result<SocketAddr> {
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

fn encode_optional_ip(ip: Option<IpAddr>, out: &mut Vec<u8>) {
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

fn decode_optional_ip(buf: &mut &[u8]) -> Result<Option<IpAddr>> {
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

fn encode_optional_ecn(ecn: Option<quinn::udp::EcnCodepoint>, out: &mut Vec<u8>) {
    out.push(ecn.map(|value| value as u8).unwrap_or(0xff));
}

fn decode_optional_ecn(buf: &mut &[u8]) -> Result<Option<quinn::udp::EcnCodepoint>> {
    let value = take_u8(buf).ok_or_else(|| anyhow!("missing ecn"))?;
    if value == 0xff {
        return Ok(None);
    }
    quinn::udp::EcnCodepoint::from_bits(value)
        .map(Some)
        .ok_or_else(|| anyhow!("invalid ecn bits {}", value))
}

fn take_u8(buf: &mut &[u8]) -> Option<u8> {
    let value = *buf.first()?;
    *buf = &buf[1..];
    Some(value)
}

fn take_u16(buf: &mut &[u8]) -> Option<u16> {
    let bytes = take_array::<2>(buf)?;
    Some(u16::from_be_bytes(bytes))
}

fn take_u32(buf: &mut &[u8]) -> Option<u32> {
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

pub(super) fn datagrams_for_transmit<'a>(
    transmit: &'a quinn::udp::Transmit<'a>,
) -> impl Iterator<Item = &'a [u8]> {
    let segment = transmit
        .segment_size
        .unwrap_or(transmit.contents.len())
        .max(1);
    transmit.contents.chunks(segment)
}
