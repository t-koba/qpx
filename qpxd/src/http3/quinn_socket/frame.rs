mod codec;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use codec::{
    decode_optional_ecn, decode_optional_ip, decode_socket_addr, encode_optional_ecn,
    encode_optional_ip, encode_socket_addr, take_u8, take_u32,
};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub(super) struct InjectedPacket {
    pub(super) addr: SocketAddr,
    pub(super) ecn: Option<quinn::udp::EcnCodepoint>,
    pub(super) dst_ip: Option<IpAddr>,
    pub(super) payload: Bytes,
}

#[derive(Debug)]
pub(super) struct OwnedTransmit {
    pub(super) destination: SocketAddr,
    pub(super) ecn: Option<quinn::udp::EcnCodepoint>,
    pub(super) contents: Bytes,
    pub(super) segment_size: Option<usize>,
    pub(super) src_ip: Option<IpAddr>,
}

impl OwnedTransmit {
    pub(super) fn borrowed(&self) -> quinn::udp::Transmit<'_> {
        quinn::udp::Transmit {
            destination: self.destination,
            ecn: self.ecn,
            contents: self.contents.as_ref(),
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

pub(super) struct EncodedFrameParts<'a> {
    pub(super) header: Vec<u8>,
    pub(super) payload: &'a Bytes,
}

impl EncodedFrameParts<'_> {
    pub(super) fn len(&self) -> usize {
        self.header.len() + self.payload.len()
    }
}

pub(super) fn encode_frame_parts(frame: &BrokerFrame) -> Result<EncodedFrameParts<'_>> {
    let mut header = Vec::with_capacity(64);
    let payload = match frame {
        BrokerFrame::InboundDatagram(packet) => {
            header.push(1);
            encode_socket_addr(packet.addr, &mut header);
            encode_optional_ecn(packet.ecn, &mut header);
            encode_optional_ip(packet.dst_ip, &mut header);
            header.extend_from_slice(&(packet.payload.len() as u32).to_be_bytes());
            &packet.payload
        }
        BrokerFrame::OutboundTransmit(transmit) => {
            header.push(2);
            encode_socket_addr(transmit.destination, &mut header);
            encode_optional_ecn(transmit.ecn, &mut header);
            encode_optional_ip(transmit.src_ip, &mut header);
            header.extend_from_slice(
                &(transmit.segment_size.unwrap_or(0).min(u32::MAX as usize) as u32).to_be_bytes(),
            );
            header.extend_from_slice(&(transmit.contents.len() as u32).to_be_bytes());
            &transmit.contents
        }
    };
    Ok(EncodedFrameParts { header, payload })
}

#[cfg(test)]
pub(super) fn encode_frame(frame: &BrokerFrame) -> Result<Vec<u8>> {
    let parts = encode_frame_parts(frame)?;
    let mut out = Vec::with_capacity(parts.len());
    out.extend_from_slice(parts.header.as_slice());
    out.extend_from_slice(parts.payload.as_ref());
    Ok(out)
}

#[cfg(test)]
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
                payload: Bytes::copy_from_slice(buf),
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
                contents: Bytes::copy_from_slice(buf),
                segment_size: (segment_size != 0).then_some(segment_size as usize),
                src_ip,
            }))
        }
        _ => Err(anyhow!("unknown broker frame kind {}", kind)),
    }
}

pub(super) fn decode_frame_bytes(bytes: Bytes) -> Result<BrokerFrame> {
    let mut buf = bytes.as_ref();
    let total = buf.len();
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
            let payload_offset = total - buf.len();
            Ok(BrokerFrame::InboundDatagram(InjectedPacket {
                addr,
                ecn,
                dst_ip,
                payload: bytes.slice(payload_offset..),
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
            let contents_offset = total - buf.len();
            Ok(BrokerFrame::OutboundTransmit(OwnedTransmit {
                destination,
                ecn,
                contents: bytes.slice(contents_offset..),
                segment_size: (segment_size != 0).then_some(segment_size as usize),
                src_ip,
            }))
        }
        _ => Err(anyhow!("unknown broker frame kind {}", kind)),
    }
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
