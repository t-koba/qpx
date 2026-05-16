use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(super) struct QuicConnectionId {
    len: u8,
    bytes: [u8; 20],
}

impl QuicConnectionId {
    fn from_slice(value: &[u8]) -> Option<Self> {
        if value.len() > 20 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes[..value.len()].copy_from_slice(value);
        Some(Self {
            len: value.len() as u8,
            bytes,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ParsedQuicLongHeader {
    dcid_len: u8,
    scid_len: u8,
    dcid: Option<QuicConnectionId>,
    scid: Option<QuicConnectionId>,
}

fn parse_quic_long_header(packet: &[u8]) -> Option<ParsedQuicLongHeader> {
    let first = *packet.first()?;
    if (first & 0x80) == 0 || packet.len() < 6 {
        return None;
    }
    let mut idx = 5usize;
    let dcid_len = *packet.get(idx)? as usize;
    idx += 1;
    if dcid_len > 20 || idx + dcid_len > packet.len() {
        return None;
    }
    let dcid = if dcid_len == 0 {
        None
    } else {
        QuicConnectionId::from_slice(&packet[idx..idx + dcid_len])
    };
    idx += dcid_len;
    let scid_len = *packet.get(idx)? as usize;
    idx += 1;
    if scid_len > 20 || idx + scid_len > packet.len() {
        return None;
    }
    let scid = if scid_len == 0 {
        None
    } else {
        QuicConnectionId::from_slice(&packet[idx..idx + scid_len])
    };
    Some(ParsedQuicLongHeader {
        dcid_len: dcid_len as u8,
        scid_len: scid_len as u8,
        dcid,
        scid,
    })
}

fn parse_quic_short_dcid(packet: &[u8], dcid_len: u8) -> Option<QuicConnectionId> {
    let first = *packet.first()?;
    if (first & 0x80) != 0 {
        return None;
    }
    let dcid_len = dcid_len as usize;
    if dcid_len == 0 || packet.len() < 1 + dcid_len {
        return None;
    }
    QuicConnectionId::from_slice(&packet[1..1 + dcid_len])
}

#[derive(Default)]
pub(super) struct RouteState {
    pub(super) addrs: HashSet<SocketAddr>,
    cids: HashSet<QuicConnectionId>,
    known_server_cid_lens: HashSet<u8>,
}

impl RouteState {
    pub(super) fn observe_inbound(&mut self, addr: SocketAddr, packet: &[u8]) {
        self.addrs.insert(addr);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.dcid {
                self.cids.insert(cid);
            }
            if long.dcid_len > 0 {
                self.known_server_cid_lens.insert(long.dcid_len);
            }
            return;
        }
        for len in self.known_server_cid_lens.clone() {
            if let Some(cid) = parse_quic_short_dcid(packet, len) {
                self.cids.insert(cid);
            }
        }
    }

    pub(super) fn observe_outbound(&mut self, addr: SocketAddr, packet: &[u8]) {
        self.addrs.insert(addr);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.scid {
                self.cids.insert(cid);
            }
            if long.scid_len > 0 {
                self.known_server_cid_lens.insert(long.scid_len);
            }
        }
    }

    pub(super) fn matches_cid(&self, packet: &[u8]) -> bool {
        if let Some(long) = parse_quic_long_header(packet) {
            return long
                .dcid
                .into_iter()
                .chain(long.scid)
                .any(|cid| self.cids.contains(&cid));
        }
        for len in &self.known_server_cid_lens {
            if let Some(cid) = parse_quic_short_dcid(packet, *len)
                && self.cids.contains(&cid)
            {
                return true;
            }
        }
        false
    }
}

pub(super) fn is_quic_long_header(packet: &[u8]) -> bool {
    packet.first().is_some_and(|first| (first & 0x80) != 0)
}
