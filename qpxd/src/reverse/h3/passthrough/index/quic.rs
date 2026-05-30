#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(in crate::reverse::h3::passthrough) struct QuicConnectionId {
    pub(in crate::reverse::h3::passthrough) len: u8,
    pub(in crate::reverse::h3::passthrough) bytes: [u8; 20],
}

impl QuicConnectionId {
    pub(in crate::reverse::h3::passthrough) fn from_slice(value: &[u8]) -> Option<Self> {
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
pub(in crate::reverse::h3::passthrough) struct ParsedQuicLongHeader {
    pub(in crate::reverse::h3::passthrough) dcid_len: u8,
    pub(in crate::reverse::h3::passthrough) scid_len: u8,
    pub(in crate::reverse::h3::passthrough) dcid: Option<QuicConnectionId>,
    pub(in crate::reverse::h3::passthrough) scid: Option<QuicConnectionId>,
}

pub(in crate::reverse::h3::passthrough) fn parse_quic_long_header(
    packet: &[u8],
) -> Option<ParsedQuicLongHeader> {
    let first = *packet.first()?;
    if (first & 0x80) == 0 {
        return None;
    }
    // long header: [type(1)] [version(4)] [dcid_len(1)] [dcid] [scid_len(1)] [scid] ...
    if packet.len() < 1 + 4 + 1 {
        return None;
    }
    let mut idx = 1 + 4;
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

pub(in crate::reverse::h3::passthrough) fn parse_quic_short_dcid(
    packet: &[u8],
    dcid_len: u8,
) -> Option<QuicConnectionId> {
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
