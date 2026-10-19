use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct QuicConnectionId {
    pub(crate) len: u8,
    pub(crate) bytes: [u8; 20],
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
pub(crate) struct ParsedQuicLongHeader {
    pub(crate) dcid_len: u8,
    pub(crate) scid_len: u8,
    pub(crate) dcid: Option<QuicConnectionId>,
    pub(crate) scid: Option<QuicConnectionId>,
}

pub(crate) fn parse_quic_long_header(packet: &[u8]) -> Option<ParsedQuicLongHeader> {
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

pub(crate) fn parse_quic_short_dcid(packet: &[u8], dcid_len: u8) -> Option<QuicConnectionId> {
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

pub(crate) fn is_quic_long_header(packet: &[u8]) -> bool {
    packet.first().is_some_and(|first| (first & 0x80) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn long_packet(first: u8, version: u32, dcid_len: u8, scid_len: u8) -> Vec<u8> {
        let mut packet = vec![first];
        packet.extend(version.to_be_bytes());
        for (len, byte) in [(dcid_len, 0x42), (scid_len, 0x24)] {
            packet.push(len);
            packet.extend(vec![byte; len as usize]);
        }
        packet
    }

    #[test]
    fn cid_parser_preserves_header_and_length_boundaries() {
        for (first, version, dcid_len, scid_len, accepted) in [
            (0x80, 0, 0, 0, true),
            (0xc0, u32::MAX, 1, 20, true),
            (0x7f, 1, 1, 1, false),
            (0x80, 1, 21, 0, false),
            (0x80, 1, 0, 21, false),
        ] {
            let packet = long_packet(first, version, dcid_len, scid_len);
            let parsed = parse_quic_long_header(&packet);
            assert_eq!(parsed.is_some(), accepted);
            if let Some(parsed) = parsed {
                assert_eq!((parsed.dcid_len, parsed.scid_len), (dcid_len, scid_len));
                assert_eq!(parsed.dcid.is_some(), dcid_len != 0);
                assert_eq!(parsed.scid.is_some(), scid_len != 0);
            }
        }

        assert!(parse_quic_long_header(&[0x80; 5]).is_none());
        assert!(parse_quic_long_header(&long_packet(0x80, 1, 1, 1)[..6]).is_none());
        for (first, len, accepted) in [
            (0x40, 0, false),
            (0x40, 1, true),
            (0x40, 20, true),
            (0x40, 21, false),
            (0x40, 255, false),
            (0x80, 1, false),
        ] {
            let mut packet = vec![first];
            packet.resize(1 + len as usize, 0xaa);
            assert_eq!(parse_quic_short_dcid(&packet, len).is_some(), accepted);
        }
        assert!(parse_quic_short_dcid(&[0x40, 0xaa], 2).is_none());
        assert!(!is_quic_long_header(&[]));
        assert!(!is_quic_long_header(&[0x40]));
        assert!(is_quic_long_header(&[0x80]));
    }
}
