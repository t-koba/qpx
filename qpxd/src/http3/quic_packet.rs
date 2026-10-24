use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};

/// The longest connection id a QUIC endpoint may use.
pub(crate) const MAX_CONNECTION_ID_LEN: u8 = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct QuicConnectionId {
    pub(crate) len: u8,
    pub(crate) bytes: [u8; 20],
}

impl QuicConnectionId {
    fn from_slice(value: &[u8]) -> Option<Self> {
        if value.len() > usize::from(MAX_CONNECTION_ID_LEN) {
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
    if dcid_len > usize::from(MAX_CONNECTION_ID_LEN) || idx + dcid_len > packet.len() {
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
    if scid_len > usize::from(MAX_CONNECTION_ID_LEN) || idx + scid_len > packet.len() {
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

/// Connection ids and directional cid-length hints learned from one packet.
/// Session indexes apply these observations while retaining ownership of their
/// own session and index state.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct QuicPacketCidObservation {
    pub(crate) connection_ids: [Option<QuicConnectionId>; 2],
    pub(crate) client_cid_len: Option<u8>,
    pub(crate) server_cid_len: Option<u8>,
}

/// Extract the connection ids learned from a client-to-server QUIC packet.
pub(crate) fn observe_client_quic_packet(
    packet: &[u8],
    server_cid_len: Option<u8>,
) -> QuicPacketCidObservation {
    if let Some(long) = parse_quic_long_header(packet) {
        return QuicPacketCidObservation {
            connection_ids: [long.dcid, long.scid],
            client_cid_len: (long.scid_len > 0).then_some(long.scid_len),
            server_cid_len: None,
        };
    }

    QuicPacketCidObservation {
        connection_ids: [
            server_cid_len.and_then(|len| parse_quic_short_dcid(packet, len)),
            None,
        ],
        ..QuicPacketCidObservation::default()
    }
}

/// Extract the connection ids and directional cid-length hints learned from
/// a server-to-client QUIC packet.
pub(crate) fn observe_upstream_quic_packet(
    packet: &[u8],
    client_cid_len: Option<u8>,
) -> QuicPacketCidObservation {
    if let Some(long) = parse_quic_long_header(packet) {
        return QuicPacketCidObservation {
            connection_ids: [long.dcid, long.scid],
            client_cid_len: (long.dcid_len > 0).then_some(long.dcid_len),
            server_cid_len: (long.scid_len > 0).then_some(long.scid_len),
        };
    }

    QuicPacketCidObservation {
        connection_ids: [
            client_cid_len.and_then(|len| parse_quic_short_dcid(packet, len)),
            None,
        ],
        ..QuicPacketCidObservation::default()
    }
}

/// Checks whether an upstream packet requires this session's CID index to update.
/// Lazy length reads preserve the index's existing order; CID ownership stays caller-owned.
pub(crate) fn upstream_packet_needs_cid_index_update(
    packet: &[u8],
    session_id: u64,
    mut server_cid_len: impl FnMut() -> Option<u8>,
    mut client_cid_len: impl FnMut() -> Option<u8>,
    mut cid_owner: impl FnMut(QuicConnectionId) -> Option<u64>,
) -> bool {
    if let Some(long) = parse_quic_long_header(packet) {
        return (long.scid_len > 0 && server_cid_len() != Some(long.scid_len))
            || (client_cid_len().is_none() && long.dcid_len > 0)
            || [long.dcid, long.scid]
                .into_iter()
                .flatten()
                .any(|cid| cid_owner(cid) != Some(session_id));
    }
    client_cid_len()
        .and_then(|len| parse_quic_short_dcid(packet, len))
        .is_some_and(|cid| cid_owner(cid) != Some(session_id))
}

/// Checks whether a client packet requires this session's CID index to update.
/// Lazy length reads preserve the index's existing order; CID ownership stays caller-owned.
pub(crate) fn client_packet_needs_cid_index_update(
    packet: &[u8],
    session_id: u64,
    mut client_cid_len: impl FnMut() -> Option<u8>,
    mut server_cid_len: impl FnMut() -> Option<u8>,
    mut cid_owner: impl FnMut(QuicConnectionId) -> Option<u64>,
) -> bool {
    if let Some(long) = parse_quic_long_header(packet) {
        if long.scid_len > 0 && client_cid_len() != Some(long.scid_len) {
            return true;
        }
        return [long.dcid, long.scid]
            .into_iter()
            .flatten()
            .any(|cid| cid_owner(cid) != Some(session_id));
    }
    let Some(server_cid_len) = server_cid_len() else {
        return false;
    };
    let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) else {
        return false;
    };
    cid_owner(cid) != Some(session_id)
}

pub(crate) fn is_quic_long_header(packet: &[u8]) -> bool {
    packet.first().is_some_and(|first| (first & 0x80) != 0)
}

/// The bit that marks a connection-id length in the set of known lengths.
pub(crate) fn connection_id_len_bit(len: u8) -> Option<u32> {
    (1..=MAX_CONNECTION_ID_LEN)
        .contains(&len)
        .then_some(1u32 << len)
}

pub(crate) fn encode_cid_len(value: Option<u8>) -> u8 {
    value.unwrap_or(0)
}

pub(crate) fn decode_cid_len(value: u8) -> Option<u8> {
    if value == 0 { None } else { Some(value) }
}

pub(crate) fn record_known_connection_id_len(bits: &AtomicU32, len: u8) {
    if let Some(bit) = connection_id_len_bit(len) {
        bits.fetch_or(bit, Ordering::Relaxed);
    }
}

/// Visits the known connection-id lengths, shortest first, until `f` returns
/// true, and reports whether it ever did.
pub(crate) fn for_each_known_connection_id_len(bits: u32, mut f: impl FnMut(u8) -> bool) -> bool {
    let mut bits = bits & !1;
    while bits != 0 {
        let len = bits.trailing_zeros() as u8;
        if f(len) {
            return true;
        }
        bits &= bits - 1;
    }
    false
}

/// Finds the session that owns a short-header packet.
///
/// A server may use several connection-id lengths, so the known lengths are
/// tried from the shortest and the first that yields a session wins.
pub(crate) fn find_by_known_connection_id_len<T>(
    bits: u32,
    packet: &[u8],
    mut lookup: impl FnMut(QuicConnectionId) -> Option<T>,
) -> Option<T> {
    let mut found = None;
    for_each_known_connection_id_len(bits, |len| {
        if let Some(cid) = parse_quic_short_dcid(packet, len)
            && let Some(value) = lookup(cid)
        {
            found = Some(value);
            true
        } else {
            false
        }
    });
    found
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
    fn packet_cid_observations_preserve_directional_lengths() {
        let client_packet = long_packet(0xc0, 1, 3, 2);
        let client = observe_client_quic_packet(&client_packet, None);
        let client_header = parse_quic_long_header(&client_packet).unwrap();
        assert_eq!(
            client.connection_ids,
            [client_header.dcid, client_header.scid]
        );
        assert_eq!(client.client_cid_len, Some(2));
        assert_eq!(client.server_cid_len, None);

        let upstream_packet = long_packet(0xc0, 1, 3, 2);
        let upstream = observe_upstream_quic_packet(&upstream_packet, None);
        let upstream_header = parse_quic_long_header(&upstream_packet).unwrap();
        assert_eq!(
            upstream.connection_ids,
            [upstream_header.dcid, upstream_header.scid]
        );
        assert_eq!(upstream.client_cid_len, Some(3));
        assert_eq!(upstream.server_cid_len, Some(2));

        let zero_scid_packet = long_packet(0xc0, 1, 3, 0);
        let zero_scid = observe_client_quic_packet(&zero_scid_packet, None);
        assert_eq!(zero_scid.client_cid_len, None);
    }

    #[test]
    fn short_packet_cid_observations_require_the_opposite_direction_length() {
        let packet = [0x40, 0xa1, 0xb2, 0xc3];
        let client = observe_client_quic_packet(&packet, Some(2));
        assert_eq!(client.connection_ids[0], parse_quic_short_dcid(&packet, 2));
        assert_eq!(client.connection_ids[1], None);
        assert_eq!(client.client_cid_len, None);
        assert_eq!(client.server_cid_len, None);
        assert_eq!(
            observe_client_quic_packet(&packet, None).connection_ids,
            [None, None]
        );

        let upstream = observe_upstream_quic_packet(&packet, Some(3));
        assert_eq!(
            upstream.connection_ids[0],
            parse_quic_short_dcid(&packet, 3)
        );
        assert_eq!(upstream.connection_ids[1], None);
        assert_eq!(upstream.client_cid_len, None);
        assert_eq!(upstream.server_cid_len, None);
        assert_eq!(
            observe_upstream_quic_packet(&packet, None).connection_ids,
            [None, None]
        );
    }

    #[test]
    fn upstream_index_update_preserves_directional_reads_and_owner_checks() {
        use std::cell::RefCell;

        let packet = long_packet(0xc0, 1, 3, 2);
        let reads = RefCell::new(Vec::new());
        assert!(!upstream_packet_needs_cid_index_update(
            &packet,
            7,
            || {
                reads.borrow_mut().push("server");
                Some(2)
            },
            || {
                reads.borrow_mut().push("client");
                Some(3)
            },
            |_| Some(7),
        ));
        assert_eq!(*reads.borrow(), ["server", "client"]);

        assert!(upstream_packet_needs_cid_index_update(
            &packet,
            7,
            || Some(1),
            || panic!("client CID length is not read after server mismatch"),
            |_| Some(7),
        ));
        assert!(upstream_packet_needs_cid_index_update(
            &packet,
            7,
            || Some(2),
            || None,
            |_| Some(7),
        ));
        assert!(upstream_packet_needs_cid_index_update(
            &packet,
            7,
            || Some(2),
            || Some(3),
            |_| Some(8),
        ));

        let short_packet = [0x40, 0x42, 0x24];
        assert!(!upstream_packet_needs_cid_index_update(
            &short_packet,
            7,
            || panic!("server CID length is not read for short headers"),
            || Some(2),
            |_| Some(7),
        ));
        assert!(upstream_packet_needs_cid_index_update(
            &short_packet,
            7,
            || panic!("server CID length is not read for short headers"),
            || Some(2),
            |_| Some(8),
        ));
        assert!(!upstream_packet_needs_cid_index_update(
            &short_packet,
            7,
            || panic!("server CID length is not read for short headers"),
            || None,
            |_| Some(8),
        ));
    }

    #[test]
    fn client_index_update_preserves_lazy_directional_reads_and_owner_checks() {
        use std::cell::{Cell, RefCell};

        let packet = long_packet(0xc0, 1, 3, 2);
        let reads = RefCell::new(Vec::new());
        let owners = RefCell::new(Vec::new());
        assert!(!client_packet_needs_cid_index_update(
            &packet,
            7,
            || {
                reads.borrow_mut().push("client");
                Some(2)
            },
            || panic!("server CID length is not read for long headers"),
            |cid| {
                owners.borrow_mut().push(cid);
                Some(7)
            },
        ));
        assert_eq!(*reads.borrow(), ["client"]);
        assert_eq!(owners.borrow().len(), 2);

        assert!(client_packet_needs_cid_index_update(
            &packet,
            7,
            || Some(1),
            || panic!("server CID length is not read for long headers"),
            |_| panic!("CID ownership is not read after client length mismatch"),
        ));

        let zero_scid_packet = long_packet(0xc0, 1, 3, 0);
        let owner_calls = Cell::new(0);
        assert!(!client_packet_needs_cid_index_update(
            &zero_scid_packet,
            7,
            || panic!("client CID length is not read for a zero-length SCID"),
            || panic!("server CID length is not read for long headers"),
            |_| {
                owner_calls.set(owner_calls.get() + 1);
                Some(7)
            },
        ));
        assert_eq!(owner_calls.get(), 1);

        let short_packet = [0x40, 0x42, 0x24];
        assert!(!client_packet_needs_cid_index_update(
            &short_packet,
            7,
            || panic!("client CID length is not read for short headers"),
            || Some(2),
            |_| Some(7),
        ));
        assert!(client_packet_needs_cid_index_update(
            &short_packet,
            7,
            || panic!("client CID length is not read for short headers"),
            || Some(2),
            |_| Some(8),
        ));
        assert!(!client_packet_needs_cid_index_update(
            &short_packet,
            7,
            || panic!("client CID length is not read for short headers"),
            || None,
            |_| panic!("CID ownership is not read without a server CID length"),
        ));
        assert!(!client_packet_needs_cid_index_update(
            &short_packet[..2],
            7,
            || panic!("client CID length is not read for short headers"),
            || Some(2),
            |_| panic!("CID ownership is not read for a malformed short header"),
        ));
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
