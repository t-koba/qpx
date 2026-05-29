use super::index::{
    SessionIndex, parse_quic_long_header, parse_quic_short_dcid, should_queue_touch_at,
};
use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::AtomicU64;

fn drain_session_touches(index: &mut SessionIndex, touch_rx: &mut mpsc::Receiver<SessionTouch>) {
    while let Ok(touch) = touch_rx.try_recv() {
        if index.sessions.contains_key(&touch.session_id) {
            index.record_touch(touch.session_id, touch.seen_ms);
        }
    }
}

fn upstream_packet_needs_index_update(
    index: &SessionIndex,
    session_id: u64,
    session: &PassthroughSession,
    packet: &[u8],
) -> bool {
    if let Some(long) = parse_quic_long_header(packet) {
        if long.scid_len > 0 && session.server_cid_len() != Some(long.scid_len) {
            return true;
        }
        if session.client_cid_len().is_none() && long.dcid_len > 0 {
            return true;
        }
        return [long.dcid, long.scid]
            .into_iter()
            .flatten()
            .any(|cid| index.by_cid.get(&cid).copied() != Some(session_id));
    }
    let Some(client_cid_len) = session.client_cid_len() else {
        return false;
    };
    let Some(cid) = parse_quic_short_dcid(packet, client_cid_len) else {
        return false;
    };
    index.by_cid.get(&cid).copied() != Some(session_id)
}

fn client_packet_needs_index_update(
    index: &SessionIndex,
    session_id: u64,
    session: &PassthroughSession,
    packet: &[u8],
) -> bool {
    if let Some(long) = parse_quic_long_header(packet) {
        if long.scid_len > 0 && session.client_cid_len() != Some(long.scid_len) {
            return true;
        }
        return [long.dcid, long.scid]
            .into_iter()
            .flatten()
            .any(|cid| index.by_cid.get(&cid).copied() != Some(session_id));
    }
    let Some(server_cid_len) = session.server_cid_len() else {
        return false;
    };
    let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) else {
        return false;
    };
    index.by_cid.get(&cid).copied() != Some(session_id)
}

fn test_quic_long_header() -> Vec<u8> {
    vec![0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, 0]
}

#[tokio::test]
async fn cid_lookup_does_not_migrate_reverse_h3_session() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
    let (close_tx, _close_rx) = watch::channel(false);
    let original = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001);
    let (client_addr_tx, _client_addr_rx) = watch::channel(original);
    let session = Arc::new(PassthroughSession::new(
        socket,
        close_tx,
        original,
        client_addr_tx,
        0,
        1200,
        0,
    ));
    let mut index = SessionIndex::new();
    index.by_addr.insert(original, 1);
    index.sessions.insert(1, session);
    let packet = test_quic_long_header();
    index.observe_client_packet(1, &packet);

    let attacker = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40002);
    assert_eq!(
        index.find_session_for_client_packet(original, &packet),
        Some(1)
    );
    assert_eq!(
        index.find_session_for_client_packet(attacker, &packet),
        None
    );
}

#[tokio::test]
async fn passthrough_session_index_maintenance_paths() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
    let (close_tx, _close_rx) = watch::channel(false);
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40011);
    let updated = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40012);
    let (client_addr_tx, _client_addr_rx) = watch::channel(client);
    let session = Arc::new(PassthroughSession::new(
        socket,
        close_tx,
        client,
        client_addr_tx,
        10,
        1200,
        0,
    ));
    let mut index = SessionIndex::new();
    index.insert_restored(9, session.clone(), Vec::new());
    assert!(index.session(9).is_some());
    let packet = test_quic_long_header();
    index.observe_client_packet(9, &packet);
    index.observe_upstream_packet(9, &packet);
    let _ = client_packet_needs_index_update(&index, 9, session.as_ref(), &packet);
    let _ = upstream_packet_needs_index_update(&index, 9, session.as_ref(), &packet);
    index.update_client_address(9, updated);
    assert_eq!(
        index.find_session_for_client_packet(updated, &packet),
        Some(9)
    );
    let (touch_tx, mut touch_rx) = mpsc::channel(4);
    touch_tx
        .try_send(SessionTouch {
            seen_ms: 10,
            session_id: 9,
        })
        .expect("touch");
    drain_session_touches(&mut index, &mut touch_rx);
    assert!(index.evict_oldest().is_some());

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
    let (close_tx, _close_rx) = watch::channel(false);
    let (client_addr_tx, _client_addr_rx) = watch::channel(client);
    let session = Arc::new(PassthroughSession::new(
        socket,
        close_tx,
        client,
        client_addr_tx,
        10,
        1200,
        0,
    ));
    index.insert_restored(10, session, Vec::new());
    assert_eq!(index.evict_expired(1_000, 1).len(), 1);
    assert!(index.drain_all().is_empty());
}

#[test]
fn session_touches_are_coalesced_per_session() {
    let queued = AtomicU64::new(0);

    assert!(should_queue_touch_at(&queued, 1_000));
    assert!(!should_queue_touch_at(&queued, 1_001));
    assert!(!should_queue_touch_at(&queued, 1_999));
    assert!(should_queue_touch_at(&queued, 2_000));
}
