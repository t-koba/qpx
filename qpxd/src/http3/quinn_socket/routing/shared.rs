use super::state::RouteState;
use super::{ROUTE_STATE_REFRESH_INTERVAL, ROUTE_STATE_SHARDS};
use crate::http3::quic_packet::{
    QuicConnectionId, connection_id_len_bit, for_each_known_connection_id_len,
    parse_quic_long_header, parse_quic_short_dcid,
};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub(crate) struct SharedRouteState {
    shards: Vec<RwLock<RouteState>>,
    addr_snapshots: Vec<ArcSwap<HashMap<SocketAddr, u64>>>,
    cid_snapshots: Vec<ArcSwap<HashMap<QuicConnectionId, u64>>>,
    clock_origin: Instant,
    known_server_cid_len_bits: AtomicU32,
}

impl Default for SharedRouteState {
    fn default() -> Self {
        Self {
            clock_origin: Instant::now(),
            shards: (0..ROUTE_STATE_SHARDS)
                .map(|_| RwLock::new(RouteState::default()))
                .collect(),
            addr_snapshots: (0..ROUTE_STATE_SHARDS)
                .map(|_| ArcSwap::from_pointee(HashMap::new()))
                .collect(),
            cid_snapshots: (0..ROUTE_STATE_SHARDS)
                .map(|_| ArcSwap::from_pointee(HashMap::new()))
                .collect(),
            known_server_cid_len_bits: AtomicU32::new(0),
        }
    }
}

impl SharedRouteState {
    pub(crate) fn reset(&self) {
        for (idx, shard) in self.shards.iter().enumerate() {
            *shard
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = RouteState::default();
            self.addr_snapshots[idx].store(Arc::new(HashMap::new()));
            self.cid_snapshots[idx].store(Arc::new(HashMap::new()));
        }
        self.known_server_cid_len_bits.store(0, Ordering::Relaxed);
    }

    pub(crate) fn observe_inbound(&self, addr: SocketAddr, packet: &[u8]) {
        self.observe_inbound_at(addr, packet, Instant::now());
    }

    fn observe_inbound_at(&self, addr: SocketAddr, packet: &[u8], now: Instant) {
        self.insert_addr(addr, now);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.dcid {
                self.insert_cid(cid, now);
            }
            if long.dcid_len > 0 {
                self.record_server_cid_len(long.dcid_len);
            }
            return;
        }
        self.for_each_server_cid_len(|len| {
            if let Some(cid) = parse_quic_short_dcid(packet, len) {
                self.insert_cid(cid, now);
            }
        });
    }

    pub(crate) fn observe_outbound(&self, addr: SocketAddr, packet: &[u8]) {
        self.observe_outbound_at(addr, packet, Instant::now());
    }

    fn observe_outbound_at(&self, addr: SocketAddr, packet: &[u8], now: Instant) {
        self.insert_addr(addr, now);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.scid {
                self.insert_cid(cid, now);
            }
            if long.scid_len > 0 {
                self.record_server_cid_len(long.scid_len);
            }
        }
    }

    pub(crate) fn inbound_update_needed(&self, addr: SocketAddr, packet: &[u8]) -> bool {
        self.inbound_update_needed_at(addr, packet, Instant::now())
    }

    fn inbound_update_needed_at(&self, addr: SocketAddr, packet: &[u8], now: Instant) -> bool {
        let now_secs = self.seconds_since_origin(now);
        if self.addr_update_needed(addr, now_secs) {
            return true;
        }
        if let Some(long) = parse_quic_long_header(packet) {
            if long.dcid_len > 0 && !self.server_cid_len_known(long.dcid_len) {
                return true;
            }
            return long
                .dcid
                .is_some_and(|cid| self.cid_update_needed(cid, now_secs));
        }
        self.any_server_cid_len(|len| {
            parse_quic_short_dcid(packet, len)
                .is_some_and(|cid| self.cid_update_needed(cid, now_secs))
        })
    }

    pub(crate) fn outbound_update_needed(&self, addr: SocketAddr, packet: &[u8]) -> bool {
        self.outbound_update_needed_at(addr, packet, Instant::now())
    }

    fn outbound_update_needed_at(&self, addr: SocketAddr, packet: &[u8], now: Instant) -> bool {
        let now_secs = self.seconds_since_origin(now);
        if self.addr_update_needed(addr, now_secs) {
            return true;
        }
        if let Some(long) = parse_quic_long_header(packet) {
            if long.scid_len > 0 && !self.server_cid_len_known(long.scid_len) {
                return true;
            }
            return long
                .scid
                .is_some_and(|cid| self.cid_update_needed(cid, now_secs));
        }
        false
    }

    pub(crate) fn matches_addr(&self, addr: SocketAddr) -> bool {
        self.addr_known(addr)
    }

    pub(crate) fn matches_cid(&self, packet: &[u8]) -> bool {
        if let Some(long) = parse_quic_long_header(packet) {
            return long
                .dcid
                .into_iter()
                .chain(long.scid)
                .any(|cid| self.cid_known(cid));
        }
        self.any_server_cid_len(|len| {
            parse_quic_short_dcid(packet, len).is_some_and(|cid| self.cid_known(cid))
        })
    }

    fn insert_addr(&self, addr: SocketAddr, now: Instant) {
        let idx = self.addr_shard_idx(addr);
        let mut shard = self.shards[idx]
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        shard.prune(now);
        shard.insert_addr(addr, now);
        self.refresh_shard_snapshots(idx, &shard);
    }

    fn insert_cid(&self, cid: QuicConnectionId, now: Instant) {
        let idx = self.cid_shard_idx(cid);
        let mut shard = self.shards[idx]
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        shard.prune(now);
        shard.insert_cid(cid, now);
        self.refresh_shard_snapshots(idx, &shard);
    }

    fn addr_known(&self, addr: SocketAddr) -> bool {
        self.addr_snapshots[self.addr_shard_idx(addr)]
            .load()
            .contains_key(&addr)
    }

    fn cid_known(&self, cid: QuicConnectionId) -> bool {
        self.cid_snapshots[self.cid_shard_idx(cid)]
            .load()
            .contains_key(&cid)
    }

    fn seconds_since_origin(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.clock_origin).as_secs()
    }

    fn addr_update_needed(&self, addr: SocketAddr, now_secs: u64) -> bool {
        self.addr_snapshots[self.addr_shard_idx(addr)]
            .load()
            .get(&addr)
            .is_none_or(|seen_secs| {
                now_secs.saturating_sub(*seen_secs) >= ROUTE_STATE_REFRESH_INTERVAL.as_secs()
            })
    }

    fn cid_update_needed(&self, cid: QuicConnectionId, now_secs: u64) -> bool {
        self.cid_snapshots[self.cid_shard_idx(cid)]
            .load()
            .get(&cid)
            .is_none_or(|seen_secs| {
                now_secs.saturating_sub(*seen_secs) >= ROUTE_STATE_REFRESH_INTERVAL.as_secs()
            })
    }

    fn record_server_cid_len(&self, len: u8) {
        if let Some(bit) = connection_id_len_bit(len) {
            self.known_server_cid_len_bits
                .fetch_or(bit, Ordering::Relaxed);
        }
    }

    fn server_cid_len_known(&self, len: u8) -> bool {
        connection_id_len_bit(len)
            .is_some_and(|bit| self.known_server_cid_len_bits.load(Ordering::Relaxed) & bit != 0)
    }

    fn for_each_server_cid_len(&self, mut f: impl FnMut(u8)) {
        for_each_known_connection_id_len(
            self.known_server_cid_len_bits.load(Ordering::Relaxed),
            |len| {
                f(len);
                false
            },
        );
    }

    fn any_server_cid_len(&self, f: impl FnMut(u8) -> bool) -> bool {
        for_each_known_connection_id_len(self.known_server_cid_len_bits.load(Ordering::Relaxed), f)
    }

    fn addr_shard_idx(&self, addr: SocketAddr) -> usize {
        qpx_http::sharding::modulo(&addr, self.shards.len())
    }

    fn cid_shard_idx(&self, cid: QuicConnectionId) -> usize {
        qpx_http::sharding::modulo(&cid, self.shards.len())
    }

    fn refresh_shard_snapshots(&self, idx: usize, shard: &RouteState) {
        self.addr_snapshots[idx].store(Arc::new(
            shard
                .addrs
                .iter()
                .map(|(key, entry)| {
                    (
                        *key,
                        entry
                            .seen
                            .saturating_duration_since(self.clock_origin)
                            .as_secs(),
                    )
                })
                .collect(),
        ));
        self.cid_snapshots[idx].store(Arc::new(
            shard
                .cids
                .iter()
                .map(|(key, entry)| {
                    (
                        *key,
                        entry
                            .seen
                            .saturating_duration_since(self.clock_origin)
                            .as_secs(),
                    )
                })
                .collect(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http3::quinn_socket::routing::ROUTE_STATE_TTL;
    use std::time::Duration;

    #[derive(Clone, Copy)]
    enum Traffic {
        InboundLong,
        InboundShort,
        OutboundLong,
    }

    fn long_packet(value: u64) -> Vec<u8> {
        let cid = value.to_be_bytes();
        let mut packet = vec![0xc0, 0, 0, 0, 1, cid.len() as u8];
        packet.extend_from_slice(&cid);
        packet.push(cid.len() as u8);
        packet.extend_from_slice(&cid);
        packet
    }

    fn cid(value: u64) -> QuicConnectionId {
        parse_quic_long_header(&long_packet(value))
            .unwrap()
            .dcid
            .unwrap()
    }

    fn packet(traffic: Traffic, value: u64) -> Vec<u8> {
        if matches!(traffic, Traffic::InboundShort) {
            let mut packet = vec![0x40];
            packet.extend_from_slice(&value.to_be_bytes());
            packet
        } else {
            long_packet(value)
        }
    }

    fn update_needed(
        state: &SharedRouteState,
        traffic: Traffic,
        addr: SocketAddr,
        packet: &[u8],
        now: Instant,
    ) -> bool {
        match traffic {
            Traffic::InboundLong | Traffic::InboundShort => {
                state.inbound_update_needed_at(addr, packet, now)
            }
            Traffic::OutboundLong => state.outbound_update_needed_at(addr, packet, now),
        }
    }

    fn observe(
        state: &SharedRouteState,
        traffic: Traffic,
        addr: SocketAddr,
        packet: &[u8],
        now: Instant,
    ) {
        match traffic {
            Traffic::InboundLong | Traffic::InboundShort => {
                state.observe_inbound_at(addr, packet, now);
            }
            Traffic::OutboundLong => state.observe_outbound_at(addr, packet, now),
        }
    }

    fn assert_active_routes_survive_pruning(traffic: Traffic) {
        let state = SharedRouteState::default();
        let start = state.clock_origin;
        let active_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        // Deterministically force unrelated inserts to prune both active shards.
        let peers: Vec<_> = (4434..=65535)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .filter(|addr| state.addr_shard_idx(*addr) == state.addr_shard_idx(active_addr))
            .take(2)
            .collect();
        let cids: Vec<_> = (2..10000)
            .filter(|value| state.cid_shard_idx(cid(*value)) == state.cid_shard_idx(cid(1)))
            .take(2)
            .collect();
        assert_eq!(peers.len(), 2);
        assert_eq!(cids.len(), 2);
        // Seed long headers so the short-header path knows the server CID length.
        for (addr, value) in [(active_addr, 1), (peers[0], cids[0])] {
            let packet = long_packet(value);
            assert!(state.inbound_update_needed_at(addr, &packet, start));
            state.observe_inbound_at(addr, &packet, start);
        }
        let active_packet = packet(traffic, 1);
        assert!(!update_needed(
            &state,
            traffic,
            active_addr,
            &active_packet,
            start
        ));
        for tick in 1..=3 {
            let now = start + ROUTE_STATE_REFRESH_INTERVAL * tick;
            assert!(!update_needed(
                &state,
                traffic,
                active_addr,
                &active_packet,
                now - Duration::from_nanos(1),
            ));
            assert!(update_needed(
                &state,
                traffic,
                active_addr,
                &active_packet,
                now
            ));
            observe(&state, traffic, active_addr, &active_packet, now);
            assert!(!update_needed(
                &state,
                traffic,
                active_addr,
                &active_packet,
                now
            ));
        }
        let last_refresh = start + ROUTE_STATE_REFRESH_INTERVAL * 3;
        let churn = long_packet(cids[1]);
        let now = last_refresh + Duration::from_secs(1);
        assert!(now.duration_since(start) > ROUTE_STATE_TTL);
        assert!(state.inbound_update_needed_at(peers[1], &churn, now));
        state.observe_inbound_at(peers[1], &churn, now);
        assert!(state.matches_addr(active_addr));
        assert!(state.matches_cid(&active_packet));
        assert!(!state.matches_addr(peers[0]));
        assert!(!state.matches_cid(&long_packet(cids[0])));
        let migrated_addr: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        assert!(!state.matches_addr(migrated_addr));
        assert!(
            state.matches_cid(&active_packet),
            "CID affinity survives tuple migration"
        );

        // Once traffic stops, a later same-shard insertion still expires the route.
        let expired = last_refresh + ROUTE_STATE_TTL + Duration::from_secs(1);
        assert!(state.inbound_update_needed_at(peers[1], &churn, expired));
        state.observe_inbound_at(peers[1], &churn, expired);
        assert!(!state.matches_addr(active_addr));
        assert!(!state.matches_cid(&active_packet));
    }

    #[test]
    fn inbound_long_active_routes_survive_same_shard_pruning() {
        assert_active_routes_survive_pruning(Traffic::InboundLong);
    }

    #[test]
    fn inbound_short_active_routes_survive_same_shard_pruning() {
        assert_active_routes_survive_pruning(Traffic::InboundShort);
    }

    #[test]
    fn outbound_long_active_routes_survive_same_shard_pruning() {
        assert_active_routes_survive_pruning(Traffic::OutboundLong);
    }

    #[test]
    fn stale_cid_requests_refresh_even_when_address_is_fresh() {
        for traffic in [
            Traffic::InboundLong,
            Traffic::InboundShort,
            Traffic::OutboundLong,
        ] {
            let state = SharedRouteState::default();
            let start = state.clock_origin;
            let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
            state.observe_inbound_at(addr, &long_packet(1), start);
            let now = start + ROUTE_STATE_REFRESH_INTERVAL;
            state.insert_addr(addr, now);
            assert!(!state.addr_update_needed(addr, state.seconds_since_origin(now)));
            let packet = packet(traffic, 1);
            assert!(update_needed(&state, traffic, addr, &packet, now));
            observe(&state, traffic, addr, &packet, now);
            assert!(!update_needed(&state, traffic, addr, &packet, now));
        }
    }

    #[test]
    fn stale_address_requests_refresh_without_a_cid() {
        for traffic in [Traffic::InboundLong, Traffic::OutboundLong] {
            let state = SharedRouteState::default();
            let start = state.clock_origin;
            let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
            assert!(update_needed(&state, traffic, addr, &[], start));
            observe(&state, traffic, addr, &[], start);
            assert!(!update_needed(&state, traffic, addr, &[], start));
            let now = start + ROUTE_STATE_REFRESH_INTERVAL;
            assert!(update_needed(&state, traffic, addr, &[], now));
            observe(&state, traffic, addr, &[], now);
            assert!(!update_needed(&state, traffic, addr, &[], now));
        }
    }
}
