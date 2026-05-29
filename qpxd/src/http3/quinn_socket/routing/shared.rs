use super::parse::{QuicConnectionId, parse_quic_long_header, parse_quic_short_dcid};
use super::state::{RouteState, shard_index};
use super::{ROUTE_STATE_SHARDS, ROUTE_STATE_TTL};
use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub(crate) struct SharedRouteState {
    shards: Vec<RwLock<RouteState>>,
    addr_snapshots: Vec<ArcSwap<HashSet<SocketAddr>>>,
    cid_snapshots: Vec<ArcSwap<HashSet<QuicConnectionId>>>,
    known_server_cid_lens: RwLock<HashMap<u8, Instant>>,
}

impl Default for SharedRouteState {
    fn default() -> Self {
        Self {
            shards: (0..ROUTE_STATE_SHARDS)
                .map(|_| RwLock::new(RouteState::default()))
                .collect(),
            addr_snapshots: (0..ROUTE_STATE_SHARDS)
                .map(|_| ArcSwap::from_pointee(HashSet::new()))
                .collect(),
            cid_snapshots: (0..ROUTE_STATE_SHARDS)
                .map(|_| ArcSwap::from_pointee(HashSet::new()))
                .collect(),
            known_server_cid_lens: RwLock::new(HashMap::new()),
        }
    }
}

impl SharedRouteState {
    pub(crate) fn reset(&self) {
        for (idx, shard) in self.shards.iter().enumerate() {
            *shard
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = RouteState::default();
            self.addr_snapshots[idx].store(Arc::new(HashSet::new()));
            self.cid_snapshots[idx].store(Arc::new(HashSet::new()));
        }
        self.known_server_cid_lens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    pub(crate) fn observe_inbound(&self, addr: SocketAddr, packet: &[u8]) {
        let now = Instant::now();
        self.insert_addr(addr, now);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.dcid {
                self.insert_cid(cid, now);
            }
            if long.dcid_len > 0 {
                self.record_server_cid_len(long.dcid_len, now);
            }
            return;
        }
        for len in self.server_cid_lens(now) {
            if let Some(cid) = parse_quic_short_dcid(packet, len) {
                self.insert_cid(cid, now);
            }
        }
    }

    pub(crate) fn observe_outbound(&self, addr: SocketAddr, packet: &[u8]) {
        let now = Instant::now();
        self.insert_addr(addr, now);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.scid {
                self.insert_cid(cid, now);
            }
            if long.scid_len > 0 {
                self.record_server_cid_len(long.scid_len, now);
            }
        }
    }

    pub(crate) fn inbound_update_needed(&self, addr: SocketAddr, packet: &[u8]) -> bool {
        if !self.addr_known(addr) {
            return true;
        }
        if let Some(long) = parse_quic_long_header(packet) {
            if long.dcid_len > 0 && !self.server_cid_len_known(long.dcid_len) {
                return true;
            }
            return long.dcid.is_some_and(|cid| !self.cid_known(cid));
        }
        self.server_cid_lens(Instant::now())
            .into_iter()
            .any(|len| parse_quic_short_dcid(packet, len).is_some_and(|cid| !self.cid_known(cid)))
    }

    pub(crate) fn outbound_update_needed(&self, addr: SocketAddr, packet: &[u8]) -> bool {
        if !self.addr_known(addr) {
            return true;
        }
        if let Some(long) = parse_quic_long_header(packet) {
            if long.scid_len > 0 && !self.server_cid_len_known(long.scid_len) {
                return true;
            }
            return long.scid.is_some_and(|cid| !self.cid_known(cid));
        }
        false
    }

    pub(crate) fn matches_addr_or_cid(&self, addr: SocketAddr, packet: &[u8]) -> bool {
        self.addr_known(addr) || self.matches_cid(packet)
    }

    fn matches_cid(&self, packet: &[u8]) -> bool {
        if let Some(long) = parse_quic_long_header(packet) {
            return long
                .dcid
                .into_iter()
                .chain(long.scid)
                .any(|cid| self.cid_known(cid));
        }
        self.server_cid_lens(Instant::now())
            .into_iter()
            .any(|len| parse_quic_short_dcid(packet, len).is_some_and(|cid| self.cid_known(cid)))
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
            .contains(&addr)
    }

    fn cid_known(&self, cid: QuicConnectionId) -> bool {
        self.cid_snapshots[self.cid_shard_idx(cid)]
            .load()
            .contains(&cid)
    }

    fn record_server_cid_len(&self, len: u8, now: Instant) {
        self.known_server_cid_lens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(len, now);
    }

    fn server_cid_len_known(&self, len: u8) -> bool {
        self.known_server_cid_lens
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&len)
    }

    fn server_cid_lens(&self, now: Instant) -> Vec<u8> {
        let mut lens = self
            .known_server_cid_lens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        lens.retain(|_, seen| now.duration_since(*seen) <= ROUTE_STATE_TTL);
        lens.keys().copied().collect()
    }

    fn addr_shard_idx(&self, addr: SocketAddr) -> usize {
        shard_index(&addr, self.shards.len())
    }

    fn cid_shard_idx(&self, cid: QuicConnectionId) -> usize {
        shard_index(&cid, self.shards.len())
    }

    fn refresh_shard_snapshots(&self, idx: usize, shard: &RouteState) {
        self.addr_snapshots[idx].store(Arc::new(shard.addrs.keys().copied().collect()));
        self.cid_snapshots[idx].store(Arc::new(shard.cids.keys().copied().collect()));
    }
}
