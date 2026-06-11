use super::ROUTE_STATE_SHARDS;
use super::parse::{QuicConnectionId, parse_quic_long_header, parse_quic_short_dcid};
use super::state::RouteState;
use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub(crate) struct SharedRouteState {
    shards: Vec<RwLock<RouteState>>,
    addr_snapshots: Vec<ArcSwap<HashSet<SocketAddr>>>,
    cid_snapshots: Vec<ArcSwap<HashSet<QuicConnectionId>>>,
    known_server_cid_len_bits: AtomicU32,
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
            self.addr_snapshots[idx].store(Arc::new(HashSet::new()));
            self.cid_snapshots[idx].store(Arc::new(HashSet::new()));
        }
        self.known_server_cid_len_bits.store(0, Ordering::Relaxed);
    }

    pub(crate) fn observe_inbound(&self, addr: SocketAddr, packet: &[u8]) {
        let now = Instant::now();
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
        let now = Instant::now();
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
        if !self.addr_known(addr) {
            return true;
        }
        if let Some(long) = parse_quic_long_header(packet) {
            if long.dcid_len > 0 && !self.server_cid_len_known(long.dcid_len) {
                return true;
            }
            return long.dcid.is_some_and(|cid| !self.cid_known(cid));
        }
        self.any_server_cid_len(|len| {
            parse_quic_short_dcid(packet, len).is_some_and(|cid| !self.cid_known(cid))
        })
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
            .contains(&addr)
    }

    fn cid_known(&self, cid: QuicConnectionId) -> bool {
        self.cid_snapshots[self.cid_shard_idx(cid)]
            .load()
            .contains(&cid)
    }

    fn record_server_cid_len(&self, len: u8) {
        if let Some(bit) = cid_len_bit(len) {
            self.known_server_cid_len_bits
                .fetch_or(bit, Ordering::Relaxed);
        }
    }

    fn server_cid_len_known(&self, len: u8) -> bool {
        cid_len_bit(len)
            .is_some_and(|bit| self.known_server_cid_len_bits.load(Ordering::Relaxed) & bit != 0)
    }

    fn for_each_server_cid_len(&self, mut f: impl FnMut(u8)) {
        for_server_cid_len_bit(
            self.known_server_cid_len_bits.load(Ordering::Relaxed),
            |len| {
                f(len);
                false
            },
        );
    }

    fn any_server_cid_len(&self, f: impl FnMut(u8) -> bool) -> bool {
        for_server_cid_len_bit(self.known_server_cid_len_bits.load(Ordering::Relaxed), f)
    }

    fn addr_shard_idx(&self, addr: SocketAddr) -> usize {
        qpx_http::sharding::modulo(&addr, self.shards.len())
    }

    fn cid_shard_idx(&self, cid: QuicConnectionId) -> usize {
        qpx_http::sharding::modulo(&cid, self.shards.len())
    }

    fn refresh_shard_snapshots(&self, idx: usize, shard: &RouteState) {
        self.addr_snapshots[idx].store(Arc::new(shard.addrs.keys().copied().collect()));
        self.cid_snapshots[idx].store(Arc::new(shard.cids.keys().copied().collect()));
    }
}

fn cid_len_bit(len: u8) -> Option<u32> {
    (1..=20).contains(&len).then_some(1u32 << len)
}

fn for_server_cid_len_bit(mut bits: u32, mut f: impl FnMut(u8) -> bool) -> bool {
    bits &= !1;
    while bits != 0 {
        let len = bits.trailing_zeros() as u8;
        if f(len) {
            return true;
        }
        bits &= bits - 1;
    }
    false
}
