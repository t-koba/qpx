use super::parse::QuicConnectionId;
#[cfg(test)]
use super::parse::{parse_quic_long_header, parse_quic_short_dcid};
use super::{
    ROUTE_STATE_MAX_ADDRS, ROUTE_STATE_MAX_CIDS, ROUTE_STATE_QUEUE_COMPACTION_FACTOR,
    ROUTE_STATE_TTL,
};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct RouteState {
    pub(crate) addrs: HashMap<SocketAddr, RouteEntry>,
    addr_queue: VecDeque<(SocketAddr, u64)>,
    pub(super) cids: HashMap<QuicConnectionId, RouteEntry>,
    cid_queue: VecDeque<(QuicConnectionId, u64)>,
    known_server_cid_lens: HashMap<u8, Instant>,
    next_generation: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct RouteEntry {
    seen: Instant,
    generation: u64,
}

impl RouteState {
    #[cfg(test)]
    pub(crate) fn observe_inbound(&mut self, addr: SocketAddr, packet: &[u8]) {
        let now = Instant::now();
        self.prune(now);
        self.insert_addr(addr, now);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.dcid {
                self.insert_cid(cid, now);
            }
            if long.dcid_len > 0 {
                self.known_server_cid_lens.insert(long.dcid_len, now);
            }
            return;
        }
        for len in self
            .known_server_cid_lens
            .keys()
            .copied()
            .collect::<Vec<_>>()
        {
            if let Some(cid) = parse_quic_short_dcid(packet, len) {
                self.insert_cid(cid, now);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn observe_outbound(&mut self, addr: SocketAddr, packet: &[u8]) {
        let now = Instant::now();
        self.prune(now);
        self.insert_addr(addr, now);
        if let Some(long) = parse_quic_long_header(packet) {
            if let Some(cid) = long.scid {
                self.insert_cid(cid, now);
            }
            if long.scid_len > 0 {
                self.known_server_cid_lens.insert(long.scid_len, now);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn matches_cid(&self, packet: &[u8]) -> bool {
        if let Some(long) = parse_quic_long_header(packet) {
            return long
                .dcid
                .into_iter()
                .chain(long.scid)
                .any(|cid| self.cids.contains_key(&cid));
        }
        for len in self.known_server_cid_lens.keys() {
            if let Some(cid) = parse_quic_short_dcid(packet, *len)
                && self.cids.contains_key(&cid)
            {
                return true;
            }
        }
        false
    }

    #[cfg(test)]
    pub(crate) fn cid_count(&self) -> usize {
        self.cids.len()
    }

    #[cfg(test)]
    pub(crate) fn queue_lengths(&self) -> (usize, usize) {
        (self.addr_queue.len(), self.cid_queue.len())
    }

    pub(super) fn insert_addr(&mut self, addr: SocketAddr, now: Instant) {
        insert_bounded(
            &mut self.addrs,
            &mut self.addr_queue,
            &mut self.next_generation,
            addr,
            now,
            ROUTE_STATE_MAX_ADDRS,
        );
    }

    pub(super) fn insert_cid(&mut self, cid: QuicConnectionId, now: Instant) {
        insert_bounded(
            &mut self.cids,
            &mut self.cid_queue,
            &mut self.next_generation,
            cid,
            now,
            ROUTE_STATE_MAX_CIDS,
        );
    }

    pub(super) fn prune(&mut self, now: Instant) {
        prune_expired(&mut self.addrs, &mut self.addr_queue, now, ROUTE_STATE_TTL);
        prune_expired(&mut self.cids, &mut self.cid_queue, now, ROUTE_STATE_TTL);
        self.known_server_cid_lens
            .retain(|_, seen| now.duration_since(*seen) <= ROUTE_STATE_TTL);
    }
}

fn insert_bounded<K>(
    entries: &mut HashMap<K, RouteEntry>,
    queue: &mut VecDeque<(K, u64)>,
    next_generation: &mut u64,
    key: K,
    now: Instant,
    max_entries: usize,
) where
    K: Copy + Eq + std::hash::Hash,
{
    if let Some(entry) = entries.get_mut(&key) {
        let generation = *next_generation;
        *next_generation = next_generation.wrapping_add(1);
        entry.seen = now;
        entry.generation = generation;
        queue.push_back((key, generation));
        compact_queue_if_needed(entries, queue, max_entries);
        return;
    }
    evict_to_capacity(entries, queue, max_entries.saturating_sub(1));
    let generation = *next_generation;
    *next_generation = next_generation.wrapping_add(1);
    entries.insert(
        key,
        RouteEntry {
            seen: now,
            generation,
        },
    );
    queue.push_back((key, generation));
    compact_queue_if_needed(entries, queue, max_entries);
}

fn prune_expired<K>(
    entries: &mut HashMap<K, RouteEntry>,
    queue: &mut VecDeque<(K, u64)>,
    now: Instant,
    ttl: Duration,
) where
    K: Copy + Eq + std::hash::Hash,
{
    while let Some((key, generation)) = queue.front() {
        let should_pop = match entries.get(key) {
            Some(entry)
                if entry.generation == *generation && now.duration_since(entry.seen) > ttl =>
            {
                entries.remove(key);
                true
            }
            Some(entry) if entry.generation == *generation => false,
            _ => true,
        };
        if !should_pop {
            break;
        }
        queue.pop_front();
    }
}

fn evict_to_capacity<K>(
    entries: &mut HashMap<K, RouteEntry>,
    queue: &mut VecDeque<(K, u64)>,
    target_len: usize,
) where
    K: Copy + Eq + std::hash::Hash,
{
    while entries.len() > target_len {
        let Some((key, generation)) = queue.pop_front() else {
            break;
        };
        if entries
            .get(&key)
            .is_some_and(|entry| entry.generation == generation)
        {
            entries.remove(&key);
        }
    }
}

fn compact_queue_if_needed<K>(
    entries: &HashMap<K, RouteEntry>,
    queue: &mut VecDeque<(K, u64)>,
    max_entries: usize,
) where
    K: Copy + Eq + std::hash::Hash,
{
    if queue.len() <= max_entries.saturating_mul(ROUTE_STATE_QUEUE_COMPACTION_FACTOR) {
        return;
    }
    queue.retain(|(key, generation)| {
        entries
            .get(key)
            .is_some_and(|entry| entry.generation == *generation)
    });
}

pub(super) fn shard_index<T: std::hash::Hash>(value: &T, shard_count: usize) -> usize {
    use std::hash::Hasher;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count.max(1)
}
