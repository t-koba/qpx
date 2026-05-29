use std::cmp::Reverse;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::mpsc;

use super::quic::{QuicConnectionId, parse_quic_long_header, parse_quic_short_dcid};
use super::session::{PassthroughSession, SessionTouch};

const MAX_CIDS_PER_SESSION: usize = 32;

const PASSTHROUGH_SESSION_INDEX_SHARDS: usize = 64;

struct SharedSessionIndexShard {
    sessions: RwLock<HashMap<u64, Arc<PassthroughSession>>>,
    by_addr: RwLock<HashMap<SocketAddr, u64>>,
    by_cid: RwLock<HashMap<QuicConnectionId, u64>>,
}

pub(in crate::reverse::h3::passthrough) struct SharedSessionIndex {
    shards: Vec<SharedSessionIndexShard>,
    known_server_cid_lens: RwLock<HashSet<u8>>,
    touches: Mutex<BinaryHeap<Reverse<SessionTouch>>>,
}

impl SharedSessionIndex {
    pub(in crate::reverse::h3::passthrough) fn new() -> Self {
        Self {
            shards: (0..PASSTHROUGH_SESSION_INDEX_SHARDS)
                .map(|_| SharedSessionIndexShard {
                    sessions: RwLock::new(HashMap::new()),
                    by_addr: RwLock::new(HashMap::new()),
                    by_cid: RwLock::new(HashMap::new()),
                })
                .collect(),
            known_server_cid_lens: RwLock::new(HashSet::new()),
            touches: Mutex::new(BinaryHeap::new()),
        }
    }

    fn session_shard(&self, session_id: u64) -> &SharedSessionIndexShard {
        &self.shards[(session_id as usize) % self.shards.len()]
    }

    fn addr_shard(&self, addr: SocketAddr) -> &SharedSessionIndexShard {
        let mut hasher = DefaultHasher::new();
        addr.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % self.shards.len()]
    }

    fn cid_shard(&self, cid: QuicConnectionId) -> &SharedSessionIndexShard {
        let mut hasher = DefaultHasher::new();
        cid.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % self.shards.len()]
    }

    pub(in crate::reverse::h3::passthrough) fn session(
        &self,
        session_id: u64,
    ) -> Option<Arc<PassthroughSession>> {
        self.session_shard(session_id)
            .sessions
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&session_id)
            .cloned()
    }

    pub(in crate::reverse::h3::passthrough) fn session_count(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                shard
                    .sessions
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len()
            })
            .sum()
    }

    pub(in crate::reverse::h3::passthrough) fn remove_session(
        &self,
        session_id: u64,
    ) -> Option<Arc<PassthroughSession>> {
        let session = self
            .session_shard(session_id)
            .sessions
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&session_id)?;
        self.addr_shard(session.current_client_addr())
            .by_addr
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&session.current_client_addr());
        let cids = session.snapshot_cids();
        for cid in cids {
            let mut by_cid = self
                .cid_shard(cid)
                .by_cid
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if by_cid.get(&cid).copied() == Some(session_id) {
                by_cid.remove(&cid);
            }
        }
        Some(session)
    }

    pub(in crate::reverse::h3::passthrough) fn record_touch(&self, session_id: u64, seen_ms: u64) {
        self.touches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Reverse(SessionTouch {
                seen_ms,
                session_id,
            }));
    }

    pub(in crate::reverse::h3::passthrough) fn insert_new(
        &self,
        session_id: u64,
        session: Arc<PassthroughSession>,
    ) {
        self.addr_shard(session.current_client_addr())
            .by_addr
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(session.current_client_addr(), session_id);
        self.session_shard(session_id)
            .sessions
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(session_id, session.clone());
        self.record_touch(session_id, session.last_seen_ms());
    }

    pub(in crate::reverse::h3::passthrough) fn insert_restored(
        &self,
        session_id: u64,
        session: Arc<PassthroughSession>,
        cids: Vec<QuicConnectionId>,
    ) {
        if let Some(server_cid_len) = session.server_cid_len() {
            self.known_server_cid_lens
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(server_cid_len);
        }
        self.insert_new(session_id, session);
        self.register_cids(session_id, cids);
    }

    pub(in crate::reverse::h3::passthrough) fn register_cids(
        &self,
        session_id: u64,
        cids: Vec<QuicConnectionId>,
    ) {
        if cids.is_empty() {
            return;
        }
        let Some(session) = self.session(session_id) else {
            return;
        };
        let mut session_cids = session
            .cids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for cid in cids {
            if session_cids.contains(&cid) {
                continue;
            }
            if session_cids.len() >= MAX_CIDS_PER_SESSION {
                break;
            }
            let mut by_cid = self
                .cid_shard(cid)
                .by_cid
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(existing) = by_cid.get(&cid).copied()
                && existing != session_id
            {
                continue;
            }
            session_cids.insert(cid);
            by_cid.insert(cid, session_id);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn observe_client_packet(
        &self,
        session_id: u64,
        packet: &[u8],
    ) {
        let Some(session) = self.session(session_id) else {
            return;
        };
        let Some(server_cid_len) = session.server_cid_len() else {
            if let Some(long) = parse_quic_long_header(packet) {
                self.register_cids(
                    session_id,
                    [long.dcid, long.scid].into_iter().flatten().collect(),
                );
                if long.scid_len > 0 {
                    session.set_client_cid_len(long.scid_len);
                }
            }
            return;
        };

        if let Some(long) = parse_quic_long_header(packet) {
            self.register_cids(
                session_id,
                [long.dcid, long.scid].into_iter().flatten().collect(),
            );
            if long.scid_len > 0 {
                session.set_client_cid_len(long.scid_len);
            }
        } else if let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) {
            self.register_cids(session_id, vec![cid]);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn observe_upstream_packet(
        &self,
        session_id: u64,
        packet: &[u8],
    ) {
        let Some(session) = self.session(session_id) else {
            return;
        };
        let client_cid_len = session.client_cid_len();
        if let Some(long) = parse_quic_long_header(packet) {
            self.register_cids(
                session_id,
                [long.dcid, long.scid].into_iter().flatten().collect(),
            );
            if long.scid_len > 0 {
                session.set_server_cid_len(long.scid_len);
                self.known_server_cid_lens
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert(long.scid_len);
            }
            if session.client_cid_len().is_none() && long.dcid_len > 0 {
                session.set_client_cid_len(long.dcid_len);
            }
        } else if let Some(len) = client_cid_len
            && let Some(cid) = parse_quic_short_dcid(packet, len)
        {
            self.register_cids(session_id, vec![cid]);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn find_session_for_client_packet(
        &self,
        client_addr: SocketAddr,
        packet: &[u8],
    ) -> Option<(u64, Arc<PassthroughSession>)> {
        if let Some(id) = self
            .addr_shard(client_addr)
            .by_addr
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&client_addr)
            .copied()
            && let Some(session) = self.session(id)
        {
            return Some((id, session));
        }

        if let Some(long) = parse_quic_long_header(packet) {
            for cid in [long.dcid, long.scid].into_iter().flatten() {
                if let Some((id, session)) = self.session_by_cid(cid)
                    && session.current_client_addr() == client_addr
                {
                    return Some((id, session));
                }
            }
        }

        let first = *packet.first()?;
        if (first & 0x80) == 0 {
            let lens = self
                .known_server_cid_lens
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .copied()
                .collect::<Vec<_>>();
            for len in lens {
                if let Some(cid) = parse_quic_short_dcid(packet, len)
                    && let Some((id, session)) = self.session_by_cid(cid)
                    && session.current_client_addr() == client_addr
                {
                    return Some((id, session));
                }
            }
        }
        None
    }

    pub(in crate::reverse::h3::passthrough) fn session_by_cid(
        &self,
        cid: QuicConnectionId,
    ) -> Option<(u64, Arc<PassthroughSession>)> {
        let id = self
            .cid_shard(cid)
            .by_cid
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&cid)
            .copied()?;
        self.session(id).map(|session| (id, session))
    }

    pub(in crate::reverse::h3::passthrough) fn update_client_address(
        &self,
        session_id: u64,
        client_addr: SocketAddr,
    ) {
        let Some(session) = self.session(session_id) else {
            return;
        };
        if let Some(old_addr) = session.update_client_addr(client_addr) {
            self.addr_shard(old_addr)
                .by_addr
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&old_addr);
            self.addr_shard(client_addr)
                .by_addr
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(client_addr, session_id);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn client_packet_needs_index_update(
        &self,
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
                .any(|cid| self.cid_owner(cid) != Some(session_id));
        }
        let Some(server_cid_len) = session.server_cid_len() else {
            return false;
        };
        let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) else {
            return false;
        };
        self.cid_owner(cid) != Some(session_id)
    }

    pub(in crate::reverse::h3::passthrough) fn upstream_packet_needs_index_update(
        &self,
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
                .any(|cid| self.cid_owner(cid) != Some(session_id));
        }
        let Some(client_cid_len) = session.client_cid_len() else {
            return false;
        };
        let Some(cid) = parse_quic_short_dcid(packet, client_cid_len) else {
            return false;
        };
        self.cid_owner(cid) != Some(session_id)
    }

    pub(in crate::reverse::h3::passthrough) fn cid_owner(
        &self,
        cid: QuicConnectionId,
    ) -> Option<u64> {
        self.cid_shard(cid)
            .by_cid
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&cid)
            .copied()
    }

    pub(in crate::reverse::h3::passthrough) fn drain_session_touches(
        &self,
        touch_rx: &mut mpsc::Receiver<SessionTouch>,
    ) {
        let mut touches = self
            .touches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Ok(touch) = touch_rx.try_recv() {
            if self.session(touch.session_id).is_some() {
                touches.push(Reverse(touch));
            }
        }
    }

    pub(in crate::reverse::h3::passthrough) fn evict_expired(
        &self,
        now_ms: u64,
        idle_timeout_ms: u64,
    ) -> Vec<Arc<PassthroughSession>> {
        let mut removed = Vec::new();
        let mut touches = self
            .touches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(Reverse(touch)) = touches.peek().copied() {
            if now_ms.saturating_sub(touch.seen_ms) <= idle_timeout_ms {
                break;
            }
            touches.pop();
            let Some(session) = self.session(touch.session_id) else {
                continue;
            };
            if session.last_seen_ms() != touch.seen_ms {
                touches.push(Reverse(SessionTouch {
                    seen_ms: session.last_seen_ms(),
                    session_id: touch.session_id,
                }));
                continue;
            }
            drop(touches);
            if let Some(session) = self.remove_session(touch.session_id) {
                removed.push(session);
            }
            touches = self
                .touches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        removed
    }

    pub(in crate::reverse::h3::passthrough) fn evict_oldest(
        &self,
    ) -> Option<Arc<PassthroughSession>> {
        let mut touches = self
            .touches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(Reverse(touch)) = touches.pop() {
            let Some(session) = self.session(touch.session_id) else {
                continue;
            };
            if session.last_seen_ms() != touch.seen_ms {
                touches.push(Reverse(SessionTouch {
                    seen_ms: session.last_seen_ms(),
                    session_id: touch.session_id,
                }));
                continue;
            }
            drop(touches);
            return self.remove_session(touch.session_id);
        }
        None
    }

    pub(in crate::reverse::h3::passthrough) fn drain_all(
        &self,
    ) -> Vec<(u64, Arc<PassthroughSession>)> {
        let mut drained = Vec::new();
        for shard in &self.shards {
            drained.extend(
                shard
                    .sessions
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .drain(),
            );
            shard
                .by_addr
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
            shard
                .by_cid
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
        }
        self.known_server_cid_lens
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.touches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        drained
    }
}
