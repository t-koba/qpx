use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use super::quic::{QuicConnectionId, parse_quic_long_header, parse_quic_short_dcid};
use super::session::{PassthroughSession, SessionTouch};

const MAX_CIDS_PER_SESSION: usize = 32;

pub(in crate::reverse::h3::passthrough) struct SessionIndex {
    pub(in crate::reverse::h3::passthrough) sessions: HashMap<u64, Arc<PassthroughSession>>,
    pub(in crate::reverse::h3::passthrough) by_addr: HashMap<SocketAddr, u64>,
    pub(in crate::reverse::h3::passthrough) by_cid: HashMap<QuicConnectionId, u64>,
    pub(in crate::reverse::h3::passthrough) known_server_cid_lens: HashSet<u8>,
    pub(in crate::reverse::h3::passthrough) touches: BinaryHeap<Reverse<SessionTouch>>,
}

impl SessionIndex {
    pub(in crate::reverse::h3::passthrough) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            by_addr: HashMap::new(),
            by_cid: HashMap::new(),
            known_server_cid_lens: HashSet::new(),
            touches: BinaryHeap::new(),
        }
    }

    pub(in crate::reverse::h3::passthrough) fn session(
        &self,
        session_id: u64,
    ) -> Option<Arc<PassthroughSession>> {
        self.sessions.get(&session_id).cloned()
    }

    pub(in crate::reverse::h3::passthrough) fn remove_session(
        &mut self,
        session_id: u64,
    ) -> Option<Arc<PassthroughSession>> {
        let session = self.sessions.remove(&session_id)?;
        self.by_addr.remove(&session.current_client_addr());
        let cids = session
            .cids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for cid in cids {
            if self.by_cid.get(&cid).copied() == Some(session_id) {
                self.by_cid.remove(&cid);
            }
        }
        Some(session)
    }

    pub(in crate::reverse::h3::passthrough) fn record_touch(
        &mut self,
        session_id: u64,
        seen_ms: u64,
    ) {
        self.touches.push(Reverse(SessionTouch {
            seen_ms,
            session_id,
        }));
    }

    pub(in crate::reverse::h3::passthrough) fn insert_restored(
        &mut self,
        session_id: u64,
        session: Arc<PassthroughSession>,
        cids: Vec<QuicConnectionId>,
    ) {
        if let Some(server_cid_len) = session.server_cid_len() {
            self.known_server_cid_lens.insert(server_cid_len);
        }
        self.by_addr
            .insert(session.current_client_addr(), session_id);
        self.sessions.insert(session_id, session.clone());
        self.record_touch(session_id, session.last_seen_ms());
        self.register_cids(session_id, cids);
    }

    pub(in crate::reverse::h3::passthrough) fn register_cids(
        &mut self,
        session_id: u64,
        cids: Vec<QuicConnectionId>,
    ) {
        if cids.is_empty() {
            return;
        }
        let Some(session) = self.sessions.get(&session_id) else {
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
            // Avoid allowing one session to steal CID routing from another session.
            if let Some(existing) = self.by_cid.get(&cid).copied()
                && existing != session_id
            {
                continue;
            }
            session_cids.insert(cid);
            self.by_cid.insert(cid, session_id);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn observe_client_packet(
        &mut self,
        session_id: u64,
        packet: &[u8],
    ) {
        let Some(server_cid_len) = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.server_cid_len())
        else {
            // long headers can still be parsed/registered without server CID length.
            if let Some(long) = parse_quic_long_header(packet) {
                self.register_cids(
                    session_id,
                    [long.dcid, long.scid].into_iter().flatten().collect(),
                );
                if long.scid_len > 0
                    && let Some(session) = self.sessions.get(&session_id)
                {
                    session.set_client_cid_len(long.scid_len);
                }
            }
            return;
        };

        // Prefer long header parsing, otherwise parse short header DCID using known server CID length.
        if let Some(long) = parse_quic_long_header(packet) {
            self.register_cids(
                session_id,
                [long.dcid, long.scid].into_iter().flatten().collect(),
            );
            if long.scid_len > 0
                && let Some(session) = self.sessions.get(&session_id)
            {
                session.set_client_cid_len(long.scid_len);
            }
        } else if let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) {
            self.register_cids(session_id, vec![cid]);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn observe_upstream_packet(
        &mut self,
        session_id: u64,
        packet: &[u8],
    ) {
        let client_cid_len = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.client_cid_len());
        if let Some(long) = parse_quic_long_header(packet) {
            self.register_cids(
                session_id,
                [long.dcid, long.scid].into_iter().flatten().collect(),
            );
            // For server->client long headers:
            // - SCID length is the server CID length (used as DCID by client).
            // - DCID length is the client CID length (used as DCID by server).
            if let Some(session) = self.sessions.get(&session_id) {
                if long.scid_len > 0 {
                    session.set_server_cid_len(long.scid_len);
                    self.known_server_cid_lens.insert(long.scid_len);
                }
                if session.client_cid_len().is_none() && long.dcid_len > 0 {
                    session.set_client_cid_len(long.dcid_len);
                }
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
    ) -> Option<u64> {
        if let Some(id) = self.by_addr.get(&client_addr).copied() {
            return Some(id);
        }

        // Try long-header IDs first.
        if let Some(long) = parse_quic_long_header(packet) {
            for cid in [long.dcid, long.scid].into_iter().flatten() {
                if let Some(id) = self.by_cid.get(&cid).copied()
                    && self
                        .sessions
                        .get(&id)
                        .is_some_and(|session| session.current_client_addr() == client_addr)
                {
                    return Some(id);
                }
            }
        }

        // For short headers we don't know DCID length; try known server CID lengths.
        let first = *packet.first()?;
        if (first & 0x80) == 0 {
            for len in &self.known_server_cid_lens {
                if let Some(cid) = parse_quic_short_dcid(packet, *len)
                    && let Some(id) = self.by_cid.get(&cid).copied()
                    && self
                        .sessions
                        .get(&id)
                        .is_some_and(|session| session.current_client_addr() == client_addr)
                {
                    return Some(id);
                }
            }
        }
        None
    }

    pub(in crate::reverse::h3::passthrough) fn update_client_address(
        &mut self,
        session_id: u64,
        client_addr: SocketAddr,
    ) {
        let Some(session) = self.sessions.get(&session_id) else {
            return;
        };
        if let Some(old_addr) = session.update_client_addr(client_addr) {
            self.by_addr.remove(&old_addr);
            self.by_addr.insert(client_addr, session_id);
        }
    }

    pub(in crate::reverse::h3::passthrough) fn evict_expired(
        &mut self,
        now_ms: u64,
        idle_timeout_ms: u64,
    ) -> Vec<Arc<PassthroughSession>> {
        let mut removed = Vec::new();
        while let Some(Reverse(touch)) = self.touches.peek().copied() {
            if now_ms.saturating_sub(touch.seen_ms) <= idle_timeout_ms {
                break;
            }
            self.touches.pop();
            let Some(session) = self.sessions.get(&touch.session_id) else {
                continue;
            };
            if session.last_seen_ms() != touch.seen_ms {
                self.record_touch(touch.session_id, session.last_seen_ms());
                continue;
            }
            if let Some(session) = self.remove_session(touch.session_id) {
                removed.push(session);
            }
        }
        removed
    }

    pub(in crate::reverse::h3::passthrough) fn evict_oldest(
        &mut self,
    ) -> Option<Arc<PassthroughSession>> {
        while let Some(Reverse(touch)) = self.touches.pop() {
            let Some(session) = self.sessions.get(&touch.session_id) else {
                continue;
            };
            if session.last_seen_ms() != touch.seen_ms {
                self.record_touch(touch.session_id, session.last_seen_ms());
                continue;
            }
            return self.remove_session(touch.session_id);
        }
        None
    }

    pub(in crate::reverse::h3::passthrough) fn drain_all(
        &mut self,
    ) -> Vec<(u64, Arc<PassthroughSession>)> {
        let drained = self.sessions.drain().collect::<Vec<_>>();
        self.by_addr.clear();
        self.by_cid.clear();
        self.known_server_cid_lens.clear();
        while self.touches.pop().is_some() {}
        drained
    }
}
