use super::{
    MAX_CIDS_PER_SESSION, QuicConnectionId, TransparentUdpSession, parse_quic_long_header,
    parse_quic_short_dcid,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

const SESSION_INDEX_SHARDS: usize = 64;

struct SessionIndexShard {
    sessions: RwLock<HashMap<u64, Arc<TransparentUdpSession>>>,
    by_target: RwLock<HashMap<SocketAddr, HashMap<Arc<str>, u64>>>,
    by_cid: RwLock<HashMap<QuicConnectionId, u64>>,
}

pub(in crate::transparent::udp) struct SharedSessionIndex {
    shards: Vec<SessionIndexShard>,
    known_server_cid_len_bits: AtomicU32,
}

impl SharedSessionIndex {
    pub(in crate::transparent::udp) fn new() -> Self {
        Self {
            shards: (0..SESSION_INDEX_SHARDS)
                .map(|_| SessionIndexShard {
                    sessions: RwLock::new(HashMap::new()),
                    by_target: RwLock::new(HashMap::new()),
                    by_cid: RwLock::new(HashMap::new()),
                })
                .collect(),
            known_server_cid_len_bits: AtomicU32::new(0),
        }
    }

    fn session_shard(&self, session_id: u64) -> &SessionIndexShard {
        &self.shards[qpx_http::sharding::modulo_u64(session_id, self.shards.len())]
    }

    fn target_shard(&self, client_addr: SocketAddr, target_key: &str) -> &SessionIndexShard {
        &self.shards[qpx_http::sharding::modulo(&(client_addr, target_key), self.shards.len())]
    }

    fn cid_shard(&self, cid: QuicConnectionId) -> &SessionIndexShard {
        &self.shards[qpx_http::sharding::modulo(&cid, self.shards.len())]
    }

    pub(in crate::transparent::udp) fn session(
        &self,
        session_id: u64,
    ) -> Option<Arc<TransparentUdpSession>> {
        self.session_shard(session_id)
            .sessions
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&session_id)
            .cloned()
    }

    pub(in crate::transparent::udp) fn insert(
        &self,
        session_id: u64,
        session: Arc<TransparentUdpSession>,
    ) {
        self.target_shard(session.current_client_addr(), session.target_key.as_str())
            .by_target
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(session.current_client_addr())
            .or_default()
            .insert(Arc::<str>::from(session.target_key.as_str()), session_id);
        self.session_shard(session_id)
            .sessions
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(session_id, session);
    }

    pub(in crate::transparent::udp) fn insert_restored(
        &self,
        session_id: u64,
        session: Arc<TransparentUdpSession>,
        cids: Vec<QuicConnectionId>,
    ) {
        if let Some(server_cid_len) = session.server_cid_len() {
            self.record_known_server_cid_len(server_cid_len);
        }
        self.insert(session_id, session);
        self.register_cids(session_id, cids);
    }

    pub(in crate::transparent::udp) fn remove_session(
        &self,
        session_id: u64,
    ) -> Option<Arc<TransparentUdpSession>> {
        let session = self
            .session_shard(session_id)
            .sessions
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&session_id)?;
        self.target_shard(session.current_client_addr(), session.target_key.as_str())
            .by_target
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove_target(session.current_client_addr(), session.target_key.as_str());
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

    fn register_cids<I>(&self, session_id: u64, cids: I)
    where
        I: IntoIterator<Item = QuicConnectionId>,
    {
        let Some(session) = self.session(session_id) else {
            return;
        };
        let mut session_cids = session
            .cids
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    pub(in crate::transparent::udp) fn observe_client_packet(
        &self,
        session_id: u64,
        packet: &[u8],
    ) {
        let Some(session) = self.session(session_id) else {
            return;
        };
        let Some(server_cid_len) = session.server_cid_len() else {
            if let Some(long) = parse_quic_long_header(packet) {
                self.register_cids(session_id, [long.dcid, long.scid].into_iter().flatten());
                if long.scid_len > 0 {
                    session.set_client_cid_len(long.scid_len);
                }
            }
            return;
        };

        if let Some(long) = parse_quic_long_header(packet) {
            self.register_cids(session_id, [long.dcid, long.scid].into_iter().flatten());
            if long.scid_len > 0 {
                session.set_client_cid_len(long.scid_len);
            }
        } else if let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) {
            self.register_cids(session_id, std::iter::once(cid));
        }
    }

    pub(in crate::transparent::udp) fn observe_upstream_packet(
        &self,
        session_id: u64,
        packet: &[u8],
    ) {
        let Some(session) = self.session(session_id) else {
            return;
        };
        let client_cid_len = session.client_cid_len();
        if let Some(long) = parse_quic_long_header(packet) {
            self.register_cids(session_id, [long.dcid, long.scid].into_iter().flatten());
            if long.scid_len > 0 {
                session.set_server_cid_len(long.scid_len);
                self.record_known_server_cid_len(long.scid_len);
            }
            if session.client_cid_len().is_none() && long.dcid_len > 0 {
                session.set_client_cid_len(long.dcid_len);
            }
        } else if let Some(len) = client_cid_len
            && let Some(cid) = parse_quic_short_dcid(packet, len)
        {
            self.register_cids(session_id, std::iter::once(cid));
        }
    }

    pub(in crate::transparent::udp) fn find_session_for_client_packet(
        &self,
        client_addr: SocketAddr,
        target_key: Option<&str>,
        packet: &[u8],
    ) -> Option<(u64, Arc<TransparentUdpSession>)> {
        if let Some(target_key) = target_key
            && let Some(session_id) = self
                .target_shard(client_addr, target_key)
                .by_target
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&client_addr)
                .and_then(|targets| targets.get(target_key))
                .copied()
            && let Some(session) = self.session(session_id)
        {
            return Some((session_id, session));
        }

        if let Some(long) = parse_quic_long_header(packet) {
            for cid in [long.dcid, long.scid].into_iter().flatten() {
                if let Some((session_id, session)) = self.session_by_cid(cid)
                    && session.current_client_addr() == client_addr
                {
                    return Some((session_id, session));
                }
            }
        }

        let first = *packet.first()?;
        if (first & 0x80) == 0
            && let Some(found) = for_known_server_cid_len(
                self.known_server_cid_len_bits.load(Ordering::Relaxed),
                |len| {
                    if let Some(cid) = parse_quic_short_dcid(packet, len)
                        && let Some((session_id, session)) = self.session_by_cid(cid)
                        && session.current_client_addr() == client_addr
                    {
                        Some((session_id, session))
                    } else {
                        None
                    }
                },
            )
        {
            return Some(found);
        }
        None
    }

    fn session_by_cid(&self, cid: QuicConnectionId) -> Option<(u64, Arc<TransparentUdpSession>)> {
        let session_id = self
            .cid_shard(cid)
            .by_cid
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&cid)
            .copied()?;
        self.session(session_id)
            .map(|session| (session_id, session))
    }

    pub(in crate::transparent::udp) fn update_client_address(
        &self,
        session_id: u64,
        client_addr: SocketAddr,
    ) {
        let Some(session) = self.session(session_id) else {
            return;
        };
        if let Some(old_addr) = session.update_client_addr(client_addr) {
            self.target_shard(old_addr, session.target_key.as_str())
                .by_target
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove_target(old_addr, session.target_key.as_str());
            self.target_shard(client_addr, session.target_key.as_str())
                .by_target
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .entry(client_addr)
                .or_default()
                .insert(Arc::<str>::from(session.target_key.as_str()), session_id);
        }
    }

    pub(in crate::transparent::udp) fn client_packet_needs_index_update(
        &self,
        session_id: u64,
        session: &TransparentUdpSession,
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

    pub(in crate::transparent::udp) fn upstream_packet_needs_index_update(
        &self,
        session_id: u64,
        session: &TransparentUdpSession,
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

    fn cid_owner(&self, cid: QuicConnectionId) -> Option<u64> {
        self.cid_shard(cid)
            .by_cid
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&cid)
            .copied()
    }

    pub(in crate::transparent::udp) fn evict_expired(
        &self,
        now_ms: u64,
        idle_timeout_ms: u64,
    ) -> Vec<Arc<TransparentUdpSession>> {
        let mut expired = Vec::new();
        for shard in &self.shards {
            expired.extend(
                shard
                    .sessions
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .iter()
                    .filter_map(|(session_id, session)| {
                        (now_ms.saturating_sub(session.last_seen_ms()) > idle_timeout_ms)
                            .then_some(*session_id)
                    }),
            );
        }
        expired
            .into_iter()
            .filter_map(|session_id| self.remove_session(session_id))
            .collect()
    }

    pub(in crate::transparent::udp) fn drain_all(&self) -> Vec<(u64, Arc<TransparentUdpSession>)> {
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
                .by_target
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
            shard
                .by_cid
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
        }
        self.known_server_cid_len_bits.store(0, Ordering::Relaxed);
        drained
    }

    fn record_known_server_cid_len(&self, len: u8) {
        if let Some(bit) = cid_len_bit(len) {
            self.known_server_cid_len_bits
                .fetch_or(bit, Ordering::Relaxed);
        }
    }
}

trait TargetIndexExt {
    fn remove_target(&mut self, client_addr: SocketAddr, target_key: &str);
}

impl TargetIndexExt for HashMap<SocketAddr, HashMap<Arc<str>, u64>> {
    fn remove_target(&mut self, client_addr: SocketAddr, target_key: &str) {
        if let Some(targets) = self.get_mut(&client_addr) {
            targets.remove(target_key);
            if targets.is_empty() {
                self.remove(&client_addr);
            }
        }
    }
}

fn cid_len_bit(len: u8) -> Option<u32> {
    (1..=20).contains(&len).then_some(1u32 << len)
}

fn for_known_server_cid_len<T>(mut bits: u32, mut f: impl FnMut(u8) -> Option<T>) -> Option<T> {
    bits &= !1;
    while bits != 0 {
        let len = bits.trailing_zeros() as u8;
        if let Some(value) = f(len) {
            return Some(value);
        }
        bits &= bits - 1;
    }
    None
}
