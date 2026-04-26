use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const MAX_CIDS_PER_SESSION: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct QuicConnectionId {
    pub(super) len: u8,
    pub(super) bytes: [u8; 20],
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
pub(super) struct ParsedQuicLongHeader {
    pub(super) dcid_len: u8,
    pub(super) scid_len: u8,
    pub(super) dcid: Option<QuicConnectionId>,
    pub(super) scid: Option<QuicConnectionId>,
}

pub(super) fn parse_quic_long_header(packet: &[u8]) -> Option<ParsedQuicLongHeader> {
    let first = *packet.first()?;
    if (first & 0x80) == 0 {
        return None;
    }
    if packet.len() < 1 + 4 + 1 {
        return None;
    }
    let mut idx = 1 + 4;
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

fn parse_quic_short_dcid(packet: &[u8], dcid_len: u8) -> Option<QuicConnectionId> {
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

pub(super) struct TransparentUdpSession {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) close_tx: watch::Sender<bool>,
    client_addr: StdMutex<SocketAddr>,
    pub(super) target_key: String,
    pub(super) matched_rule: Option<String>,
    pub(super) rate_limit_profile: Option<String>,
    last_seen_ms: AtomicU64,
    client_cid_len: AtomicU8,
    server_cid_len: AtomicU8,
    cids: StdMutex<HashSet<QuicConnectionId>>,
    relay_task: StdMutex<Option<JoinHandle<()>>>,
    pub(super) limits: AppliedRateLimits,
    pub(super) rate_limit_ctx: RateLimitContext,
    pub(super) _concurrency_permits: crate::rate_limit::ConcurrencyPermits,
}

pub(super) struct TransparentUdpSessionInit {
    pub(super) socket: Arc<UdpSocket>,
    pub(super) close_tx: watch::Sender<bool>,
    pub(super) client_addr: SocketAddr,
    pub(super) target_key: String,
    pub(super) matched_rule: Option<String>,
    pub(super) rate_limit_profile: Option<String>,
    pub(super) seen_ms: u64,
    pub(super) limits: AppliedRateLimits,
    pub(super) rate_limit_ctx: RateLimitContext,
    pub(super) concurrency_permits: crate::rate_limit::ConcurrencyPermits,
}

impl TransparentUdpSession {
    pub(super) fn new(init: TransparentUdpSessionInit) -> Self {
        let TransparentUdpSessionInit {
            socket,
            close_tx,
            client_addr,
            target_key,
            matched_rule,
            rate_limit_profile,
            seen_ms,
            limits,
            rate_limit_ctx,
            concurrency_permits,
        } = init;
        Self {
            socket,
            close_tx,
            client_addr: StdMutex::new(client_addr),
            target_key,
            matched_rule,
            rate_limit_profile,
            last_seen_ms: AtomicU64::new(seen_ms),
            client_cid_len: AtomicU8::new(0),
            server_cid_len: AtomicU8::new(0),
            cids: StdMutex::new(HashSet::new()),
            relay_task: StdMutex::new(None),
            limits,
            rate_limit_ctx,
            _concurrency_permits: concurrency_permits,
        }
    }

    pub(super) fn current_client_addr(&self) -> SocketAddr {
        *self.client_addr.lock().expect("client addr lock")
    }

    pub(super) fn update_client_addr(&self, client_addr: SocketAddr) -> Option<SocketAddr> {
        let mut guard = self.client_addr.lock().expect("client addr lock");
        if *guard == client_addr {
            return None;
        }
        let old = *guard;
        *guard = client_addr;
        Some(old)
    }

    pub(super) fn mark_client_seen(&self, seen_ms: u64) {
        self.last_seen_ms.fetch_max(seen_ms, Ordering::Relaxed);
    }

    pub(super) fn mark_upstream_seen(&self, seen_ms: u64) {
        self.last_seen_ms.fetch_max(seen_ms, Ordering::Relaxed);
    }

    pub(super) fn last_seen_ms(&self) -> u64 {
        self.last_seen_ms.load(Ordering::Relaxed)
    }

    pub(super) fn client_cid_len(&self) -> Option<u8> {
        decode_cid_len(self.client_cid_len.load(Ordering::Relaxed))
    }

    pub(super) fn server_cid_len(&self) -> Option<u8> {
        decode_cid_len(self.server_cid_len.load(Ordering::Relaxed))
    }

    fn set_client_cid_len(&self, len: u8) {
        self.client_cid_len
            .store(encode_cid_len(Some(len)), Ordering::Relaxed);
    }

    fn set_server_cid_len(&self, len: u8) {
        self.server_cid_len
            .store(encode_cid_len(Some(len)), Ordering::Relaxed);
    }

    pub(super) fn set_client_cid_len_if_some(&self, len: Option<u8>) {
        if let Some(len) = len {
            self.set_client_cid_len(len);
        }
    }

    pub(super) fn set_server_cid_len_if_some(&self, len: Option<u8>) {
        if let Some(len) = len {
            self.set_server_cid_len(len);
        }
    }

    pub(super) fn snapshot_cids(&self) -> Vec<QuicConnectionId> {
        self.cids
            .lock()
            .expect("session cids lock")
            .iter()
            .copied()
            .collect()
    }

    pub(super) fn attach_relay_task(&self, task: JoinHandle<()>) {
        *self.relay_task.lock().expect("relay task lock") = Some(task);
    }

    pub(super) fn take_relay_task(&self) -> Option<JoinHandle<()>> {
        self.relay_task.lock().expect("relay task lock").take()
    }
}

pub(super) struct SessionIndex {
    pub(super) sessions: HashMap<u64, Arc<TransparentUdpSession>>,
    pub(super) by_target: HashMap<(SocketAddr, String), u64>,
    by_cid: HashMap<QuicConnectionId, u64>,
    known_server_cid_lens: HashSet<u8>,
}

impl SessionIndex {
    pub(super) fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            by_target: HashMap::new(),
            by_cid: HashMap::new(),
            known_server_cid_lens: HashSet::new(),
        }
    }

    pub(super) fn session(&self, session_id: u64) -> Option<Arc<TransparentUdpSession>> {
        self.sessions.get(&session_id).cloned()
    }

    pub(super) fn insert(&mut self, session_id: u64, session: Arc<TransparentUdpSession>) {
        self.by_target.insert(
            (session.current_client_addr(), session.target_key.clone()),
            session_id,
        );
        self.sessions.insert(session_id, session);
    }

    pub(super) fn insert_restored(
        &mut self,
        session_id: u64,
        session: Arc<TransparentUdpSession>,
        cids: Vec<QuicConnectionId>,
    ) {
        if let Some(server_cid_len) = session.server_cid_len() {
            self.known_server_cid_lens.insert(server_cid_len);
        }
        self.by_target.insert(
            (session.current_client_addr(), session.target_key.clone()),
            session_id,
        );
        self.sessions.insert(session_id, session.clone());
        self.register_cids(session_id, cids);
    }

    pub(super) fn remove_session(&mut self, session_id: u64) -> Option<Arc<TransparentUdpSession>> {
        let session = self.sessions.remove(&session_id)?;
        self.by_target
            .remove(&(session.current_client_addr(), session.target_key.clone()));
        let cids = session
            .cids
            .lock()
            .expect("session cids lock")
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

    fn register_cids(&mut self, session_id: u64, cids: Vec<QuicConnectionId>) {
        if cids.is_empty() {
            return;
        }
        let Some(session) = self.sessions.get(&session_id) else {
            return;
        };
        let mut session_cids = session.cids.lock().expect("session cids lock");
        for cid in cids {
            if session_cids.contains(&cid) {
                continue;
            }
            if session_cids.len() >= MAX_CIDS_PER_SESSION {
                break;
            }
            if let Some(existing) = self.by_cid.get(&cid).copied() {
                if existing != session_id {
                    continue;
                }
            }
            session_cids.insert(cid);
            self.by_cid.insert(cid, session_id);
        }
    }

    pub(super) fn observe_client_packet(&mut self, session_id: u64, packet: &[u8]) {
        let Some(server_cid_len) = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.server_cid_len())
        else {
            if let Some(long) = parse_quic_long_header(packet) {
                self.register_cids(
                    session_id,
                    [long.dcid, long.scid].into_iter().flatten().collect(),
                );
                if long.scid_len > 0 {
                    if let Some(session) = self.sessions.get(&session_id) {
                        session.set_client_cid_len(long.scid_len);
                    }
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
                if let Some(session) = self.sessions.get(&session_id) {
                    session.set_client_cid_len(long.scid_len);
                }
            }
        } else if let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) {
            self.register_cids(session_id, vec![cid]);
        }
    }

    pub(super) fn observe_upstream_packet(&mut self, session_id: u64, packet: &[u8]) {
        let client_cid_len = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.client_cid_len());
        if let Some(long) = parse_quic_long_header(packet) {
            self.register_cids(
                session_id,
                [long.dcid, long.scid].into_iter().flatten().collect(),
            );
            if let Some(session) = self.sessions.get(&session_id) {
                if long.scid_len > 0 {
                    session.set_server_cid_len(long.scid_len);
                    self.known_server_cid_lens.insert(long.scid_len);
                }
                if session.client_cid_len().is_none() && long.dcid_len > 0 {
                    session.set_client_cid_len(long.dcid_len);
                }
            }
        } else if let Some(len) = client_cid_len {
            if let Some(cid) = parse_quic_short_dcid(packet, len) {
                self.register_cids(session_id, vec![cid]);
            }
        }
    }

    pub(super) fn find_session_for_client_packet(
        &self,
        client_addr: SocketAddr,
        target_key: Option<&str>,
        packet: &[u8],
    ) -> Option<u64> {
        if let Some(target_key) = target_key {
            if let Some(session_id) = self
                .by_target
                .get(&(client_addr, target_key.to_string()))
                .copied()
            {
                return Some(session_id);
            }
        }

        if let Some(long) = parse_quic_long_header(packet) {
            for cid in [long.dcid, long.scid].into_iter().flatten() {
                if let Some(id) = self.by_cid.get(&cid).copied() {
                    if self
                        .sessions
                        .get(&id)
                        .is_some_and(|session| session.current_client_addr() == client_addr)
                    {
                        return Some(id);
                    }
                }
            }
        }

        let first = *packet.first()?;
        if (first & 0x80) == 0 {
            for len in &self.known_server_cid_lens {
                if let Some(cid) = parse_quic_short_dcid(packet, *len) {
                    if let Some(id) = self.by_cid.get(&cid).copied() {
                        if self
                            .sessions
                            .get(&id)
                            .is_some_and(|session| session.current_client_addr() == client_addr)
                        {
                            return Some(id);
                        }
                    }
                }
            }
        }
        None
    }

    pub(super) fn update_client_address(&mut self, session_id: u64, client_addr: SocketAddr) {
        let Some(session) = self.sessions.get(&session_id) else {
            return;
        };
        if let Some(old_addr) = session.update_client_addr(client_addr) {
            self.by_target
                .remove(&(old_addr, session.target_key.clone()));
            self.by_target
                .insert((client_addr, session.target_key.clone()), session_id);
        }
    }

    pub(super) fn evict_expired(
        &mut self,
        now_ms: u64,
        idle_timeout_ms: u64,
    ) -> Vec<Arc<TransparentUdpSession>> {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                (now_ms.saturating_sub(session.last_seen_ms()) > idle_timeout_ms)
                    .then_some(*session_id)
            })
            .collect::<Vec<_>>();
        expired
            .into_iter()
            .filter_map(|session_id| self.remove_session(session_id))
            .collect()
    }

    pub(super) fn drain_all(&mut self) -> Vec<(u64, Arc<TransparentUdpSession>)> {
        let drained = self.sessions.drain().collect::<Vec<_>>();
        self.by_target.clear();
        self.by_cid.clear();
        self.known_server_cid_lens.clear();
        drained
    }
}

fn encode_cid_len(value: Option<u8>) -> u8 {
    value.unwrap_or(0)
}

fn decode_cid_len(value: u8) -> Option<u8> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}
