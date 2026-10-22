use crate::rate_limit::{AppliedRateLimits, RateLimitContext};
#[cfg(test)]
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

mod index;

pub(super) use self::index::SharedSessionIndex;

const MAX_CIDS_PER_SESSION: usize = 32;

pub(super) use crate::http3::quic_packet::{
    QuicConnectionId, connection_id_len_bit, find_by_known_connection_id_len,
    observe_client_quic_packet, observe_upstream_quic_packet, parse_quic_long_header,
    parse_quic_short_dcid,
};

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
        *self
            .client_addr
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn update_client_addr(&self, client_addr: SocketAddr) -> Option<SocketAddr> {
        let mut guard = self
            .client_addr
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .copied()
            .collect()
    }

    pub(super) fn attach_relay_task(&self, task: JoinHandle<()>) {
        *self
            .relay_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(task);
    }

    pub(super) fn take_relay_task(&self) -> Option<JoinHandle<()>> {
        self.relay_task
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

#[cfg(test)]
pub(super) struct SessionIndex {
    pub(super) sessions: HashMap<u64, Arc<TransparentUdpSession>>,
    pub(super) by_target: HashMap<(SocketAddr, String), u64>,
    pub(super) by_cid: HashMap<QuicConnectionId, u64>,
    known_server_cid_lens: HashSet<u8>,
}

#[cfg(test)]
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
            .unwrap_or_else(|poisoned| poisoned.into_inner())
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

    fn register_cids<I>(&mut self, session_id: u64, cids: I)
    where
        I: IntoIterator<Item = QuicConnectionId>,
    {
        let Some(session) = self.sessions.get(&session_id) else {
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
            if let Some(existing) = self.by_cid.get(&cid).copied()
                && existing != session_id
            {
                continue;
            }
            session_cids.insert(cid);
            self.by_cid.insert(cid, session_id);
        }
    }

    pub(super) fn observe_client_packet(&mut self, session_id: u64, packet: &[u8]) {
        let server_cid_len = self
            .sessions
            .get(&session_id)
            .and_then(|session| session.server_cid_len());
        let observation = observe_client_quic_packet(packet, server_cid_len);
        self.register_cids(session_id, observation.connection_ids.into_iter().flatten());
        if let Some(len) = observation.client_cid_len
            && let Some(session) = self.sessions.get(&session_id)
        {
            session.set_client_cid_len(len);
        }
    }

    pub(super) fn observe_upstream_packet(&mut self, session_id: u64, packet: &[u8]) {
        let client_cid_len = self
            .sessions
            .get(&session_id)
            .and_then(|session| session.client_cid_len());
        let observation = observe_upstream_quic_packet(packet, client_cid_len);
        self.register_cids(session_id, observation.connection_ids.into_iter().flatten());
        if let Some(session) = self.sessions.get(&session_id) {
            if let Some(len) = observation.server_cid_len {
                session.set_server_cid_len(len);
                self.known_server_cid_lens.insert(len);
            }
            if let Some(len) = observation.client_cid_len
                && session.client_cid_len().is_none()
            {
                session.set_client_cid_len(len);
            }
        }
    }

    pub(super) fn find_session_for_client_packet(
        &self,
        client_addr: SocketAddr,
        target_key: Option<&str>,
        packet: &[u8],
    ) -> Option<u64> {
        if let Some(target_key) = target_key
            && let Some(session_id) = self
                .by_target
                .get(&(client_addr, target_key.to_string()))
                .copied()
        {
            return Some(session_id);
        }

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
    if value == 0 { None } else { Some(value) }
}
