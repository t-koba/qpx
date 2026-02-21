use anyhow::{anyhow, Result};
use qpx_core::config::ReverseHttp3Config;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
use tokio::time::{Duration, Instant, MissedTickBehavior};

const MAX_CIDS_PER_SESSION: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct QuicConnectionId {
    len: u8,
    bytes: [u8; 20],
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
struct ParsedQuicLongHeader {
    dcid_len: u8,
    scid_len: u8,
    dcid: Option<QuicConnectionId>,
    scid: Option<QuicConnectionId>,
}

fn parse_quic_long_header(packet: &[u8]) -> Option<ParsedQuicLongHeader> {
    let first = *packet.first()?;
    if (first & 0x80) == 0 {
        return None;
    }
    // long header: [type(1)] [version(4)] [dcid_len(1)] [dcid] [scid_len(1)] [scid] ...
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

struct PassthroughSession {
    socket: Arc<UdpSocket>,
    last_seen: Instant,
    close_tx: watch::Sender<bool>,
    client_addr: SocketAddr,
    client_addr_tx: watch::Sender<SocketAddr>,
    bytes_in: u64,
    bytes_out: u64,
    client_cid_len: Option<u8>,
    server_cid_len: Option<u8>,
    cids: HashSet<QuicConnectionId>,
}

struct SessionIndex {
    sessions: HashMap<u64, PassthroughSession>,
    by_addr: HashMap<SocketAddr, u64>,
    by_cid: HashMap<QuicConnectionId, u64>,
    known_server_cid_lens: HashSet<u8>,
}

impl SessionIndex {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            by_addr: HashMap::new(),
            by_cid: HashMap::new(),
            known_server_cid_lens: HashSet::new(),
        }
    }

    fn remove_session(&mut self, session_id: u64) {
        let Some(session) = self.sessions.remove(&session_id) else {
            return;
        };
        self.by_addr.remove(&session.client_addr);
        for cid in session.cids {
            if self.by_cid.get(&cid).copied() == Some(session_id) {
                self.by_cid.remove(&cid);
            }
        }
    }

    fn register_cids(&mut self, session_id: u64, cids: Vec<QuicConnectionId>) {
        if cids.is_empty() {
            return;
        }
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return;
        };
        for cid in cids {
            if session.cids.contains(&cid) {
                continue;
            }
            if session.cids.len() >= MAX_CIDS_PER_SESSION {
                break;
            }
            // Avoid allowing one session to steal CID routing from another session.
            if let Some(existing) = self.by_cid.get(&cid).copied() {
                if existing != session_id {
                    continue;
                }
            }
            session.cids.insert(cid);
            self.by_cid.insert(cid, session_id);
        }
    }

    fn observe_client_packet(&mut self, session_id: u64, packet: &[u8]) {
        let Some(server_cid_len) = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.server_cid_len)
        else {
            // long headers can still be parsed/registered without server CID length.
            if let Some(long) = parse_quic_long_header(packet) {
                self.register_cids(
                    session_id,
                    [long.dcid, long.scid].into_iter().flatten().collect(),
                );
                if long.scid_len > 0 {
                    if let Some(session) = self.sessions.get_mut(&session_id) {
                        session.client_cid_len = Some(long.scid_len);
                    }
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
            if long.scid_len > 0 {
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    session.client_cid_len = Some(long.scid_len);
                }
            }
        } else if let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) {
            self.register_cids(session_id, vec![cid]);
        }
    }

    fn observe_upstream_packet(&mut self, session_id: u64, packet: &[u8]) {
        let client_cid_len = self
            .sessions
            .get(&session_id)
            .and_then(|s| s.client_cid_len);
        if let Some(long) = parse_quic_long_header(packet) {
            self.register_cids(
                session_id,
                [long.dcid, long.scid].into_iter().flatten().collect(),
            );
            // For server->client long headers:
            // - SCID length is the server CID length (used as DCID by client).
            // - DCID length is the client CID length (used as DCID by server).
            if let Some(session) = self.sessions.get_mut(&session_id) {
                if long.scid_len > 0 {
                    session.server_cid_len = Some(long.scid_len);
                    self.known_server_cid_lens.insert(long.scid_len);
                }
                if session.client_cid_len.is_none() && long.dcid_len > 0 {
                    session.client_cid_len = Some(long.dcid_len);
                }
            }
        } else if let Some(len) = client_cid_len {
            if let Some(cid) = parse_quic_short_dcid(packet, len) {
                self.register_cids(session_id, vec![cid]);
            }
        }
    }

    fn find_session_for_client_packet(
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
                if let Some(id) = self.by_cid.get(&cid).copied() {
                    return Some(id);
                }
            }
        }

        // For short headers we don't know DCID length; try known server CID lengths.
        let first = *packet.first()?;
        if (first & 0x80) == 0 {
            for len in &self.known_server_cid_lens {
                if let Some(cid) = parse_quic_short_dcid(packet, *len) {
                    if let Some(id) = self.by_cid.get(&cid).copied() {
                        return Some(id);
                    }
                }
            }
        }
        None
    }
}

pub(super) async fn run_http3_passthrough(
    listen_addr: SocketAddr,
    upstreams: Vec<String>,
    cfg: &ReverseHttp3Config,
    upstream_resolve_timeout: Duration,
) -> Result<()> {
    let mut upstream_addrs = Vec::with_capacity(upstreams.len());
    for upstream in upstreams {
        upstream_addrs.push(
            crate::upstream::origin::resolve_upstream_socket_addr(
                &upstream,
                443,
                upstream_resolve_timeout,
            )
            .await?,
        );
    }
    if upstream_addrs.is_empty() {
        return Err(anyhow!(
            "reverse HTTP/3 passthrough requires at least one upstream"
        ));
    }
    let upstream_addrs = Arc::new(upstream_addrs);
    let rr_counter = Arc::new(AtomicUsize::new(0));
    let listener = Arc::new(UdpSocket::bind(listen_addr).await?);
    let sessions: Arc<Mutex<SessionIndex>> = Arc::new(Mutex::new(SessionIndex::new()));
    let max_sessions = cfg.passthrough_max_sessions.max(1);
    let idle_timeout = Duration::from_secs(cfg.passthrough_idle_timeout_secs.max(1));
    let max_new_per_sec = cfg.passthrough_max_new_sessions_per_sec.max(1);
    let min_client_bytes = cfg.passthrough_min_client_bytes.max(1);
    let max_amplification = cfg.passthrough_max_amplification.max(1) as u64;
    let mut new_window_start = Instant::now();
    let mut new_sessions_in_window = 0u64;
    let mut next_session_id = 1u64;

    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            biased;
            _ = cleanup.tick() => {
                let now = Instant::now();
                let mut guard = sessions.lock().await;
                let stale = guard
                    .sessions
                    .iter()
                    .filter_map(|(id, session)| {
                        if now.duration_since(session.last_seen) > idle_timeout {
                            Some(*id)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                for id in stale {
                    if let Some(session) = guard.sessions.get(&id) {
                        let _ = session.close_tx.send(true);
                    }
                    guard.remove_session(id);
                }
            },
            recv = listener.recv_from(&mut buf) => {
                let (n, client_addr) = recv?;
        let payload = buf[..n].to_vec();
        let now = Instant::now();

        let mut upstream_socket: Option<Arc<UdpSocket>> = None;
        let mut session_id: Option<u64> = None;
        {
            let mut guard = sessions.lock().await;

            if let Some(id) = guard.find_session_for_client_packet(client_addr, &payload) {
                // NAT rebinding / connection migration: update the address index.
                let mut old_addr = None;
                if let Some(session) = guard.sessions.get_mut(&id) {
                    if session.client_addr != client_addr {
                        old_addr = Some(session.client_addr);
                        session.client_addr = client_addr;
                        let _ = session.client_addr_tx.send(client_addr);
                    }
                    session.last_seen = now;
                    session.bytes_in = session.bytes_in.saturating_add(payload.len() as u64);
                    upstream_socket = Some(session.socket.clone());
                    session_id = Some(id);
                }
                if let Some(old_addr) = old_addr {
                    guard.by_addr.remove(&old_addr);
                    guard.by_addr.insert(client_addr, id);
                }
            }

            if let Some(id) = session_id {
                guard.observe_client_packet(id, &payload);
            }
        }

        let upstream_socket = if let Some(socket) = upstream_socket {
            socket
        } else {
            if payload.len() < min_client_bytes {
                continue;
            }
            if now.duration_since(new_window_start) >= Duration::from_secs(1) {
                new_window_start = now;
                new_sessions_in_window = 0;
            }
            if new_sessions_in_window >= max_new_per_sec {
                continue;
            }
            let idx = rr_counter.fetch_add(1, Ordering::Relaxed);
            let upstream_addr = upstream_addrs[idx % upstream_addrs.len()];
            let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let socket: Arc<UdpSocket> = Arc::new(UdpSocket::bind(bind_addr).await?);
            socket.connect(upstream_addr).await?;
            let (close_tx, mut close_rx) = watch::channel(false);
            let (client_addr_tx, client_addr_rx) = watch::channel(client_addr);
            let session_id = next_session_id;
            next_session_id = next_session_id.wrapping_add(1);

            let mut created = false;
            let socket = {
                let mut guard = sessions.lock().await;
                while guard.sessions.len() >= max_sessions {
                    let oldest = guard
                        .sessions
                        .iter()
                        .min_by_key(|(_, session)| session.last_seen)
                        .map(|(id, _)| *id);
                    let Some(oldest) = oldest else {
                        break;
                    };
                    if let Some(evicted) = guard.sessions.get(&oldest) {
                        let _ = evicted.close_tx.send(true);
                    }
                    guard.remove_session(oldest);
                }
                if let Some(existing_id) = guard.by_addr.get(&client_addr).copied() {
                    guard
                        .sessions
                        .get(&existing_id)
                        .map(|s| s.socket.clone())
                        .unwrap_or(socket.clone())
                } else {
                    guard.by_addr.insert(client_addr, session_id);
                    guard.sessions.insert(
                        session_id,
                        PassthroughSession {
                            socket: socket.clone(),
                            last_seen: now,
                            close_tx,
                            client_addr,
                            client_addr_tx,
                            bytes_in: payload.len() as u64,
                            bytes_out: 0,
                            client_cid_len: None,
                            server_cid_len: None,
                            cids: HashSet::new(),
                        },
                    );
                    created = true;
                    guard.observe_client_packet(session_id, &payload);
                    socket
                }
            };

            if created {
                new_sessions_in_window = new_sessions_in_window.saturating_add(1);
                let listener_out = listener.clone();
                let sessions_out = sessions.clone();
                let upstream_out = socket.clone();
                tokio::spawn(async move {
                    let mut recv_buf = vec![0u8; 65535];
                    let client_addr_rx = client_addr_rx;
                    loop {
                        let n = tokio::select! {
                            changed = close_rx.changed() => {
                                if changed.is_ok() && *close_rx.borrow() {
                                    break;
                                }
                                continue;
                            }
                            recv = tokio::time::timeout(idle_timeout, upstream_out.recv(&mut recv_buf)) => {
                                match recv {
                                    Ok(Ok(n)) => n,
                                    Ok(Err(_)) | Err(_) => break,
                                }
                            }
                        };
                        let allowed = {
                            let mut guard = sessions_out.lock().await;
                            guard.observe_upstream_packet(session_id, &recv_buf[..n]);
                            match guard.sessions.get_mut(&session_id) {
                                Some(session) => {
                                    session.last_seen = Instant::now();
                                    let budget = session.bytes_in.saturating_mul(max_amplification);
                                    let proposed = session.bytes_out.saturating_add(n as u64);
                                    if proposed > budget {
                                        false
                                    } else {
                                        session.bytes_out = proposed;
                                        true
                                    }
                                }
                                None => false,
                            }
                        };
                        if !allowed {
                            continue;
                        }
                        let client_addr = *client_addr_rx.borrow();
                        if listener_out
                            .send_to(&recv_buf[..n], client_addr)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    let mut guard = sessions_out.lock().await;
                    guard.remove_session(session_id);
                });
            }

            socket
        };

        upstream_socket.send(&payload).await?;
            },
        }
    }
}
