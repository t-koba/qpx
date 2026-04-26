use crate::sidecar_control::SidecarControl;
use crate::udp_session_handoff::{
    ExportedQuicConnectionId, ReversePassthroughListenerRestore, ReversePassthroughSessionRestore,
    UdpSessionRestoreState,
};
use crate::udp_socket_handoff::duplicate_tokio_udp_socket;
use anyhow::{anyhow, Result};
use qpx_core::config::ReverseHttp3Config;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Mutex as StdMutex, RwLock};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, MissedTickBehavior};

const MAX_CIDS_PER_SESSION: usize = 32;

pub(crate) struct Http3PassthroughRuntime {
    pub(crate) reverse: super::ReloadableReverse,
    pub(crate) upstream_resolve_timeout: Duration,
    pub(crate) shutdown: watch::Receiver<SidecarControl>,
    pub(crate) listener_socket: std::net::UdpSocket,
    pub(crate) restore: Option<ReversePassthroughListenerRestore>,
    pub(crate) export_sink: Arc<Mutex<UdpSessionRestoreState>>,
}

struct PassthroughRelayContext {
    listener: Arc<UdpSocket>,
    sessions: Arc<RwLock<SessionIndex>>,
    session_id: u64,
    session: Arc<PassthroughSession>,
    upstream: Arc<UdpSocket>,
    client_addr_rx: watch::Receiver<SocketAddr>,
    touch_tx: mpsc::UnboundedSender<SessionTouch>,
    idle_timeout: Duration,
    run_started: Instant,
    max_amplification: u64,
}

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
    close_tx: watch::Sender<bool>,
    client_addr_tx: watch::Sender<SocketAddr>,
    client_addr: StdMutex<SocketAddr>,
    last_seen_ms: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    client_cid_len: AtomicU8,
    server_cid_len: AtomicU8,
    cids: StdMutex<HashSet<QuicConnectionId>>,
    relay_task: StdMutex<Option<JoinHandle<()>>>,
}

impl PassthroughSession {
    fn new(
        socket: Arc<UdpSocket>,
        close_tx: watch::Sender<bool>,
        client_addr: SocketAddr,
        client_addr_tx: watch::Sender<SocketAddr>,
        seen_ms: u64,
        bytes_in: u64,
        bytes_out: u64,
    ) -> Self {
        Self {
            socket,
            close_tx,
            client_addr_tx,
            client_addr: StdMutex::new(client_addr),
            last_seen_ms: AtomicU64::new(seen_ms),
            bytes_in: AtomicU64::new(bytes_in),
            bytes_out: AtomicU64::new(bytes_out),
            client_cid_len: AtomicU8::new(0),
            server_cid_len: AtomicU8::new(0),
            cids: StdMutex::new(HashSet::new()),
            relay_task: StdMutex::new(None),
        }
    }

    fn current_client_addr(&self) -> SocketAddr {
        *self.client_addr.lock().expect("client addr lock")
    }

    fn update_client_addr(&self, client_addr: SocketAddr) -> Option<SocketAddr> {
        let mut guard = self.client_addr.lock().expect("client addr lock");
        if *guard == client_addr {
            return None;
        }
        let old = *guard;
        *guard = client_addr;
        let _ = self.client_addr_tx.send(client_addr);
        Some(old)
    }

    fn mark_client_seen(&self, seen_ms: u64, bytes: u64) {
        self.last_seen_ms.fetch_max(seen_ms, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    fn mark_upstream_seen(&self, seen_ms: u64) {
        self.last_seen_ms.fetch_max(seen_ms, Ordering::Relaxed);
    }

    fn last_seen_ms(&self) -> u64 {
        self.last_seen_ms.load(Ordering::Relaxed)
    }

    fn client_cid_len(&self) -> Option<u8> {
        decode_cid_len(self.client_cid_len.load(Ordering::Relaxed))
    }

    fn server_cid_len(&self) -> Option<u8> {
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

    fn try_reserve_upstream_bytes(&self, bytes: u64, max_amplification: u64) -> bool {
        loop {
            let budget = self
                .bytes_in
                .load(Ordering::Relaxed)
                .saturating_mul(max_amplification);
            let current = self.bytes_out.load(Ordering::Relaxed);
            let proposed = current.saturating_add(bytes);
            if proposed > budget {
                return false;
            }
            if self
                .bytes_out
                .compare_exchange(current, proposed, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }

    fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    fn set_client_cid_len_if_some(&self, len: Option<u8>) {
        if let Some(len) = len {
            self.set_client_cid_len(len);
        }
    }

    fn set_server_cid_len_if_some(&self, len: Option<u8>) {
        if let Some(len) = len {
            self.set_server_cid_len(len);
        }
    }

    fn snapshot_cids(&self) -> Vec<QuicConnectionId> {
        self.cids
            .lock()
            .expect("session cids lock")
            .iter()
            .copied()
            .collect()
    }

    fn attach_relay_task(&self, task: JoinHandle<()>) {
        *self.relay_task.lock().expect("relay task lock") = Some(task);
    }

    fn take_relay_task(&self) -> Option<JoinHandle<()>> {
        self.relay_task.lock().expect("relay task lock").take()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SessionTouch {
    seen_ms: u64,
    session_id: u64,
}

struct SessionIndex {
    sessions: HashMap<u64, Arc<PassthroughSession>>,
    by_addr: HashMap<SocketAddr, u64>,
    by_cid: HashMap<QuicConnectionId, u64>,
    known_server_cid_lens: HashSet<u8>,
    touches: BinaryHeap<Reverse<SessionTouch>>,
}

impl SessionIndex {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            by_addr: HashMap::new(),
            by_cid: HashMap::new(),
            known_server_cid_lens: HashSet::new(),
            touches: BinaryHeap::new(),
        }
    }

    fn session(&self, session_id: u64) -> Option<Arc<PassthroughSession>> {
        self.sessions.get(&session_id).cloned()
    }

    fn remove_session(&mut self, session_id: u64) -> Option<Arc<PassthroughSession>> {
        let session = self.sessions.remove(&session_id)?;
        self.by_addr.remove(&session.current_client_addr());
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

    fn record_touch(&mut self, session_id: u64, seen_ms: u64) {
        self.touches.push(Reverse(SessionTouch {
            seen_ms,
            session_id,
        }));
    }

    fn insert_restored(
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
            // Avoid allowing one session to steal CID routing from another session.
            if let Some(existing) = self.by_cid.get(&cid).copied() {
                if existing != session_id {
                    continue;
                }
            }
            session_cids.insert(cid);
            self.by_cid.insert(cid, session_id);
        }
    }

    fn observe_client_packet(&mut self, session_id: u64, packet: &[u8]) {
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
                if long.scid_len > 0 {
                    if let Some(session) = self.sessions.get(&session_id) {
                        session.set_client_cid_len(long.scid_len);
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
                if let Some(session) = self.sessions.get(&session_id) {
                    session.set_client_cid_len(long.scid_len);
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

        // For short headers we don't know DCID length; try known server CID lengths.
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

    fn update_client_address(&mut self, session_id: u64, client_addr: SocketAddr) {
        let Some(session) = self.sessions.get(&session_id) else {
            return;
        };
        if let Some(old_addr) = session.update_client_addr(client_addr) {
            self.by_addr.remove(&old_addr);
            self.by_addr.insert(client_addr, session_id);
        }
    }

    fn evict_expired(&mut self, now_ms: u64, idle_timeout_ms: u64) -> Vec<Arc<PassthroughSession>> {
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
                continue;
            }
            if let Some(session) = self.remove_session(touch.session_id) {
                removed.push(session);
            }
        }
        removed
    }

    fn evict_oldest(&mut self) -> Option<Arc<PassthroughSession>> {
        while let Some(Reverse(touch)) = self.touches.pop() {
            let Some(session) = self.sessions.get(&touch.session_id) else {
                continue;
            };
            if session.last_seen_ms() != touch.seen_ms {
                continue;
            }
            return self.remove_session(touch.session_id);
        }
        None
    }

    fn drain_all(&mut self) -> Vec<(u64, Arc<PassthroughSession>)> {
        let drained = self.sessions.drain().collect::<Vec<_>>();
        self.by_addr.clear();
        self.by_cid.clear();
        self.known_server_cid_lens.clear();
        while self.touches.pop().is_some() {}
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

fn instant_to_millis(start: Instant, now: Instant) -> u64 {
    now.duration_since(start).as_millis() as u64
}

fn drain_session_touches(
    index: &mut SessionIndex,
    touch_rx: &mut mpsc::UnboundedReceiver<SessionTouch>,
) {
    while let Ok(touch) = touch_rx.try_recv() {
        if index.sessions.contains_key(&touch.session_id) {
            index.record_touch(touch.session_id, touch.seen_ms);
        }
    }
}

fn client_packet_needs_index_update(
    index: &SessionIndex,
    session_id: u64,
    session: &PassthroughSession,
    client_addr: SocketAddr,
    packet: &[u8],
) -> bool {
    if session.current_client_addr() != client_addr {
        return true;
    }
    if let Some(long) = parse_quic_long_header(packet) {
        if long.scid_len > 0 && session.client_cid_len() != Some(long.scid_len) {
            return true;
        }
        return [long.dcid, long.scid]
            .into_iter()
            .flatten()
            .any(|cid| index.by_cid.get(&cid).copied() != Some(session_id));
    }
    let Some(server_cid_len) = session.server_cid_len() else {
        return false;
    };
    let Some(cid) = parse_quic_short_dcid(packet, server_cid_len) else {
        return false;
    };
    index.by_cid.get(&cid).copied() != Some(session_id)
}

fn upstream_packet_needs_index_update(
    index: &SessionIndex,
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
            .any(|cid| index.by_cid.get(&cid).copied() != Some(session_id));
    }
    let Some(client_cid_len) = session.client_cid_len() else {
        return false;
    };
    let Some(cid) = parse_quic_short_dcid(packet, client_cid_len) else {
        return false;
    };
    index.by_cid.get(&cid).copied() != Some(session_id)
}

pub(crate) async fn run_http3_passthrough(
    listen_addr: SocketAddr,
    upstreams: Vec<String>,
    cfg: &ReverseHttp3Config,
    runtime: Http3PassthroughRuntime,
) -> Result<()> {
    let Http3PassthroughRuntime {
        reverse,
        upstream_resolve_timeout,
        mut shutdown,
        listener_socket,
        restore,
        export_sink,
    } = runtime;
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
    listener_socket.set_nonblocking(true)?;
    let listener = Arc::new(UdpSocket::from_std(listener_socket)?);
    let sessions: Arc<RwLock<SessionIndex>> = Arc::new(RwLock::new(SessionIndex::new()));
    let (touch_tx, mut touch_rx) = mpsc::unbounded_channel::<SessionTouch>();
    let max_sessions = cfg.passthrough_max_sessions.max(1);
    let idle_timeout = Duration::from_secs(cfg.passthrough_idle_timeout_secs.max(1));
    let idle_timeout_ms = idle_timeout.as_millis() as u64;
    let max_new_per_sec = cfg.passthrough_max_new_sessions_per_sec.max(1);
    let min_client_bytes = cfg.passthrough_min_client_bytes.max(1);
    let max_amplification = cfg.passthrough_max_amplification.max(1) as u64;
    let mut new_window_start = Instant::now();
    let mut new_sessions_in_window = 0u64;
    let mut next_session_id = 1u64;
    let run_started = restore
        .as_ref()
        .map(|state| run_started_from_exported_elapsed(state.exported_elapsed_ms))
        .unwrap_or_else(Instant::now);

    let mut cleanup = tokio::time::interval(Duration::from_secs(1));
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut buf = vec![0u8; 65535];
    if let Some(restore) = restore {
        next_session_id = restore_passthrough_sessions(
            listener.clone(),
            sessions.clone(),
            &touch_tx,
            restore,
            idle_timeout,
            run_started,
            max_amplification,
        )
        .await?;
    }
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                let stop_mode = if changed.is_err() {
                    SidecarControl::Stop
                } else {
                    *shutdown.borrow()
                };
                if stop_mode.should_stop() {
                    drain_passthrough_sessions(
                        reverse.name.as_ref(),
                        listen_addr,
                        sessions.clone(),
                        run_started,
                        stop_mode.should_export(),
                        export_sink.as_ref(),
                    )
                    .await?;
                    break;
                }
            },
            _ = cleanup.tick() => {
                let now_ms = instant_to_millis(run_started, Instant::now());
                let expired = {
                    let mut guard = sessions.write().expect("session index write lock");
                    drain_session_touches(&mut guard, &mut touch_rx);
                    guard.evict_expired(now_ms, idle_timeout_ms)
                };
                for session in expired {
                    let _ = session.close_tx.send(true);
                }
            },
            recv = listener.recv_from(&mut buf) => {
                let (n, client_addr) = recv?;
                let payload = buf[..n].to_vec();
                if let Some((stage, matched_rule, sni)) =
                    super::reverse_quic_connection_filter_match(
                        &reverse,
                        client_addr,
                        listen_addr.port(),
                        payload.as_slice(),
                    )
                {
                    super::record_reverse_connection_filter_block(
                        &reverse,
                        client_addr,
                        listen_addr.port(),
                        stage,
                        matched_rule.as_str(),
                        sni.as_deref(),
                    );
                    continue;
                }
                let now = Instant::now();
                let now_ms = instant_to_millis(run_started, now);

                let mut upstream_socket: Option<Arc<UdpSocket>> = None;
                let mut session_id: Option<u64> = None;
                let mut needs_index_update = false;

                {
                    let guard = sessions.read().expect("session index read lock");
                    if let Some(id) = guard.find_session_for_client_packet(client_addr, &payload) {
                        if let Some(session) = guard.session(id) {
                            session.mark_client_seen(now_ms, payload.len() as u64);
                            let _ = touch_tx.send(SessionTouch {
                                seen_ms: now_ms,
                                session_id: id,
                            });
                            upstream_socket = Some(session.socket.clone());
                            session_id = Some(id);
                            needs_index_update = client_packet_needs_index_update(
                                &guard,
                                id,
                                session.as_ref(),
                                client_addr,
                                &payload,
                            );
                        }
                    }
                }

                if let Some(id) = session_id.filter(|_| needs_index_update) {
                    let mut guard = sessions.write().expect("session index write lock");
                    guard.update_client_address(id, client_addr);
                    guard.observe_client_packet(id, &payload);
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
            let (close_tx, _close_rx) = watch::channel(false);
            let (client_addr_tx, client_addr_rx) = watch::channel(client_addr);
            let session_id = next_session_id;
            next_session_id = next_session_id.wrapping_add(1);

            let mut created = false;
            let socket = {
                let mut guard = sessions.write().expect("session index write lock");
                drain_session_touches(&mut guard, &mut touch_rx);
                while guard.sessions.len() >= max_sessions {
                    let Some(evicted) = guard.evict_oldest() else {
                        break;
                    };
                    let _ = evicted.close_tx.send(true);
                }
                if let Some(existing_id) = guard.by_addr.get(&client_addr).copied() {
                    guard
                        .session(existing_id)
                        .map(|s| s.socket.clone())
                        .unwrap_or(socket.clone())
                } else {
                    guard.by_addr.insert(client_addr, session_id);
                    guard.sessions.insert(
                        session_id,
                        Arc::new(PassthroughSession::new(
                            socket.clone(),
                            close_tx,
                            client_addr,
                            client_addr_tx,
                            now_ms,
                            payload.len() as u64,
                            0,
                        )),
                    );
                    created = true;
                    guard.record_touch(session_id, now_ms);
                    guard.observe_client_packet(session_id, &payload);
                    socket
                }
            };

            if created {
                new_sessions_in_window = new_sessions_in_window.saturating_add(1);
                let listener_out = listener.clone();
                let sessions_out = sessions.clone();
                let upstream_out = socket.clone();
                let touch_tx_out = touch_tx.clone();
                if let Some(session) = {
                    let guard = sessions.read().expect("session index read lock");
                    guard.session(session_id)
                } {
                    let relay_task = spawn_passthrough_upstream_relay(PassthroughRelayContext {
                        listener: listener_out,
                        sessions: sessions_out,
                        session_id,
                        session: session.clone(),
                        upstream: upstream_out,
                        client_addr_rx,
                        touch_tx: touch_tx_out,
                        idle_timeout,
                        run_started,
                        max_amplification,
                    });
                    session.attach_relay_task(relay_task);
                }
            }

            socket
        };

        upstream_socket.send(&payload).await?;
            },
        }
    }
    Ok(())
}

fn run_started_from_exported_elapsed(exported_elapsed_ms: u64) -> Instant {
    Instant::now()
        .checked_sub(Duration::from_millis(exported_elapsed_ms))
        .unwrap_or_else(Instant::now)
}

async fn drain_passthrough_sessions(
    reverse_name: &str,
    listen_addr: SocketAddr,
    sessions: Arc<RwLock<SessionIndex>>,
    run_started: Instant,
    export: bool,
    export_sink: &Mutex<UdpSessionRestoreState>,
) -> Result<()> {
    let drained = {
        let mut guard = sessions.write().expect("session index write lock");
        guard.drain_all()
    };
    for (_, session) in &drained {
        let _ = session.close_tx.send(true);
    }
    for task in drained
        .iter()
        .filter_map(|(_, session)| session.take_relay_task())
    {
        task.await
            .map_err(|err| anyhow!("reverse h3 passthrough relay join failed: {err}"))?;
    }
    if export && !drained.is_empty() {
        let exported_elapsed_ms = run_started.elapsed().as_millis() as u64;
        let mut restored = Vec::with_capacity(drained.len());
        for (session_id, session) in drained {
            restored.push(ReversePassthroughSessionRestore {
                session_id,
                upstream_local_addr: session
                    .socket
                    .local_addr()
                    .map_err(|err| anyhow!("failed to resolve passthrough local addr: {err}"))?,
                upstream_peer_addr: session
                    .socket
                    .peer_addr()
                    .map_err(|err| anyhow!("failed to resolve passthrough peer addr: {err}"))?,
                socket: duplicate_tokio_udp_socket(session.socket.as_ref())?,
                client_addr: session.current_client_addr(),
                last_seen_ms: session.last_seen_ms(),
                bytes_in: session.bytes_in(),
                bytes_out: session.bytes_out(),
                client_cid_len: session.client_cid_len(),
                server_cid_len: session.server_cid_len(),
                cids: session
                    .snapshot_cids()
                    .into_iter()
                    .map(|cid| ExportedQuicConnectionId {
                        len: cid.len,
                        bytes: cid.bytes,
                    })
                    .collect(),
            });
        }
        export_sink
            .lock()
            .expect("reverse passthrough export lock")
            .insert_reverse_passthrough(
                reverse_name.to_string(),
                ReversePassthroughListenerRestore {
                    listen: listen_addr.to_string(),
                    exported_elapsed_ms,
                    sessions: restored,
                },
            );
    }
    Ok(())
}

async fn restore_passthrough_sessions(
    listener: Arc<UdpSocket>,
    sessions: Arc<RwLock<SessionIndex>>,
    touch_tx: &mpsc::UnboundedSender<SessionTouch>,
    restore: ReversePassthroughListenerRestore,
    idle_timeout: Duration,
    run_started: Instant,
    max_amplification: u64,
) -> Result<u64> {
    let mut next_session_id = 1u64;
    for restored in restore.sessions {
        restored.socket.set_nonblocking(true).map_err(|err| {
            anyhow!("failed to set restored passthrough session nonblocking: {err}")
        })?;
        let socket = Arc::new(
            UdpSocket::from_std(restored.socket)
                .map_err(|err| anyhow!("failed to adopt restored passthrough session: {err}"))?,
        );
        let (close_tx, _close_rx) = watch::channel(false);
        let (client_addr_tx, client_addr_rx) = watch::channel(restored.client_addr);
        let session = Arc::new(PassthroughSession::new(
            socket.clone(),
            close_tx,
            restored.client_addr,
            client_addr_tx,
            restored.last_seen_ms,
            restored.bytes_in,
            restored.bytes_out,
        ));
        session.set_client_cid_len_if_some(restored.client_cid_len);
        session.set_server_cid_len_if_some(restored.server_cid_len);
        let cids = restored
            .cids
            .into_iter()
            .map(|cid| QuicConnectionId {
                len: cid.len,
                bytes: cid.bytes,
            })
            .collect::<Vec<_>>();
        {
            let mut guard = sessions.write().expect("session index write lock");
            guard.insert_restored(restored.session_id, session.clone(), cids);
        }
        let relay_task = spawn_passthrough_upstream_relay(PassthroughRelayContext {
            listener: listener.clone(),
            sessions: sessions.clone(),
            session_id: restored.session_id,
            session: session.clone(),
            upstream: socket,
            client_addr_rx,
            touch_tx: touch_tx.clone(),
            idle_timeout,
            run_started,
            max_amplification,
        });
        session.attach_relay_task(relay_task);
        next_session_id = next_session_id.max(restored.session_id.wrapping_add(1));
    }
    Ok(next_session_id)
}

fn spawn_passthrough_upstream_relay(ctx: PassthroughRelayContext) -> JoinHandle<()> {
    let PassthroughRelayContext {
        listener,
        sessions,
        session_id,
        session,
        upstream,
        client_addr_rx,
        touch_tx,
        idle_timeout,
        run_started,
        max_amplification,
    } = ctx;
    tokio::spawn(async move {
        let mut recv_buf = vec![0u8; 65535];
        let mut close_rx = session.close_tx.subscribe();
        let client_addr_rx = client_addr_rx;
        loop {
            let n = tokio::select! {
                changed = close_rx.changed() => {
                    if changed.is_ok() && *close_rx.borrow() {
                        break;
                    }
                    continue;
                }
                recv = tokio::time::timeout(idle_timeout, upstream.recv(&mut recv_buf)) => {
                    match recv {
                        Ok(Ok(n)) => n,
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
            };
            let now_ms = instant_to_millis(run_started, Instant::now());
            let (allowed, needs_index_update) = {
                let guard = sessions.read().expect("session index read lock");
                match guard.session(session_id) {
                    Some(session) => {
                        session.mark_upstream_seen(now_ms);
                        let _ = touch_tx.send(SessionTouch {
                            seen_ms: now_ms,
                            session_id,
                        });
                        let allowed =
                            session.try_reserve_upstream_bytes(n as u64, max_amplification);
                        let needs_index_update = allowed
                            && upstream_packet_needs_index_update(
                                &guard,
                                session_id,
                                session.as_ref(),
                                &recv_buf[..n],
                            );
                        (allowed, needs_index_update)
                    }
                    None => (false, false),
                }
            };
            if !allowed {
                continue;
            }
            if needs_index_update {
                let mut guard = sessions.write().expect("session index write lock");
                guard.observe_upstream_packet(session_id, &recv_buf[..n]);
            }
            let client_addr = *client_addr_rx.borrow();
            if listener.send_to(&recv_buf[..n], client_addr).await.is_err() {
                break;
            }
        }
        let mut guard = sessions.write().expect("session index write lock");
        let _ = guard.remove_session(session_id);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_quic_long_header() -> Vec<u8> {
        vec![0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, 0]
    }

    #[tokio::test]
    async fn cid_lookup_does_not_migrate_reverse_h3_session() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let (close_tx, _close_rx) = watch::channel(false);
        let original = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001);
        let (client_addr_tx, _client_addr_rx) = watch::channel(original);
        let session = Arc::new(PassthroughSession::new(
            socket,
            close_tx,
            original,
            client_addr_tx,
            0,
            1200,
            0,
        ));
        let mut index = SessionIndex::new();
        index.by_addr.insert(original, 1);
        index.sessions.insert(1, session);
        let packet = test_quic_long_header();
        index.observe_client_packet(1, &packet);

        let attacker = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40002);
        assert_eq!(
            index.find_session_for_client_packet(original, &packet),
            Some(1)
        );
        assert_eq!(
            index.find_session_for_client_packet(attacker, &packet),
            None
        );
    }
}
