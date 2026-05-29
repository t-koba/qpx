use super::super::{
    ReloadableReverse, record_reverse_connection_filter_block, reverse_quic_connection_filter_match,
};
use crate::server::control::SidecarControl;
use crate::udp_session_handoff::{
    ExportedQuicConnectionId, ReversePassthroughListenerRestore, ReversePassthroughSessionRestore,
    UdpSessionRestoreState,
};
use crate::udp_socket_handoff::duplicate_tokio_udp_socket;
use anyhow::{Result, anyhow};
use qpx_core::config::ReverseHttp3Config;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, MissedTickBehavior};

mod index;

use self::index::{PassthroughSession, QuicConnectionId, SessionTouch, SharedSessionIndex};

const UNSPECIFIED_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
const UNSPECIFIED_V6: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);

pub(crate) struct Http3PassthroughRuntime {
    pub(crate) reverse: ReloadableReverse,
    pub(crate) upstream_resolve_timeout: Duration,
    pub(crate) shutdown: watch::Receiver<SidecarControl>,
    pub(crate) listener_socket: std::net::UdpSocket,
    pub(crate) restore: Option<ReversePassthroughListenerRestore>,
    pub(crate) export_sink: Arc<Mutex<UdpSessionRestoreState>>,
}

struct PassthroughRelayContext {
    listener: Arc<UdpSocket>,
    sessions: Arc<SharedSessionIndex>,
    session_id: u64,
    session: Arc<PassthroughSession>,
    upstream: Arc<UdpSocket>,
    client_addr_rx: watch::Receiver<SocketAddr>,
    touch_tx: mpsc::Sender<SessionTouch>,
    idle_timeout: Duration,
    run_started: Instant,
    max_amplification: u64,
}

fn instant_to_millis(start: Instant, now: Instant) -> u64 {
    now.duration_since(start).as_millis() as u64
}

fn queue_session_touch(
    touch_tx: &mpsc::Sender<SessionTouch>,
    session_id: u64,
    session: &PassthroughSession,
    seen_ms: u64,
) {
    if session.should_queue_touch(seen_ms) {
        let _ = touch_tx.try_send(SessionTouch {
            seen_ms,
            session_id,
        });
    }
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
    let sessions = Arc::new(SharedSessionIndex::new());
    let max_sessions = cfg.passthrough_max_sessions.max(1);
    let (touch_tx, mut touch_rx) =
        mpsc::channel::<SessionTouch>(max_sessions.saturating_mul(2).max(64));
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
                cleanup_sessions(sessions.clone(), &mut touch_rx, run_started, idle_timeout_ms)?;
            },
            recv = listener.recv_from(&mut buf) => {
                let (n, client_addr) = recv?;
                handle_client_packet(PassthroughPacketContext {
                    reverse: &reverse,
                    listen_addr,
                    listener: listener.clone(),
                    sessions: sessions.clone(),
                    touch_tx: touch_tx.clone(),
                    touch_rx: &mut touch_rx,
                    upstream_addrs: upstream_addrs.as_slice(),
                    rr_counter: rr_counter.clone(),
                    max_sessions,
                    idle_timeout,
                    max_new_per_sec,
                    min_client_bytes,
                    max_amplification,
                    run_started,
                    new_window_start: &mut new_window_start,
                    new_sessions_in_window: &mut new_sessions_in_window,
                    next_session_id: &mut next_session_id,
                }, client_addr, &buf[..n]).await?;
            },
        }
    }
    Ok(())
}

fn cleanup_sessions(
    sessions: Arc<SharedSessionIndex>,
    touch_rx: &mut mpsc::Receiver<SessionTouch>,
    run_started: Instant,
    idle_timeout_ms: u64,
) -> Result<()> {
    let now_ms = instant_to_millis(run_started, Instant::now());
    sessions.drain_session_touches(touch_rx);
    let expired = sessions.evict_expired(now_ms, idle_timeout_ms);
    for session in expired {
        let _ = session.close_tx.send(true);
    }
    Ok(())
}

struct PassthroughPacketContext<'a> {
    reverse: &'a ReloadableReverse,
    listen_addr: SocketAddr,
    listener: Arc<UdpSocket>,
    sessions: Arc<SharedSessionIndex>,
    touch_tx: mpsc::Sender<SessionTouch>,
    touch_rx: &'a mut mpsc::Receiver<SessionTouch>,
    upstream_addrs: &'a [SocketAddr],
    rr_counter: Arc<AtomicUsize>,
    max_sessions: usize,
    idle_timeout: Duration,
    max_new_per_sec: u64,
    min_client_bytes: usize,
    max_amplification: u64,
    run_started: Instant,
    new_window_start: &'a mut Instant,
    new_sessions_in_window: &'a mut u64,
    next_session_id: &'a mut u64,
}

async fn handle_client_packet(
    mut ctx: PassthroughPacketContext<'_>,
    client_addr: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    if let Some((stage, matched_rule, sni)) = reverse_quic_connection_filter_match(
        ctx.reverse,
        client_addr,
        ctx.listen_addr.port(),
        payload,
    ) {
        record_reverse_connection_filter_block(
            ctx.reverse,
            client_addr,
            ctx.listen_addr.port(),
            stage,
            matched_rule.as_str(),
            sni.as_deref(),
        );
        return Ok(());
    }

    let now = Instant::now();
    let now_ms = instant_to_millis(ctx.run_started, now);
    if let Some(socket) = existing_passthrough_session_socket(&ctx, client_addr, payload, now_ms)? {
        socket.send(payload).await?;
        return Ok(());
    }
    if let Some(socket) =
        create_passthrough_session(&mut ctx, client_addr, payload, now, now_ms).await?
    {
        socket.send(payload).await?;
    }
    Ok(())
}

fn existing_passthrough_session_socket(
    ctx: &PassthroughPacketContext<'_>,
    client_addr: SocketAddr,
    payload: &[u8],
    now_ms: u64,
) -> Result<Option<Arc<UdpSocket>>> {
    let (id, session, needs_index_update) = {
        let Some((id, session)) = ctx
            .sessions
            .find_session_for_client_packet(client_addr, payload)
        else {
            return Ok(None);
        };
        let needs_index_update =
            ctx.sessions
                .client_packet_needs_index_update(id, session.as_ref(), payload);
        (id, session, needs_index_update)
    };
    session.mark_client_seen(now_ms, payload.len() as u64);
    queue_session_touch(&ctx.touch_tx, id, session.as_ref(), now_ms);
    let upstream_socket = session.socket.clone();
    if session.current_client_addr() != client_addr || needs_index_update {
        ctx.sessions.update_client_address(id, client_addr);
        if needs_index_update {
            ctx.sessions.observe_client_packet(id, payload);
        }
    }
    Ok(Some(upstream_socket))
}

async fn create_passthrough_session(
    ctx: &mut PassthroughPacketContext<'_>,
    client_addr: SocketAddr,
    payload: &[u8],
    now: Instant,
    now_ms: u64,
) -> Result<Option<Arc<UdpSocket>>> {
    if payload.len() < ctx.min_client_bytes {
        return Ok(None);
    }
    if now.duration_since(*ctx.new_window_start) >= Duration::from_secs(1) {
        *ctx.new_window_start = now;
        *ctx.new_sessions_in_window = 0;
    }
    if *ctx.new_sessions_in_window >= ctx.max_new_per_sec {
        return Ok(None);
    }

    let idx = ctx.rr_counter.fetch_add(1, Ordering::Relaxed);
    let upstream_addr = ctx.upstream_addrs[idx % ctx.upstream_addrs.len()];
    let bind_addr = if upstream_addr.is_ipv4() {
        UNSPECIFIED_V4
    } else {
        UNSPECIFIED_V6
    };
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    socket.connect(upstream_addr).await?;
    let (close_tx, _close_rx) = watch::channel(false);
    let (client_addr_tx, client_addr_rx) = watch::channel(client_addr);
    let session_id = *ctx.next_session_id;
    *ctx.next_session_id = ctx.next_session_id.wrapping_add(1);

    let mut created = false;
    let socket = {
        ctx.sessions.drain_session_touches(ctx.touch_rx);
        while ctx.sessions.session_count() >= ctx.max_sessions {
            let Some(evicted) = ctx.sessions.evict_oldest() else {
                break;
            };
            let _ = evicted.close_tx.send(true);
        }
        if let Some((_, existing)) = ctx
            .sessions
            .find_session_for_client_packet(client_addr, payload)
        {
            existing.socket.clone()
        } else {
            let session = Arc::new(PassthroughSession::new(
                socket.clone(),
                close_tx,
                client_addr,
                client_addr_tx,
                now_ms,
                payload.len() as u64,
                0,
            ));
            ctx.sessions.insert_new(session_id, session);
            created = true;
            ctx.sessions.observe_client_packet(session_id, payload);
            socket
        }
    };

    if created {
        *ctx.new_sessions_in_window = ctx.new_sessions_in_window.saturating_add(1);
        if let Some(session) = ctx.sessions.session(session_id) {
            let relay_task = spawn_passthrough_upstream_relay(PassthroughRelayContext {
                listener: ctx.listener.clone(),
                sessions: ctx.sessions.clone(),
                session_id,
                session: session.clone(),
                upstream: socket.clone(),
                client_addr_rx,
                touch_tx: ctx.touch_tx.clone(),
                idle_timeout: ctx.idle_timeout,
                run_started: ctx.run_started,
                max_amplification: ctx.max_amplification,
            });
            session.attach_relay_task(relay_task);
        }
    }
    Ok(Some(socket))
}

fn run_started_from_exported_elapsed(exported_elapsed_ms: u64) -> Instant {
    Instant::now()
        .checked_sub(Duration::from_millis(exported_elapsed_ms))
        .unwrap_or_else(Instant::now)
}

async fn drain_passthrough_sessions(
    reverse_name: &str,
    listen_addr: SocketAddr,
    sessions: Arc<SharedSessionIndex>,
    run_started: Instant,
    export: bool,
    export_sink: &Mutex<UdpSessionRestoreState>,
) -> Result<()> {
    let drained = sessions.drain_all();
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
            .map_err(|_| anyhow!("reverse passthrough export lock poisoned"))?
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
    sessions: Arc<SharedSessionIndex>,
    touch_tx: &mpsc::Sender<SessionTouch>,
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
        sessions.insert_restored(restored.session_id, session.clone(), cids);
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
                match sessions.session(session_id) {
                    Some(session) => {
                        session.mark_upstream_seen(now_ms);
                        queue_session_touch(&touch_tx, session_id, session.as_ref(), now_ms);
                        let allowed =
                            session.try_reserve_upstream_bytes(n as u64, max_amplification);
                        let needs_index_update = allowed
                            && sessions.upstream_packet_needs_index_update(
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
                sessions.observe_upstream_packet(session_id, &recv_buf[..n]);
            }
            let client_addr = *client_addr_rx.borrow();
            if listener.send_to(&recv_buf[..n], client_addr).await.is_err() {
                break;
            }
        }
        let _ = sessions.remove_session(session_id);
    })
}

#[cfg(test)]
mod tests;
