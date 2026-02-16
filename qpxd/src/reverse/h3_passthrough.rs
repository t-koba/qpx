use anyhow::{anyhow, Result};
use qpx_core::config::ReverseHttp3Config;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{watch, Mutex};
use tokio::time::{Duration, Instant};

struct PassthroughSession {
    id: u64,
    socket: Arc<UdpSocket>,
    last_seen: Instant,
    close_tx: watch::Sender<bool>,
    bytes_in: u64,
    bytes_out: u64,
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
    let sessions: Arc<Mutex<HashMap<SocketAddr, PassthroughSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let max_sessions = cfg.passthrough_max_sessions.max(1);
    let idle_timeout = Duration::from_secs(cfg.passthrough_idle_timeout_secs.max(1));
    let max_new_per_sec = cfg.passthrough_max_new_sessions_per_sec.max(1);
    let min_client_bytes = cfg.passthrough_min_client_bytes.max(1);
    let max_amplification = cfg.passthrough_max_amplification.max(1) as u64;
    let mut new_window_start = Instant::now();
    let mut new_sessions_in_window = 0u64;
    let mut next_session_id = 1u64;

    let mut buf = vec![0u8; 65535];
    loop {
        let (n, client_addr) = listener.recv_from(&mut buf).await?;
        let payload = buf[..n].to_vec();
        let now = Instant::now();

        let stale_clients = {
            let guard = sessions.lock().await;
            guard
                .iter()
                .filter_map(|(client, session)| {
                    if now.duration_since(session.last_seen) > idle_timeout {
                        Some(*client)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        if !stale_clients.is_empty() {
            let mut guard = sessions.lock().await;
            for client in stale_clients {
                if let Some(session) = guard.remove(&client) {
                    let _ = session.close_tx.send(true);
                }
            }
        }

        let existing = {
            let mut guard = sessions.lock().await;
            guard.get_mut(&client_addr).map(|session| {
                session.last_seen = now;
                session.bytes_in = session.bytes_in.saturating_add(payload.len() as u64);
                session.socket.clone()
            })
        };
        let upstream_socket = if let Some(socket) = existing {
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
            let session_id = next_session_id;
            next_session_id = next_session_id.wrapping_add(1);

            let mut created = false;
            let socket = {
                let mut guard = sessions.lock().await;
                while guard.len() >= max_sessions {
                    let oldest = guard
                        .iter()
                        .min_by_key(|(_, session)| session.last_seen)
                        .map(|(client, _)| *client);
                    let Some(oldest) = oldest else {
                        break;
                    };
                    if let Some(evicted) = guard.remove(&oldest) {
                        let _ = evicted.close_tx.send(true);
                    }
                }
                if let Some(existing) = guard.get(&client_addr) {
                    existing.socket.clone()
                } else {
                    guard.insert(
                        client_addr,
                        PassthroughSession {
                            id: session_id,
                            socket: socket.clone(),
                            last_seen: now,
                            close_tx,
                            bytes_in: payload.len() as u64,
                            bytes_out: 0,
                        },
                    );
                    created = true;
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
                            match guard.get_mut(&client_addr) {
                                Some(session) => {
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
                        if listener_out
                            .send_to(&recv_buf[..n], client_addr)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    let mut guard = sessions_out.lock().await;
                    if guard
                        .get(&client_addr)
                        .map(|session| session.id == session_id)
                        .unwrap_or(false)
                    {
                        guard.remove(&client_addr);
                    }
                });
            }

            socket
        };

        upstream_socket.send(&payload).await?;
    }
}
