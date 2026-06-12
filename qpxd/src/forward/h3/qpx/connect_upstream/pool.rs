use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::lookup_host;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant, timeout, timeout_at};

const QPX_H3_UPSTREAM_SESSION_POOL_SHARDS: usize = 64;
const MAX_QPX_H3_UPSTREAM_SESSIONS: usize = 1024;
const DEFAULT_QPX_H3_UPSTREAM_SESSIONS_PER_KEY: usize = 4;
const DEFAULT_QPX_H3_INFLIGHT_STREAMS_PER_SESSION: usize = 64;

/// Per-runtime pool of upstream qpx-h3 CONNECT sessions (datagram / WebTransport).
/// Owned by [`crate::pool::PoolRegistry`] (formerly a process-global `LazyLock`).
pub(crate) struct QpxH3UpstreamSessionPool {
    shards: Vec<QpxH3UpstreamSessionPoolShard>,
    max_sessions_per_key: AtomicUsize,
    max_inflight_streams_per_session: AtomicUsize,
}

struct QpxH3UpstreamSessionPoolShard {
    sessions: Mutex<HashMap<QpxH3UpstreamSessionKey, Vec<PooledQpxH3Session>>>,
    connecting: crate::pool::SingleFlight<QpxH3UpstreamSessionKey>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct QpxH3UpstreamSessionKey {
    pub(super) connect_host: String,
    pub(super) connect_port: u16,
    pub(super) verify_upstream: bool,
    pub(super) trust_key: Option<String>,
    pub(super) enable_datagram: bool,
    pub(super) enable_webtransport: bool,
}

struct PooledQpxH3Session {
    session: qpx_h3::ClientSession,
    created_at: Instant,
}

impl QpxH3UpstreamSessionPool {
    pub(crate) fn set_limits(
        &self,
        max_sessions_per_key: usize,
        max_inflight_streams_per_session: usize,
    ) {
        self.max_sessions_per_key
            .store(max_sessions_per_key.max(1), Ordering::Relaxed);
        self.max_inflight_streams_per_session
            .store(max_inflight_streams_per_session.max(1), Ordering::Relaxed);
    }

    pub(crate) fn max_sessions_per_key(&self) -> usize {
        self.max_sessions_per_key.load(Ordering::Relaxed)
    }

    pub(crate) fn max_inflight_streams_per_session(&self) -> usize {
        self.max_inflight_streams_per_session
            .load(Ordering::Relaxed)
    }

    pub(crate) fn new() -> Self {
        let shards = (0..QPX_H3_UPSTREAM_SESSION_POOL_SHARDS)
            .map(|_| QpxH3UpstreamSessionPoolShard {
                sessions: Mutex::new(HashMap::new()),
                connecting: crate::pool::SingleFlight::new(),
            })
            .collect();
        Self {
            shards,
            max_sessions_per_key: AtomicUsize::new(DEFAULT_QPX_H3_UPSTREAM_SESSIONS_PER_KEY),
            max_inflight_streams_per_session: AtomicUsize::new(
                DEFAULT_QPX_H3_INFLIGHT_STREAMS_PER_SESSION,
            ),
        }
    }

    fn shard_for(&self, key: &QpxH3UpstreamSessionKey) -> &QpxH3UpstreamSessionPoolShard {
        &self.shards[qpx_http::sharding::modulo(key, self.shards.len())]
    }

    fn max_keys_per_shard(&self) -> usize {
        MAX_QPX_H3_UPSTREAM_SESSIONS
            .div_ceil(self.shards.len().max(1))
            .max(1)
    }

    async fn acquire(
        &self,
        key: QpxH3UpstreamSessionKey,
        trust: Option<&qpx_core::tls::CompiledUpstreamTlsTrust>,
        timeout_dur: Duration,
    ) -> Result<qpx_h3::ClientSession> {
        let connecting_guard = loop {
            let max_sessions_per_key = self.max_sessions_per_key.load(Ordering::Relaxed);
            let max_inflight_streams_per_session = self
                .max_inflight_streams_per_session
                .load(Ordering::Relaxed);
            let mut saturated_session = None;
            {
                let shard = self.shard_for(&key);
                let mut sessions = shard.sessions.lock().await;
                prune_qpx_h3_upstream_sessions(&mut sessions);
                if let Some(session) = sessions.get(&key).and_then(|entries| {
                    least_loaded_qpx_h3_session(
                        entries.as_slice(),
                        max_inflight_streams_per_session,
                    )
                }) {
                    return Ok(session);
                }
                if sessions
                    .get(&key)
                    .is_some_and(|entries| entries.len() >= max_sessions_per_key)
                {
                    saturated_session = sessions
                        .get(&key)
                        .and_then(|entries| least_busy_qpx_h3_session(entries.as_slice()));
                }
            }
            if let Some(session) = saturated_session {
                if session
                    .wait_for_inflight_below(max_inflight_streams_per_session, timeout_dur)
                    .await
                {
                    continue;
                }
                return Err(anyhow!(
                    "qpx-h3 upstream session pool is saturated for {}:{}",
                    key.connect_host,
                    key.connect_port
                ));
            }

            match self.shard_for(&key).connecting.join(&key).await {
                crate::pool::FlightRole::Follower(notify) => {
                    // Bounded wait (normalized with the HTTP/3 origin pool): wake on the
                    // leader's completion or the connect timeout, then retry the lookup.
                    let deadline = Instant::now() + timeout_dur;
                    timeout_at(deadline, notify.notified()).await.map_err(|_| {
                        anyhow!(
                            "qpx-h3 upstream session pool connect wait timed out for {}:{}",
                            key.connect_host,
                            key.connect_port
                        )
                    })?;
                    continue;
                }
                crate::pool::FlightRole::Leader(guard) => break guard,
            }
        };

        let max_sessions_per_key = self.max_sessions_per_key.load(Ordering::Relaxed);
        let max_inflight_streams_per_session = self
            .max_inflight_streams_per_session
            .load(Ordering::Relaxed);
        let session = match connect_qpx_h3_upstream_session(
            &key,
            trust,
            timeout_dur,
            max_inflight_streams_per_session,
        )
        .await
        {
            Ok(session) => session,
            Err(err) => {
                connecting_guard.finish().await;
                return Err(err);
            }
        };
        let shard = self.shard_for(&key);
        let mut sessions = shard.sessions.lock().await;
        prune_qpx_h3_upstream_sessions(&mut sessions);
        evict_qpx_h3_upstream_session_if_full(&mut sessions, &key, self.max_keys_per_shard());
        let entry = sessions.entry(key.clone()).or_default();
        if entry.len() < max_sessions_per_key {
            entry.push(PooledQpxH3Session {
                session: session.clone(),
                created_at: Instant::now(),
            });
        }
        let session =
            least_loaded_qpx_h3_session(entry.as_slice(), max_inflight_streams_per_session)
                .unwrap_or(session);
        drop(sessions);
        connecting_guard.finish().await;
        Ok(session)
    }

    async fn forget(&self, key: &QpxH3UpstreamSessionKey) {
        let shard = self.shard_for(key);
        shard.sessions.lock().await.remove(key);
    }
}

async fn connect_qpx_h3_upstream_session(
    key: &QpxH3UpstreamSessionKey,
    trust: Option<&qpx_core::tls::CompiledUpstreamTlsTrust>,
    timeout_dur: Duration,
    max_inflight_streams_per_session: usize,
) -> Result<qpx_h3::ClientSession> {
    let upstream_addr = match timeout(
        timeout_dur,
        lookup_host((key.connect_host.as_str(), key.connect_port)),
    )
    .await
    {
        Ok(Ok(mut addrs)) => addrs
            .next()
            .ok_or_else(|| anyhow!("failed to resolve qpx-h3 upstream"))?,
        Ok(Err(err)) => return Err(anyhow!(err)),
        Err(_) => return Err(anyhow!("qpx-h3 upstream resolution timed out")),
    };
    let bind_addr: SocketAddr = if upstream_addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(crate::http3::quic::build_h3_client_config(
        key.verify_upstream,
        trust,
    )?);
    let connection = match timeout(
        timeout_dur,
        endpoint.connect(upstream_addr, &key.connect_host)?,
    )
    .await
    {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => return Err(anyhow!(err)),
        Err(_) => return Err(anyhow!("qpx-h3 upstream connect timed out")),
    };
    crate::http3::quic::enforce_h3_connection_trust(&connection, &key.connect_host, trust)?;
    qpx_h3::ClientSession::new(
        endpoint,
        connection,
        qpx_h3_upstream_session_settings(key, timeout_dur, max_inflight_streams_per_session),
        timeout_dur,
    )
    .await
    .map_err(Into::into)
}

fn qpx_h3_upstream_session_settings(
    key: &QpxH3UpstreamSessionKey,
    timeout_dur: Duration,
    max_inflight_streams_per_session: usize,
) -> qpx_h3::Settings {
    qpx_h3::Settings {
        enable_extended_connect: true,
        enable_datagram: key.enable_datagram,
        enable_webtransport: key.enable_webtransport,
        max_webtransport_sessions: if key.enable_webtransport { 64 } else { 0 },
        max_request_body_bytes: 16 * 1024 * 1024,
        max_concurrent_streams_per_connection: max_inflight_streams_per_session,
        read_timeout: timeout_dur,
        ..Default::default()
    }
}

fn prune_qpx_h3_upstream_sessions(
    sessions: &mut HashMap<QpxH3UpstreamSessionKey, Vec<PooledQpxH3Session>>,
) {
    sessions.retain(|_, entries| {
        entries.retain(|entry| !entry.session.is_closed());
        !entries.is_empty()
    });
}

fn evict_qpx_h3_upstream_session_if_full(
    sessions: &mut HashMap<QpxH3UpstreamSessionKey, Vec<PooledQpxH3Session>>,
    inserting_key: &QpxH3UpstreamSessionKey,
    max_keys: usize,
) {
    crate::pool::evict_oldest_if_full(sessions, inserting_key, max_keys, |entries| {
        entries.iter().map(|entry| entry.created_at).min()
    });
}

fn least_loaded_qpx_h3_session(
    entries: &[PooledQpxH3Session],
    max_inflight_streams_per_session: usize,
) -> Option<qpx_h3::ClientSession> {
    entries
        .iter()
        .filter(|entry| entry.session.inflight_streams() < max_inflight_streams_per_session)
        .min_by_key(|entry| (entry.session.inflight_streams(), entry.created_at))
        .map(|entry| entry.session.clone())
}

fn least_busy_qpx_h3_session(entries: &[PooledQpxH3Session]) -> Option<qpx_h3::ClientSession> {
    entries
        .iter()
        .min_by_key(|entry| (entry.session.inflight_streams(), entry.created_at))
        .map(|entry| entry.session.clone())
}

pub(super) async fn open_pooled_qpx_h3_extended_connect_stream(
    pool: &QpxH3UpstreamSessionPool,
    key: QpxH3UpstreamSessionKey,
    trust: Option<&qpx_core::tls::CompiledUpstreamTlsTrust>,
    request: http::Request<()>,
    protocol: Option<qpx_h3::Protocol>,
    timeout_dur: Duration,
) -> Result<qpx_h3::ExtendedConnectStream> {
    let mut last_err = None;
    for attempt in 0..2 {
        let session = pool.acquire(key.clone(), trust, timeout_dur).await?;
        match session
            .open_extended_connect_stream(request.clone(), protocol.clone(), timeout_dur)
            .await
        {
            Ok(stream) => return Ok(stream),
            Err(err) if attempt == 0 && session.is_closed() => {
                pool.forget(&key).await;
                last_err = Some(err);
            }
            Err(err) => return Err(err.into()),
        }
    }
    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("failed to open qpx-h3 upstream stream")))
}
