use anyhow::Result;
use bytes::Bytes;
use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::task::Poll;
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tracing::warn;

use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_http::tls::client::{BoxTlsStream, connect_tls_h2_h1_with_info_with_options};

pub(super) type SharedOriginH2Sender = h2::client::SendRequest<Bytes>;
const DIRECT_ORIGIN_POOL_SHARDS: usize = 32;
const DIRECT_ORIGIN_POOL_MAX_SLOTS: usize = 4096;
const DIRECT_ORIGIN_POOL_MAX_SLOTS_PER_SHARD: usize =
    DIRECT_ORIGIN_POOL_MAX_SLOTS / DIRECT_ORIGIN_POOL_SHARDS;
pub(super) const MAX_POOLED_HTTP1_CONNECTIONS_PER_ORIGIN: usize = 8;
const MAX_POOLED_H2_CONNECTIONS_PER_ORIGIN: usize = 4;
static DIRECT_ORIGIN_POOL_EVICTIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct PlainHttpOriginPoolKey {
    connect_authority: Arc<str>,
    host_authority: Arc<str>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct HttpsOriginPoolKey {
    connect_authority: Arc<str>,
    host_authority: Arc<str>,
    server_name: Arc<str>,
    verify_upstream_cert: bool,
    trust_key: Option<Arc<str>>,
}

pub(super) struct PlainHttpOriginSlot {
    pub(super) idle: Arc<AsyncMutex<Vec<TcpStream>>>,
}

pub(super) struct TlsHttp1OriginConnection {
    pub(super) stream: qpx_http::tls::client::BoxTlsStream,
    pub(super) upstream_cert: UpstreamCertificateInfo,
}

pub(super) struct SharedTlsH2OriginConnection {
    pub(super) sender: SharedOriginH2Sender,
    pub(super) upstream_cert: UpstreamCertificateInfo,
    pub(super) inflight_streams: Arc<AtomicUsize>,
}

pub(super) enum HttpsConnectionAcquisition {
    H2Ready {
        shared: Arc<SharedTlsH2OriginConnection>,
        ready: SharedOriginH2Sender,
    },
    H1(TlsHttp1OriginConnection),
}

#[derive(Default)]
struct H2PoolState {
    connections: Vec<Arc<SharedTlsH2OriginConnection>>,
    connecting: usize,
}

pub(super) struct HttpsOriginSlot {
    pub(super) http1_idle: Arc<AsyncMutex<Vec<TlsHttp1OriginConnection>>>,
    h2: StdMutex<H2PoolState>,
    h2_ready: Arc<Notify>,
    h2_rr: AtomicUsize,
}

pub(super) struct H2ConnectionReservation<'a> {
    slot: Option<&'a HttpsOriginSlot>,
}

impl HttpsOriginSlot {
    pub(super) fn has_h2_connections(&self) -> bool {
        !self
            .h2
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .connections
            .is_empty()
    }

    fn has_h2_connecting(&self) -> bool {
        self.h2
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .connecting
            > 0
    }

    fn h2_snapshot(&self) -> Vec<Arc<SharedTlsH2OriginConnection>> {
        self.h2
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .connections
            .clone()
    }

    pub(super) fn try_reserve_h2_connection(&self) -> Option<H2ConnectionReservation<'_>> {
        let mut guard = self
            .h2
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.connections.len() + guard.connecting >= MAX_POOLED_H2_CONNECTIONS_PER_ORIGIN {
            return None;
        }
        guard.connecting += 1;
        Some(H2ConnectionReservation { slot: Some(self) })
    }

    fn can_open_additional_h2_connection(&self) -> bool {
        let guard = self
            .h2
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.connections.len() + guard.connecting < MAX_POOLED_H2_CONNECTIONS_PER_ORIGIN
    }

    pub(super) fn add_h2_connection(&self, connection: Arc<SharedTlsH2OriginConnection>) {
        let mut guard = self
            .h2
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.connecting = guard.connecting.saturating_sub(1);
        if guard
            .connections
            .iter()
            .any(|current| Arc::ptr_eq(current, &connection))
        {
            self.h2_ready.notify_waiters();
            return;
        }
        guard.connections.push(connection);
        self.h2_ready.notify_waiters();
    }

    fn release_h2_connection_reservation(&self) {
        let mut guard = self
            .h2
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.connecting = guard.connecting.saturating_sub(1);
        self.h2_ready.notify_waiters();
    }

    pub(super) fn remove_h2_connection(&self, connection: &Arc<SharedTlsH2OriginConnection>) {
        let mut guard = self
            .h2
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .connections
            .retain(|current| !Arc::ptr_eq(current, connection));
        self.h2_ready.notify_waiters();
    }
}

impl<'a> H2ConnectionReservation<'a> {
    pub(super) fn complete(mut self, connection: Arc<SharedTlsH2OriginConnection>) {
        if let Some(slot) = self.slot.take() {
            slot.add_h2_connection(connection);
        }
    }
}

impl Drop for H2ConnectionReservation<'_> {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            slot.release_h2_connection_reservation();
        }
    }
}

type PlainHttpOriginPoolShard = RwLock<HashMap<PlainHttpOriginPoolKey, Arc<PlainHttpOriginSlot>>>;
type HttpsOriginPoolShard = RwLock<HashMap<HttpsOriginPoolKey, Arc<HttpsOriginSlot>>>;

/// Per-runtime direct-origin connection pools (plain HTTP/1 + HTTPS H1/H2).
/// Owned by [`crate::pool::PoolRegistry`] (formerly process-global `OnceLock`s).
pub(crate) struct DirectOriginPools {
    plain: Vec<PlainHttpOriginPoolShard>,
    https: Vec<HttpsOriginPoolShard>,
}

impl Default for DirectOriginPools {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectOriginPools {
    pub(crate) fn new() -> Self {
        Self {
            plain: init_sharded_pool(),
            https: init_sharded_pool(),
        }
    }

    pub(crate) fn clear(&self) {
        for shard in &self.plain {
            shard
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
        }
        for shard in &self.https {
            shard
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
        }
    }

    pub(super) fn plain_slot(&self, key: PlainHttpOriginPoolKey) -> Arc<PlainHttpOriginSlot> {
        typed_pool_slot(&self.plain, key, || PlainHttpOriginSlot {
            idle: Arc::new(AsyncMutex::new(Vec::new())),
        })
    }

    pub(super) fn https_slot(&self, key: HttpsOriginPoolKey) -> Arc<HttpsOriginSlot> {
        typed_pool_slot(&self.https, key, || HttpsOriginSlot {
            http1_idle: Arc::new(AsyncMutex::new(Vec::new())),
            h2: StdMutex::new(H2PoolState::default()),
            h2_ready: Arc::new(Notify::new()),
            h2_rr: AtomicUsize::new(0),
        })
    }
}

fn init_sharded_pool<K, V>() -> Vec<RwLock<HashMap<K, Arc<V>>>> {
    (0..DIRECT_ORIGIN_POOL_SHARDS)
        .map(|_| RwLock::new(HashMap::new()))
        .collect()
}

fn typed_pool_slot<K, V, F>(pool: &[RwLock<HashMap<K, Arc<V>>>], key: K, init: F) -> Arc<V>
where
    K: Eq + Hash + Clone + std::fmt::Debug,
    F: FnOnce() -> V,
{
    let shard = &pool[qpx_http::sharding::modulo(&key, DIRECT_ORIGIN_POOL_SHARDS)];
    if let Some(slot) = shard
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&key)
        .cloned()
    {
        return slot;
    }
    let mut guard = shard
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !guard.contains_key(&key) && guard.len() >= DIRECT_ORIGIN_POOL_MAX_SLOTS_PER_SHARD {
        evict_direct_origin_pool_slot(&mut guard);
    }
    guard.entry(key).or_insert_with(|| Arc::new(init())).clone()
}

fn evict_direct_origin_pool_slot<K, V>(guard: &mut HashMap<K, Arc<V>>)
where
    K: Eq + Hash + Clone + std::fmt::Debug,
{
    let Some(key) = guard
        .iter()
        .find(|(_, slot)| Arc::strong_count(slot) == 1)
        .map(|(key, _)| key.clone())
        .or_else(|| guard.keys().next().cloned())
    else {
        return;
    };
    let evicted_active = guard
        .get(&key)
        .is_some_and(|slot| Arc::strong_count(slot) > 1);
    guard.remove(&key);
    let evictions = DIRECT_ORIGIN_POOL_EVICTIONS.fetch_add(1, Ordering::Relaxed) + 1;
    super::metrics::direct_origin_pool_eviction();
    warn!(
        ?key,
        evicted_active,
        evictions,
        "direct origin connection pool evicted origin slot after reaching cardinality cap"
    );
}

pub(super) fn plain_http_origin_pool_key(
    connect_authority: &str,
    host_authority: &str,
) -> PlainHttpOriginPoolKey {
    PlainHttpOriginPoolKey {
        connect_authority: Arc::from(connect_authority),
        host_authority: Arc::from(host_authority),
    }
}

pub(super) fn https_origin_pool_key(
    connect_authority: &str,
    host_authority: &str,
    server_name: &str,
    verify_upstream_cert: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> HttpsOriginPoolKey {
    HttpsOriginPoolKey {
        connect_authority: Arc::from(connect_authority),
        host_authority: Arc::from(host_authority),
        server_name: Arc::from(server_name),
        verify_upstream_cert,
        trust_key: trust.map(|value| Arc::<str>::from(value.pool_key())),
    }
}

async fn sender_ready_now(sender: &mut SharedOriginH2Sender) -> Option<Result<(), h2::Error>> {
    poll_fn(|cx| match sender.poll_ready(cx) {
        Poll::Ready(result) => Poll::Ready(Some(result)),
        Poll::Pending => Poll::Ready(None),
    })
    .await
}

fn h2_connection_scale_out_threshold(sender: &SharedOriginH2Sender) -> usize {
    sender.current_max_send_streams().max(1)
}

pub(super) fn spawn_origin_h2_connection_task(
    connection: impl Future<Output = Result<(), h2::Error>> + Send + 'static,
) {
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            warn!(error = ?err, "reverse_edges upstream h2 connection closed");
        }
    });
}

pub(super) async fn try_take_ready_h2_sender(
    slot: &HttpsOriginSlot,
    upstream: &str,
) -> Option<(Arc<SharedTlsH2OriginConnection>, SharedOriginH2Sender)> {
    let snapshot = slot.h2_snapshot();
    if snapshot.is_empty() {
        return None;
    }
    let start = slot.h2_rr.fetch_add(1, Ordering::Relaxed);
    let mut best_reusable = None::<(
        Arc<SharedTlsH2OriginConnection>,
        SharedOriginH2Sender,
        usize,
        usize,
    )>;
    let mut best_saturated = None::<(
        Arc<SharedTlsH2OriginConnection>,
        SharedOriginH2Sender,
        usize,
        usize,
    )>;
    for offset in 0..snapshot.len() {
        let shared = snapshot[(start + offset) % snapshot.len()].clone();
        let mut sender = shared.sender.clone();
        match sender_ready_now(&mut sender).await {
            Some(Ok(())) => {
                let inflight = shared.inflight_streams.load(Ordering::Relaxed);
                let threshold = h2_connection_scale_out_threshold(&sender);
                if inflight < threshold {
                    let headroom = threshold - inflight;
                    match &best_reusable {
                        Some((_, _, best_inflight, best_headroom))
                            if headroom < *best_headroom
                                || (headroom == *best_headroom && inflight >= *best_inflight) => {}
                        _ => best_reusable = Some((shared, sender, inflight, headroom)),
                    }
                } else {
                    match &best_saturated {
                        Some((_, _, best_inflight, best_threshold))
                            if inflight > *best_inflight
                                || (inflight == *best_inflight && threshold >= *best_threshold) => {
                        }
                        _ => best_saturated = Some((shared, sender, inflight, threshold)),
                    }
                }
            }
            Some(Err(err)) => {
                slot.remove_h2_connection(&shared);
                warn!(
                    error = ?err,
                    upstream = %upstream,
                    "reverse_edges upstream pooled h2 connection closed"
                );
            }
            None => {}
        }
    }
    if let Some((shared, sender, _, _)) = best_reusable {
        return Some((shared, sender));
    }
    if !slot.can_open_additional_h2_connection() {
        return best_saturated.map(|(shared, sender, _, _)| (shared, sender));
    }
    None
}

pub(super) async fn wait_for_h2_sender(
    slot: &HttpsOriginSlot,
    upstream: &str,
) -> Option<(Arc<SharedTlsH2OriginConnection>, SharedOriginH2Sender)> {
    loop {
        let snapshot = slot.h2_snapshot();
        if snapshot.is_empty() {
            return None;
        }
        let shared = snapshot
            .into_iter()
            .min_by_key(|connection| connection.inflight_streams.load(Ordering::Relaxed))?;
        match shared.sender.clone().ready().await {
            Ok(ready) => return Some((shared, ready)),
            Err(err) => {
                slot.remove_h2_connection(&shared);
                warn!(
                    error = ?err,
                    upstream = %upstream,
                    "reverse_edges upstream pooled h2 connection closed"
                );
            }
        }
    }
}

pub(super) async fn open_https_origin_stream(
    connect_authority: &str,
    server_name: &str,
    verify_upstream_cert: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<(BoxTlsStream, bool, UpstreamCertificateInfo)> {
    let tcp = TcpStream::connect(connect_authority).await?;
    let _ = tcp.set_nodelay(true);
    connect_tls_h2_h1_with_info_with_options(server_name, tcp, verify_upstream_cert, trust).await
}

pub(super) async fn acquire_https_connection(
    slot: &HttpsOriginSlot,
    connect_authority: &str,
    server_name: &str,
    verify_upstream_cert: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<HttpsConnectionAcquisition> {
    if let Some((shared, ready)) = try_take_ready_h2_sender(slot, connect_authority).await {
        return Ok(HttpsConnectionAcquisition::H2Ready { shared, ready });
    }

    if slot.has_h2_connections()
        && let Some(reservation) = slot.try_reserve_h2_connection()
    {
        match open_https_origin_stream(connect_authority, server_name, verify_upstream_cert, trust)
            .await
        {
            Ok((tls, negotiated_h2, upstream_cert)) => {
                if negotiated_h2 {
                    let (sender, connection) = h2::client::Builder::new().handshake(tls).await?;
                    spawn_origin_h2_connection_task(connection);
                    let shared = Arc::new(SharedTlsH2OriginConnection {
                        sender: sender.clone(),
                        upstream_cert: upstream_cert.clone(),
                        inflight_streams: Arc::new(AtomicUsize::new(0)),
                    });
                    reservation.complete(shared.clone());
                    let ready = match sender.ready().await {
                        Ok(ready) => ready,
                        Err(err) => {
                            slot.remove_h2_connection(&shared);
                            return Err(err.into());
                        }
                    };
                    return Ok(HttpsConnectionAcquisition::H2Ready { shared, ready });
                }
                drop(reservation);
                return Ok(HttpsConnectionAcquisition::H1(TlsHttp1OriginConnection {
                    stream: tls,
                    upstream_cert,
                }));
            }
            Err(err) => {
                drop(reservation);
                if let Some((shared, ready)) = wait_for_h2_sender(slot, connect_authority).await {
                    return Ok(HttpsConnectionAcquisition::H2Ready { shared, ready });
                }
                return Err(err);
            }
        }
    }

    if let Some((shared, ready)) = wait_for_h2_sender(slot, connect_authority).await {
        return Ok(HttpsConnectionAcquisition::H2Ready { shared, ready });
    }

    if let Some(entry) = { slot.http1_idle.lock().await.pop() } {
        return Ok(HttpsConnectionAcquisition::H1(entry));
    }

    loop {
        let notified = slot.h2_ready.notified();
        if !slot.has_h2_connecting() {
            break;
        }
        notified.await;
        if let Some((shared, ready)) = wait_for_h2_sender(slot, connect_authority).await {
            return Ok(HttpsConnectionAcquisition::H2Ready { shared, ready });
        }
        if let Some(entry) = { slot.http1_idle.lock().await.pop() } {
            return Ok(HttpsConnectionAcquisition::H1(entry));
        }
    }

    let reservation = loop {
        if let Some(reservation) = slot.try_reserve_h2_connection() {
            break reservation;
        }
        let notified = slot.h2_ready.notified();
        notified.await;
        if let Some((shared, ready)) = wait_for_h2_sender(slot, connect_authority).await {
            return Ok(HttpsConnectionAcquisition::H2Ready { shared, ready });
        }
        if let Some(entry) = { slot.http1_idle.lock().await.pop() } {
            return Ok(HttpsConnectionAcquisition::H1(entry));
        }
    };
    let (tls, negotiated_h2, upstream_cert) =
        open_https_origin_stream(connect_authority, server_name, verify_upstream_cert, trust)
            .await?;
    if negotiated_h2 {
        let (sender, connection) = h2::client::Builder::new().handshake(tls).await?;
        spawn_origin_h2_connection_task(connection);
        let shared = Arc::new(SharedTlsH2OriginConnection {
            sender: sender.clone(),
            upstream_cert: upstream_cert.clone(),
            inflight_streams: Arc::new(AtomicUsize::new(0)),
        });
        reservation.complete(shared.clone());
        let ready = match sender.ready().await {
            Ok(ready) => ready,
            Err(err) => {
                slot.remove_h2_connection(&shared);
                return Err(err.into());
            }
        };
        return Ok(HttpsConnectionAcquisition::H2Ready { shared, ready });
    }

    drop(reservation);
    Ok(HttpsConnectionAcquisition::H1(TlsHttp1OriginConnection {
        stream: tls,
        upstream_cert,
    }))
}

#[cfg(test)]
mod tests;
