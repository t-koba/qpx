use anyhow::Result;
use bytes::Bytes;
use metrics::counter;
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::future::{poll_fn, Future};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::task::Poll;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tracing::warn;

use crate::tls::CompiledUpstreamTlsTrust;
use crate::tls::UpstreamCertificateInfo;

pub(super) type SharedOriginH2Sender = h2::client::SendRequest<Bytes>;
const DIRECT_ORIGIN_POOL_SHARDS: usize = 32;
const DIRECT_ORIGIN_POOL_MAX_SLOTS: usize = 4096;
const DIRECT_ORIGIN_POOL_MAX_SLOTS_PER_SHARD: usize =
    DIRECT_ORIGIN_POOL_MAX_SLOTS / DIRECT_ORIGIN_POOL_SHARDS;
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
    trust_identity: usize,
}

pub(super) struct PlainHttpOriginSlot {
    pub(super) idle: Arc<AsyncMutex<Vec<TcpStream>>>,
}

pub(super) struct TlsHttp1OriginConnection {
    pub(super) stream: crate::tls::client::BoxTlsStream,
    pub(super) upstream_cert: UpstreamCertificateInfo,
}

pub(super) struct SharedTlsH2OriginConnection {
    pub(super) sender: SharedOriginH2Sender,
    pub(super) upstream_cert: UpstreamCertificateInfo,
    pub(super) inflight_streams: Arc<AtomicUsize>,
}

#[derive(Default)]
struct H2PoolState {
    connections: Vec<Arc<SharedTlsH2OriginConnection>>,
    connecting: usize,
}

pub(super) struct HttpsOriginSlot {
    pub(super) http1_idle: Arc<AsyncMutex<Vec<TlsHttp1OriginConnection>>>,
    h2: StdMutex<H2PoolState>,
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
            .expect("https origin h2 pool poisoned")
            .connections
            .is_empty()
    }

    fn h2_snapshot(&self) -> Vec<Arc<SharedTlsH2OriginConnection>> {
        self.h2
            .lock()
            .expect("https origin h2 pool poisoned")
            .connections
            .clone()
    }

    pub(super) fn try_reserve_h2_connection(&self) -> Option<H2ConnectionReservation<'_>> {
        let mut guard = self.h2.lock().expect("https origin h2 pool poisoned");
        if guard.connections.len() + guard.connecting >= MAX_POOLED_H2_CONNECTIONS_PER_ORIGIN {
            return None;
        }
        guard.connecting += 1;
        Some(H2ConnectionReservation { slot: Some(self) })
    }

    fn can_open_additional_h2_connection(&self) -> bool {
        let guard = self.h2.lock().expect("https origin h2 pool poisoned");
        guard.connections.len() + guard.connecting < MAX_POOLED_H2_CONNECTIONS_PER_ORIGIN
    }

    pub(super) fn add_h2_connection(&self, connection: Arc<SharedTlsH2OriginConnection>) {
        let mut guard = self.h2.lock().expect("https origin h2 pool poisoned");
        guard.connecting = guard.connecting.saturating_sub(1);
        if guard
            .connections
            .iter()
            .any(|current| Arc::ptr_eq(current, &connection))
        {
            return;
        }
        guard.connections.push(connection);
    }

    fn release_h2_connection_reservation(&self) {
        let mut guard = self.h2.lock().expect("https origin h2 pool poisoned");
        guard.connecting = guard.connecting.saturating_sub(1);
    }

    pub(super) fn remove_h2_connection(&self, connection: &Arc<SharedTlsH2OriginConnection>) {
        let mut guard = self.h2.lock().expect("https origin h2 pool poisoned");
        guard
            .connections
            .retain(|current| !Arc::ptr_eq(current, connection));
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

fn plain_http_origin_pool() -> &'static [PlainHttpOriginPoolShard] {
    static POOL: OnceLock<Vec<PlainHttpOriginPoolShard>> = OnceLock::new();
    POOL.get_or_init(init_sharded_pool).as_slice()
}

fn https_origin_pool() -> &'static [HttpsOriginPoolShard] {
    static POOL: OnceLock<Vec<HttpsOriginPoolShard>> = OnceLock::new();
    POOL.get_or_init(init_sharded_pool).as_slice()
}

fn init_sharded_pool<K, V>() -> Vec<RwLock<HashMap<K, Arc<V>>>> {
    (0..DIRECT_ORIGIN_POOL_SHARDS)
        .map(|_| RwLock::new(HashMap::new()))
        .collect()
}

fn pool_shard_idx<K: Hash>(key: &K) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % DIRECT_ORIGIN_POOL_SHARDS
}

fn typed_pool_slot<K, V, F>(pool: &[RwLock<HashMap<K, Arc<V>>>], key: K, init: F) -> Arc<V>
where
    K: Eq + Hash + Clone + std::fmt::Debug,
    F: FnOnce() -> V,
{
    let shard = &pool[pool_shard_idx(&key)];
    if let Some(slot) = shard
        .read()
        .expect("direct origin pool shard poisoned")
        .get(&key)
        .cloned()
    {
        return slot;
    }
    let mut guard = shard.write().expect("direct origin pool shard poisoned");
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
    counter!("qpx_direct_origin_pool_evictions_total").increment(1);
    warn!(
        ?key,
        evicted_active,
        evictions,
        "direct origin connection pool evicted origin slot after reaching cardinality cap"
    );
}

pub(crate) fn clear_direct_origin_connection_pools() {
    for shard in plain_http_origin_pool() {
        shard
            .write()
            .expect("plain direct origin pool shard poisoned")
            .clear();
    }
    for shard in https_origin_pool() {
        shard
            .write()
            .expect("https direct origin pool shard poisoned")
            .clear();
    }
}

pub(super) fn plain_http_origin_slot(key: PlainHttpOriginPoolKey) -> Arc<PlainHttpOriginSlot> {
    typed_pool_slot(plain_http_origin_pool(), key, || PlainHttpOriginSlot {
        idle: Arc::new(AsyncMutex::new(Vec::new())),
    })
}

pub(super) fn https_origin_slot(key: HttpsOriginPoolKey) -> Arc<HttpsOriginSlot> {
    typed_pool_slot(https_origin_pool(), key, || HttpsOriginSlot {
        http1_idle: Arc::new(AsyncMutex::new(Vec::new())),
        h2: StdMutex::new(H2PoolState::default()),
        h2_rr: AtomicUsize::new(0),
    })
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
        trust_identity: trust.map_or(0usize, |value| value as *const _ as usize),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::UpstreamCertificateInfo;
    use tokio::io::duplex;

    fn test_https_origin_slot() -> HttpsOriginSlot {
        HttpsOriginSlot {
            http1_idle: Arc::new(AsyncMutex::new(Vec::new())),
            h2: StdMutex::new(H2PoolState::default()),
            h2_rr: AtomicUsize::new(0),
        }
    }

    async fn spawn_test_h2_sender_with_limits(
        max_concurrent_streams: Option<u32>,
        initial_max_send_streams: Option<usize>,
    ) -> Result<SharedOriginH2Sender> {
        let (client_io, server_io) = duplex(16 * 1024);
        tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            if let Some(max_concurrent_streams) = max_concurrent_streams {
                builder.max_concurrent_streams(max_concurrent_streams);
            }
            let mut server = builder
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server handshake");
            while let Some(result) = server.accept().await {
                let _ = result.expect("server accept");
            }
        });
        let mut builder = h2::client::Builder::new();
        if let Some(initial_max_send_streams) = initial_max_send_streams {
            builder.initial_max_send_streams(initial_max_send_streams);
        }
        let (sender, connection) = builder.handshake(client_io).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(sender)
    }

    async fn spawn_test_h2_sender() -> Result<SharedOriginH2Sender> {
        spawn_test_h2_sender_with_limits(None, None).await
    }

    #[test]
    fn h2_connection_reservation_drop_releases_connecting_slot() {
        let slot = test_https_origin_slot();
        let reservation = slot
            .try_reserve_h2_connection()
            .expect("reservation should succeed");
        assert_eq!(slot.h2.lock().expect("pool").connecting, 1);
        drop(reservation);
        let guard = slot.h2.lock().expect("pool");
        assert_eq!(guard.connecting, 0);
        assert!(guard.connections.is_empty());
    }

    #[tokio::test]
    async fn h2_connection_reservation_complete_moves_connection_into_pool() -> Result<()> {
        let slot = test_https_origin_slot();
        let reservation = slot
            .try_reserve_h2_connection()
            .expect("reservation should succeed");
        let shared = Arc::new(SharedTlsH2OriginConnection {
            sender: spawn_test_h2_sender().await?,
            upstream_cert: UpstreamCertificateInfo::default(),
            inflight_streams: Arc::new(AtomicUsize::new(0)),
        });
        reservation.complete(shared.clone());
        let guard = slot.h2.lock().expect("pool");
        assert_eq!(guard.connecting, 0);
        assert_eq!(guard.connections.len(), 1);
        assert!(Arc::ptr_eq(&guard.connections[0], &shared));
        Ok(())
    }

    #[tokio::test]
    async fn try_take_ready_h2_sender_reuses_busy_connection_below_scale_out_threshold(
    ) -> Result<()> {
        let slot = test_https_origin_slot();
        let shared = Arc::new(SharedTlsH2OriginConnection {
            sender: spawn_test_h2_sender_with_limits(Some(64), Some(64)).await?,
            upstream_cert: UpstreamCertificateInfo::default(),
            inflight_streams: Arc::new(AtomicUsize::new(63)),
        });
        slot.add_h2_connection(shared.clone());

        let selected = try_take_ready_h2_sender(&slot, "test-upstream")
            .await
            .expect("busy h2 connection should still be reused");
        assert!(Arc::ptr_eq(&selected.0, &shared));
        Ok(())
    }

    #[tokio::test]
    async fn try_take_ready_h2_sender_uses_large_peer_budget_without_premature_scale_out(
    ) -> Result<()> {
        let slot = test_https_origin_slot();
        let shared = Arc::new(SharedTlsH2OriginConnection {
            sender: spawn_test_h2_sender_with_limits(Some(128), Some(128)).await?,
            upstream_cert: UpstreamCertificateInfo::default(),
            inflight_streams: Arc::new(AtomicUsize::new(96)),
        });
        slot.add_h2_connection(shared.clone());

        let selected = try_take_ready_h2_sender(&slot, "test-upstream")
            .await
            .expect("high-budget h2 connection should still be reused");
        assert!(Arc::ptr_eq(&selected.0, &shared));
        Ok(())
    }

    #[tokio::test]
    async fn try_take_ready_h2_sender_prefers_scale_out_for_saturated_connection() -> Result<()> {
        let slot = test_https_origin_slot();
        let shared = Arc::new(SharedTlsH2OriginConnection {
            sender: spawn_test_h2_sender_with_limits(Some(1), Some(1)).await?,
            upstream_cert: UpstreamCertificateInfo::default(),
            inflight_streams: Arc::new(AtomicUsize::new(1)),
        });
        slot.add_h2_connection(shared);

        assert!(slot.can_open_additional_h2_connection());
        assert!(try_take_ready_h2_sender(&slot, "test-upstream")
            .await
            .is_none());
        Ok(())
    }

    #[tokio::test]
    async fn try_take_ready_h2_sender_prefers_reusable_connection_over_saturated_one() -> Result<()>
    {
        let slot = test_https_origin_slot();
        let saturated = Arc::new(SharedTlsH2OriginConnection {
            sender: spawn_test_h2_sender_with_limits(Some(1), Some(1)).await?,
            upstream_cert: UpstreamCertificateInfo::default(),
            inflight_streams: Arc::new(AtomicUsize::new(1)),
        });
        let reusable = Arc::new(SharedTlsH2OriginConnection {
            sender: spawn_test_h2_sender().await?,
            upstream_cert: UpstreamCertificateInfo::default(),
            inflight_streams: Arc::new(AtomicUsize::new(2)),
        });
        slot.add_h2_connection(saturated);
        slot.add_h2_connection(reusable.clone());

        let selected = try_take_ready_h2_sender(&slot, "test-upstream")
            .await
            .expect("reusable h2 connection should be selected");
        assert!(Arc::ptr_eq(&selected.0, &reusable));
        Ok(())
    }
}
