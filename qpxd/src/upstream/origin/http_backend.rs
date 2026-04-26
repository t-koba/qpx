use crate::http::body::Body;
use ::http::{Request as Http1Request, Response as Http1Response};
use anyhow::{anyhow, Result};
use bytes::Bytes;
use hyper::header::{HeaderValue, HOST};
use hyper::{Request, Response, Uri};
use metrics::counter;
use std::collections::{hash_map::DefaultHasher, HashMap};
use std::future::{poll_fn, Future};
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, RwLock};
use std::task::Poll;
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;
use tracing::warn;

use crate::http::common::request_with_shared_client;
use crate::http::h2_codec::{
    h1_headers_to_http, h2_response_to_hyper_with_inflight, http_headers_to_h1,
    parse_declared_content_length,
};
use crate::http::l7::prepare_request_with_headers_in_place;
use crate::tls::client::connect_tls_h2_h1_with_info_with_options;
use crate::tls::{CompiledUpstreamTlsTrust, UpstreamCertificateInfo};
use crate::upstream::raw_http1::{
    send_http1_request_with_interim_reusable, Http1ConnectionRecycler, Http1ResponseWithInterim,
};

use super::dispatch::{origin_scheme, OriginScheme};
use super::ipc_backend::proxy_ipc_with_interim;
use super::OriginEndpoint;

pub(crate) async fn proxy_http(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Response<Body>> {
    let mut proxied = proxy_http_with_interim(req, origin, proxy_name, trust).await?;
    if !proxied.interim.is_empty() {
        proxied.response.extensions_mut().insert(proxied.interim);
    }
    Ok(proxied.response)
}

pub(crate) async fn proxy_http_with_interim(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Http1ResponseWithInterim> {
    match origin_scheme(origin)? {
        OriginScheme::Http | OriginScheme::Ws => proxy_plain_http(req, origin, proxy_name).await,
        OriginScheme::Https | OriginScheme::Wss => {
            proxy_https(req, origin, proxy_name, trust).await
        }
        OriginScheme::Ipc | OriginScheme::IpcUnix => {
            proxy_ipc_with_interim(req, origin, proxy_name).await
        }
    }
}

pub(crate) struct SharedReverseHttpClient;

pub(crate) fn shared_reverse_http_client() -> &'static SharedReverseHttpClient {
    static CLIENT: SharedReverseHttpClient = SharedReverseHttpClient;
    &CLIENT
}

impl SharedReverseHttpClient {
    pub(crate) async fn request(&self, req: Request<Body>) -> Result<Response<Body>> {
        Ok(request_with_shared_client(req).await?)
    }
}

pub(crate) struct SharedReverseHttpsClient;

pub(crate) fn shared_reverse_https_client() -> &'static SharedReverseHttpsClient {
    static CLIENT: OnceLock<SharedReverseHttpsClient> = OnceLock::new();
    CLIENT.get_or_init(|| SharedReverseHttpsClient)
}

impl SharedReverseHttpsClient {
    pub(crate) async fn request(&self, req: Request<Body>) -> Result<Response<Body>> {
        let target = absolute_request_target(req.uri())?;
        let authority =
            crate::http::address::format_authority_host_port(target.host.as_str(), target.port);
        let slot = https_origin_slot(https_origin_pool_key(
            authority.as_str(),
            authority.as_str(),
            target.host.as_str(),
            true,
            None,
        ));

        if let Some((shared_h2, ready)) = try_take_ready_h2_sender(&slot, authority.as_str()).await
        {
            let req = prepare_internal_h2_request(req, target.scheme.as_str(), authority.as_str())?;
            let mut proxied = send_h2_request_with_sender(
                req,
                ready,
                Some(shared_h2.upstream_cert.clone()),
                Some(shared_h2.inflight_streams.clone()),
            )
            .await?;
            if !proxied.interim.is_empty() {
                proxied.response.extensions_mut().insert(proxied.interim);
            }
            return Ok(proxied.response);
        }

        if slot.has_h2_connections() {
            if let Some(reservation) = slot.try_reserve_h2_connection() {
                match open_https_origin_stream(authority.as_str(), target.host.as_str(), true, None)
                    .await
                {
                    Ok((tls, negotiated_h2, upstream_cert)) => {
                        if negotiated_h2 {
                            let (sender, connection) =
                                match h2::client::Builder::new().handshake(tls).await {
                                    Ok(handshake) => handshake,
                                    Err(err) => return Err(err.into()),
                                };
                            spawn_origin_h2_connection_task(connection);
                            let shared_h2 = Arc::new(SharedTlsH2OriginConnection {
                                sender: sender.clone(),
                                upstream_cert: upstream_cert.clone(),
                                inflight_streams: Arc::new(AtomicUsize::new(0)),
                            });
                            reservation.complete(shared_h2.clone());
                            let req = prepare_internal_h2_request(
                                req,
                                target.scheme.as_str(),
                                authority.as_str(),
                            )?;
                            let ready = match sender.ready().await {
                                Ok(ready) => ready,
                                Err(err) => {
                                    slot.remove_h2_connection(&shared_h2);
                                    return Err(err.into());
                                }
                            };
                            let mut proxied = send_h2_request_with_sender(
                                req,
                                ready,
                                Some(upstream_cert),
                                Some(shared_h2.inflight_streams.clone()),
                            )
                            .await?;
                            if !proxied.interim.is_empty() {
                                proxied.response.extensions_mut().insert(proxied.interim);
                            }
                            return Ok(proxied.response);
                        }
                        drop(reservation);
                        let req = prepare_internal_http1_request(req, authority.as_str())?;
                        let mut proxied = send_http1_request_with_interim_reusable(
                            tls,
                            req,
                            Http1ConnectionRecycler::new({
                                let idle = slot.http1_idle.clone();
                                let upstream_cert = upstream_cert.clone();
                                move |stream| {
                                    let idle = idle.clone();
                                    let upstream_cert = upstream_cert.clone();
                                    async move {
                                        idle.lock().await.push(TlsHttp1OriginConnection {
                                            stream,
                                            upstream_cert,
                                        });
                                    }
                                }
                            }),
                        )
                        .await?;
                        if !proxied.interim.is_empty() {
                            proxied.response.extensions_mut().insert(proxied.interim);
                        }
                        proxied.upstream_cert = Some(upstream_cert);
                        return Ok(proxied.response);
                    }
                    Err(err) => {
                        drop(reservation);
                        if let Some((shared_h2, ready)) =
                            wait_for_h2_sender(&slot, authority.as_str()).await
                        {
                            let req = prepare_internal_h2_request(
                                req,
                                target.scheme.as_str(),
                                authority.as_str(),
                            )?;
                            let mut proxied = send_h2_request_with_sender(
                                req,
                                ready,
                                Some(shared_h2.upstream_cert.clone()),
                                Some(shared_h2.inflight_streams.clone()),
                            )
                            .await?;
                            if !proxied.interim.is_empty() {
                                proxied.response.extensions_mut().insert(proxied.interim);
                            }
                            return Ok(proxied.response);
                        }
                        return Err(err);
                    }
                }
            }
        }

        if let Some((shared_h2, ready)) = wait_for_h2_sender(&slot, authority.as_str()).await {
            let req = prepare_internal_h2_request(req, target.scheme.as_str(), authority.as_str())?;
            let mut proxied = send_h2_request_with_sender(
                req,
                ready,
                Some(shared_h2.upstream_cert.clone()),
                Some(shared_h2.inflight_streams.clone()),
            )
            .await?;
            if !proxied.interim.is_empty() {
                proxied.response.extensions_mut().insert(proxied.interim);
            }
            return Ok(proxied.response);
        }

        if let Some(entry) = { slot.http1_idle.lock().await.pop() } {
            let req = prepare_internal_http1_request(req, authority.as_str())?;
            let mut proxied = send_http1_request_with_interim_reusable(
                entry.stream,
                req,
                Http1ConnectionRecycler::new({
                    let idle = slot.http1_idle.clone();
                    let upstream_cert = entry.upstream_cert.clone();
                    move |stream| {
                        let idle = idle.clone();
                        let upstream_cert = upstream_cert.clone();
                        async move {
                            idle.lock().await.push(TlsHttp1OriginConnection {
                                stream,
                                upstream_cert,
                            });
                        }
                    }
                }),
            )
            .await?;
            if !proxied.interim.is_empty() {
                proxied.response.extensions_mut().insert(proxied.interim);
            }
            proxied.upstream_cert = Some(entry.upstream_cert);
            return Ok(proxied.response);
        }

        let (tls, negotiated_h2, upstream_cert) =
            open_https_origin_stream(authority.as_str(), target.host.as_str(), true, None).await?;
        if negotiated_h2 {
            let (sender, connection) = h2::client::Builder::new().handshake(tls).await?;
            spawn_origin_h2_connection_task(connection);
            let shared_h2 = Arc::new(SharedTlsH2OriginConnection {
                sender: sender.clone(),
                upstream_cert: upstream_cert.clone(),
                inflight_streams: Arc::new(AtomicUsize::new(0)),
            });
            slot.add_h2_connection(shared_h2.clone());
            let req = prepare_internal_h2_request(req, target.scheme.as_str(), authority.as_str())?;
            let ready = match sender.ready().await {
                Ok(ready) => ready,
                Err(err) => {
                    slot.remove_h2_connection(&shared_h2);
                    return Err(err.into());
                }
            };
            let mut proxied = send_h2_request_with_sender(
                req,
                ready,
                Some(upstream_cert),
                Some(shared_h2.inflight_streams.clone()),
            )
            .await?;
            if !proxied.interim.is_empty() {
                proxied.response.extensions_mut().insert(proxied.interim);
            }
            return Ok(proxied.response);
        }

        let req = prepare_internal_http1_request(req, authority.as_str())?;
        let mut proxied = send_http1_request_with_interim_reusable(
            tls,
            req,
            Http1ConnectionRecycler::new({
                let idle = slot.http1_idle.clone();
                let upstream_cert = upstream_cert.clone();
                move |stream| {
                    let idle = idle.clone();
                    let upstream_cert = upstream_cert.clone();
                    async move {
                        idle.lock().await.push(TlsHttp1OriginConnection {
                            stream,
                            upstream_cert,
                        });
                    }
                }
            }),
        )
        .await?;
        if !proxied.interim.is_empty() {
            proxied.response.extensions_mut().insert(proxied.interim);
        }
        proxied.upstream_cert = Some(upstream_cert);
        Ok(proxied.response)
    }
}

struct AbsoluteRequestTarget {
    scheme: String,
    host: String,
    port: u16,
}

type SharedOriginH2Sender = h2::client::SendRequest<Bytes>;
const DIRECT_ORIGIN_POOL_SHARDS: usize = 32;
const DIRECT_ORIGIN_POOL_MAX_SLOTS: usize = 4096;
const DIRECT_ORIGIN_POOL_MAX_SLOTS_PER_SHARD: usize =
    DIRECT_ORIGIN_POOL_MAX_SLOTS / DIRECT_ORIGIN_POOL_SHARDS;
const MAX_POOLED_H2_CONNECTIONS_PER_ORIGIN: usize = 4;
static DIRECT_ORIGIN_POOL_EVICTIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PlainHttpOriginPoolKey {
    connect_authority: Arc<str>,
    host_authority: Arc<str>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct HttpsOriginPoolKey {
    connect_authority: Arc<str>,
    host_authority: Arc<str>,
    server_name: Arc<str>,
    verify_upstream_cert: bool,
    trust_identity: usize,
}

struct PlainHttpOriginSlot {
    idle: Arc<AsyncMutex<Vec<TcpStream>>>,
}

struct TlsHttp1OriginConnection {
    stream: crate::tls::client::BoxTlsStream,
    upstream_cert: UpstreamCertificateInfo,
}

struct SharedTlsH2OriginConnection {
    sender: SharedOriginH2Sender,
    upstream_cert: UpstreamCertificateInfo,
    inflight_streams: Arc<AtomicUsize>,
}

#[derive(Default)]
struct HttpsOriginH2Pool {
    connections: Vec<Arc<SharedTlsH2OriginConnection>>,
    connecting: usize,
}

struct HttpsOriginSlot {
    http1_idle: Arc<AsyncMutex<Vec<TlsHttp1OriginConnection>>>,
    h2: StdMutex<HttpsOriginH2Pool>,
    h2_rr: AtomicUsize,
}

struct H2ConnectionReservation<'a> {
    slot: Option<&'a HttpsOriginSlot>,
}

impl HttpsOriginSlot {
    fn has_h2_connections(&self) -> bool {
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

    fn try_reserve_h2_connection(&self) -> Option<H2ConnectionReservation<'_>> {
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

    fn add_h2_connection(&self, connection: Arc<SharedTlsH2OriginConnection>) {
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

    fn remove_h2_connection(&self, connection: &Arc<SharedTlsH2OriginConnection>) {
        let mut guard = self.h2.lock().expect("https origin h2 pool poisoned");
        guard
            .connections
            .retain(|current| !Arc::ptr_eq(current, connection));
    }
}

impl<'a> H2ConnectionReservation<'a> {
    fn complete(mut self, connection: Arc<SharedTlsH2OriginConnection>) {
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

fn plain_http_origin_slot(key: PlainHttpOriginPoolKey) -> Arc<PlainHttpOriginSlot> {
    typed_pool_slot(plain_http_origin_pool(), key, || PlainHttpOriginSlot {
        idle: Arc::new(AsyncMutex::new(Vec::new())),
    })
}

fn https_origin_slot(key: HttpsOriginPoolKey) -> Arc<HttpsOriginSlot> {
    typed_pool_slot(https_origin_pool(), key, || HttpsOriginSlot {
        http1_idle: Arc::new(AsyncMutex::new(Vec::new())),
        h2: StdMutex::new(HttpsOriginH2Pool::default()),
        h2_rr: AtomicUsize::new(0),
    })
}

fn plain_http_origin_pool_key(
    connect_authority: &str,
    host_authority: &str,
) -> PlainHttpOriginPoolKey {
    PlainHttpOriginPoolKey {
        connect_authority: Arc::from(connect_authority),
        host_authority: Arc::from(host_authority),
    }
}

fn https_origin_pool_key(
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

async fn open_plain_http_origin_stream(connect_authority: &str) -> Result<TcpStream> {
    let stream = TcpStream::connect(connect_authority).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn open_https_origin_stream(
    connect_authority: &str,
    server_name: &str,
    verify_upstream_cert: bool,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<(
    crate::tls::client::BoxTlsStream,
    bool,
    UpstreamCertificateInfo,
)> {
    let tcp = TcpStream::connect(connect_authority).await?;
    let _ = tcp.set_nodelay(true);
    connect_tls_h2_h1_with_info_with_options(server_name, tcp, verify_upstream_cert, trust).await
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

fn spawn_origin_h2_connection_task(
    connection: impl Future<Output = Result<(), h2::Error>> + Send + 'static,
) {
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            warn!(error = ?err, "reverse upstream h2 connection closed");
        }
    });
}

async fn try_take_ready_h2_sender(
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
                    "reverse upstream pooled h2 connection closed"
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

async fn wait_for_h2_sender(
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
                    "reverse upstream pooled h2 connection closed"
                );
            }
        }
    }
}

async fn proxy_plain_http(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
) -> Result<Http1ResponseWithInterim> {
    let default_port = origin.default_port_hint();
    let connect_authority = origin.connect_authority(default_port)?;
    let host_authority = origin.host_header_authority(default_port)?;
    let slot = plain_http_origin_slot(plain_http_origin_pool_key(
        connect_authority.as_str(),
        host_authority.as_str(),
    ));
    let req = prepare_proxy_http1_request(req, host_authority.as_str(), proxy_name)?;
    let stream = match slot.idle.lock().await.pop() {
        Some(stream) => stream,
        None => open_plain_http_origin_stream(connect_authority.as_str()).await?,
    };
    send_http1_request_with_interim_reusable(
        stream,
        req,
        Http1ConnectionRecycler::from_idle(slot.idle.clone()),
    )
    .await
}

async fn proxy_https(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Http1ResponseWithInterim> {
    proxy_https_with_options(req, origin, proxy_name, trust, true).await
}

async fn proxy_https_with_options(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
    verify_upstream_cert: bool,
) -> Result<Http1ResponseWithInterim> {
    let default_port = origin.default_port_hint();
    let connect_authority = origin.connect_authority(default_port)?;
    let host_authority = origin.host_header_authority(default_port)?;
    let server_name = origin.tls_server_name()?;
    let pool_key = https_origin_pool_key(
        connect_authority.as_str(),
        host_authority.as_str(),
        server_name.as_str(),
        verify_upstream_cert,
        trust,
    );
    let slot = https_origin_slot(pool_key);

    if let Some((shared_h2, ready)) =
        try_take_ready_h2_sender(&slot, connect_authority.as_str()).await
    {
        let req = prepare_proxy_h2_request(req, "https", host_authority.as_str(), proxy_name)?;
        let proxied = send_h2_request_with_sender(
            req,
            ready,
            Some(shared_h2.upstream_cert.clone()),
            Some(shared_h2.inflight_streams.clone()),
        )
        .await;
        if proxied.is_err() {
            slot.remove_h2_connection(&shared_h2);
        }
        return proxied;
    }

    if slot.has_h2_connections() {
        if let Some(reservation) = slot.try_reserve_h2_connection() {
            match open_https_origin_stream(
                connect_authority.as_str(),
                server_name.as_str(),
                verify_upstream_cert,
                trust,
            )
            .await
            {
                Ok((tls, negotiated_h2, upstream_cert)) => {
                    if negotiated_h2 {
                        let req = prepare_proxy_h2_request(
                            req,
                            "https",
                            host_authority.as_str(),
                            proxy_name,
                        )?;
                        let (sender, connection) =
                            match h2::client::Builder::new().handshake(tls).await {
                                Ok(handshake) => handshake,
                                Err(err) => return Err(err.into()),
                            };
                        spawn_origin_h2_connection_task(connection);
                        let shared_h2 = Arc::new(SharedTlsH2OriginConnection {
                            sender: sender.clone(),
                            upstream_cert: upstream_cert.clone(),
                            inflight_streams: Arc::new(AtomicUsize::new(0)),
                        });
                        reservation.complete(shared_h2.clone());
                        let ready = match sender.ready().await {
                            Ok(ready) => ready,
                            Err(err) => {
                                slot.remove_h2_connection(&shared_h2);
                                return Err(err.into());
                            }
                        };
                        let proxied = send_h2_request_with_sender(
                            req,
                            ready,
                            Some(upstream_cert),
                            Some(shared_h2.inflight_streams.clone()),
                        )
                        .await;
                        if proxied.is_err() {
                            slot.remove_h2_connection(&shared_h2);
                        }
                        return proxied;
                    }
                    drop(reservation);
                    let req =
                        prepare_proxy_http1_request(req, host_authority.as_str(), proxy_name)?;
                    let mut proxied = send_http1_request_with_interim_reusable(
                        tls,
                        req,
                        Http1ConnectionRecycler::new({
                            let idle = slot.http1_idle.clone();
                            let upstream_cert = upstream_cert.clone();
                            move |stream| {
                                let idle = idle.clone();
                                let upstream_cert = upstream_cert.clone();
                                async move {
                                    idle.lock().await.push(TlsHttp1OriginConnection {
                                        stream,
                                        upstream_cert,
                                    });
                                }
                            }
                        }),
                    )
                    .await?;
                    proxied.upstream_cert = Some(upstream_cert);
                    return Ok(proxied);
                }
                Err(err) => {
                    drop(reservation);
                    if let Some((shared_h2, ready)) =
                        wait_for_h2_sender(&slot, connect_authority.as_str()).await
                    {
                        let req = prepare_proxy_h2_request(
                            req,
                            "https",
                            host_authority.as_str(),
                            proxy_name,
                        )?;
                        let proxied = send_h2_request_with_sender(
                            req,
                            ready,
                            Some(shared_h2.upstream_cert.clone()),
                            Some(shared_h2.inflight_streams.clone()),
                        )
                        .await;
                        if proxied.is_err() {
                            slot.remove_h2_connection(&shared_h2);
                        }
                        return proxied;
                    }
                    return Err(err);
                }
            }
        }
    }

    if let Some((shared_h2, ready)) = wait_for_h2_sender(&slot, connect_authority.as_str()).await {
        let req = prepare_proxy_h2_request(req, "https", host_authority.as_str(), proxy_name)?;
        let proxied = send_h2_request_with_sender(
            req,
            ready,
            Some(shared_h2.upstream_cert.clone()),
            Some(shared_h2.inflight_streams.clone()),
        )
        .await;
        if proxied.is_err() {
            slot.remove_h2_connection(&shared_h2);
        }
        return proxied;
    }

    if let Some(entry) = { slot.http1_idle.lock().await.pop() } {
        let req = prepare_proxy_http1_request(req, host_authority.as_str(), proxy_name)?;
        let mut proxied = send_http1_request_with_interim_reusable(
            entry.stream,
            req,
            Http1ConnectionRecycler::new({
                let idle = slot.http1_idle.clone();
                let upstream_cert = entry.upstream_cert.clone();
                move |stream| {
                    let idle = idle.clone();
                    let upstream_cert = upstream_cert.clone();
                    async move {
                        idle.lock().await.push(TlsHttp1OriginConnection {
                            stream,
                            upstream_cert,
                        });
                    }
                }
            }),
        )
        .await?;
        proxied.upstream_cert = Some(entry.upstream_cert);
        return Ok(proxied);
    }

    let (tls, negotiated_h2, upstream_cert) = open_https_origin_stream(
        connect_authority.as_str(),
        server_name.as_str(),
        verify_upstream_cert,
        trust,
    )
    .await?;
    if negotiated_h2 {
        let req = prepare_proxy_h2_request(req, "https", host_authority.as_str(), proxy_name)?;
        let (sender, connection) = h2::client::Builder::new().handshake(tls).await?;
        spawn_origin_h2_connection_task(connection);
        let shared_h2 = Arc::new(SharedTlsH2OriginConnection {
            sender: sender.clone(),
            upstream_cert: upstream_cert.clone(),
            inflight_streams: Arc::new(AtomicUsize::new(0)),
        });
        slot.add_h2_connection(shared_h2.clone());
        let ready = match sender.ready().await {
            Ok(ready) => ready,
            Err(err) => {
                slot.remove_h2_connection(&shared_h2);
                return Err(err.into());
            }
        };
        let proxied = send_h2_request_with_sender(
            req,
            ready,
            Some(upstream_cert),
            Some(shared_h2.inflight_streams.clone()),
        )
        .await;
        if proxied.is_err() {
            slot.remove_h2_connection(&shared_h2);
        }
        return proxied;
    }

    let req = prepare_proxy_http1_request(req, host_authority.as_str(), proxy_name)?;
    let mut proxied = send_http1_request_with_interim_reusable(
        tls,
        req,
        Http1ConnectionRecycler::new({
            let idle = slot.http1_idle.clone();
            let upstream_cert = upstream_cert.clone();
            move |stream| {
                let idle = idle.clone();
                let upstream_cert = upstream_cert.clone();
                async move {
                    idle.lock().await.push(TlsHttp1OriginConnection {
                        stream,
                        upstream_cert,
                    });
                }
            }
        }),
    )
    .await?;
    proxied.upstream_cert = Some(upstream_cert);
    Ok(proxied)
}

fn prepare_proxy_http1_request(
    mut req: Request<Body>,
    host_authority: &str,
    proxy_name: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    prepare_request_with_headers_in_place(&mut req, proxy_name, None, false);
    *req.version_mut() = http::Version::HTTP_11;
    *req.uri_mut() = Uri::builder().path_and_query(path.as_str()).build()?;
    req.headers_mut()
        .insert(HOST, HeaderValue::from_str(host_authority)?);
    Ok(req)
}

fn prepare_proxy_h2_request(
    mut req: Request<Body>,
    scheme: &str,
    authority: &str,
    proxy_name: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    prepare_request_with_headers_in_place(&mut req, proxy_name, None, false);
    req.headers_mut().remove(HOST);
    *req.version_mut() = http::Version::HTTP_2;
    *req.uri_mut() = Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path.as_str())
        .build()?;
    Ok(req)
}

fn prepare_internal_http1_request(
    mut req: Request<Body>,
    authority: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    *req.version_mut() = http::Version::HTTP_11;
    *req.uri_mut() = Uri::builder().path_and_query(path.as_str()).build()?;
    if !req.headers().contains_key(HOST) {
        req.headers_mut()
            .insert(HOST, HeaderValue::from_str(authority)?);
    }
    Ok(req)
}

fn prepare_internal_h2_request(
    mut req: Request<Body>,
    scheme: &str,
    authority: &str,
) -> Result<Request<Body>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .to_string();
    req.headers_mut().remove(HOST);
    *req.version_mut() = http::Version::HTTP_2;
    *req.uri_mut() = Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(path.as_str())
        .build()?;
    Ok(req)
}

async fn send_h2_request_with_sender(
    req: Request<Body>,
    mut sender: h2::client::SendRequest<Bytes>,
    upstream_cert: Option<UpstreamCertificateInfo>,
    inflight_streams: Option<Arc<AtomicUsize>>,
) -> Result<Http1ResponseWithInterim> {
    let inflight = H2InflightReservation::new(inflight_streams);
    let (parts, mut body) = req.into_parts();
    let declared_length = parse_declared_content_length(&parts.headers)?;
    let mut request = Http1Request::builder()
        .method(parts.method.as_str())
        .uri(http_uri_to_http1_uri(&parts.uri)?)
        .body(())?;
    *request.headers_mut() = http_headers_to_h1(&parts.headers)?;
    *request.version_mut() = ::http::Version::HTTP_2;

    let (mut response, mut send_stream) = sender.send_request(request, false)?;
    stream_request_body_to_h2(&mut body, &mut send_stream, declared_length).await?;
    let (interim, response) = recv_h2_response_with_interim(&mut response).await?;
    let response = h2_response_to_hyper_with_inflight(response, inflight.into_counter())?;
    Ok(Http1ResponseWithInterim {
        interim,
        response,
        upstream_cert,
    })
}

struct H2InflightReservation(Option<Arc<AtomicUsize>>);

impl H2InflightReservation {
    fn new(counter: Option<Arc<AtomicUsize>>) -> Self {
        if let Some(counter) = &counter {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Self(counter)
    }

    fn into_counter(mut self) -> Option<Arc<AtomicUsize>> {
        self.0.take()
    }
}

impl Drop for H2InflightReservation {
    fn drop(&mut self) {
        if let Some(counter) = self.0.take() {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

async fn stream_request_body_to_h2(
    body: &mut Body,
    send_stream: &mut h2::SendStream<Bytes>,
    declared_length: Option<u64>,
) -> Result<()> {
    let mut sent_len = 0u64;
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        sent_len = sent_len
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow!("HTTP/2 request body length overflow"))?;
        if let Some(expected) = declared_length {
            if sent_len > expected {
                send_stream.send_reset(h2::Reason::PROTOCOL_ERROR);
                return Err(anyhow!(
                    "HTTP/2 request body exceeded declared content-length"
                ));
            }
        }
        if !chunk.is_empty() {
            send_stream.send_data(chunk, false)?;
        }
    }

    let trailers = body.trailers().await?;
    if let Some(expected) = declared_length {
        if sent_len != expected {
            send_stream.send_reset(h2::Reason::PROTOCOL_ERROR);
            return Err(anyhow!(
                "HTTP/2 request body ended before declared content-length was satisfied"
            ));
        }
    }
    if let Some(trailers) = trailers {
        crate::http::semantics::validate_request_trailers(&trailers)
            .map_err(|err| anyhow!("{}", err))?;
        send_stream.send_trailers(http_headers_to_h1(&trailers)?)?;
    } else {
        send_stream.send_data(Bytes::new(), true)?;
    }
    Ok(())
}

async fn recv_h2_response_with_interim(
    response: &mut h2::client::ResponseFuture,
) -> Result<(
    Vec<crate::upstream::raw_http1::InterimResponseHead>,
    Http1Response<h2::RecvStream>,
)> {
    let mut interim = Vec::new();
    loop {
        enum H2ResponseEvent {
            Informational(Http1Response<()>),
            Final(Http1Response<h2::RecvStream>),
        }

        let event = poll_fn(|cx| match Pin::new(&mut *response).poll(cx) {
            Poll::Ready(Ok(response)) => Poll::Ready(Ok(H2ResponseEvent::Final(response))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(anyhow!(err))),
            Poll::Pending => match response.poll_informational(cx) {
                Poll::Ready(Some(Ok(response))) => {
                    Poll::Ready(Ok(H2ResponseEvent::Informational(response)))
                }
                Poll::Ready(Some(Err(err))) => Poll::Ready(Err(anyhow!(err))),
                Poll::Ready(None) | Poll::Pending => Poll::Pending,
            },
        })
        .await?;

        match event {
            H2ResponseEvent::Informational(response) => {
                if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
                    return Err(anyhow!("HTTP/2 upstream must not send 101"));
                }
                interim.push(crate::upstream::raw_http1::InterimResponseHead {
                    status: hyper::StatusCode::from_u16(response.status().as_u16())?,
                    headers: h1_headers_to_http(response.headers())?,
                });
            }
            H2ResponseEvent::Final(response) => return Ok((interim, response)),
        }
    }
}

fn http_uri_to_http1_uri(uri: &Uri) -> Result<::http::Uri> {
    uri.to_string()
        .parse::<::http::Uri>()
        .or_else(|_| {
            let mut builder = ::http::Uri::builder();
            if let Some(scheme) = uri.scheme_str() {
                builder = builder.scheme(scheme);
            }
            if let Some(authority) = uri.authority() {
                builder = builder.authority(authority.as_str());
            }
            builder
                .path_and_query(
                    uri.path_and_query()
                        .map(|value| value.as_str())
                        .unwrap_or("/"),
                )
                .build()
        })
        .map_err(|err| anyhow!("invalid HTTP/2 upstream URI: {err}"))
}

fn absolute_request_target(uri: &Uri) -> Result<AbsoluteRequestTarget> {
    let parsed = url::Url::parse(uri.to_string().as_str())?;
    let scheme = parsed.scheme().to_string();
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("absolute request URI missing host"))?
        .to_string();
    let port = parsed
        .port()
        .unwrap_or_else(|| super::dispatch::default_port_for_scheme(scheme.as_str()));
    Ok(AbsoluteRequestTarget { scheme, host, port })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::body::to_bytes;
    use bytes::Bytes;
    use http_body_util::{BodyExt as _, Full};
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::duplex;
    use tokio::net::TcpListener;
    #[cfg(feature = "tls-rustls")]
    use tokio::sync::Notify;
    use tokio::task::yield_now;

    fn test_https_origin_slot() -> HttpsOriginSlot {
        HttpsOriginSlot {
            http1_idle: Arc::new(AsyncMutex::new(Vec::new())),
            h2: StdMutex::new(HttpsOriginH2Pool::default()),
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

    async fn spawn_counting_http1_origin(
        scheme: &str,
    ) -> Result<(OriginEndpoint, Arc<AtomicUsize>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = accepts.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                accepts_task.fetch_add(1, Ordering::SeqCst);
                let service =
                    service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"OK")).boxed())
                                .expect("response"),
                        )
                    });
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Ok((
            OriginEndpoint::direct(format!("{scheme}://127.0.0.1:{}", addr.port())),
            accepts,
        ))
    }

    #[tokio::test]
    async fn proxy_plain_http_reuses_direct_origin_connection() -> Result<()> {
        let (origin, accepts) = spawn_counting_http1_origin("http").await?;

        let first = proxy_http_with_interim(
            Request::builder()
                .uri("http://reverse.test/one")
                .body(Body::empty())?,
            &origin,
            "qpx-test",
            None,
        )
        .await?;
        assert_eq!(to_bytes(first.response.into_body()).await?, "OK");
        yield_now().await;

        let second = proxy_http_with_interim(
            Request::builder()
                .uri("http://reverse.test/two")
                .body(Body::empty())?,
            &origin,
            "qpx-test",
            None,
        )
        .await?;
        assert_eq!(to_bytes(second.response.into_body()).await?, "OK");

        assert_eq!(accepts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[cfg(feature = "tls-rustls")]
    async fn tls_trust_for_localhost(
        alpn: &[u8],
    ) -> Result<(tokio_rustls::TlsAcceptor, Arc<CompiledUpstreamTlsTrust>)> {
        use crate::tls::cert_info::extract_upstream_certificate_info;
        use qpx_core::config::UpstreamTlsTrustConfig;
        use qpx_core::tls::init_rustls_crypto_provider;
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        init_rustls_crypto_provider();
        let certified =
            generate_simple_self_signed(vec!["localhost".to_string()]).expect("self-signed cert");
        let cert_der = certified.cert.der().clone();
        let fingerprint = extract_upstream_certificate_info(Some(cert_der.as_ref()))
            .fingerprint_sha256
            .expect("fingerprint");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let trust = CompiledUpstreamTlsTrust::from_config(Some(&UpstreamTlsTrustConfig {
            pin_sha256: vec![fingerprint],
            issuer: Vec::new(),
            san_dns: Vec::new(),
            san_uri: Vec::new(),
            client_cert: None,
            client_key: None,
        }))?
        .expect("trust");
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .expect("server config");
        config.alpn_protocols = vec![alpn.to_vec()];
        Ok((tokio_rustls::TlsAcceptor::from(Arc::new(config)), trust))
    }

    #[cfg(feature = "tls-rustls")]
    async fn spawn_counting_https_http1_origin() -> Result<(
        OriginEndpoint,
        Arc<CompiledUpstreamTlsTrust>,
        Arc<AtomicUsize>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (acceptor, trust) = tls_trust_for_localhost(b"http/1.1").await?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = accepts.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                accepts_task.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls = acceptor.accept(stream).await.expect("tls");
                    let service =
                        service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(b"OK")).boxed())
                                    .expect("response"),
                            )
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Ok((
            OriginEndpoint::direct(format!("https://localhost:{}", addr.port())),
            trust,
            accepts,
        ))
    }

    #[cfg(feature = "tls-rustls")]
    async fn spawn_counting_https_h2_origin() -> Result<(
        OriginEndpoint,
        Arc<CompiledUpstreamTlsTrust>,
        Arc<AtomicUsize>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (acceptor, trust) = tls_trust_for_localhost(b"h2").await?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = accepts.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                accepts_task.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls = acceptor.accept(stream).await.expect("tls");
                    let mut conn = h2::server::handshake(tls).await.expect("handshake");
                    while let Some(result) = conn.accept().await {
                        let (_request, mut respond) = result.expect("request");
                        tokio::spawn(async move {
                            let response = Http1Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .expect("response");
                            let mut send = respond.send_response(response, false).expect("send");
                            send.send_data(Bytes::from_static(b"OK"), true)
                                .expect("body");
                        });
                    }
                });
            }
        });
        Ok((
            OriginEndpoint::direct(format!("https://localhost:{}", addr.port())),
            trust,
            accepts,
        ))
    }

    #[cfg(feature = "tls-rustls")]
    async fn spawn_limited_https_h2_origin() -> Result<(
        OriginEndpoint,
        Arc<CompiledUpstreamTlsTrust>,
        Arc<AtomicUsize>,
        Arc<Notify>,
    )> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (acceptor, trust) = tls_trust_for_localhost(b"h2").await?;
        let accepts = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::new(AtomicUsize::new(0));
        let release_first = Arc::new(Notify::new());
        let accepts_task = accepts.clone();
        let request_count_task = request_count.clone();
        let release_first_task = release_first.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept");
                accepts_task.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let request_count = request_count_task.clone();
                let release_first = release_first_task.clone();
                tokio::spawn(async move {
                    let tls = acceptor.accept(stream).await.expect("tls");
                    let mut conn = h2::server::Builder::new()
                        .max_concurrent_streams(1)
                        .handshake(tls)
                        .await
                        .expect("handshake");
                    while let Some(result) = conn.accept().await {
                        let request_idx = request_count.fetch_add(1, Ordering::SeqCst);
                        let (_request, mut respond) = result.expect("request");
                        let release_first = release_first.clone();
                        tokio::spawn(async move {
                            let response = Http1Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .expect("response");
                            let mut send = respond.send_response(response, false).expect("send");
                            if request_idx == 0 {
                                release_first.notified().await;
                            }
                            send.send_data(Bytes::from_static(b"OK"), true)
                                .expect("body");
                        });
                    }
                });
            }
        });
        Ok((
            OriginEndpoint::direct(format!("https://localhost:{}", addr.port())),
            trust,
            accepts,
            release_first,
        ))
    }

    #[cfg(feature = "tls-rustls")]
    #[tokio::test]
    async fn proxy_https_http1_reuses_direct_origin_connection() -> Result<()> {
        let (origin, trust, accepts) = spawn_counting_https_http1_origin().await?;

        let first = proxy_https_with_options(
            Request::builder()
                .uri("https://reverse.test/one")
                .body(Body::empty())?,
            &origin,
            "qpx-test",
            Some(trust.as_ref()),
            false,
        )
        .await?;
        assert!(first
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false));
        assert_eq!(to_bytes(first.response.into_body()).await?, "OK");
        yield_now().await;

        let second = proxy_https_with_options(
            Request::builder()
                .uri("https://reverse.test/two")
                .body(Body::empty())?,
            &origin,
            "qpx-test",
            Some(trust.as_ref()),
            false,
        )
        .await?;
        assert!(second
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false));
        assert_eq!(to_bytes(second.response.into_body()).await?, "OK");

        assert_eq!(accepts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[cfg(feature = "tls-rustls")]
    #[tokio::test]
    async fn proxy_https_h2_reuses_direct_origin_connection() -> Result<()> {
        let (origin, trust, accepts) = spawn_counting_https_h2_origin().await?;

        let first = proxy_https_with_options(
            Request::builder()
                .uri("https://reverse.test/one")
                .body(Body::empty())?,
            &origin,
            "qpx-test",
            Some(trust.as_ref()),
            false,
        )
        .await?;
        assert!(first
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false));
        assert_eq!(to_bytes(first.response.into_body()).await?, "OK");

        let second = proxy_https_with_options(
            Request::builder()
                .uri("https://reverse.test/two")
                .body(Body::empty())?,
            &origin,
            "qpx-test",
            Some(trust.as_ref()),
            false,
        )
        .await?;
        assert!(second
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false));
        assert_eq!(to_bytes(second.response.into_body()).await?, "OK");

        assert_eq!(accepts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[cfg(feature = "tls-rustls")]
    #[tokio::test]
    async fn proxy_https_h2_opens_additional_direct_origin_connections_under_stream_pressure(
    ) -> Result<()> {
        let (origin, trust, accepts, release_first) = spawn_limited_https_h2_origin().await?;

        let first = proxy_https_with_options(
            Request::builder()
                .uri("https://reverse.test/one")
                .body(Body::empty())?,
            &origin,
            "qpx-test",
            Some(trust.as_ref()),
            false,
        )
        .await?;
        assert!(first
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false));

        let second = proxy_https_with_options(
            Request::builder()
                .uri("https://reverse.test/two")
                .body(Body::empty())?,
            &origin,
            "qpx-test",
            Some(trust.as_ref()),
            false,
        )
        .await?;
        assert!(second
            .upstream_cert
            .as_ref()
            .map(|cert| cert.present)
            .unwrap_or(false));

        assert_eq!(accepts.load(Ordering::SeqCst), 2);
        release_first.notify_waiters();
        assert_eq!(to_bytes(first.response.into_body()).await?, "OK");
        assert_eq!(to_bytes(second.response.into_body()).await?, "OK");
        Ok(())
    }
}
