use anyhow::Result;
use arc_swap::ArcSwapOption;
use hyper::header::{HOST, HeaderValue};
use hyper::{Request, Response};
use qpx_http::body::Body;
use std::cell::RefCell;
use std::sync::Arc;
use tokio::net::TcpStream;
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
use tracing::warn;

use crate::http::protocol::l7::prepare_request_for_fixed_authority_in_place;
use crate::upstream::raw_http1::{
    BodylessHttp1Request, Http1ConnectionRecycler, Http1ResponseWithInterim,
    RawHttp1ResponseContext, RawHttp1ResponseRelay, ReusableRawHttp1Connection,
    UpstreamConnectionClosed, classify_bodyless_http1_request, idle_connection_closed_or_dirty,
    retain_active_permit, send_http1_request_with_interim_reusable,
    send_http1_request_with_interim_reusable_raw_response,
    send_prepared_http1_head_with_interim_reusable_raw_response_under_external_deadline,
    send_serialized_http1_head_with_interim_reusable_raw_response,
    serialize_bodyless_http1_request,
};
use qpx_core::tls::CompiledUpstreamTlsTrust;

use super::OriginEndpoint;
use super::dispatch::{OriginScheme, origin_scheme};
use super::ipc_backend::proxy_ipc_with_interim;

mod backend_h2;
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
mod h3_pool;
mod metrics;
mod pool;
mod shared;

const MAX_CACHED_ORIGIN_AUTHORITIES: usize = 32;

#[derive(Clone, Default)]
pub(crate) struct PreparedPlainHttp1ConnectionAffinity {
    target: Arc<ArcSwapOption<PreparedPlainHttp1ConnectionAffinityTarget>>,
}

struct PreparedPlainHttp1ConnectionAffinityTarget {
    slot: Arc<pool::PlainHttpOriginSlot>,
    idle_affinity: usize,
}

impl PreparedPlainHttp1ConnectionAffinity {
    fn target_for(
        &self,
        slot: &Arc<pool::PlainHttpOriginSlot>,
    ) -> Arc<PreparedPlainHttp1ConnectionAffinityTarget> {
        let current = self.target.load();
        if let Some(current) = current.as_ref()
            && Arc::ptr_eq(&current.slot, slot)
        {
            return Arc::clone(current);
        }
        let next = Arc::new(PreparedPlainHttp1ConnectionAffinityTarget {
            slot: Arc::clone(slot),
            idle_affinity: pool::next_http1_idle_affinity(),
        });
        self.target.store(Some(Arc::clone(&next)));
        next
    }
}

impl PreparedPlainHttp1ConnectionAffinityTarget {
    fn pop_idle(&self) -> Option<pool::PlainHttp1OriginConnection> {
        self.slot.pop_idle_preferred(self.idle_affinity)
    }
}

impl crate::upstream::raw_http1::Http1RecycleTarget<TcpStream>
    for PreparedPlainHttp1ConnectionAffinityTarget
{
    fn recycle(&self, stream: TcpStream, read_buf: bytes::BytesMut, write_buf: bytes::BytesMut) {
        self.slot.recycle_idle_preferred(
            pool::PlainHttp1OriginConnection::new(stream, read_buf, write_buf),
            self.idle_affinity,
        );
    }
}

#[derive(Clone)]
pub(crate) struct PreparedPlainHttp1Origin {
    slot: Arc<pool::PlainHttpOriginSlot>,
    connect_authority: Arc<str>,
}

#[derive(Default)]
pub(crate) struct PreparedPlainHttp1Session {
    target: Option<PreparedPlainHttp1SessionTarget>,
}

struct PreparedPlainHttp1SessionTarget {
    slot: Arc<pool::PlainHttpOriginSlot>,
    connection: Option<pool::PlainHttp1OriginConnection>,
    active_permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl PreparedPlainHttp1Session {
    async fn prepare_for(&mut self, origin: &PreparedPlainHttp1Origin) -> Result<()> {
        if let Some(target) = self
            .target
            .as_mut()
            .filter(|target| Arc::ptr_eq(&target.slot, &origin.slot))
        {
            if target.active_permit.is_none() {
                target.active_permit = Some(origin.slot.acquire_active().await?);
            }
            return Ok(());
        }
        // Never await a new origin permit while retaining a permit for the old
        // origin. Concurrent route changes must not create cross-origin lock order.
        self.target = None;
        let active_permit = origin.slot.acquire_active().await?;
        self.target = Some(PreparedPlainHttp1SessionTarget {
            slot: Arc::clone(&origin.slot),
            connection: None,
            active_permit: Some(active_permit),
        });
        Ok(())
    }

    pub(crate) fn release(&mut self) {
        if let Some(target) = self.target.as_mut() {
            target.active_permit.take();
        }
    }

    fn take_connection(&mut self) -> Option<pool::PlainHttp1OriginConnection> {
        self.target.as_mut()?.connection.take()
    }

    pub(crate) fn recycle_connection(&mut self, connection: ReusableRawHttp1Connection<TcpStream>) {
        let Some(target) = self.target.as_mut() else {
            return;
        };
        debug_assert!(target.connection.is_none());
        let ReusableRawHttp1Connection {
            stream,
            read_buf,
            write_buf,
        } = connection;
        target.connection = Some(pool::PlainHttp1OriginConnection::new(
            stream, read_buf, write_buf,
        ));
    }

    pub(crate) fn recycle_response_globally(
        &self,
        response: &mut RawHttp1ResponseRelay<TcpStream>,
    ) {
        let Some(target) = self.target.as_ref() else {
            return;
        };
        debug_assert!(response.recycler.is_none());
        response.recycler = Some(Http1ConnectionRecycler::from_target(Arc::clone(
            &target.slot,
        )));
    }
}

impl Drop for PreparedPlainHttp1SessionTarget {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            self.slot.recycle_idle(connection);
        }
    }
}

struct CachedOriginAuthority {
    authority: String,
    value: HeaderValue,
}

thread_local! {
    static ORIGIN_AUTHORITY_VALUES: RefCell<Vec<CachedOriginAuthority>> =
        const { RefCell::new(Vec::new()) };
}

use self::backend_h2::{prepare_proxy_h2_request, send_h2_request_with_sender};
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) use self::h3_pool::H3OriginPool;
pub(crate) use self::pool::DirectOriginPools;
use self::pool::{HttpsConnectionAcquisition, acquire_https_connection, https_origin_pool_key};
pub(crate) use self::shared::shared_reverse_https_request_with_trust;

pub(crate) async fn proxy_http(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Response<Body>> {
    let mut proxied = proxy_http_with_interim(pools, req, origin, proxy_name, trust).await?;
    if !proxied.interim.is_empty() {
        proxied.response.extensions_mut().insert(proxied.interim);
    }
    Ok(proxied.response)
}

pub(crate) async fn proxy_http_with_interim(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Http1ResponseWithInterim> {
    proxy_http_with_interim_timeout(
        pools,
        req,
        origin,
        proxy_name,
        trust,
        std::time::Duration::from_secs(30),
    )
    .await
}

pub(crate) async fn proxy_http_with_interim_timeout(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
    timeout_dur: std::time::Duration,
) -> Result<Http1ResponseWithInterim> {
    proxy_http_with_interim_timeout_inner(pools, req, origin, proxy_name, trust, timeout_dur, None)
        .await
}

pub(crate) async fn proxy_http_with_interim_timeout_on_connection(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
    timeout_dur: std::time::Duration,
    connection_pool: &PreparedPlainHttp1ConnectionAffinity,
) -> Result<Http1ResponseWithInterim> {
    proxy_http_with_interim_timeout_inner(
        pools,
        req,
        origin,
        proxy_name,
        trust,
        timeout_dur,
        Some(connection_pool),
    )
    .await
}

async fn proxy_http_with_interim_timeout_inner(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
    timeout_dur: std::time::Duration,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<Http1ResponseWithInterim> {
    match origin_scheme(origin)? {
        OriginScheme::Http | OriginScheme::Ws => {
            proxy_plain_http(pools, req, origin, proxy_name, connection_pool).await
        }
        OriginScheme::Https | OriginScheme::Wss => {
            proxy_https_with_options(pools, req, origin, proxy_name, trust, true, timeout_dur).await
        }
        OriginScheme::H3 => proxy_h3(pools, req, origin, proxy_name, trust, timeout_dur).await,
        OriginScheme::Ipc | OriginScheme::IpcUnix => {
            proxy_ipc_with_interim(pools, req, origin, proxy_name).await
        }
    }
}

async fn proxy_h3(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
    timeout_dur: std::time::Duration,
) -> Result<Http1ResponseWithInterim> {
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    {
        h3_pool::proxy_h3_origin(
            &pools.h3_origin,
            req,
            origin,
            proxy_name,
            trust,
            timeout_dur,
        )
        .await
    }
    #[cfg(not(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx"))))]
    {
        let _ = (pools, req, origin, proxy_name, trust, timeout_dur);
        Err(anyhow::anyhow!(
            "h3 upstream origins require the http3-backend-h3 feature"
        ))
    }
}

async fn open_plain_http_origin_stream(
    connect_authority: &str,
) -> Result<pool::PlainHttp1OriginConnection> {
    let stream = TcpStream::connect(connect_authority).await?;
    let _ = stream.set_nodelay(true);
    Ok(pool::PlainHttp1OriginConnection::new(
        stream,
        bytes::BytesMut::new(),
        bytes::BytesMut::new(),
    ))
}

async fn proxy_plain_http(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<Http1ResponseWithInterim> {
    let default_port = origin.default_port_hint();
    let connect_authority = origin.connect_authority_ref(default_port)?;
    let host_authority = origin.host_header_authority_ref(default_port)?;
    let req = prepare_proxy_http1_request(req, host_authority.as_ref(), proxy_name)?;
    proxy_direct_plain_http1_with_interim_inner(
        pools,
        req,
        connect_authority.as_ref(),
        host_authority.as_ref(),
        connection_pool,
    )
    .await
}

pub(crate) async fn proxy_direct_plain_http1_with_interim(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    connect_authority: &str,
    host_authority: &str,
) -> Result<Http1ResponseWithInterim> {
    proxy_direct_plain_http1_with_interim_inner(pools, req, connect_authority, host_authority, None)
        .await
}

async fn proxy_direct_plain_http1_with_interim_inner(
    pools: &crate::pool::PoolRegistry,
    mut req: Request<Body>,
    connect_authority: &str,
    host_authority: &str,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<Http1ResponseWithInterim> {
    let slot = pools
        .direct_origin
        .plain_slot_for(connect_authority, host_authority);
    let active_permit = slot.acquire_active().await?;
    crate::upstream::http1::ensure_origin_form_uri(&mut req)?;
    crate::upstream::http1::ensure_host_header(&mut req, host_authority)?;
    *req.version_mut() = http::Version::HTTP_11;
    let local_target = connection_pool.map(|pool| pool.target_for(&slot));
    let pooled = match local_target.as_ref() {
        Some(target) => take_reusable_plain_http_stream_from_target(target).await,
        None => take_reusable_plain_http_stream(&slot).await,
    };
    let connection = match pooled {
        Some(connection) => connection,
        None => open_plain_http_origin_stream(connect_authority).await?,
    };
    let recycler = local_target
        .map(Http1ConnectionRecycler::from_target)
        .unwrap_or_else(|| Http1ConnectionRecycler::from_target(slot));
    let mut response = send_http1_request_with_interim_reusable(
        connection.stream,
        connection.read_buf,
        connection.write_buf,
        req,
        recycler,
    )
    .await?;
    retain_active_permit(response.response.body_mut(), Some(active_permit));
    Ok(response)
}

pub(crate) async fn proxy_direct_plain_http1_raw_response_with_interim(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    connect_authority: &str,
    host_authority: &str,
    request_version: http::Version,
    proxy_name: &str,
) -> Result<Http1ResponseWithInterim> {
    proxy_direct_plain_http1_raw_response_with_interim_inner(
        pools,
        req,
        connect_authority,
        host_authority,
        request_version,
        proxy_name,
        None,
    )
    .await
}

pub(crate) async fn proxy_direct_plain_http1_raw_response_with_interim_on_connection(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    connect_authority: &str,
    host_authority: &str,
    request_version: http::Version,
    proxy_name: &str,
    connection_pool: &PreparedPlainHttp1ConnectionAffinity,
) -> Result<Http1ResponseWithInterim> {
    proxy_direct_plain_http1_raw_response_with_interim_inner(
        pools,
        req,
        connect_authority,
        host_authority,
        request_version,
        proxy_name,
        Some(connection_pool),
    )
    .await
}

async fn proxy_direct_plain_http1_raw_response_with_interim_inner(
    pools: &crate::pool::PoolRegistry,
    mut req: Request<Body>,
    connect_authority: &str,
    host_authority: &str,
    request_version: http::Version,
    proxy_name: &str,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<Http1ResponseWithInterim> {
    let slot = pools
        .direct_origin
        .plain_slot_for(connect_authority, host_authority);
    debug_assert_eq!(req.version(), http::Version::HTTP_11);
    debug_assert!(req.uri().authority().is_none());
    debug_assert_eq!(
        req.headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok()),
        Some(host_authority)
    );
    if matches!(*req.method(), http::Method::GET | http::Method::HEAD) {
        req = match classify_bodyless_http1_request(req)? {
            Ok(req) => {
                return proxy_bodyless_plain_http1_raw_response_with_interim(
                    slot,
                    req,
                    connect_authority,
                    request_version,
                    proxy_name,
                    connection_pool,
                )
                .await;
            }
            Err(req) => req,
        };
    }
    let active_permit = slot.acquire_active().await?;
    let connection = match take_reusable_plain_http_stream(&slot).await {
        Some(connection) => connection,
        None => open_plain_http_origin_stream(connect_authority).await?,
    };
    let mut response = send_http1_request_with_interim_reusable_raw_response(
        connection.stream,
        connection.read_buf,
        connection.write_buf,
        req,
        request_version,
        proxy_name,
        Http1ConnectionRecycler::from_target(slot),
    )
    .await?;
    retain_active_permit(response.response.body_mut(), Some(active_permit));
    Ok(response)
}

async fn proxy_bodyless_plain_http1_raw_response_with_interim(
    slot: Arc<pool::PlainHttpOriginSlot>,
    req: BodylessHttp1Request,
    connect_authority: &str,
    request_version: http::Version,
    proxy_name: &str,
    connection_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<Http1ResponseWithInterim> {
    let active_permit = slot.acquire_active().await?;
    let local_target = connection_pool.map(|pool| pool.target_for(&slot));
    let pooled = loop {
        let pooled = match local_target.as_ref() {
            Some(target) => target.pop_idle(),
            None => slot.pop_idle(),
        };
        let Some(mut connection) = pooled else {
            break None;
        };
        if connection.requires_idle_probe()
            && idle_connection_closed_or_dirty(&mut connection.stream).await
        {
            continue;
        }
        break Some(connection);
    };
    let (mut connection, reused) = match pooled {
        Some(connection) => (connection, true),
        None => (
            open_plain_http_origin_stream(connect_authority).await?,
            false,
        ),
    };
    let recycler = local_target
        .as_ref()
        .map(|target| Http1ConnectionRecycler::from_target(Arc::clone(target)))
        .unwrap_or_else(|| Http1ConnectionRecycler::from_target(Arc::clone(&slot)));
    let request_method = serialize_bodyless_http1_request(req, &mut connection.write_buf)?;
    let response = send_serialized_http1_head_with_interim_reusable_raw_response(
        connection.stream,
        connection.read_buf,
        connection.write_buf,
        &request_method,
        request_version,
        proxy_name,
        recycler.clone(),
    )
    .await;
    let mut relay = match response {
        Ok(relay) => relay,
        Err(first_error) => {
            let (first_error, request_head) = first_error.into_parts();
            if !reused || !is_transport_error(&first_error) {
                return Err(first_error);
            }
            let mut connection = open_plain_http_origin_stream(connect_authority).await?;
            connection.write_buf = request_head;
            send_serialized_http1_head_with_interim_reusable_raw_response(
                connection.stream,
                connection.read_buf,
                connection.write_buf,
                &request_method,
                request_version,
                proxy_name,
                recycler,
            )
            .await
            .map_err(|error| error.into_parts().0)?
        }
    };
    relay.active_permit = Some(active_permit);
    if request_version == http::Version::HTTP_2 {
        relay.into_materialized_http_response()
    } else {
        relay.into_http_response()
    }
}

pub(crate) async fn proxy_prepared_plain_http1_head_raw_response_with_interim(
    origin: &PreparedPlainHttp1Origin,
    session: &mut PreparedPlainHttp1Session,
    request_method: &http::Method,
    request_head: &[u8],
    request_version: http::Version,
    proxy_name: &str,
) -> Result<RawHttp1ResponseRelay<TcpStream>> {
    session.prepare_for(origin).await?;
    let (connection, reused) = match session.take_connection().or_else(|| origin.slot.pop_idle()) {
        Some(connection) => (connection, true),
        None => (
            open_plain_http_origin_stream(origin.connect_authority.as_ref()).await?,
            false,
        ),
    };
    let response =
        send_prepared_http1_head_with_interim_reusable_raw_response_under_external_deadline(
            connection.stream,
            connection.read_buf,
            connection.write_buf,
            request_head,
            RawHttp1ResponseContext::new(request_method, request_version, proxy_name),
            None,
        )
        .await;
    let first_error = match response {
        Ok(relay) => return Ok(relay),
        Err(error) => error,
    };
    if !reused || !is_transport_error(&first_error) {
        return Err(first_error);
    }

    let connection = open_plain_http_origin_stream(origin.connect_authority.as_ref()).await?;
    send_prepared_http1_head_with_interim_reusable_raw_response_under_external_deadline(
        connection.stream,
        connection.read_buf,
        connection.write_buf,
        request_head,
        RawHttp1ResponseContext::new(request_method, request_version, proxy_name),
        None,
    )
    .await
}

pub(crate) fn prepare_plain_http1_origin(
    pools: &crate::pool::PoolRegistry,
    connect_authority: &str,
    host_authority: &str,
) -> PreparedPlainHttp1Origin {
    PreparedPlainHttp1Origin {
        slot: pools
            .direct_origin
            .plain_slot_for(connect_authority, host_authority),
        connect_authority: Arc::from(connect_authority),
    }
}

fn is_transport_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some()
            || cause.downcast_ref::<UpstreamConnectionClosed>().is_some()
    })
}

async fn take_reusable_plain_http_stream(
    slot: &pool::PlainHttpOriginSlot,
) -> Option<pool::PlainHttp1OriginConnection> {
    loop {
        let mut connection = slot.pop_idle()?;
        if idle_connection_closed_or_dirty(&mut connection.stream).await {
            continue;
        }
        return Some(connection);
    }
}

async fn take_reusable_plain_http_stream_from_target(
    target: &Arc<PreparedPlainHttp1ConnectionAffinityTarget>,
) -> Option<pool::PlainHttp1OriginConnection> {
    loop {
        let mut connection = target.pop_idle()?;
        if idle_connection_closed_or_dirty(&mut connection.stream).await {
            continue;
        }
        return Some(connection);
    }
}

async fn proxy_https_with_options(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
    verify_upstream_cert: bool,
    timeout_dur: std::time::Duration,
) -> Result<Http1ResponseWithInterim> {
    #[cfg(not(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx"))))]
    let _ = timeout_dur;
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    if verify_upstream_cert
        && trust.is_none()
        && h3_pool::request_can_use_alt_svc_h3(&req)
        && let Some(h3_origin) = h3_pool::cached_alt_svc_h3_endpoint(origin).await?
    {
        let h3_req = h3_pool::clone_empty_body_request(&req)?;
        match h3_pool::proxy_h3_origin(
            &pools.h3_origin,
            h3_req,
            &h3_origin,
            proxy_name,
            None,
            timeout_dur,
        )
        .await
        {
            Ok(proxied) => return Ok(proxied),
            Err(err) => {
                h3_pool::forget_alt_svc_h3_endpoint(origin).await;
                warn!(error = ?err, "Alt-Svc HTTP/3 upstream attempt failed; falling back to HTTPS");
            }
        }
    }

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
    let slot = pools.direct_origin.https_slot(pool_key);

    let proxied = match acquire_https_connection(
        &slot,
        connect_authority.as_str(),
        server_name.as_str(),
        verify_upstream_cert,
        trust,
        pools.direct_origin.h2_tuning(),
    )
    .await?
    {
        HttpsConnectionAcquisition::H2Ready { shared, ready } => {
            let req = prepare_proxy_h2_request(req, "https", host_authority.as_str(), proxy_name)?;
            let proxied = send_h2_request_with_sender(
                req,
                ready,
                Some(shared.upstream_cert.clone()),
                Some(shared.inflight_streams.clone()),
            )
            .await;
            if proxied.is_err() {
                slot.remove_h2_connection(&shared);
            }
            proxied
        }
        HttpsConnectionAcquisition::H1(entry) => {
            let req = prepare_proxy_http1_request(req, host_authority.as_str(), proxy_name)?;
            shared::send_tls_http1_with_recycle(slot, entry, req).await
        }
    };
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    if let Ok(proxied) = proxied.as_ref()
        && verify_upstream_cert
        && trust.is_none()
    {
        h3_pool::record_h3_alt_svc(origin, proxied.response.headers()).await;
    }
    proxied
}

pub(crate) fn prepare_proxy_http1_request(
    mut req: Request<Body>,
    host_authority: &str,
    proxy_name: &str,
) -> Result<Request<Body>> {
    prepare_request_for_fixed_authority_in_place(&mut req, proxy_name);
    *req.version_mut() = http::Version::HTTP_11;
    crate::upstream::http1::ensure_origin_form_uri(&mut req)?;
    req.headers_mut()
        .insert(HOST, cached_origin_authority(host_authority)?);
    Ok(req)
}

fn cached_origin_authority(authority: &str) -> Result<HeaderValue> {
    ORIGIN_AUTHORITY_VALUES.with_borrow_mut(|cached| {
        if let Some(entry) = cached.iter().find(|entry| entry.authority == authority) {
            return Ok(entry.value.clone());
        }
        let value = HeaderValue::from_str(authority)?;
        if cached.len() == MAX_CACHED_ORIGIN_AUTHORITIES {
            cached.remove(0);
        }
        cached.push(CachedOriginAuthority {
            authority: authority.to_string(),
            value: value.clone(),
        });
        Ok(value)
    })
}

#[cfg(test)]
mod tests;
