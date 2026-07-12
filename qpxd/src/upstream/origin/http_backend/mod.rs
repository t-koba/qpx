use anyhow::Result;
use hyper::header::{HOST, HeaderValue};
use hyper::{Request, Response, Uri};
use qpx_http::body::Body;
use tokio::net::TcpStream;
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
use tracing::warn;

use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::upstream::raw_http1::{
    Http1ConnectionRecycler, Http1ResponseWithInterim, idle_connection_closed_or_dirty,
    send_http1_request_with_interim_reusable,
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

use self::backend_h2::{prepare_proxy_h2_request, send_h2_request_with_sender};
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) use self::h3_pool::H3OriginPool;
pub(crate) use self::pool::DirectOriginPools;
use self::pool::{
    HttpsConnectionAcquisition, acquire_https_connection, https_origin_pool_key,
    plain_http_origin_pool_key,
};
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
    match origin_scheme(origin)? {
        OriginScheme::Http | OriginScheme::Ws => {
            proxy_plain_http(pools, req, origin, proxy_name).await
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
    Ok(pool::PlainHttp1OriginConnection {
        stream,
        read_buf: bytes::BytesMut::new(),
        write_buf: bytes::BytesMut::new(),
    })
}

async fn proxy_plain_http(
    pools: &crate::pool::PoolRegistry,
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
) -> Result<Http1ResponseWithInterim> {
    let default_port = origin.default_port_hint();
    let connect_authority = origin.connect_authority(default_port)?;
    let host_authority = origin.host_header_authority(default_port)?;
    let req = prepare_proxy_http1_request(req, host_authority.as_str(), proxy_name)?;
    proxy_direct_plain_http1_with_interim(
        pools,
        req,
        connect_authority.as_str(),
        host_authority.as_str(),
    )
    .await
}

pub(crate) async fn proxy_direct_plain_http1_with_interim(
    pools: &crate::pool::PoolRegistry,
    mut req: Request<Body>,
    connect_authority: &str,
    host_authority: &str,
) -> Result<Http1ResponseWithInterim> {
    let slot = pools.direct_origin.plain_slot(plain_http_origin_pool_key(
        connect_authority,
        host_authority,
    ));
    crate::upstream::http1::ensure_origin_form_uri(&mut req)?;
    crate::upstream::http1::ensure_host_header(&mut req, host_authority)?;
    *req.version_mut() = http::Version::HTTP_11;
    let connection = match take_reusable_plain_http_stream(&slot).await {
        Some(connection) => connection,
        None => open_plain_http_origin_stream(connect_authority).await?,
    };
    let recycle_slot = slot.clone();
    send_http1_request_with_interim_reusable(
        connection.stream,
        connection.read_buf,
        connection.write_buf,
        req,
        Http1ConnectionRecycler::new(move |stream, read_buf, write_buf| {
            recycle_slot.recycle_idle(pool::PlainHttp1OriginConnection {
                stream,
                read_buf,
                write_buf,
            });
        }),
    )
    .await
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

#[cfg(test)]
mod tests;
