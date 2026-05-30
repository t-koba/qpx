use crate::http::body::Body;
use anyhow::Result;
use hyper::header::{HOST, HeaderValue};
use hyper::{Request, Response, Uri};
use tokio::net::TcpStream;
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
use tracing::warn;

use crate::http::protocol::l7::prepare_request_with_headers_in_place;
use crate::tls::CompiledUpstreamTlsTrust;
use crate::upstream::raw_http1::{
    Http1ConnectionRecycler, Http1ResponseWithInterim, send_http1_request_with_interim_reusable,
};

use super::OriginEndpoint;
use super::dispatch::{OriginScheme, origin_scheme};
use super::ipc_backend::proxy_ipc_with_interim;

mod backend_h2;
#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
mod h3_pool;
mod pool;
mod shared;

use self::backend_h2::{prepare_proxy_h2_request, send_h2_request_with_sender};
pub(crate) use self::pool::clear_direct_origin_connection_pools;
use self::pool::{
    HttpsConnectionAcquisition, acquire_https_connection, https_origin_pool_key, https_origin_slot,
    plain_http_origin_pool_key, plain_http_origin_slot,
};
pub(crate) use self::shared::{shared_reverse_http_client, shared_reverse_https_client};

#[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
pub(crate) fn configure_h3_origin_pool(
    max_connections_per_origin: usize,
    max_inflight_streams_per_connection: usize,
) {
    h3_pool::configure_h3_origin_pool(
        max_connections_per_origin,
        max_inflight_streams_per_connection,
    );
}

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
        OriginScheme::H3 => proxy_h3(req, origin, proxy_name, trust).await,
        OriginScheme::Ipc | OriginScheme::IpcUnix => {
            proxy_ipc_with_interim(req, origin, proxy_name).await
        }
    }
}

async fn proxy_h3(
    req: Request<Body>,
    origin: &OriginEndpoint,
    proxy_name: &str,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<Http1ResponseWithInterim> {
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    {
        h3_pool::proxy_h3_origin(
            req,
            origin,
            proxy_name,
            trust,
            std::time::Duration::from_secs(30),
        )
        .await
    }
    #[cfg(not(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx"))))]
    {
        let _ = (req, origin, proxy_name, trust);
        Err(anyhow::anyhow!(
            "h3 upstream origins require the http3-backend-h3 feature"
        ))
    }
}

async fn open_plain_http_origin_stream(connect_authority: &str) -> Result<TcpStream> {
    let stream = TcpStream::connect(connect_authority).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
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
    #[cfg(all(feature = "http3-backend-h3", not(feature = "http3-backend-qpx")))]
    if verify_upstream_cert
        && trust.is_none()
        && h3_pool::request_can_use_alt_svc_h3(&req)
        && let Some(h3_origin) = h3_pool::cached_alt_svc_h3_endpoint(origin).await?
    {
        let h3_req = h3_pool::clone_empty_body_request(&req)?;
        match h3_pool::proxy_h3_origin(
            h3_req,
            &h3_origin,
            proxy_name,
            None,
            std::time::Duration::from_secs(30),
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
    let slot = https_origin_slot(pool_key);

    let proxied = match acquire_https_connection(
        &slot,
        connect_authority.as_str(),
        server_name.as_str(),
        verify_upstream_cert,
        trust,
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
