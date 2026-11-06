use super::backend_h2::{prepare_h2_request, send_h2_request_with_sender};
use super::pool::{
    HttpsConnectionAcquisition, HttpsOriginSlot, TlsHttp1OriginConnection,
    acquire_https_connection, https_origin_pool_key,
};
use crate::http::dispatcher::attach_interim_response_heads;
use crate::upstream::raw_http1::{
    Http1ConnectionRecycler, Http1ResponseWithInterim, send_http1_request_with_interim_reusable,
};
use anyhow::{Result, anyhow};
use hyper::header::{HOST, HeaderValue};
use qpx_core::http_message::{
    OrdinaryHeaderName, Request as OwnerRequest, Response as OwnerResponse,
};
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_http::body::Body;
use std::sync::Arc;

pub(crate) async fn shared_reverse_https_request_with_trust(
    pools: &crate::pool::PoolRegistry,
    mut req: OwnerRequest<Body>,
    trust: Option<&CompiledUpstreamTlsTrust>,
) -> Result<OwnerResponse<Body>> {
    let parsed = url::Url::parse(req.uri().to_string().as_str())?;
    let scheme = parsed.scheme().to_string();
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("absolute request URI missing host"))?
        .to_string();
    let port = parsed
        .port()
        .unwrap_or_else(|| super::super::dispatch::default_port_for_scheme(scheme.as_str()));
    let authority = qpx_http::protocol::address::format_authority_host_port(&host, port);
    let slot = pools.direct_origin.https_slot(https_origin_pool_key(
        authority.as_str(),
        authority.as_str(),
        host.as_str(),
        true,
        trust,
    ));

    match acquire_https_connection(
        &slot,
        authority.as_str(),
        host.as_str(),
        true,
        trust,
        pools.direct_origin.h2_tuning(),
    )
    .await?
    {
        HttpsConnectionAcquisition::H2Ready { shared, ready } => {
            let req = prepare_h2_request(req, scheme.as_str(), authority.as_str(), None)?;
            let hyper_req = req.into_http_for_codec().map_err(|err| anyhow!("{err}"))?;
            let mut proxied = send_h2_request_with_sender(
                hyper_req,
                ready,
                Some(shared.upstream_cert.clone()),
                Some(shared.inflight_streams.clone()),
            )
            .await?;
            attach_interim_response_heads(&mut proxied.response, proxied.interim);
            Ok(proxied.response)
        }
        HttpsConnectionAcquisition::H1(entry) => {
            *req.version_mut() = http::Version::HTTP_11;
            crate::upstream::http1::ensure_origin_form_uri(&mut req)?;
            let host = OrdinaryHeaderName::try_from(HOST).expect("host is an ordinary field");
            if !req.headers().contains_key(&host) {
                req.headers_mut()
                    .insert(host, HeaderValue::from_str(authority.as_str())?);
            }
            let mut proxied = send_tls_http1_with_recycle(slot, entry, req).await?;
            attach_interim_response_heads(&mut proxied.response, proxied.interim);
            Ok(proxied.response)
        }
    }
}

pub(super) async fn send_tls_http1_with_recycle(
    slot: Arc<HttpsOriginSlot>,
    entry: TlsHttp1OriginConnection,
    req: OwnerRequest<Body>,
) -> Result<Http1ResponseWithInterim> {
    let upstream_cert = entry.upstream_cert.clone();
    let hyper_req = crate::upstream::http1::into_http1_for_codec(req)?;
    let mut proxied = send_http1_request_with_interim_reusable(
        entry.stream,
        entry.read_buf,
        entry.write_buf,
        hyper_req,
        Http1ConnectionRecycler::new({
            let slot = slot.clone();
            move |stream, read_buf, write_buf| {
                let upstream_cert = upstream_cert.clone();
                slot.recycle_http1_idle(TlsHttp1OriginConnection {
                    stream,
                    read_buf,
                    write_buf,
                    upstream_cert,
                });
            }
        }),
    )
    .await?;
    proxied.upstream_cert = Some(entry.upstream_cert);
    Ok(proxied)
}
