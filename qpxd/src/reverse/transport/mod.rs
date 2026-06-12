use super::router::{ReverseRouter, normalize_host_for_match};
use crate::http::dispatcher::InterimList;
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::http::protocol::l7::finalize_response_for_request;
use crate::http::protocol::preflight::{
    ConnectPolicy, PreflightOptions, PreflightOutcome, preflight_validate,
};
use crate::runtime::Runtime;
use anyhow::Result;
use hyper::{Request, Response, StatusCode};
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_http::body::Body;
use std::convert::Infallible;
use std::sync::Arc;
use tracing::warn;

mod destination;
mod dispatch;
mod metrics;
mod mirrors;
mod path_rewrite;
mod request_template;
mod response_rules;

use self::dispatch::dispatch_reverse_request;
pub(super) use self::mirrors::prune_mirror_permits;

#[derive(Debug, Clone)]
pub(crate) struct ReverseConnInfo {
    pub(crate) remote_addr: std::net::SocketAddr,
    pub(crate) dst_port: u16,
    pub(crate) tls_sni: Option<Arc<str>>,
    pub(crate) tls_terminated: bool,
    pub(crate) peer_certificates: Option<Arc<Vec<Vec<u8>>>>,
    pub(crate) peer_certificate_info: Option<Arc<UpstreamCertificateInfo>>,
}

impl ReverseConnInfo {
    pub(crate) fn plain(remote_addr: std::net::SocketAddr, dst_port: u16) -> Self {
        Self {
            remote_addr,
            dst_port,
            tls_sni: None,
            tls_terminated: false,
            peer_certificates: None,
            peer_certificate_info: None,
        }
    }

    #[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
    pub(crate) fn terminated(
        remote_addr: std::net::SocketAddr,
        dst_port: u16,
        tls_sni: Option<Arc<str>>,
        peer_certificates: Option<Arc<Vec<Vec<u8>>>>,
    ) -> Self {
        let peer_certificate_info = peer_certificates
            .as_deref()
            .and_then(|certs| certs.first())
            .map(|cert| {
                Arc::new(qpx_core::tls::extract_upstream_certificate_info(Some(
                    cert.as_slice(),
                )))
            });
        Self {
            remote_addr,
            dst_port,
            tls_sni,
            tls_terminated: true,
            peer_certificates,
            peer_certificate_info,
        }
    }
}

fn empty_interim_response(response: Response<Body>) -> (InterimList, Response<Body>) {
    (Vec::new(), response)
}

#[cfg(all(
    feature = "http3",
    feature = "http3-backend-h3",
    not(feature = "http3-backend-qpx")
))]
pub(super) async fn handle_request(
    req: Request<Body>,
    reverse: super::ReloadableReverse,
    conn: ReverseConnInfo,
) -> Result<Response<Body>, Infallible> {
    let (_, response) = handle_request_with_interim(req, reverse, conn).await?;
    Ok(response)
}

pub(super) async fn handle_request_with_interim(
    req: Request<Body>,
    reverse: super::ReloadableReverse,
    conn: ReverseConnInfo,
) -> Result<(InterimList, Response<Body>), Infallible> {
    let runtime = reverse.runtime.clone();
    let state = runtime.state();
    let request_method = req.method().clone();
    let request_version = req.version();
    match handle_request_inner(req, reverse, runtime, conn).await {
        Ok(response) => Ok(response),
        Err(err) => {
            warn!(error = ?err, "reverse handling failed");
            let mut response = Response::new(Body::from(state.messages.reverse_error.clone()));
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            Ok(empty_interim_response(finalize_response_for_request(
                &request_method,
                request_version,
                state.plan.identity.proxy_name.as_ref(),
                response,
                false,
            )))
        }
    }
}

pub(crate) async fn handle_request_inner(
    req: Request<Body>,
    reverse: super::ReloadableReverse,
    runtime: Runtime,
    conn: ReverseConnInfo,
) -> Result<(InterimList, Response<Body>)> {
    let dispatch_view = runtime.dispatch_view();
    let proxy_name = dispatch_view.plan.identity.proxy_name.as_ref();
    if let PreflightOutcome::Reject(response) = preflight_validate(
        &req,
        proxy_name,
        PreflightOptions {
            trace_enabled: dispatch_view.plan.limits.general.trace_enabled,
            trace_disabled_message: dispatch_view.messages.trace_disabled.as_str(),
            connect_policy: ConnectPolicy::Reject {
                status: StatusCode::METHOD_NOT_ALLOWED,
                body: dispatch_view.messages.reverse_error.as_str(),
            },
        },
    ) {
        return Ok(empty_interim_response(*response));
    }
    let authority_owned = req
        .uri()
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        });
    let host_header = authority_owned.as_deref().unwrap_or_default();
    let host = normalize_host_for_match(host_header);
    let base = extract_base_request_fields(
        &req,
        BaseRequestContext {
            peer_ip: Some(conn.remote_addr.ip()),
            dst_port: Some(conn.dst_port),
            host: (!host.is_empty()).then_some(host.as_str()),
            sni: conn.tls_sni.as_deref(),
            authority: authority_owned.as_deref(),
            scheme: Some(if conn.tls_terminated { "https" } else { "http" }),
        },
    );
    dispatch_reverse_request(req, base, reverse, runtime, conn).await
}

#[cfg(test)]
mod tests;
