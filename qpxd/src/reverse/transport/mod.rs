use super::router::ReverseRouter;
use crate::http::dispatcher::InterimList;
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::http::protocol::preflight::{
    ConnectPolicy, PreflightOptions, PreflightOutcome, preflight_validate,
};
use crate::runtime::Runtime;
use crate::upstream::origin::PreparedPlainHttp1ConnectionAffinity;
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
mod raw_http1;
mod request_template;
mod response_rules;

use self::dispatch::{dispatch_reverse_request, try_dispatch_unconditional_plain_reverse_request};
pub(super) use self::mirrors::prune_mirror_permits;
pub(in crate::reverse) use self::raw_http1::{
    PreparedRawHttp1Request, PreparedRawHttp1Response, RawHttp1ConnectionCache,
    RawHttp1RequestView, dispatch_prepared_raw_http1_request, prepare_raw_http1_request,
};

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

#[cfg(any(feature = "http3", test))]
pub(super) async fn handle_request_with_interim(
    req: Request<Body>,
    reverse: super::ReloadableReverse,
    conn: ReverseConnInfo,
) -> Result<(InterimList, Response<Body>), Infallible> {
    handle_request_with_interim_ref(req, &reverse, &conn).await
}

pub(super) async fn handle_request_with_interim_ref(
    req: Request<Body>,
    reverse: &super::ReloadableReverse,
    conn: &ReverseConnInfo,
) -> Result<(InterimList, Response<Body>), Infallible> {
    handle_request_with_interim_and_origin_pool_ref(req, reverse, conn, None).await
}

pub(super) async fn handle_request_with_interim_and_origin_pool_ref(
    req: Request<Body>,
    reverse: &super::ReloadableReverse,
    conn: &ReverseConnInfo,
    origin_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, Response<Body>), Infallible> {
    let runtime = &reverse.runtime;
    let state = runtime.state();
    let request_method = req.method().clone();
    let request_version = req.version();
    match handle_request_inner_with_origin_pool(req, reverse, runtime, conn, state, origin_pool)
        .await
    {
        Ok(response) => Ok(response),
        Err(err) => {
            warn!(error = ?err, "reverse handling failed");
            let state = runtime.state();
            Ok(empty_interim_response(
                response_rules::reverse_gateway_error_response(
                    &request_method,
                    request_version,
                    state.plan.identity.proxy_name.as_ref(),
                    state.messages.reverse_error.as_str(),
                ),
            ))
        }
    }
}

async fn handle_request_inner_with_origin_pool(
    mut req: Request<Body>,
    reverse: &super::ReloadableReverse,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    state: Arc<crate::runtime::RuntimeState>,
    origin_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, Response<Body>)> {
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let common_h2_request =
        qpx_http::protocol::semantics::is_intrinsically_valid_common_h2_request(&req);
    if common_h2_request {
        req = match try_dispatch_unconditional_plain_reverse_request(
            req,
            reverse,
            conn,
            &state,
            origin_pool,
        )
        .await?
        {
            Ok(response) => return Ok(response),
            Err(req) => req,
        };
    }
    let validated_request = match preflight_validate(
        &mut req,
        proxy_name,
        PreflightOptions {
            trace_enabled: state.plan.limits.general.trace_enabled,
            trace_disabled_message: state.messages.trace_disabled.as_str(),
            connect_policy: ConnectPolicy::Reject {
                status: StatusCode::METHOD_NOT_ALLOWED,
                body: state.messages.reverse_error.as_str(),
            },
        },
    ) {
        PreflightOutcome::Continue(validated) => validated,
        PreflightOutcome::Reject(response) => return Ok(empty_interim_response(*response)),
    };
    if !common_h2_request {
        req = match try_dispatch_unconditional_plain_reverse_request(
            req,
            reverse,
            conn,
            &state,
            origin_pool,
        )
        .await?
        {
            Ok(response) => return Ok(response),
            Err(req) => req,
        };
    }
    let base = extract_base_request_fields(
        &req,
        BaseRequestContext {
            peer_ip: Some(conn.remote_addr.ip()),
            dst_port: Some(conn.dst_port),
            shared_sni: conn.tls_sni.clone(),
            scheme: Some(if conn.tls_terminated {
                http::uri::Scheme::HTTPS
            } else {
                http::uri::Scheme::HTTP
            }),
            validated_request: Some(validated_request),
            ..Default::default()
        },
    );
    dispatch_reverse_request(req, base, reverse, runtime, conn, state).await
}

#[cfg(test)]
mod tests;
