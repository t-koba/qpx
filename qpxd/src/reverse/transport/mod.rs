use super::router::ReverseRouter;
use crate::http::dispatcher::InterimList;
use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
use crate::http::protocol::preflight::{
    ConnectPolicy, PreflightOptions, PreflightOutcome, preflight_validate,
};
use crate::runtime::Runtime;
use crate::upstream::origin::PreparedPlainHttp1ConnectionAffinity;
use anyhow::Result;
use hyper::{Response, StatusCode};
use qpx_core::http_message::{Headers, OrdinaryHeaderMut, Request, Response as OwnerResponse};
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

// The raw-H1 dispatcher still owns its standard head until its InMemory
// decision. Select the carrier after standard-only finalization, before the
// reverse capture/limit/audit tail and shared route effects. Ordinary services
// select the opaque owner, with no owner-to-standard bridge.
pub(super) trait ReverseTerminalResponse:
    crate::http::response_carrier::ResponseCarrier
{
    type Headers: OrdinaryHeaderMut;
    fn from_finalized_http(response: Response<Body>) -> Self;
    fn from_finalized_owner(response: OwnerResponse<Body>) -> Self;
    fn terminal_headers_mut(&mut self) -> &mut Self::Headers;
}

impl ReverseTerminalResponse for Response<Body> {
    type Headers = http::HeaderMap;
    fn from_finalized_http(response: Response<Body>) -> Self {
        response
    }
    fn from_finalized_owner(response: OwnerResponse<Body>) -> Self {
        response.into_http_for_library()
    }
    fn terminal_headers_mut(&mut self) -> &mut Self::Headers {
        self.headers_mut()
    }
}

impl ReverseTerminalResponse for OwnerResponse<Body> {
    type Headers = Headers;
    fn from_finalized_http(response: Response<Body>) -> Self {
        Self::from_http(response)
    }
    fn from_finalized_owner(response: OwnerResponse<Body>) -> Self {
        response
    }
    fn terminal_headers_mut(&mut self) -> &mut Self::Headers {
        self.headers_mut()
    }
}

fn empty_interim_response<R>(response: R) -> (InterimList, R) {
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
) -> Result<OwnerResponse<Body>, Infallible> {
    let (_, response) = handle_request_with_interim(req, reverse, conn).await?;
    Ok(response)
}

#[cfg(any(feature = "http3", test))]
pub(super) async fn handle_request_with_interim(
    req: Request<Body>,
    reverse: super::ReloadableReverse,
    conn: ReverseConnInfo,
) -> Result<(InterimList, OwnerResponse<Body>), Infallible> {
    handle_request_with_interim_ref(req, &reverse, &conn).await
}

pub(super) async fn handle_request_with_interim_ref<R: ReverseTerminalResponse>(
    req: Request<Body>,
    reverse: &super::ReloadableReverse,
    conn: &ReverseConnInfo,
) -> Result<(InterimList, R), Infallible> {
    handle_request_with_interim_and_origin_pool_ref(req, reverse, conn, None).await
}

pub(super) async fn handle_request_with_interim_and_origin_pool_ref<R: ReverseTerminalResponse>(
    req: Request<Body>,
    reverse: &super::ReloadableReverse,
    conn: &ReverseConnInfo,
    origin_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, R), Infallible> {
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
            Ok((
                Vec::new(),
                R::from_finalized_http(response_rules::reverse_gateway_error_response(
                    &request_method,
                    request_version,
                    state.plan.identity.proxy_name.as_ref(),
                    state.messages.reverse_error.as_str(),
                )),
            ))
        }
    }
}

async fn handle_request_inner_with_origin_pool<R: ReverseTerminalResponse>(
    mut req: Request<Body>,
    reverse: &super::ReloadableReverse,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    state: Arc<crate::runtime::RuntimeState>,
    origin_pool: Option<&PreparedPlainHttp1ConnectionAffinity>,
) -> Result<(InterimList, R)> {
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
            Ok((interim, response)) => return Ok((interim, response)),
            Err(req) => req,
        };
    }
    let validated_request = match preflight_validate(
        &req,
        proxy_name,
        PreflightOptions {
            trace_enabled: state.plan.limits.general.trace_enabled,
            trace_disabled_message: state.messages.trace_disabled.as_str(),
            connect_policy: ConnectPolicy::Reject {
                status: StatusCode::METHOD_NOT_ALLOWED,
                body: state.messages.reverse_error.as_str(),
            },
        },
        None,
    ) {
        PreflightOutcome::Continue(validated) => validated,
        PreflightOutcome::Reject(response) => {
            return Ok((Vec::new(), R::from_finalized_owner(*response)));
        }
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
            Ok((interim, response)) => return Ok((interim, response)),
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
    // Keep the full feature-rich dispatcher behind an allocation boundary so
    // unconditional routes do not move its large state machine on every request.
    Box::pin(dispatch_reverse_request(
        req,
        base,
        reverse,
        runtime,
        conn,
        state,
        origin_pool,
    ))
    .await
}

#[cfg(test)]
mod tests;
