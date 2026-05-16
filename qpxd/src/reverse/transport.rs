use super::request_template::{ReverseRequestTemplate, request_is_retryable};
use super::router::{ReverseRouter, normalize_host_for_match};
use crate::cache::CacheRequestKey;
use crate::http::base_fields::{
    BaseRequestContext, BaseRequestFields, extract_base_request_fields,
};
use crate::http::body::Body;
use crate::http::body_size::{buffer_request_body, observed_request_size};
use crate::http::cache_flow::{
    CacheLookupDecision, CacheWritebackContext, clone_request_head_for_revalidation,
    lookup_with_revalidation, process_upstream_response_for_cache,
};
use crate::http::common::too_many_requests_response as too_many_requests;
use crate::http::header_control::apply_request_headers;
use crate::http::l7::{
    finalize_response_for_request, finalize_response_with_headers,
    finalize_response_with_headers_in_place, handle_max_forwards_in_place,
};
use crate::http::local_response::build_local_response;
use crate::http::preflight::{
    ConnectPolicy, PreflightOptions, PreflightOutcome, preflight_validate,
};
use crate::http::websocket::is_websocket_upgrade;
use crate::ipc_client::{ClientConnInfo, proxy_ipc, proxy_ipc_upstream};
use crate::policy_context::{
    EffectivePolicyContext, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, enforce_ext_authz,
    merge_header_controls, resolve_identity, sanitize_headers_for_policy,
    strip_untrusted_identity_headers, validate_ext_authz_allow_mode,
};
use crate::rate_limit::RateLimitContext;
use crate::runtime::Runtime;
use crate::tls::UpstreamCertificateInfo;
use crate::upstream::origin::{
    OriginEndpoint, proxy_http, proxy_http_with_interim, proxy_websocket,
};
use crate::upstream::raw_http1::InterimResponseHead;
use anyhow::{Result, anyhow};
use hyper::{Method, Request, Response, StatusCode};
use metrics::{counter, histogram};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_core::rules::CompiledHeaderControl;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::{Duration, Instant, sleep, timeout};
use tracing::warn;
use url::Url;

#[path = "destination.rs"]
mod reverse_destination;
#[path = "transport_dispatch.rs"]
mod reverse_dispatch;
#[path = "mirrors.rs"]
mod reverse_mirrors;
#[path = "path_rewrite.rs"]
mod reverse_path_rewrite;
#[path = "response_rules.rs"]
mod reverse_response_rules;
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
#[path = "tls_accept.rs"]
mod tls_accept;

use self::reverse_destination::classify_reverse_destination;
use self::reverse_dispatch::dispatch_reverse_request;
use self::reverse_mirrors::{
    dispatch_mirrors, record_reverse_upstream_error, record_reverse_upstream_status,
    record_reverse_upstream_timeout, request_is_templateable, request_seed,
};
use self::reverse_path_rewrite::apply_path_rewrite;
use self::reverse_response_rules::{ResponseRuleInput, apply_response_rules};
#[cfg(any(feature = "tls-rustls", feature = "tls-native"))]
pub(in crate::reverse) use self::tls_accept::{ReverseTlsAcceptor, build_tls_acceptor};

enum ResponseRuleDecision {
    Continue {
        response: Response<Body>,
        route_headers: Option<Arc<CompiledHeaderControl>>,
        cache_bypass: bool,
        suppress_retry: bool,
        mirror: Option<bool>,
        policy_tags: Arc<[String]>,
    },
    LocalResponse {
        response: Response<Body>,
        route_headers: Option<Arc<CompiledHeaderControl>>,
        policy_tags: Arc<[String]>,
    },
}

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
                Arc::new(crate::tls::cert_info::extract_upstream_certificate_info(
                    Some(cert.as_slice()),
                ))
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

pub(crate) type ReverseInterimResponses = Vec<InterimResponseHead>;

fn empty_interim_response(response: Response<Body>) -> (ReverseInterimResponses, Response<Body>) {
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
) -> Result<(ReverseInterimResponses, Response<Body>), Infallible> {
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
) -> Result<(ReverseInterimResponses, Response<Body>)> {
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    if let PreflightOutcome::Reject(response) = preflight_validate(
        &req,
        proxy_name,
        PreflightOptions {
            trace_enabled: state.plan.limits.trace_enabled,
            trace_disabled_message: state.messages.trace_disabled.as_str(),
            connect_policy: ConnectPolicy::Reject {
                status: StatusCode::METHOD_NOT_ALLOWED,
                body: state.messages.reverse_error.as_str(),
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
#[path = "transport_tests.rs"]
mod tests;
