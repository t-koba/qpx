use super::prepare_scan::{
    ReverseRouteSelection, sanitized_headers_for_route_scan, scan_reverse_routes,
};
use super::{InlineCache, InterimList, ReverseConnInfo};
use crate::http::body::observation::RequestObservationPlan;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::policy_context::{
    EffectivePolicyContext, IdentityRequestContext, authentication_response_for_error,
};
use crate::reverse::transport::ReverseRouter;
use crate::reverse::transport::empty_interim_response;
use anyhow::Result;
use hyper::Response;
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
use std::sync::Arc;

pub(super) struct InitialReverseScan {
    pub(super) selection: ReverseRouteSelection,
    pub(super) owned_sanitized_headers: Option<http::HeaderMap>,
    pub(super) identity_request: Option<IdentityRequestContext>,
}

pub(super) fn reverse_prefilter_context<'a>(
    base: &'a BaseRequestFields,
    conn: &'a ReverseConnInfo,
    host: &'a str,
) -> MatchPrefilterContext<'a> {
    MatchPrefilterContext {
        method: Some(base.method.as_str()),
        dst_port: Some(conn.dst_port),
        src_ip: Some(conn.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host),
        sni: conn.tls_sni.as_deref(),
        path: base.path(),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "initial scan carries explicit immutable match facts for the first scan"
)]
pub(super) async fn initial_scan_reverse_routes(
    request_headers: &http::HeaderMap,
    request_version: http::Version,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    router: &ReverseRouter,
    host: &str,
    prefilter_ctx: MatchPrefilterContext<'_>,
) -> Result<std::result::Result<InitialReverseScan, (InterimList, Response<Body>)>> {
    let request_method = &base.method;
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let mut selection = ReverseRouteSelection {
        route_idx: None,
        selected_policy: EffectivePolicyContext::default(),
        selected_identity: None,
        request_destination_cache: InlineCache::new(),
        identity_cache: InlineCache::new(),
        observation_plan: RequestObservationPlan::default(),
        max_observed_request_body_bytes: state.plan.limits.body.max_observed_request_body_bytes,
        collect_observation_from_remaining: false,
    };
    let sanitized_route_headers = sanitized_headers_for_route_scan(request_headers, state, conn)?;
    let identity_request = if state.security.identity_sources.sources.is_empty() {
        None
    } else {
        IdentityRequestContext::from_base(base, if conn.tls_terminated { "https" } else { "http" })
    };
    if let Err(error) = scan_reverse_routes(
        router,
        request_headers,
        sanitized_route_headers.as_ref(),
        base,
        state,
        conn,
        host,
        prefilter_ctx,
        None,
        None,
        false,
        identity_request.as_ref(),
        &mut selection,
    )
    .await
    {
        if let Some(response) =
            authentication_response_for_error(request_method, request_version, proxy_name, &error)
        {
            return Ok(Err(empty_interim_response(response?)));
        }
        return Err(error);
    }
    let owned_sanitized_headers = match sanitized_route_headers {
        std::borrow::Cow::Borrowed(_) => None,
        std::borrow::Cow::Owned(headers) => Some(headers),
    };
    Ok(Ok(InitialReverseScan {
        selection,
        owned_sanitized_headers,
        identity_request,
    }))
}
