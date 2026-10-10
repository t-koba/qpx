use super::prepare_cors::apply_cors_to_early_response;
use super::route_constraints::{
    ReverseEarlyResult, enforce_selected_reverse_route_constraints, reverse_security_rejection,
};
use super::{InlineCache, PreparedReverseRequest, ReversePreparedContext, ReversePreparedRoute};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::reverse::transport::ReverseConnInfo;
use anyhow::{Result, anyhow};
use hyper::Request;
use qpx_http::body::Body;
use std::sync::Arc;

pub(super) fn prepare_single_plain_reverse_request(
    req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &crate::runtime::RuntimeState,
    compiled: &crate::reverse::CompiledReverse,
) -> Result<ReverseEarlyResult<Option<Request<Body>>>> {
    let Some(route) = compiled.router.single_plain_http_route() else {
        return Ok(Ok(None));
    };
    prepare_single_reverse_route_request(req, base, conn, state, compiled, route)
}

pub(super) fn prepare_single_webdav_reverse_request(
    req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &crate::runtime::RuntimeState,
    compiled: &crate::reverse::CompiledReverse,
) -> Result<ReverseEarlyResult<Option<Request<Body>>>> {
    let Some(route) = compiled.router.single_direct_webdav_route() else {
        return Ok(Ok(None));
    };
    prepare_single_reverse_route_request(req, base, conn, state, compiled, route)
}

pub(super) fn prepare_single_local_response_reverse_request(
    req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &crate::runtime::RuntimeState,
    compiled: &crate::reverse::CompiledReverse,
) -> Result<ReverseEarlyResult<Option<Request<Body>>>> {
    let Some(route) = compiled.router.single_direct_local_response_route() else {
        return Ok(Ok(None));
    };
    prepare_single_reverse_route_request(req, base, conn, state, compiled, route)
}

fn prepare_single_reverse_route_request(
    req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &crate::runtime::RuntimeState,
    compiled: &crate::reverse::CompiledReverse,
    route: &crate::reverse::router::HttpRoute,
) -> Result<ReverseEarlyResult<Option<Request<Body>>>> {
    if let Some(response) = reverse_security_rejection(&req, conn, state, compiled)? {
        return Ok(Err(response));
    }

    if !route.matches_every_request() {
        let destination = crate::destination::DestinationMetadata::default();
        let identity = crate::policy_context::ResolvedIdentity::default();
        let ctx = crate::http::policy::rule_context::build_request_rule_match_context(
            crate::http::policy::rule_context::RequestRuleContextInput {
                base,
                headers: req.headers(),
                destination: &destination,
                identity: &identity,
                request_size: None,
                rpc: None,
                client_cert: conn.peer_certificate_info.as_deref(),
                upstream_cert: None,
            },
        );
        if !route.matches(&ctx) {
            return Ok(Ok(None));
        }
    }

    match enforce_selected_reverse_route_constraints(req, route, &base.method, state, conn)? {
        Ok(req) => Ok(Ok(Some(req))),
        Err(mut response) => {
            super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response.1)?;
            Ok(Err(response))
        }
    }
}

pub(super) enum SingleHttpPrepare {
    Miss(Box<Request<Body>>),
    Hit(Box<ReverseEarlyResult<PreparedReverseRequest>>),
}

pub(super) fn try_prepare_single_http_reverse_request(
    req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    compiled: &Arc<crate::reverse::CompiledReverse>,
    cors_request: Option<&qpx_core::cors::CorsRequest>,
) -> Result<SingleHttpPrepare> {
    let router = &compiled.router;
    if state.destination_trace_enabled() || !state.security.identity_sources.sources.is_empty() {
        return Ok(SingleHttpPrepare::Miss(Box::new(req)));
    }
    let Some(route) = router.single_http_route() else {
        return Ok(SingleHttpPrepare::Miss(Box::new(req)));
    };
    if !route.plan.policy_context.identity_sources.is_empty()
        || route.response_rules.is_some()
        || route.requires_destination_context()
        || route.requires_request_size()
        || route.requires_request_body_observation()
        || route.requires_request_rpc_context()
        || route
            .plan
            .guard
            .as_deref()
            .is_some_and(|guard| guard.requires_request_body_buffering_from_headers(req.headers()))
    {
        return Ok(SingleHttpPrepare::Miss(Box::new(req)));
    }
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = crate::destination::DestinationMetadata::default();
    let match_context = crate::http::policy::rule_context::build_request_rule_match_context(
        crate::http::policy::rule_context::RequestRuleContextInput {
            base,
            headers: req.headers(),
            destination: &destination,
            identity: &identity,
            request_size: None,
            rpc: None,
            client_cert: conn.peer_certificate_info.as_deref(),
            upstream_cert: None,
        },
    );
    if !route.matches(&match_context) {
        return Err(anyhow!("no route matched"));
    }
    let selected_policy = route.plan.policy_context.clone();
    let max_observed_request_body_bytes = state.plan.limits.body.max_observed_request_body_bytes;
    let override_key = super::destination_override_key(route.plan.destination_resolution.as_ref());
    let req =
        match enforce_selected_reverse_route_constraints(req, route, &base.method, state, conn)? {
            Ok(req) => req,
            Err(mut response) => {
                super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response.1)?;
                apply_cors_to_early_response(route, cors_request, &mut response.1);
                return Ok(SingleHttpPrepare::Hit(Box::new(Err(response))));
            }
        };
    let mut request_destination_cache = InlineCache::new();
    request_destination_cache.push(override_key, destination);
    Ok(SingleHttpPrepare::Hit(Box::new(Ok(
        PreparedReverseRequest {
            req,
            context: ReversePreparedContext {
                compiled: Arc::clone(compiled),
                state: Arc::clone(state),
            },
            route: ReversePreparedRoute {
                route_idx: 0,
                selected_policy,
                identity,
                sanitized_headers: None,
                request_destination_cache,
                max_observed_request_body_bytes,
            },
            observation: crate::http::pipeline::types::RequestObservation {
                request_rpc: None,
                response_request_observation: Default::default(),
                request_body_observed: false,
                request_rpc_observed: false,
            },
        },
    ))))
}
