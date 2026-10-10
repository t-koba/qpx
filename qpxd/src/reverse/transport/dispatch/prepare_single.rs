use super::route_constraints::{
    ReverseEarlyResult, enforce_selected_reverse_route_constraints, reverse_security_rejection,
};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::reverse::transport::ReverseConnInfo;
use anyhow::Result;
use hyper::Request;
use qpx_http::body::Body;

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
