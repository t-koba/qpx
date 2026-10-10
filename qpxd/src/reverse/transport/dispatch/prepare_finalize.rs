use super::prepare_cors::apply_cors_to_early_response;
use super::prepare_scan::ReverseRouteSelection;
use super::route_constraints::enforce_selected_reverse_route_constraints;
use super::{PreparedReverseRequest, ReversePreparedContext, ReversePreparedRoute};
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::reverse::transport::destination::classify_reverse_destination;
use crate::reverse::transport::{InterimList, ReverseConnInfo};
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use qpx_http::body::Body;
use std::sync::Arc;

#[expect(
    clippy::too_many_arguments,
    reason = "route finalize assembles the prepared request from explicit selection outputs"
)]
pub(super) fn finalize_reverse_route_selection(
    req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    compiled: &Arc<crate::reverse::CompiledReverse>,
    cors_request: Option<&qpx_core::cors::CorsRequest>,
    host: &str,
    mut selection: ReverseRouteSelection,
    owned_sanitized_headers: Option<http::HeaderMap>,
    request_rpc: Option<crate::http::rpc::RpcMatchContext>,
) -> Result<std::result::Result<PreparedReverseRequest, (InterimList, Response<Body>)>> {
    let router = &compiled.router;
    let selected_route_idx = selection
        .route_idx
        .ok_or_else(|| anyhow!("no route matched"))?;
    let selected_route = router
        .route_at(selected_route_idx)
        .ok_or_else(|| anyhow!("selected reverse route is unavailable"))?;
    let selected_resolution_override = selected_route.plan.destination_resolution.as_ref();
    let selected_override_key = super::destination_override_key(selected_resolution_override);
    if !selection
        .request_destination_cache
        .contains(selected_override_key)
    {
        let destination = if selected_route.requires_destination_after_selection()
            || state.destination_trace_enabled()
        {
            classify_reverse_destination(state, conn, host, None, selected_resolution_override)
        } else {
            crate::destination::DestinationMetadata::default()
        };
        selection
            .request_destination_cache
            .push(selected_override_key, destination);
    }
    let req = match enforce_selected_reverse_route_constraints(
        req,
        selected_route,
        &base.method,
        state,
        conn,
    )? {
        Ok(req) => req,
        Err(mut response) => {
            super::apply_reverse_route_metadata(
                selected_route,
                conn.tls_terminated,
                &mut response.1,
            )?;
            apply_cors_to_early_response(selected_route, cors_request, &mut response.1);
            return Ok(Err(response));
        }
    };

    Ok(Ok(PreparedReverseRequest {
        req,
        context: ReversePreparedContext {
            compiled: Arc::clone(compiled),
            state: Arc::clone(state),
        },
        route: ReversePreparedRoute {
            route_idx: selected_route_idx,
            selected_policy: selection.selected_policy,
            identity: selection
                .selected_identity
                .ok_or_else(|| anyhow!("identity missing for selected reverse route"))?,
            sanitized_headers: owned_sanitized_headers,
            request_destination_cache: selection.request_destination_cache,
            max_observed_request_body_bytes: selection.max_observed_request_body_bytes,
        },
        observation: crate::http::pipeline::types::RequestObservation {
            request_rpc,
            response_request_observation: Default::default(),
            request_body_observed: selection.observation_plan.needs_body,
            request_rpc_observed: selection.observation_plan.needs_rpc,
        },
    }))
}
