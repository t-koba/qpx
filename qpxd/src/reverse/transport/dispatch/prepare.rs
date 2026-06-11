use super::{
    PreparedReverseRequest, ReversePreparedContext, ReversePreparedRoute, ReverseRetryDispatch,
    ReverseRetryPrepareInput,
};
use crate::http::body::observation::RequestObservationPlan;
use crate::http::body::size::{limit_request_body, observed_request_size};
use crate::http::dispatch::request_body_too_large_response;
use crate::http::policy::response_policy::response_request_obs;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::policy_context::{
    EffectivePolicyContext, resolve_identity, sanitize_headers_for_policy,
};
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::SelectedMirrorTarget;
use crate::reverse::transport::destination::classify_reverse_destination;
use crate::reverse::transport::mirrors::{
    StreamingMirrorDispatch, dispatch_streaming_mirrors, request_is_templateable,
};
use crate::reverse::transport::request_template::{
    ReverseReplayRecorder, ReverseRequestHeadTemplate, request_is_retryable,
};
use crate::reverse::transport::{
    InterimList, ReverseConnInfo, ReverseRouter, empty_interim_response,
};
use crate::runtime::Runtime;
use anyhow::{Result, anyhow};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::warn;

struct ReverseRouteSelection {
    route_idx: Option<usize>,
    selected_policy: EffectivePolicyContext,
    selected_identity: Option<crate::policy_context::ResolvedIdentity>,
    selected_headers: Option<http::HeaderMap>,
    // Keyed by the identity of the route's compiled `destination_resolution`
    // override (stable for the request lifetime); avoids cloning and hashing
    // the override config on every request.
    request_destination_cache: Vec<(usize, crate::destination::DestinationMetadata)>,
    observation_plan: RequestObservationPlan,
    max_observed_request_body_bytes: usize,
    collect_observation_from_remaining: bool,
}

pub(super) fn attach_streaming_limits(
    mut result: (InterimList, Response<Body>),
    streaming: crate::runtime::ResolvedStreamingLimits,
) -> (InterimList, Response<Body>) {
    result.1.extensions_mut().insert(streaming);
    result
}

pub(super) async fn buffer_reverse_guarded_request(
    req: Request<Body>,
    route_http_guard: Option<&crate::http::policy::guard::CompiledHttpGuardProfile>,
    max_observed_request_body_bytes: usize,
    read_timeout: Duration,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
) -> Result<std::result::Result<Request<Body>, Response<Body>>> {
    let limit_response = || -> Result<Response<Body>> {
        request_body_too_large_response(request_method, request_version, proxy_name, None)
    };
    let mut req = if !route_http_guard
        .is_some_and(|profile| profile.requires_request_body_buffering(&req))
        || crate::http::body::size::has_observed_request_bytes(&req)
    {
        req
    } else {
        match crate::http::body::size::buffer_request_body_with_reason(
            req,
            max_observed_request_body_bytes,
            read_timeout,
            "http_guard.body",
        )
        .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return Ok(Err(limit_response()?));
            }
            Err(err) => return Err(err),
        }
    };
    if let Some(limit) = route_http_guard.and_then(|profile| profile.request_body_streaming_limit())
    {
        req = match crate::http::body::size::limit_request_body(req, limit) {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return Ok(Err(limit_response()?));
            }
            Err(err) => return Err(err),
        };
    }
    Ok(Ok(req))
}

pub(super) async fn prepare_reverse_retry_dispatch(
    input: ReverseRetryPrepareInput<'_>,
) -> Result<ReverseRetryDispatch> {
    let ReverseRetryPrepareInput {
        req,
        route,
        state,
        request_method,
        seed,
        sticky_seed,
        ext_authz_mirror_upstreams,
        route_timeout,
        proxy_name,
    } = input;
    let retry_body_threshold_bytes = if route.policy.retry_body_replay {
        route.policy.retry_body_threshold_bytes
    } else {
        0
    };
    let can_retry = request_is_retryable(&req, request_method, retry_body_threshold_bytes);
    let max_template_body_bytes = state
        .plan
        .limits
        .upstream
        .max_reverse_retry_template_body_bytes;
    let templateable = request_is_templateable(&req, max_template_body_bytes);
    let attempts = if can_retry && templateable {
        route.policy.retry_attempts
    } else {
        1
    };
    let selected_mirrors = route.select_mirror_upstreams(seed, sticky_seed);
    let mut streaming_mirrors = Vec::new();
    let mut mirror_upstreams = Vec::new();
    let ext_authz_mirror_body_limit = Some(
        state
            .plan
            .limits
            .upstream
            .max_reverse_retry_template_body_bytes,
    );
    let mut ext_authz_mirrors = ext_authz_mirror_upstreams
        .into_iter()
        .map(UpstreamEndpoint::new)
        .map(Arc::new)
        .map(|upstream| SelectedMirrorTarget {
            upstream,
            max_mirror_body_bytes: ext_authz_mirror_body_limit,
        })
        .collect::<Vec<_>>();
    if attempts == 1 {
        streaming_mirrors.extend(selected_mirrors);
        streaming_mirrors.append(&mut ext_authz_mirrors);
    } else {
        mirror_upstreams.extend(selected_mirrors);
        mirror_upstreams.extend(ext_authz_mirrors);
    }
    let req = if streaming_mirrors.is_empty() {
        req
    } else {
        let mirror_limits = streaming_mirrors
            .iter()
            .map(|mirror| mirror.max_mirror_body_bytes)
            .collect::<Vec<_>>();
        let (parts, body) = req.into_parts();
        let template = ReverseRequestHeadTemplate::from_parts(&parts);
        let (primary_body, mirror_bodies) = qpx_http::body::tee::tee_body_lossy_with_metrics(
            body,
            mirror_limits,
            route.plan.streaming.body_channel_capacity,
            Some("reverse_streaming_mirror"),
        );
        dispatch_streaming_mirrors(StreamingMirrorDispatch {
            pools: state.pools.clone(),
            template,
            mirror_upstreams: streaming_mirrors,
            mirror_bodies,
            timeout_dur: route_timeout,
            health_policy: route.policy.health.clone(),
            lifecycle: route.policy.lifecycle.clone(),
            upstream_trust: route.upstream_trust.clone(),
            proxy_name,
        });
        Request::from_parts(parts, primary_body)
    };
    let need_template = attempts > 1 || !mirror_upstreams.is_empty();
    let (first_request, template, replay_recorder) = if need_template {
        let (req, recorder) = ReverseReplayRecorder::wrap_first_request(
            req,
            max_template_body_bytes,
            Duration::from_millis(route.plan.streaming.body_read_timeout_ms),
            route.plan.streaming.body_channel_capacity,
        );
        (Some(req), None, Some(recorder))
    } else {
        (Some(req), None, None)
    };
    Ok(ReverseRetryDispatch {
        attempts,
        first_request,
        template,
        replay_recorder,
        mirror_upstreams,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "route scan receives explicit immutable match facts instead of a broad mutable context"
)]
fn scan_reverse_routes(
    router: &ReverseRouter,
    req: &Request<Body>,
    base: &BaseRequestFields,
    state: &Arc<crate::runtime::RuntimeState>,
    conn: &ReverseConnInfo,
    host: &str,
    prefilter_ctx: MatchPrefilterContext<'_>,
    request_size: Option<u64>,
    request_rpc: Option<&crate::http::rpc::RpcMatchContext>,
    selection: &mut ReverseRouteSelection,
) -> Result<()> {
    router.try_for_each_candidate_route(prefilter_ctx.clone(), |idx, route| {
        let resolution_override = route.plan.destination_resolution.as_ref();
        let effective_policy = route.plan.policy_context.clone();
        let mut sanitized_headers = req.headers().clone();
        sanitize_headers_for_policy(
            state,
            &effective_policy,
            conn.remote_addr.ip(),
            &mut sanitized_headers,
        )?;
        let identity = resolve_identity(
            state,
            &effective_policy,
            conn.remote_addr.ip(),
            Some(&sanitized_headers),
            conn.peer_certificates
                .as_deref()
                .map(|certs| certs.as_slice()),
        )?;
        let override_key = super::destination_override_key(resolution_override);
        let request_destination = match selection
            .request_destination_cache
            .iter()
            .find(|(key, _)| *key == override_key)
        {
            Some((_, destination)) => destination.clone(),
            None => {
                let destination =
                    classify_reverse_destination(state, conn, host, None, resolution_override);
                selection
                    .request_destination_cache
                    .push((override_key, destination.clone()));
                destination
            }
        };
        let ctx = crate::http::policy::rule_context::build_request_rule_match_context(
            crate::http::policy::rule_context::RequestRuleContextInput {
                base,
                headers: &sanitized_headers,
                destination: &request_destination,
                identity: &identity,
                request_size,
                rpc: request_rpc,
                client_cert: conn.peer_certificate_info.as_deref(),
                upstream_cert: None,
            },
        );
        if request_size.is_some() || request_rpc.is_some() {
            if route.matches(&ctx) {
                selection.route_idx = Some(idx);
                selection.selected_policy = effective_policy;
                selection.selected_identity = Some(identity);
                selection.selected_headers = Some(sanitized_headers);
                return Ok::<bool, anyhow::Error>(true);
            }
            return Ok::<bool, anyhow::Error>(false);
        }
        let route_http_guard = route.plan.guard.as_deref();
        let guard_requires_buffering =
            route_http_guard.is_some_and(|profile| profile.requires_request_body_buffering(req));
        let response_rule_candidates = route.response_rule_candidate_profile(prefilter_ctx.clone());
        let response_rule_request_observation = response_request_obs(
            route.response_rules.as_deref(),
            &response_rule_candidates,
            &ctx,
        );
        let route_needs_observation = route.requires_request_size()
            || route.requires_request_body_observation()
            || route.requires_request_rpc_context()
            || response_rule_request_observation.needs_body
            || response_rule_request_observation.needs_rpc
            || guard_requires_buffering;
        if route_needs_observation || selection.collect_observation_from_remaining {
            if route.matches_without_request_body_observation(&ctx) {
                selection.collect_observation_from_remaining = true;
                let mut route_limit = route_http_guard
                    .and_then(|profile| profile.request_body_observation_cap())
                    .unwrap_or(state.plan.limits.body.max_observed_request_body_bytes)
                    .min(state.plan.limits.body.max_observed_request_body_bytes);
                route_limit = route.plan.request_body_observation_limit(route_limit);
                selection.max_observed_request_body_bytes =
                    selection.max_observed_request_body_bytes.min(route_limit);
                selection.observation_plan.include(
                    route.requires_request_size(),
                    route.requires_request_body_observation()
                        || response_rule_request_observation.needs_body,
                    route.requires_request_rpc_context()
                        || response_rule_request_observation.needs_rpc,
                );
                selection
                    .observation_plan
                    .include_body_with_reason(guard_requires_buffering, "http_guard.body");
            }
            return Ok::<bool, anyhow::Error>(false);
        }
        if route.matches(&ctx) {
            selection.route_idx = Some(idx);
            selection.selected_policy = effective_policy;
            selection.selected_identity = Some(identity);
            selection.selected_headers = Some(sanitized_headers);
            return Ok::<bool, anyhow::Error>(true);
        }
        Ok::<bool, anyhow::Error>(false)
    })?;
    Ok(())
}

pub(super) async fn prepare_reverse_request(
    mut req: Request<Body>,
    base: &BaseRequestFields,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    compiled: Arc<crate::reverse::CompiledReverse>,
) -> Result<std::result::Result<PreparedReverseRequest, (InterimList, Response<Body>)>> {
    let router: Arc<ReverseRouter> = compiled.router.clone();
    let security_policy = compiled.security_policy.as_ref();
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.to_string();
    if let Err(err) =
        security_policy.validate_request(&req, conn.tls_sni.as_deref(), conn.tls_terminated)
    {
        warn!(error = ?err, "reverse TLS host policy rejected request");
        let request_method = req.method().clone();
        return Ok(Err(empty_interim_response(finalize_response_for_request(
            &request_method,
            req.version(),
            state.plan.identity.proxy_name.as_ref(),
            Response::builder()
                .status(StatusCode::MISDIRECTED_REQUEST)
                .body(Body::from("misdirected request"))?,
            false,
        ))));
    }

    let host = base.host.clone().unwrap_or_default();
    let request_method = req.method().clone();
    let request_version = req.version();
    let request_body_too_large = || {
        request_body_too_large_response(&request_method, request_version, proxy_name.as_ref(), None)
            .map(empty_interim_response)
    };
    let path_owned = base.path.clone();
    let request_uri = base.request_uri.clone();
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(request_method.as_str()),
        dst_port: Some(conn.dst_port),
        src_ip: Some(conn.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host.as_str()),
        sni: conn.tls_sni.as_deref(),
        path: path_owned.as_deref(),
    };
    let mut selection = ReverseRouteSelection {
        route_idx: None,
        selected_policy: EffectivePolicyContext::default(),
        selected_identity: None,
        selected_headers: None,
        request_destination_cache: Vec::new(),
        observation_plan: RequestObservationPlan::default(),
        max_observed_request_body_bytes: state.plan.limits.body.max_observed_request_body_bytes,
        collect_observation_from_remaining: false,
    };
    scan_reverse_routes(
        &router,
        &req,
        base,
        &state,
        conn,
        host.as_str(),
        prefilter_ctx.clone(),
        None,
        None,
        &mut selection,
    )?;

    if selection.route_idx.is_none() && !selection.observation_plan.is_empty() {
        req = match selection
            .observation_plan
            .observe_request(
                req,
                selection.max_observed_request_body_bytes,
                std::time::Duration::from_millis(compiled.streaming.body_read_timeout_ms),
            )
            .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return Ok(Err(request_body_too_large()?));
            }
            Err(err) => return Err(err),
        };
    }
    let request_rpc = if selection.observation_plan.needs_rpc {
        Some(crate::http::rpc::inspect_request(&req).await)
    } else {
        None
    };

    if selection.route_idx.is_none() {
        scan_reverse_routes(
            &router,
            &req,
            base,
            &state,
            conn,
            host.as_str(),
            prefilter_ctx,
            observed_request_size(&req),
            request_rpc.as_ref(),
            &mut selection,
        )?;
    }

    let selected_route_idx = selection
        .route_idx
        .ok_or_else(|| anyhow!("no route matched"))?;
    let selected_route = router
        .route_at(selected_route_idx)
        .ok_or_else(|| anyhow!("selected reverse route is unavailable"))?;
    let route_request_limit = selected_route.plan.streaming.max_request_body_bytes;
    if let Some(size) = observed_request_size(&req)
        && size > route_request_limit as u64
    {
        return Ok(Err(request_body_too_large()?));
    }
    req = match limit_request_body(req, route_request_limit) {
        Ok(req) => req,
        Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
            return Ok(Err(request_body_too_large()?));
        }
        Err(err) => return Err(err),
    };

    Ok(Ok(PreparedReverseRequest {
        req,
        context: ReversePreparedContext {
            router,
            state,
            proxy_name,
        },
        route: ReversePreparedRoute {
            host,
            request_method,
            request_version,
            path_owned,
            request_uri,
            route_idx: selected_route_idx,
            selected_policy: selection.selected_policy,
            identity: selection
                .selected_identity
                .ok_or_else(|| anyhow!("identity missing for selected reverse route"))?,
            sanitized_headers: selection
                .selected_headers
                .ok_or_else(|| anyhow!("sanitized headers missing for selected reverse route"))?,
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
