use super::{
    InlineCache, PreparedReverseRequest, ReversePreparedContext, ReversePreparedRoute,
    ReverseRetryDispatch, ReverseRetryPrepareInput,
};
use crate::http::body::observation::RequestObservationPlan;
use crate::http::body::size::{limit_request_body, observed_request_size};
use crate::http::dispatch::request_body_too_large_response;
use crate::http::policy::response_policy::response_request_obs;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::policy_context::{
    EffectivePolicyContext, IdentityRequestContext, authentication_response_for_error,
    resolve_identity_for_request, sanitize_headers_for_policy,
};
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::SelectedMirrorTarget;
use crate::reverse::transport::destination::classify_reverse_destination;
use crate::reverse::transport::mirrors::{
    StreamingMirrorDispatch, dispatch_streaming_mirrors, request_is_templateable,
};
use crate::reverse::transport::request_template::{
    ReverseReplayRecorder, ReverseRequestHeadTemplate, ReverseRequestTemplate,
    request_is_retryable, request_may_have_body,
};
use crate::reverse::transport::{
    InterimList, ReverseConnInfo, ReverseRouter, empty_interim_response,
};
use anyhow::{Result, anyhow};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::warn;

type ReverseEarlyResult<T> = std::result::Result<T, (InterimList, Response<Body>)>;

struct ReverseRouteSelection {
    route_idx: Option<usize>,
    selected_policy: EffectivePolicyContext,
    selected_identity: Option<crate::policy_context::ResolvedIdentity>,
    // Keyed by the identity of the route's compiled `destination_resolution`
    // override (stable for the request lifetime); avoids cloning and hashing
    // the override config on every request.
    request_destination_cache: InlineCache<crate::destination::DestinationMetadata>,
    // Keyed by the address of the route's compiled policy context. The compiled
    // router is immutable for the request lifetime, so the address is stable.
    identity_cache: InlineCache<crate::policy_context::ResolvedIdentity>,
    observation_plan: RequestObservationPlan,
    max_observed_request_body_bytes: usize,
    collect_observation_from_remaining: bool,
}

pub(super) fn attach_streaming_limits(
    mut result: (InterimList, Response<Body>),
    streaming: crate::runtime::ResolvedStreamingLimits,
    downstream_version: http::Version,
) -> (InterimList, Response<Body>) {
    if downstream_version == http::Version::HTTP_3 {
        result.1.extensions_mut().insert(streaming);
    }
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
        decision_service_mirror_upstreams,
        route_timeout,
        proxy_name,
    } = input;
    if route.policy.retry_attempts == 1
        && !route
            .plan
            .flags
            .contains(crate::runtime::PlanFlags::MIRRORING)
        && decision_service_mirror_upstreams.is_empty()
    {
        return Ok(ReverseRetryDispatch {
            attempts: 1,
            first_request: Some(req),
            template: None,
            replay_recorder: None,
            mirror_upstreams: Vec::new(),
        });
    }
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
    let decision_service_mirror_body_limit = Some(
        state
            .plan
            .limits
            .upstream
            .max_reverse_retry_template_body_bytes,
    );
    let mut decision_service_mirrors = decision_service_mirror_upstreams
        .into_iter()
        .map(UpstreamEndpoint::new)
        .map(Arc::new)
        .map(|upstream| SelectedMirrorTarget {
            upstream,
            max_mirror_body_bytes: decision_service_mirror_body_limit,
        })
        .collect::<Vec<_>>();
    if attempts == 1 {
        streaming_mirrors.extend(selected_mirrors);
        streaming_mirrors.append(&mut decision_service_mirrors);
    } else {
        mirror_upstreams.extend(selected_mirrors);
        mirror_upstreams.extend(decision_service_mirrors);
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
    let (first_request, template, replay_recorder) =
        if need_template && !request_may_have_body(&req) {
            let template = ReverseRequestTemplate::without_body(&req);
            (Some(req), Some(template), None)
        } else if need_template {
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
async fn scan_reverse_routes(
    router: &ReverseRouter,
    request_headers: &http::HeaderMap,
    sanitized_headers: &http::HeaderMap,
    base: &BaseRequestFields,
    state: &Arc<crate::runtime::RuntimeState>,
    conn: &ReverseConnInfo,
    host: &str,
    prefilter_ctx: MatchPrefilterContext<'_>,
    request_size: Option<u64>,
    request_rpc: Option<&crate::http::rpc::RpcMatchContext>,
    cors_only: bool,
    identity_request: Option<&IdentityRequestContext>,
    selection: &mut ReverseRouteSelection,
) -> Result<()> {
    let empty_destination = crate::destination::DestinationMetadata::default();
    if !state.security.identity_sources.sources.is_empty() {
        let mut unresolved_policies = InlineCache::new();
        router.try_for_each_candidate_route(prefilter_ctx.clone(), |_idx, route| {
            if cors_only {
                return Ok::<bool, anyhow::Error>(false);
            }
            let policy = &route.plan.policy_context;
            let key = policy_context_cache_key(policy);
            if !policy.identity_sources.is_empty()
                && !selection.identity_cache.contains(key)
                && !unresolved_policies.contains(key)
            {
                unresolved_policies.push(key, policy.clone());
            }
            Ok::<bool, anyhow::Error>(false)
        })?;
        for (policy_key, policy) in unresolved_policies {
            let identity = resolve_identity_for_request(
                state,
                &policy,
                conn.remote_addr.ip(),
                Some(sanitized_headers),
                conn.peer_certificates
                    .as_deref()
                    .map(|certs| certs.as_slice()),
                identity_request,
            )
            .await?;
            selection.identity_cache.push(policy_key, identity);
        }
    }
    router.try_for_each_candidate_route(prefilter_ctx.clone(), |idx, route| {
        if cors_only && route.plan.cors.is_none() {
            return Ok::<bool, anyhow::Error>(false);
        }
        let resolution_override = route.plan.destination_resolution.as_ref();
        let effective_policy = &route.plan.policy_context;
        let policy_key = policy_context_cache_key(effective_policy);
        let identity = if cors_only {
            crate::policy_context::ResolvedIdentity::default()
        } else {
            match selection.identity_cache.get(policy_key) {
                Some(identity) => identity.clone(),
                None if effective_policy.identity_sources.is_empty() => {
                    crate::policy_context::ResolvedIdentity::default()
                }
                None => return Err(anyhow!("identity cache was not populated for route policy")),
            }
        };
        let request_destination = if route.requires_destination_context() {
            let override_key = super::destination_override_key(resolution_override);
            if !selection.request_destination_cache.contains(override_key) {
                let destination =
                    classify_reverse_destination(state, conn, host, None, resolution_override);
                selection
                    .request_destination_cache
                    .push(override_key, destination);
            }
            selection
                .request_destination_cache
                .get(override_key)
                .ok_or_else(|| anyhow!("destination cache was not populated for route"))?
        } else {
            &empty_destination
        };
        let ctx = crate::http::policy::rule_context::build_request_rule_match_context(
            crate::http::policy::rule_context::RequestRuleContextInput {
                base,
                headers: sanitized_headers,
                destination: request_destination,
                identity: &identity,
                request_size,
                rpc: request_rpc,
                client_cert: conn.peer_certificate_info.as_deref(),
                upstream_cert: None,
            },
        );
        if cors_only {
            if route.matches(&ctx) {
                selection.route_idx = Some(idx);
                selection.selected_policy = effective_policy.clone();
                selection.selected_identity = Some(identity);
                return Ok::<bool, anyhow::Error>(true);
            }
            return Ok::<bool, anyhow::Error>(false);
        }
        if request_size.is_some() || request_rpc.is_some() {
            if route.matches(&ctx) {
                selection.route_idx = Some(idx);
                selection.selected_policy = effective_policy.clone();
                selection.selected_identity = Some(identity);
                return Ok::<bool, anyhow::Error>(true);
            }
            return Ok::<bool, anyhow::Error>(false);
        }
        let route_http_guard = route.plan.guard.as_deref();
        let guard_requires_buffering = route_http_guard.is_some_and(|profile| {
            profile.requires_request_body_buffering_from_headers(request_headers)
        });
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
            selection.selected_policy = effective_policy.clone();
            selection.selected_identity = Some(identity);
            return Ok::<bool, anyhow::Error>(true);
        }
        Ok::<bool, anyhow::Error>(false)
    })?;
    Ok(())
}

fn sanitized_headers_for_route_scan<'a>(
    req: &'a Request<Body>,
    state: &crate::runtime::RuntimeState,
    conn: &ReverseConnInfo,
) -> Result<std::borrow::Cow<'a, http::HeaderMap>> {
    if state.security.identity_sources.sources.is_empty() {
        return Ok(std::borrow::Cow::Borrowed(req.headers()));
    }
    let mut sanitized = req.headers().clone();
    sanitize_headers_for_policy(
        state,
        &EffectivePolicyContext::default(),
        conn.remote_addr.ip(),
        &mut sanitized,
    )?;
    Ok(std::borrow::Cow::Owned(sanitized))
}

fn policy_context_cache_key(policy: &EffectivePolicyContext) -> usize {
    policy as *const EffectivePolicyContext as usize
}

pub(super) fn reverse_security_rejection(
    req: &Request<Body>,
    conn: &ReverseConnInfo,
    state: &crate::runtime::RuntimeState,
    compiled: &crate::reverse::CompiledReverse,
) -> Result<Option<(InterimList, Response<Body>)>> {
    let Err(err) = compiled.security_policy.validate_request(
        req,
        conn.tls_sni.as_deref(),
        conn.tls_terminated,
    ) else {
        return Ok(None);
    };
    warn!(error = ?err, "reverse TLS host policy rejected request");
    Ok(Some(empty_interim_response(finalize_response_for_request(
        req.method(),
        req.version(),
        state.plan.identity.proxy_name.as_ref(),
        Response::builder()
            .status(StatusCode::MISDIRECTED_REQUEST)
            .body(Body::from("misdirected request"))?,
        false,
    ))))
}

pub(super) fn enforce_selected_reverse_route_constraints(
    mut req: Request<Body>,
    route: &crate::reverse::router::HttpRoute,
    request_method: &Method,
    state: &crate::runtime::RuntimeState,
    conn: &ReverseConnInfo,
) -> Result<ReverseEarlyResult<Request<Body>>> {
    let request_version = req.version();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    if let Err(error) = route.plan.client_certificate.apply(
        req.headers_mut(),
        conn.peer_certificates.as_deref().map(Vec::as_slice),
    ) {
        if matches!(
            error,
            qpx_http::client_cert::ClientCertError::InboundHeader { .. }
        ) {
            let status = StatusCode::BAD_REQUEST;
            let body = qpx_http::problem::ProblemDetails::new(
                status,
                "Untrusted client certificate field",
            )
            .with_detail(error.to_string())
            .to_json()?;
            let response = Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
                .body(Body::from(body))?;
            return Ok(Err(empty_interim_response(finalize_response_for_request(
                request_method,
                request_version,
                proxy_name,
                response,
                false,
            ))));
        }
        return Err(error.into());
    }
    if let Some(policy) = route.plan.fetch_metadata.as_deref() {
        let decision = match policy.evaluate_headers(req.headers()) {
            Ok(decision) => decision,
            Err(error) => {
                return fetch_metadata_rejection(
                    request_method,
                    request_version,
                    proxy_name,
                    route,
                    conn,
                    (
                        StatusCode::BAD_REQUEST,
                        "Invalid Fetch Metadata",
                        error.to_string(),
                    ),
                );
            }
        };
        if decision != qpx_core::browser_policy::FetchMetadataDecision::Allowed {
            return fetch_metadata_rejection(
                request_method,
                request_version,
                proxy_name,
                route,
                conn,
                (
                    StatusCode::FORBIDDEN,
                    "Fetch Metadata policy rejected request",
                    format!("request rejected by {decision:?} policy decision"),
                ),
            );
        }
    }
    if route.plan.require_precondition
        && qpx_http::protocol::method::precondition_is_missing(request_method, req.headers())
    {
        let status = StatusCode::PRECONDITION_REQUIRED;
        let body = qpx_http::problem::ProblemDetails::new(status, "Precondition required")
            .with_detail("This route requires If-Match or If-Unmodified-Since")
            .to_json()?;
        let response = Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
            .body(Body::from(body))?;
        return Ok(Err(empty_interim_response(finalize_response_for_request(
            request_method,
            request_version,
            proxy_name,
            response,
            false,
        ))));
    }
    let max_request_body_bytes = route.plan.streaming.max_request_body_bytes;
    if let Some(size) = observed_request_size(&req)
        && size > max_request_body_bytes as u64
    {
        return Ok(Err(request_body_too_large_response(
            request_method,
            request_version,
            proxy_name,
            None,
        )
        .map(empty_interim_response)?));
    }
    req = match limit_request_body(req, max_request_body_bytes) {
        Ok(req) => req,
        Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
            return Ok(Err(request_body_too_large_response(
                request_method,
                request_version,
                proxy_name,
                None,
            )
            .map(empty_interim_response)?));
        }
        Err(err) => return Err(err),
    };
    Ok(Ok(req))
}

fn fetch_metadata_rejection(
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    route: &crate::reverse::router::HttpRoute,
    conn: &ReverseConnInfo,
    problem: (StatusCode, &'static str, String),
) -> Result<ReverseEarlyResult<Request<Body>>> {
    let (status, title, detail) = problem;
    let body = qpx_http::problem::ProblemDetails::new(status, title)
        .with_detail(detail)
        .to_json()?;
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
        .body(Body::from(body))?;
    let mut response =
        finalize_response_for_request(request_method, request_version, proxy_name, response, false);
    super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
    Ok(Err(empty_interim_response(response)))
}

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

pub(super) async fn prepare_reverse_request(
    mut req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: Arc<crate::runtime::RuntimeState>,
    compiled: Arc<crate::reverse::CompiledReverse>,
    cors_request: Option<&qpx_core::cors::CorsRequest>,
) -> Result<std::result::Result<PreparedReverseRequest, (InterimList, Response<Body>)>> {
    let router = &compiled.router;
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    if let Some(response) = reverse_security_rejection(&req, conn, &state, &compiled)? {
        return Ok(Err(response));
    }

    if let Some(cors_request) = cors_request.filter(|request| request.is_preflight())
        && let Some(response) = prepare_cors_preflight(
            req.headers().clone(),
            req.version(),
            base,
            conn,
            &state,
            router,
            cors_request,
        )
        .await?
    {
        return Ok(Err(response));
    }

    let host = base.host().unwrap_or_default();
    let request_method = &base.method;
    let request_version = req.version();
    let identity_request =
        IdentityRequestContext::from_base(base, if conn.tls_terminated { "https" } else { "http" });
    if !state.destination_trace_enabled()
        && state.security.identity_sources.sources.is_empty()
        && let Some(route) = router.single_http_route()
        && route.plan.policy_context.identity_sources.is_empty()
        && route.response_rules.is_none()
        && !route.requires_destination_context()
        && !route.requires_request_size()
        && !route.requires_request_body_observation()
        && !route.requires_request_rpc_context()
        && !route
            .plan
            .guard
            .as_deref()
            .is_some_and(|guard| guard.requires_request_body_buffering_from_headers(req.headers()))
    {
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
        let max_observed_request_body_bytes =
            state.plan.limits.body.max_observed_request_body_bytes;
        let override_key =
            super::destination_override_key(route.plan.destination_resolution.as_ref());
        let req = match enforce_selected_reverse_route_constraints(
            req,
            route,
            request_method,
            &state,
            conn,
        )? {
            Ok(req) => req,
            Err(mut response) => {
                super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response.1)?;
                apply_cors_to_early_response(route, cors_request, &mut response.1);
                return Ok(Err(response));
            }
        };
        let mut request_destination_cache = InlineCache::new();
        request_destination_cache.push(override_key, destination);
        return Ok(Ok(PreparedReverseRequest {
            req,
            context: ReversePreparedContext { compiled, state },
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
        }));
    }
    let request_body_too_large = || {
        request_body_too_large_response(request_method, request_version, proxy_name, None)
            .map(empty_interim_response)
    };
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(request_method.as_str()),
        dst_port: Some(conn.dst_port),
        src_ip: Some(conn.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host),
        sni: conn.tls_sni.as_deref(),
        path: base.path(),
    };
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
    let sanitized_route_headers = sanitized_headers_for_route_scan(&req, &state, conn)?;
    if let Err(error) = scan_reverse_routes(
        router,
        req.headers(),
        sanitized_route_headers.as_ref(),
        base,
        &state,
        conn,
        host,
        prefilter_ctx.clone(),
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
    let mut owned_sanitized_headers = match sanitized_route_headers {
        std::borrow::Cow::Borrowed(_) => None,
        std::borrow::Cow::Owned(headers) => Some(headers),
    };

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

    if selection.route_idx.is_none()
        && let Err(error) = scan_reverse_routes(
            router,
            req.headers(),
            owned_sanitized_headers
                .as_ref()
                .unwrap_or_else(|| req.headers()),
            base,
            &state,
            conn,
            host,
            prefilter_ctx,
            observed_request_size(&req),
            request_rpc.as_ref(),
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
            classify_reverse_destination(&state, conn, host, None, selected_resolution_override)
        } else {
            crate::destination::DestinationMetadata::default()
        };
        selection
            .request_destination_cache
            .push(selected_override_key, destination);
    }
    req = match enforce_selected_reverse_route_constraints(
        req,
        selected_route,
        &base.method,
        &state,
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
        context: ReversePreparedContext { compiled, state },
        route: ReversePreparedRoute {
            route_idx: selected_route_idx,
            selected_policy: selection.selected_policy,
            identity: selection
                .selected_identity
                .ok_or_else(|| anyhow!("identity missing for selected reverse route"))?,
            sanitized_headers: owned_sanitized_headers.take(),
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

async fn prepare_cors_preflight(
    request_headers: http::HeaderMap,
    request_version: http::Version,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    router: &ReverseRouter,
    cors_request: &qpx_core::cors::CorsRequest,
) -> Result<Option<(InterimList, Response<Body>)>> {
    let preflight = cors_request
        .preflight()
        .ok_or_else(|| anyhow!("CORS preflight facts are missing"))?;
    let mut route_base = base.clone();
    route_base.method = preflight.method().clone();
    let host = route_base.host().unwrap_or_default();
    let prefilter_ctx = MatchPrefilterContext {
        method: Some(route_base.method.as_str()),
        dst_port: Some(conn.dst_port),
        src_ip: Some(conn.remote_addr.ip()),
        host: (!host.is_empty()).then_some(host),
        sni: conn.tls_sni.as_deref(),
        path: route_base.path(),
    };
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
    scan_reverse_routes(
        router,
        &request_headers,
        &request_headers,
        &route_base,
        state,
        conn,
        host,
        prefilter_ctx,
        None,
        None,
        true,
        None,
        &mut selection,
    )
    .await?;
    let Some(route_idx) = selection.route_idx else {
        return Ok(None);
    };
    let route = router
        .route_at(route_idx)
        .ok_or_else(|| anyhow!("selected CORS route is unavailable"))?;
    let policy = route
        .plan
        .cors
        .as_deref()
        .ok_or_else(|| anyhow!("selected CORS route has no compiled policy"))?;
    if let Some(fetch_metadata) = route.plan.fetch_metadata.as_deref() {
        let (status, detail) = match fetch_metadata.evaluate_headers(&request_headers) {
            Ok(qpx_core::browser_policy::FetchMetadataDecision::Allowed) => (StatusCode::OK, None),
            Ok(decision) => (
                StatusCode::FORBIDDEN,
                Some(format!("request rejected by {decision:?} policy decision")),
            ),
            Err(error) => (StatusCode::BAD_REQUEST, Some(error.to_string())),
        };
        if let Some(detail) = detail {
            let body = qpx_http::problem::ProblemDetails::new(
                status,
                "Fetch Metadata policy rejected preflight",
            )
            .with_detail(detail)
            .to_json()?;
            let mut response = Response::builder()
                .status(status)
                .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
                .body(Body::from(body))?;
            crate::http::protocol::l7::finalize_response_with_headers_in_place(
                &Method::OPTIONS,
                request_version,
                state.plan.identity.proxy_name.as_ref(),
                &mut response,
                route.headers.as_deref(),
                false,
            );
            policy.apply_actual_response(Some(cors_request), response.headers_mut());
            super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
            return Ok(Some(empty_interim_response(response)));
        }
    }
    let mut response = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())?;
    crate::http::protocol::l7::finalize_response_with_headers_in_place(
        &Method::OPTIONS,
        request_version,
        state.plan.identity.proxy_name.as_ref(),
        &mut response,
        route.headers.as_deref(),
        false,
    );
    if let Err(rejection) = policy.apply_preflight_response(cors_request, response.headers_mut()) {
        let status = StatusCode::FORBIDDEN;
        let body = qpx_http::problem::ProblemDetails::new(status, "CORS preflight rejected")
            .with_detail(rejection.to_string())
            .to_json()?;
        response = Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, qpx_http::problem::PROBLEM_JSON)
            .body(Body::from(body))?;
        crate::http::protocol::l7::finalize_response_with_headers_in_place(
            &Method::OPTIONS,
            request_version,
            state.plan.identity.proxy_name.as_ref(),
            &mut response,
            route.headers.as_deref(),
            false,
        );
        policy.apply_actual_response(None, response.headers_mut());
    }
    super::apply_reverse_route_metadata(route, conn.tls_terminated, &mut response)?;
    Ok(Some(empty_interim_response(response)))
}

fn apply_cors_to_early_response(
    route: &crate::reverse::router::HttpRoute,
    cors_request: Option<&qpx_core::cors::CorsRequest>,
    response: &mut Response<Body>,
) {
    if let Some(policy) = route.plan.cors.as_deref() {
        policy.apply_actual_response(cors_request, response.headers_mut());
    }
}
