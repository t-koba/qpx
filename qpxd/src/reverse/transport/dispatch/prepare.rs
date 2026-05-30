use super::{
    PreparedReverseRequest, ReversePreparedContext, ReversePreparedRoute, ReverseRetryDispatch,
    ReverseRetryPrepareInput,
};
use crate::http::body::Body;
use crate::http::body::observation::RequestObservationPlan;
use crate::http::body::size::observed_request_size;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::l7::finalize_response_for_request;
use crate::policy_context::identity_facade;
use crate::reverse::health::UpstreamEndpoint;
use crate::reverse::router::SelectedMirrorTarget;
use crate::reverse::transport::destination::classify_reverse_destination;
use crate::reverse::transport::mirrors::{
    StreamingMirrorDispatch, dispatch_streaming_mirrors, request_is_templateable,
};
use crate::reverse::transport::request_template::{
    ReverseRequestHeadTemplate, ReverseRequestTemplate, request_is_retryable,
};
use crate::reverse::transport::{
    ReverseConnInfo, ReverseInterimResponses, ReverseRouter, empty_interim_response,
};
use crate::runtime::Runtime;
use anyhow::{Result, anyhow};
use hyper::{Method, Request, Response, StatusCode};
use qpx_core::prefilter::MatchPrefilterContext;
use std::sync::Arc;
use tokio::time::Duration;
use tracing::warn;

pub(super) fn attach_streaming_limits(
    mut result: (ReverseInterimResponses, Response<Body>),
    streaming: crate::runtime::ResolvedStreamingLimits,
) -> (ReverseInterimResponses, Response<Body>) {
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
        Ok(finalize_response_for_request(
            request_method,
            request_version,
            proxy_name,
            Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Body::from("request body too large"))
                .map_err(anyhow::Error::from)?,
            false,
        ))
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
    let can_retry = request_is_retryable(
        &req,
        request_method,
        route.policy.retry_body_threshold_bytes,
    );
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
        let (primary_body, mirror_bodies) = crate::http::body::tee::tee_body_lossy_with_metrics(
            body,
            mirror_limits,
            route.plan.streaming.body_channel_capacity,
            Some("reverse_streaming_mirror"),
        );
        dispatch_streaming_mirrors(StreamingMirrorDispatch {
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
    let (first_request, template) = if need_template {
        (
            None,
            Some(
                ReverseRequestTemplate::from_request(
                    req,
                    max_template_body_bytes,
                    Duration::from_millis(route.plan.streaming.body_read_timeout_ms),
                )
                .await?,
            ),
        )
    } else {
        (Some(req), None)
    };
    Ok(ReverseRetryDispatch {
        attempts,
        first_request,
        template,
        mirror_upstreams,
    })
}

pub(super) async fn prepare_reverse_request(
    mut req: Request<Body>,
    base: &BaseRequestFields,
    runtime: &Runtime,
    conn: &ReverseConnInfo,
    compiled: Arc<crate::reverse::CompiledReverse>,
) -> Result<std::result::Result<PreparedReverseRequest, (ReverseInterimResponses, Response<Body>)>>
{
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
    let mut observation_plan = RequestObservationPlan::default();
    let mut max_observed_request_body_bytes =
        state.plan.limits.body.max_observed_request_body_bytes;
    let mut route_idx = None;
    let mut selected_policy = identity_facade::EffectivePolicyContext::default();
    let mut selected_identity = None;
    let mut selected_headers = None;
    let mut request_destination_cache =
        std::collections::HashMap::<String, crate::destination::DestinationMetadata>::new();
    let mut collect_observation_from_remaining = false;
    for idx in router.candidate_route_indices(prefilter_ctx.clone()) {
        let Some(route) = router.route_at(idx) else {
            continue;
        };
        let route_http_guard = route.plan.guard.as_deref();
        let guard_requires_buffering =
            route_http_guard.is_some_and(|profile| profile.requires_request_body_buffering(&req));
        let response_rule_candidates = route.response_rule_candidate_profile(prefilter_ctx.clone());

        let resolution_override = route.plan.destination_resolution.as_ref();
        let effective_policy = route.plan.policy_context.clone();
        let mut sanitized_headers = req.headers().clone();
        identity_facade::sanitize_headers_for_policy(
            &state,
            &effective_policy,
            conn.remote_addr.ip(),
            &mut sanitized_headers,
        )?;
        let identity = identity_facade::resolve_identity(
            &state,
            &effective_policy,
            conn.remote_addr.ip(),
            Some(&sanitized_headers),
            conn.peer_certificates
                .as_deref()
                .map(|certs| certs.as_slice()),
        )?;
        let request_destination = request_destination_cache
            .entry(format!("{:?}", resolution_override))
            .or_insert_with(|| {
                classify_reverse_destination(&state, conn, host.as_str(), None, resolution_override)
            })
            .clone();
        let ctx = crate::http::policy::rule_context::build_request_rule_match_context(
            crate::http::policy::rule_context::RequestRuleContextInput {
                base,
                headers: &sanitized_headers,
                destination: &request_destination,
                identity: &identity,
                request_size: None,
                rpc: None,
                client_cert: conn.peer_certificate_info.as_deref(),
                upstream_cert: None,
            },
        );
        let response_rule_request_observation = route
            .response_rules
            .as_deref()
            .map(|engine| {
                engine.request_observation_requirements_for_candidates(
                    &response_rule_candidates,
                    &ctx,
                )
            })
            .unwrap_or_default();
        let route_needs_observation = route.requires_request_size()
            || route.requires_request_body_observation()
            || route.requires_request_rpc_context()
            || response_rule_request_observation.needs_body
            || response_rule_request_observation.needs_rpc
            || guard_requires_buffering;
        if route_needs_observation || collect_observation_from_remaining {
            if route.matches_without_request_body_observation(&ctx) {
                collect_observation_from_remaining = true;
                let mut route_limit = state.plan.limits.body.max_observed_request_body_bytes;
                if let Some(cap) =
                    route_http_guard.and_then(|profile| profile.request_body_observation_cap())
                {
                    route_limit = route_limit.min(cap);
                }
                route_limit = route.plan.body_observation_limit(route_limit);
                max_observed_request_body_bytes = max_observed_request_body_bytes.min(route_limit);
                observation_plan.include(
                    route.requires_request_size(),
                    route.requires_request_body_observation()
                        || response_rule_request_observation.needs_body,
                    route.requires_request_rpc_context()
                        || response_rule_request_observation.needs_rpc,
                );
                observation_plan
                    .include_body_with_reason(guard_requires_buffering, "http_guard.body");
            }
            continue;
        }
        if route.matches(&ctx) {
            route_idx = Some(idx);
            selected_policy = effective_policy;
            selected_identity = Some(identity);
            selected_headers = Some(sanitized_headers);
            break;
        }
    }

    if route_idx.is_none() && !observation_plan.is_empty() {
        req = match observation_plan
            .observe_request(
                req,
                max_observed_request_body_bytes,
                std::time::Duration::from_millis(compiled.streaming.body_read_timeout_ms),
            )
            .await
        {
            Ok(req) => req,
            Err(err) if crate::http::body::size::is_observed_body_limit_exceeded(&err) => {
                return Ok(Err(empty_interim_response(finalize_response_for_request(
                    &request_method,
                    request_version,
                    proxy_name.as_ref(),
                    Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Body::from("request body too large"))?,
                    false,
                ))));
            }
            Err(err) => return Err(err),
        };
    }
    let request_rpc = if observation_plan.needs_rpc {
        Some(crate::http::rpc::inspect_request(&req).await)
    } else {
        None
    };

    if route_idx.is_none() {
        router.try_for_each_candidate_route(prefilter_ctx, |idx, candidate| {
            let resolution_override = candidate.plan.destination_resolution.as_ref();
            let effective_policy = candidate.plan.policy_context.clone();
            let mut sanitized_headers = req.headers().clone();
            identity_facade::sanitize_headers_for_policy(
                &state,
                &effective_policy,
                conn.remote_addr.ip(),
                &mut sanitized_headers,
            )?;
            let identity = identity_facade::resolve_identity(
                &state,
                &effective_policy,
                conn.remote_addr.ip(),
                Some(&sanitized_headers),
                conn.peer_certificates
                    .as_deref()
                    .map(|certs| certs.as_slice()),
            )?;
            let request_destination = request_destination_cache
                .entry(format!("{:?}", resolution_override))
                .or_insert_with(|| {
                    classify_reverse_destination(
                        &state,
                        conn,
                        host.as_str(),
                        None,
                        resolution_override,
                    )
                })
                .clone();
            let ctx = crate::http::policy::rule_context::build_request_rule_match_context(
                crate::http::policy::rule_context::RequestRuleContextInput {
                    base,
                    headers: &sanitized_headers,
                    destination: &request_destination,
                    identity: &identity,
                    request_size: observed_request_size(&req),
                    rpc: request_rpc.as_ref(),
                    client_cert: conn.peer_certificate_info.as_deref(),
                    upstream_cert: None,
                },
            );
            if candidate.matches(&ctx) {
                route_idx = Some(idx);
                selected_policy = effective_policy;
                selected_identity = Some(identity);
                selected_headers = Some(sanitized_headers);
                Ok::<bool, anyhow::Error>(true)
            } else {
                Ok::<bool, anyhow::Error>(false)
            }
        })?;
    }

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
            route_idx: route_idx.ok_or_else(|| anyhow!("no route matched"))?,
            selected_policy,
            identity: selected_identity
                .ok_or_else(|| anyhow!("identity missing for selected reverse route"))?,
            sanitized_headers: selected_headers
                .ok_or_else(|| anyhow!("sanitized headers missing for selected reverse route"))?,
            request_destination_cache,
            max_observed_request_body_bytes,
        },
        observation: crate::http::pipeline::types::RequestObservation {
            request_rpc,
            response_request_observation: Default::default(),
            request_body_observed: observation_plan.needs_body,
            request_rpc_observed: observation_plan.needs_rpc,
        },
    }))
}
