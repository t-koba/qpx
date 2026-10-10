use super::InlineCache;
use crate::http::body::observation::RequestObservationPlan;
use crate::http::body::size::observed_request_size;
use crate::http::dispatch::request_body_too_large_response;
use crate::http::policy::response_policy::response_request_obs;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::policy_context::authentication_response_for_error;
use crate::policy_context::{
    EffectivePolicyContext, IdentityRequestContext, resolve_identity_for_request,
    sanitize_headers_for_policy,
};
use crate::reverse::transport::destination::classify_reverse_destination;
use crate::reverse::transport::{
    InterimList, ReverseConnInfo, ReverseRouter, empty_interim_response,
};
use anyhow::{Result, anyhow};
use hyper::{Request, Response};
use qpx_core::prefilter::MatchPrefilterContext;
use qpx_http::body::Body;
use std::sync::Arc;

pub(super) struct ReverseRouteSelection {
    pub(super) route_idx: Option<usize>,
    pub(super) selected_policy: EffectivePolicyContext,
    pub(super) selected_identity: Option<crate::policy_context::ResolvedIdentity>,
    // Keyed by the identity of the route's compiled `destination_resolution`
    // override (stable for the request lifetime); avoids cloning and hashing
    // the override config on every request.
    pub(super) request_destination_cache: InlineCache<crate::destination::DestinationMetadata>,
    // Keyed by the address of the route's compiled policy context. The compiled
    // router is immutable for the request lifetime, so the address is stable.
    pub(super) identity_cache: InlineCache<crate::policy_context::ResolvedIdentity>,
    pub(super) observation_plan: RequestObservationPlan,
    pub(super) max_observed_request_body_bytes: usize,
    pub(super) collect_observation_from_remaining: bool,
}

#[expect(
    clippy::too_many_arguments,
    reason = "route scan receives explicit immutable match facts instead of a broad mutable context"
)]
pub(super) async fn scan_reverse_routes(
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

pub(super) fn sanitized_headers_for_route_scan<'a>(
    headers: &'a http::HeaderMap,
    state: &crate::runtime::RuntimeState,
    conn: &ReverseConnInfo,
) -> Result<std::borrow::Cow<'a, http::HeaderMap>> {
    if state.security.identity_sources.sources.is_empty() {
        return Ok(std::borrow::Cow::Borrowed(headers));
    }
    let mut sanitized = headers.clone();
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

#[expect(
    clippy::too_many_arguments,
    reason = "observed-body rescan carries explicit immutable match facts for the second scan"
)]
pub(super) async fn observe_body_and_rescan_reverse_routes(
    mut req: Request<Body>,
    base: &BaseRequestFields,
    conn: &ReverseConnInfo,
    state: &Arc<crate::runtime::RuntimeState>,
    compiled: &Arc<crate::reverse::CompiledReverse>,
    host: &str,
    prefilter_ctx: MatchPrefilterContext<'_>,
    identity_request: Option<&IdentityRequestContext>,
    selection: &mut ReverseRouteSelection,
    owned_sanitized_headers: &Option<http::HeaderMap>,
) -> Result<
    std::result::Result<
        (Request<Body>, Option<crate::http::rpc::RpcMatchContext>),
        (InterimList, Response<Body>),
    >,
> {
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let request_method = &base.method;
    let request_version = req.version();
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
                let response = request_body_too_large_response(
                    request_method,
                    request_version,
                    proxy_name,
                    None,
                )
                .map(empty_interim_response)?;
                return Ok(Err(response));
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
            &compiled.router,
            req.headers(),
            owned_sanitized_headers
                .as_ref()
                .unwrap_or_else(|| req.headers()),
            base,
            state,
            conn,
            host,
            prefilter_ctx,
            observed_request_size(&req),
            request_rpc.as_ref(),
            false,
            identity_request,
            selection,
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
    Ok(Ok((req, request_rpc)))
}
