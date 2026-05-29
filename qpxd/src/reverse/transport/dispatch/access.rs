use super::{ReverseAccessControl, ReverseAccessInput, ReverseAccessOutcome, ReverseExtAuthzAllow};
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchGuardInput, DispatchRateLimitInput, ExtAuthzDenyResponseInput,
    annotate_dispatch_response, evaluate_http_guard, ext_authz_deny_response, rate_limit_response,
};
use crate::http::local_response::build_local_response;
use crate::http::protocol::l7::finalize_response_with_headers;
use crate::policy_context::{
    ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, enforce_ext_authz, merge_header_controls,
    validate_ext_authz_allow_mode,
};
use crate::rate_limit::RateLimitContext;
use crate::reverse::router::HttpRoute;
use crate::runtime;
use anyhow::Result;
use hyper::{Method, Request, Response, StatusCode};
use metrics::counter;
use qpx_core::rules::CompiledHeaderControl;
use std::sync::Arc;

pub(super) async fn enforce_reverse_access_control(
    input: ReverseAccessInput<'_>,
) -> Result<ReverseAccessOutcome> {
    let ReverseAccessInput {
        state,
        reverse_name,
        proxy_name,
        conn,
        host,
        request_method,
        path,
        request_uri,
        req,
        route,
        selected_policy,
        identity,
        sanitized_headers,
        request_destination,
    } = input;
    let ext_authz = enforce_ext_authz(
        state,
        selected_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Reverse,
            proxy_name,
            scope_name: reverse_name,
            remote_ip: conn.remote_addr.ip(),
            dst_port: Some(conn.dst_port),
            host: (!host.is_empty()).then_some(host),
            sni: conn.tls_sni.as_deref(),
            method: Some(request_method.as_str()),
            path,
            uri: Some(request_uri),
            matched_rule: None,
            matched_route: route.name.as_deref(),
            action: None,
            headers: Some(sanitized_headers),
            identity,
        },
    )
    .await?;
    let ext_authz_policy_id = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    };
    let ext_authz_policy_tags = match &ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
    };
    let mut log_context =
        identity.to_log_context(None, route.name.as_deref(), ext_authz_policy_id.as_deref());
    crate::http::policy::rule_context::attach_destination_trace(
        &mut log_context,
        request_destination,
    );
    log_context.policy_tags = ext_authz_policy_tags;
    let audit_ctx = DispatchAuditContext::new(
        state.clone(),
        crate::http::dispatch::ProxyKind::Reverse,
        reverse_name,
        conn.remote_addr,
        request_method.clone(),
        path.map(ToOwned::to_owned),
        log_context.clone(),
    )
    .with_host((!host.is_empty()).then_some(host.to_string()))
    .with_sni(conn.tls_sni.as_deref().map(ToOwned::to_owned))
    .with_matched_route(route.name.as_deref().map(ToOwned::to_owned))
    .with_ext_authz_policy_id(ext_authz_policy_id.clone());
    if let Some(response) = evaluate_http_guard(DispatchGuardInput {
        profile: route.plan.guard.as_deref(),
        req: &req,
        destination: request_destination,
        proxy_name,
        audit: audit_ctx.clone(),
    })
    .await?
    {
        return Ok(ReverseAccessOutcome::Response(Box::new(response)));
    }
    let allowed = match resolve_reverse_ext_authz(
        ext_authz,
        route.headers.clone(),
        &req,
        request_method,
        proxy_name,
        state,
        &audit_ctx,
    )? {
        Ok(values) => values,
        Err(response) => return Ok(ReverseAccessOutcome::Response(Box::new(response))),
    };
    let route_timeout = allowed.timeout_override.unwrap_or(route.policy.timeout);
    let request_limit_ctx = RateLimitContext::from_identity(
        conn.remote_addr.ip(),
        identity,
        route.name.as_deref(),
        allowed.override_upstream.as_deref(),
    );
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &route.plan.rate_limits,
        None,
        crate::rate_limit::TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        return Ok(ReverseAccessOutcome::Response(Box::new(
            rate_limit_response(DispatchRateLimitInput {
                req: &req,
                proxy_name,
                retry_after: Some(retry_after),
                audit: audit_ctx.clone(),
            }),
        )));
    }
    if let Some(retry_after) = request_limits.merge_profile_and_check(
        &state.policy.rate_limiters,
        allowed.rate_limit_profile.as_deref(),
        crate::rate_limit::TransportScope::Request,
        &request_limit_ctx,
        1,
    )? {
        return Ok(ReverseAccessOutcome::Response(Box::new(
            rate_limit_response(DispatchRateLimitInput {
                req: &req,
                proxy_name,
                retry_after: Some(retry_after),
                audit: audit_ctx.clone(),
            }),
        )));
    }
    if let Some(response) = reverse_local_route_response(
        route,
        request_method,
        req.version(),
        proxy_name,
        allowed.route_headers.as_deref(),
        &audit_ctx,
    )? {
        return Ok(ReverseAccessOutcome::Response(Box::new(response)));
    }
    Ok(ReverseAccessOutcome::Continue(Box::new(
        ReverseAccessControl {
            req,
            log_context,
            ext_authz_policy_id,
            route_headers: allowed.route_headers,
            override_upstream: allowed.override_upstream,
            route_timeout,
            cache_bypass: allowed.cache_bypass,
            ext_authz_mirror_upstreams: allowed.mirror_upstreams,
            request_limit_ctx,
            request_limits,
        },
    )))
}

fn resolve_reverse_ext_authz(
    ext_authz: ExtAuthzEnforcement,
    mut route_headers: Option<Arc<CompiledHeaderControl>>,
    req: &Request<Body>,
    request_method: &Method,
    proxy_name: &str,
    state: &runtime::RuntimeState,
    audit_ctx: &DispatchAuditContext,
) -> Result<std::result::Result<ReverseExtAuthzAllow, Response<Body>>> {
    match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ReverseHttp)?;
            route_headers = merge_header_controls(route_headers, allow.headers);
            Ok(Ok(ReverseExtAuthzAllow {
                route_headers,
                override_upstream: allow.override_upstream,
                timeout_override: allow.timeout_override,
                cache_bypass: allow.cache_bypass,
                mirror_upstreams: allow.mirror_upstreams,
                rate_limit_profile: allow.rate_limit_profile,
            }))
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let response = ext_authz_deny_response(ExtAuthzDenyResponseInput {
                ext_authz: ExtAuthzEnforcement::Deny(deny),
                base_headers: route_headers,
                request_method,
                request_version: req.version(),
                proxy_name,
                default_response: Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from(state.messages.reverse_error.clone()))?,
                audit: audit_ctx,
            })?;
            Ok(Err(response))
        }
    }
}

fn reverse_local_route_response(
    route: &HttpRoute,
    request_method: &Method,
    request_version: http::Version,
    proxy_name: &str,
    route_headers: Option<&CompiledHeaderControl>,
    audit_ctx: &DispatchAuditContext,
) -> Result<Option<Response<Body>>> {
    let Some(local) = route.local_response.as_ref() else {
        return Ok(None);
    };
    let mut response = finalize_response_with_headers(
        request_method,
        request_version,
        proxy_name,
        build_local_response(local)?,
        route_headers,
        false,
    );
    counter!(
        audit_ctx
            .state
            .observability
            .metric_names
            .reverse_local_response_total
            .clone()
    )
    .increment(1);
    annotate_dispatch_response(
        &mut response,
        audit_ctx,
        crate::http::dispatch::DispatchOutcome::Respond,
        &[],
    );
    Ok(Some(response))
}
