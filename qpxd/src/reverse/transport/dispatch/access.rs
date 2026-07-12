use super::{ReverseAccessControl, ReverseAccessInput, ReverseAccessOutcome};
use crate::http::dispatch::{
    DecisionServiceHttpAccessInput, DecisionServiceHttpAccessOutcome, DispatchAuditContext,
    DispatchAuditInput, DispatchGuardInput, DispatchOutcome, ProxyKind, annotated_local_response,
    apply_decision_service_http_access, build_dispatch_audit_context, evaluate_http_guard,
    rate_limit_response_for_parts,
};
use crate::policy_context::{DecisionServiceInput, DecisionServiceMode, enforce_decision_service};
use crate::rate_limit::{RateLimitContext, TransportScope};
use crate::reverse::router::HttpRoute;
use anyhow::Result;
use hyper::{Method, Response, StatusCode};
use qpx_core::rules::CompiledHeaderControl;
use qpx_http::body::Body;

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
    let decision_service = enforce_decision_service(
        state,
        selected_policy,
        DecisionServiceInput {
            mode: DecisionServiceMode::ReverseHttp,
            proxy_kind: ProxyKind::Reverse,
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
    let audit_ctx = build_dispatch_audit_context(DispatchAuditInput {
        state: state.clone(),
        kind: ProxyKind::Reverse,
        scope_name: reverse_name,
        remote_addr: conn.remote_addr,
        host: (!host.is_empty()).then_some(host),
        sni: conn.tls_sni.as_deref(),
        request_method: request_method.clone(),
        path,
        matched_rule: None,
        matched_route: route.name.as_deref(),
        identity,
        destination: request_destination,
        decision_service: Some(&decision_service),
    });
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
    let allowed = match apply_decision_service_http_access(DecisionServiceHttpAccessInput {
        enforcement: decision_service,
        mode: DecisionServiceMode::ReverseHttp,
        base_headers: route.headers.clone(),
        request_limit: None,
        request_head: (request_method, req.version()),
        proxy_name,
        default_deny_response: Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from(state.messages.reverse_error.clone()))?,
        audit: &audit_ctx,
    })? {
        DecisionServiceHttpAccessOutcome::Continue(allow) => allow,
        DecisionServiceHttpAccessOutcome::Blocked(response, _) => {
            return Ok(ReverseAccessOutcome::Response(Box::new(response)));
        }
    };
    let route_timeout = allowed.timeout_override.unwrap_or(route.policy.timeout);
    let request_version = req.version();
    let rate_limited_response = |retry_after| {
        ReverseAccessOutcome::Response(Box::new(rate_limit_response_for_parts(
            request_method,
            request_version,
            proxy_name,
            Some(retry_after),
            audit_ctx.clone(),
        )))
    };
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
        TransportScope::Request,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        return Ok(rate_limited_response(retry_after));
    }
    if let Some(retry_after) = request_limits.merge_profile_and_check(
        &state.policy.rate_limiters,
        allowed.rate_limit_profile.as_deref(),
        TransportScope::Request,
        &request_limit_ctx,
        1,
    )? {
        return Ok(rate_limited_response(retry_after));
    }
    if let Some(response) = reverse_local_route_response(
        route,
        request_method,
        req.version(),
        proxy_name,
        allowed.headers.as_deref(),
        &audit_ctx,
    )? {
        return Ok(ReverseAccessOutcome::Response(Box::new(response)));
    }
    let authorization_decision = qpx_core::ipc::meta::AuthorizationDecisionContext {
        external_decision_id: allowed.external_decision_id.clone(),
        policy_id: allowed.policy_id.clone(),
        policy_tags: allowed.policy_tags.clone(),
    };
    let authorization_decision =
        (!authorization_decision.is_empty()).then_some(authorization_decision);
    Ok(ReverseAccessOutcome::Continue(ReverseAccessControl {
        req,
        audit_ctx,
        route_headers: allowed.headers,
        override_upstream: allowed.override_upstream,
        route_timeout,
        cache_bypass: allowed.cache_bypass,
        decision_service_mirror_upstreams: allowed.mirror_upstreams,
        authorization_decision,
        request_limit_ctx,
        request_limits,
    }))
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
    super::super::metrics::local_response(&audit_ctx.state);
    annotated_local_response(
        request_method,
        request_version,
        proxy_name,
        local,
        route_headers,
        audit_ctx,
        DispatchOutcome::Respond,
    )
    .map(Some)
}
