use super::audit::ConnectAuditContext;
use super::extended::{
    H2ExtendedConnectUpstream, default_port_for_scheme, open_upstream_h2_extended_connect_stream,
    spawn_h2_extended_connect_relay,
};
use super::inspect::listener_upstream_trust;
use crate::destination::DestinationInputs;
use crate::forward::policy::{ForwardPolicyDecision, evaluate_forward_policy};
#[cfg(feature = "auth-basic")]
use crate::forward::request::proxy_auth_required;
use crate::forward::request::resolve_upstream_url;
use crate::http::codec::h2::{
    h1_headers_to_http, h2_response_to_hyper,
    parse_declared_content_length as parse_h2_content_length,
};
use crate::http::dispatch::{DispatchOutcome, ProxyKind};
use crate::http::local_response::finalized_local_response;
use crate::http::protocol::common::{
    blocked_response as blocked, forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::{
    finalize_extended_connect_response_with_headers, finalize_response_for_request,
    finalize_response_with_headers,
};
use crate::policy_context::{
    ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, enforce_ext_authz,
    prepare_ext_authz_allow_controls, resolve_identity, sanitize_headers_for_policy,
};
use crate::rate_limit::{RateLimitContext, TransportScope};
use crate::runtime::Runtime;
use ::http::{Method, Request, Response, StatusCode};
use anyhow::{Result, anyhow};
use h2::ext::Protocol as H2Protocol;
use qpx_core::config::ActionKind;
use qpx_core::rules::RuleMatchContext;
use qpx_http::body::Body;
use qpx_http::protocol::address::parse_authority_host_port;
use std::net::SocketAddr;
use tokio::time::Duration;
use tracing::warn;

pub(super) async fn handle_h2_extended_connect(
    req: Request<Body>,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: SocketAddr,
) -> Result<Response<Body>> {
    let protocol = req
        .extensions()
        .get::<H2Protocol>()
        .cloned()
        .ok_or_else(|| anyhow!("missing HTTP/2 extended CONNECT protocol"))?;
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let req_version = req.version();
    let listener_cfg = state
        .ingress_edge_settings(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let base_plan = state
        .plan
        .ingress_edge_execution_plan(listener_name, None)
        .ok_or_else(|| anyhow!("listener plan not found"))?;
    let effective_policy = base_plan.policy_context.clone();

    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| anyhow!("missing authority"))?
        .as_str()
        .to_string();
    let scheme = req.uri().scheme_str().unwrap_or("https").to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let (host, port) =
        parse_authority_host_port(authority.as_str(), default_port_for_scheme(&scheme))
            .ok_or_else(|| anyhow!("invalid extended CONNECT authority"))?;
    let mut sanitized_headers = req.headers().clone();
    sanitize_headers_for_policy(
        &state,
        &effective_policy,
        remote_addr.ip(),
        &mut sanitized_headers,
    )?;
    let mut identity = resolve_identity(
        &state,
        &effective_policy,
        remote_addr.ip(),
        Some(&sanitized_headers),
        None,
    )?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: Some(scheme.as_str()),
            port: Some(port),
            alpn: Some("h2"),
            ..Default::default()
        },
        base_plan.destination_resolution.as_ref(),
    );
    let request_uri = req.uri().to_string();
    let request_query_owned = req
        .uri()
        .path_and_query()
        .and_then(|pq| pq.query())
        .map(str::to_string);
    let ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: Some(port),
        host: Some(host.as_str()),
        sni: Some(host.as_str()),
        method: Some("CONNECT"),
        path: Some(path.as_str()),
        query: request_query_owned.as_deref(),
        authority: Some(authority.as_str()),
        scheme: Some(scheme.as_str()),
        http_version: Some(http_version_label(req_version)),
        alpn: Some("h2"),
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        headers: Some(&sanitized_headers),
        user: identity.user.as_deref(),
        user_groups: &identity.groups,
        device_id: identity.device_id.as_deref(),
        posture: &identity.posture,
        tenant: identity.tenant.as_deref(),
        auth_strength: identity.auth_strength.as_deref(),
        idp: identity.idp.as_deref(),
        ..Default::default()
    };
    #[cfg(feature = "auth-basic")]
    macro_rules! pre_access_response {
        ($base:expr, $log_context:expr, $outcome:expr) => {{
            let mut response = finalize_response_for_request(
                &Method::CONNECT,
                req_version,
                proxy_name,
                $base,
                false,
            );
            ConnectAuditContext {
                state: &state,
                listener_name,
                remote_ip: remote_addr.ip(),
                audit_host: host.as_str(),
                path: Some(path.as_str()),
                matched_rule: None,
                ext_authz_policy_id: None,
                log_context: $log_context,
            }
            .annotate(&mut response, $outcome);
            response
        }};
    }
    let (mut action, matched_rule) = match evaluate_forward_policy(
        &runtime,
        listener_name,
        ctx,
        &sanitized_headers,
        "CONNECT",
        request_uri.as_str(),
    )
    .await?
    {
        ForwardPolicyDecision::Allow(allowed) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (allowed.action, allowed.matched_rule)
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Challenge(chal) => {
            let log_context = identity.to_log_context(None, None, None);
            return Ok(pre_access_response!(
                proxy_auth_required(chal, state.messages.proxy_auth_required.as_str()),
                &log_context,
                DispatchOutcome::Challenge
            ));
        }
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Forbidden => {
            let log_context = identity.to_log_context(None, None, None);
            return Ok(pre_access_response!(
                forbidden(state.messages.forbidden.as_str()),
                &log_context,
                DispatchOutcome::Forbidden
            ));
        }
    };
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(listener_name, matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled HTTP/2 CONNECT listener execution plan not found"))?;
    let matched_rule_name = matched_rule.as_deref();
    let request_limit_ctx =
        RateLimitContext::from_identity(remote_addr.ip(), &identity, matched_rule_name, None);
    let crate::rate_limit::RequestLimitAcquire {
        limits: mut request_limits,
        retry_after,
    } = state.policy.rate_limiters.collect_checked_plan_request(
        &selected_plan.rate_limits,
        None,
        TransportScope::Connect,
        &request_limit_ctx,
        1,
    )?;
    if let Some(retry_after) = retry_after {
        return Ok(finalize_response_for_request(
            &Method::CONNECT,
            req_version,
            proxy_name,
            too_many_requests(Some(retry_after)),
            false,
        ));
    }
    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: ProxyKind::Forward,
            proxy_name,
            scope_name: listener_name,
            remote_ip: remote_addr.ip(),
            dst_port: Some(port),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: Some(path.as_str()),
            uri: Some(request_uri.as_str()),
            matched_rule: matched_rule_name,
            matched_route: None,
            action: Some(&action),
            headers: Some(&sanitized_headers),
            identity: &identity,
        },
    )
    .await?;
    let ext_authz_policy_id = ext_authz.policy_id().map(str::to_owned);
    let ext_authz_policy_tags = ext_authz.policy_tags().to_vec();
    let mut log_context =
        identity.to_log_context(matched_rule_name, None, ext_authz_policy_id.as_deref());
    log_context.policy_tags = ext_authz_policy_tags;
    let audit = ConnectAuditContext {
        state: &state,
        listener_name,
        remote_ip: remote_addr.ip(),
        audit_host: host.as_str(),
        path: Some(path.as_str()),
        matched_rule: matched_rule_name,
        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        log_context: &log_context,
    };
    let (response_headers, timeout_override) = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            let allow =
                prepare_ext_authz_allow_controls(allow, ExtAuthzMode::ForwardConnect, None)?;
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                &state.policy.rate_limiters,
                allow.rate_limit_profile.as_deref(),
                TransportScope::Connect,
                &request_limit_ctx,
                1,
            )? {
                return Ok(finalize_response_for_request(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                ));
            }
            allow.apply_action_overrides(&mut action);
            (allow.headers, allow.timeout_override)
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let mut response = if let Some(local) = deny.local_response.as_ref() {
                finalized_local_response(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    local,
                    deny.headers.as_deref(),
                )?
            } else {
                finalize_response_with_headers(
                    &Method::CONNECT,
                    req_version,
                    proxy_name,
                    forbidden(state.messages.forbidden.as_str()),
                    deny.headers.as_deref(),
                    false,
                )
            };
            audit.annotate(
                &mut response,
                if deny.local_response.is_some() {
                    DispatchOutcome::ExtAuthzLocalResponse
                } else {
                    DispatchOutcome::ExtAuthzDeny
                },
            );
            return Ok(response);
        }
    };
    macro_rules! connect_response {
        ($base:expr, $outcome:expr) => {{
            let mut response = finalize_response_with_headers(
                &Method::CONNECT,
                req_version,
                proxy_name,
                $base,
                response_headers.as_deref(),
                false,
            );
            audit.annotate(&mut response, $outcome);
            response
        }};
    }
    macro_rules! too_many_connect_response {
        () => {
            connect_response!(too_many_requests(None), DispatchOutcome::ConcurrencyLimited)
        };
    }
    macro_rules! proxy_error_connect_response {
        () => {
            connect_response!(
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(state.messages.proxy_error.clone()))?,
                DispatchOutcome::Error
            )
        };
    }

    match action.kind {
        ActionKind::Block | ActionKind::Inspect => {
            return Ok(connect_response!(
                blocked(state.messages.blocked.as_str()),
                DispatchOutcome::Block
            ));
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            let mut response = finalized_local_response(
                &Method::CONNECT,
                req_version,
                proxy_name,
                local,
                response_headers.as_deref(),
            )?;
            audit.annotate(&mut response, DispatchOutcome::Respond);
            return Ok(response);
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }

    let upstream_url = resolve_upstream_url(&action, &state, listener_name)?;
    let rate_limit_ctx = RateLimitContext::from_identity(
        remote_addr.ip(),
        &identity,
        matched_rule_name,
        upstream_url.as_deref(),
    );
    let _concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
        Some(permits) => permits,
        None => return Ok(too_many_connect_response!()),
    };
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
    let tunnel_idle_timeout =
        Duration::from_millis(state.plan.limits.timeouts.tunnel_idle_timeout_ms.max(1));
    let declared_request_length = parse_h2_content_length(req.headers())?;
    let upstream = match open_upstream_h2_extended_connect_stream(
        req.uri(),
        &sanitized_headers,
        protocol,
        proxy_name,
        upstream_url.as_deref(),
        upstream_timeout,
        listener_upstream_trust(listener_cfg)?.as_deref(),
    )
    .await
    {
        Ok(upstream) => upstream,
        Err(err) => {
            warn!(error = ?err, "forward HTTP/2 extended CONNECT establish failed");
            return Ok(proxy_error_connect_response!());
        }
    };

    let H2ExtendedConnectUpstream {
        interim,
        response,
        send_stream,
    } = upstream;
    let downstream_body = req.into_body();
    if !response.status().is_success() {
        let mut response = finalize_response_with_headers(
            &Method::CONNECT,
            req_version,
            proxy_name,
            h2_response_to_hyper(response)?,
            response_headers.as_deref(),
            false,
        );
        if !interim.is_empty() {
            response.extensions_mut().insert(interim);
        }
        audit.annotate(&mut response, DispatchOutcome::Allow);
        return Ok(response);
    }

    let (parts, upstream_body) = response.into_parts();
    let status = qpx_http::protocol::semantics::validate_http_status_class(
        parts.status,
        "HTTP/2 CONNECT response",
    )?;
    let mut response = Response::builder()
        .status(status)
        .body(spawn_h2_extended_connect_relay(
            downstream_body,
            declared_request_length,
            send_stream,
            upstream_body,
            tunnel_idle_timeout,
        ))?;
    *response.headers_mut() = h1_headers_to_http(&parts.headers)?;
    *response.version_mut() = http::Version::HTTP_2;
    let mut response = finalize_extended_connect_response_with_headers(
        req_version,
        proxy_name,
        response,
        response_headers.as_deref(),
        false,
    );
    if !interim.is_empty() {
        response.extensions_mut().insert(interim);
    }
    audit.annotate(&mut response, DispatchOutcome::Allow);
    Ok(response)
}
