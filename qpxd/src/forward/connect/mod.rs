use super::policy::{ForwardPolicyDecision, evaluate_forward_policy};
use crate::destination::DestinationInputs;
#[cfg(feature = "auth-basic")]
use crate::forward::request::proxy_auth_required;
use crate::forward::request::resolve_upstream;
use crate::http::dispatch::{
    DispatchConnectRuleContextInput, DispatchOutcome, build_dispatch_connect_rule_context,
};
use crate::http::local_response::finalized_local_response;
use crate::http::protocol::common::{
    blocked_response as blocked, connect_established_response as connect_established,
    forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::policy_context::{
    ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, enforce_ext_authz,
    prepare_ext_authz_allow_controls, resolve_identity, sanitize_headers_for_policy,
};
use crate::rate_limit::{RateLimitContext, TransportScope};
use crate::runtime::Runtime;
use crate::upstream::connect::connect_tunnel_target;
use crate::upstream::io_copy::BandwidthThrottle;
use ::http::{Method, Request, Response, StatusCode};
use anyhow::{Result, anyhow};
use h2::ext::Protocol as H2Protocol;
use qpx_core::config::ActionKind;
use qpx_http::body::Body;
use qpx_http::protocol::address::parse_authority_host_port;
use std::net::SocketAddr;
use tokio::task;
use tokio::time::Duration;
use tracing::warn;

mod audit;
mod connect_h2;
mod extended;
mod inspect;
mod tunnel;
#[cfg(feature = "http3")]
pub(in crate::forward) mod udp_upstream;

use self::audit::ConnectAuditContext;
use self::connect_h2::handle_h2_extended_connect;
pub(super) use self::inspect::{
    ConnectPolicyInput, decide_connect_action_from_client_hello,
    decide_connect_action_from_tls_metadata, listener_requires_upstream_cert_preview,
    listener_upstream_trust,
};
use self::tunnel::{TunnelConnectContext, tunnel_connect};

pub(super) async fn handle_connect(
    req: Request<Body>,
    runtime: Runtime,
    listener_name: &str,
    remote_addr: SocketAddr,
) -> Result<Response<Body>> {
    if req.version() == http::Version::HTTP_2 && req.extensions().get::<H2Protocol>().is_some() {
        return handle_h2_extended_connect(req, runtime, listener_name, remote_addr).await;
    }
    let state = runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let req_version = req.version();
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
    let (host, port) = parse_authority_host_port(&authority, 443)
        .ok_or_else(|| anyhow!("invalid connect authority"))?;
    let audit_host = host.clone();
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
            scheme: Some("https"),
            port: Some(port),
            ..Default::default()
        },
        base_plan.destination_resolution.as_ref(),
    );

    let ctx = build_dispatch_connect_rule_context(DispatchConnectRuleContextInput {
        remote_ip: remote_addr.ip(),
        port,
        host: host.as_str(),
        path: None,
        authority: authority.as_str(),
        http_version: http_version_label(req_version),
        alpn: None,
        destination: &destination,
        headers: &sanitized_headers,
        identity: &identity,
    });
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
                path: None,
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
        &authority,
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
        .ok_or_else(|| anyhow!("compiled CONNECT listener execution plan not found"))?;
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
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name,
            scope_name: listener_name,
            remote_ip: remote_addr.ip(),
            dst_port: Some(port),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: None,
            uri: Some(authority.as_str()),
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
        audit_host: audit_host.as_str(),
        path: None,
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
    let upstream_timeout = timeout_override.unwrap_or_else(|| {
        Duration::from_millis(state.plan.limits.timeouts.upstream_http_timeout_ms)
    });
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
    macro_rules! blocked_connect_response {
        () => {
            connect_response!(
                blocked(state.messages.blocked.as_str()),
                DispatchOutcome::Block
            )
        };
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
                    .body(Body::from(state.messages.proxy_error.clone()))
                    .unwrap_or_else(|_| Response::new(Body::empty())),
                DispatchOutcome::Error
            )
        };
    }
    macro_rules! established_connect_response {
        () => {
            connect_response!(connect_established(), DispatchOutcome::Allow)
        };
    }

    match action.kind {
        ActionKind::Block => Ok(blocked_connect_response!()),
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
            Ok(response)
        }
        ActionKind::Inspect => {
            #[cfg(not(feature = "mitm"))]
            {
                Ok(blocked_connect_response!())
            }

            #[cfg(feature = "mitm")]
            {
                let listener_cfg = state
                    .ingress_edge_settings(listener_name)
                    .ok_or_else(|| anyhow!("listener not found"))?;
                let tls_inspection = listener_cfg.tls_inspection.as_ref();
                if !tls_inspection.map(|t| t.enabled).unwrap_or(false) {
                    return Ok(blocked_connect_response!());
                }
                let verify = tls_inspection
                    .map(|t| {
                        t.verify_upstream
                            && !state.tls_verify_exception_matches(listener_name, &host)
                    })
                    .unwrap_or(true);
                let upstream = resolve_upstream(&action, &state, listener_name)?;
                let rate_limit_ctx = RateLimitContext::from_identity(
                    remote_addr.ip(),
                    &identity,
                    matched_rule_name,
                    upstream.as_ref().map(|upstream| upstream.key()),
                );
                let concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx)
                {
                    Some(permits) => Some(permits),
                    None => return Ok(too_many_connect_response!()),
                };
                let upstream_connected = match connect_tunnel_target(
                    &host,
                    port,
                    upstream.as_ref(),
                    proxy_name,
                    upstream_timeout,
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(_) => return Ok(proxy_error_connect_response!()),
                };
                let runtime_for_mitm = runtime.clone();
                let listener_name_owned = listener_name.to_string();
                let authority_for_task = authority.clone();
                let sanitized_headers_for_task = sanitized_headers.clone();
                let identity_for_task = identity.clone();
                let action_for_task = action.clone();
                let matched_rule_for_task = matched_rule.as_ref().map(|rule| rule.to_string());
                task::spawn(async move {
                    if let Err(err) = tunnel_connect(
                        req,
                        upstream_connected,
                        runtime_for_mitm,
                        TunnelConnectContext {
                            remote_addr,
                            listener_name: listener_name_owned,
                            host,
                            port,
                            authority: authority_for_task,
                            sanitized_headers: sanitized_headers_for_task,
                            identity: identity_for_task,
                            initial_action: action_for_task,
                            matched_rule: matched_rule_for_task,
                            verify_upstream: verify,
                            _concurrency_permits: concurrency_permits,
                            throttle: None,
                        },
                    )
                    .await
                    {
                        warn!(error = ?err, "mitm tunnel failed");
                    }
                });
                Ok(established_connect_response!())
            }
        }
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {
            let upstream = resolve_upstream(&action, &state, listener_name)?;
            let rate_limit_ctx = RateLimitContext::from_identity(
                remote_addr.ip(),
                &identity,
                matched_rule_name,
                upstream.as_ref().map(|upstream| upstream.key()),
            );
            let concurrency_permits = match request_limits.acquire_concurrency(&rate_limit_ctx) {
                Some(permits) => Some(permits),
                None => return Ok(too_many_connect_response!()),
            };
            let connected = match connect_tunnel_target(
                &host,
                port,
                upstream.as_ref(),
                proxy_name,
                upstream_timeout,
            )
            .await
            {
                Ok(stream) => stream,
                Err(_) => return Ok(proxy_error_connect_response!()),
            };
            let throttle = BandwidthThrottle::with_context(
                rate_limit_ctx,
                request_limits.byte_limiters.clone(),
                request_limits.byte_quota_limiters.clone(),
            );
            let runtime_for_tunnel = runtime.clone();
            let listener_name_owned = listener_name.to_string();
            let authority_for_task = authority.clone();
            let sanitized_headers_for_task = sanitized_headers.clone();
            let identity_for_task = identity.clone();
            let action_for_task = action.clone();
            let matched_rule_for_task = matched_rule.as_ref().map(|rule| rule.to_string());
            task::spawn(async move {
                if let Err(err) = tunnel_connect(
                    req,
                    connected,
                    runtime_for_tunnel,
                    TunnelConnectContext {
                        remote_addr,
                        listener_name: listener_name_owned,
                        host,
                        port,
                        authority: authority_for_task,
                        sanitized_headers: sanitized_headers_for_task,
                        identity: identity_for_task,
                        initial_action: action_for_task,
                        matched_rule: matched_rule_for_task,
                        verify_upstream: false,
                        _concurrency_permits: concurrency_permits,
                        throttle,
                    },
                )
                .await
                {
                    warn!(error = ?err, "tunnel failed");
                }
            });
            Ok(established_connect_response!())
        }
    }
}

#[cfg(test)]
mod tests;
