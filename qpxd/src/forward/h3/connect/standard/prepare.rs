use super::super::super::backend_h3::ForwardH3Handler;
use super::super::parse::{format_authority, validate_h3_connect_head};
use super::target::{H3ConnectTargetInput, prepare_h3_connect_target};
use super::{H3PolicyResponseContext, PreparedH3Connect, send_h3_policy_response};
use crate::destination::DestinationInputs;
#[cfg(feature = "auth-basic")]
use crate::forward::request::proxy_auth_required;
use crate::http::dispatch::{
    DispatchConnectRuleContextInput, DispatchOutcome, build_dispatch_connect_rule_context,
};
use crate::http::local_response::finalized_local_response;
use crate::http::protocol::common::{
    blocked_response as blocked, forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::http3::codec::h1_headers_to_http;
use crate::http3::listener::H3ConnInfo;
use crate::http3::server::{H3ServerRequestStream, send_h3_static_response};
use crate::policy_context::{
    ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, enforce_ext_authz,
    prepare_ext_authz_allow_controls, resolve_identity, sanitize_headers_for_policy,
};
use crate::rate_limit::{RateLimitContext, TransportScope};
use anyhow::{Result, anyhow};
use qpx_core::config::{ActionKind, ConnectUdpConfig};
use tracing::warn;

pub(crate) async fn prepare_h3_connect_request(
    req_head: &::http::Request<()>,
    req_stream: &mut H3ServerRequestStream,
    handler: &ForwardH3Handler,
    conn: &H3ConnInfo,
    connect_udp_cfg: Option<&ConnectUdpConfig>,
) -> Result<Option<Box<PreparedH3Connect>>> {
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let max_h3_response_body_bytes = state.plan.limits.body.max_h3_response_body_bytes;
    let protocol = req_head.extensions().get::<::h3::ext::Protocol>().copied();
    let is_connect_udp = protocol == Some(::h3::ext::Protocol::CONNECT_UDP);
    let is_extended_connect = protocol.is_some();

    let Some(target) = prepare_h3_connect_target(H3ConnectTargetInput {
        req_head,
        req_stream,
        connect_udp_cfg,
        proxy_name,
        max_h3_response_body_bytes,
        is_connect_udp,
        is_extended_connect,
        connect_udp_disabled_message: state.messages.connect_udp_disabled.as_str(),
    })
    .await?
    else {
        return Ok(None);
    };
    let req_authority = target.req_authority;
    let host = target.host;
    let port = target.port;
    let authority_host_for_validation = target.authority_host_for_validation;
    let authority_port_for_validation = target.authority_port_for_validation;
    let auth_uri = target.auth_uri;
    macro_rules! reject_bad_request {
        ($message:expr) => {
            send_h3_static_response(
                req_stream,
                ::http::StatusCode::BAD_REQUEST,
                $message,
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
        };
    }

    let headers = match h1_headers_to_http(req_head.headers()) {
        Ok(headers) => headers,
        Err(_) => {
            let message = if is_connect_udp {
                b"invalid CONNECT-UDP headers".as_slice()
            } else {
                b"invalid CONNECT headers".as_slice()
            };
            reject_bad_request!(message).await?;
            return Ok(None);
        }
    };

    if let Err(err) = validate_h3_connect_head(
        req_head,
        &headers,
        authority_host_for_validation.as_str(),
        authority_port_for_validation,
        is_extended_connect,
    ) {
        if is_connect_udp {
            warn!(error = ?err, "invalid forward HTTP/3 CONNECT-UDP request");
        } else {
            warn!(error = ?err, "invalid forward HTTP/3 CONNECT request");
        }
        let message = if is_connect_udp {
            b"bad CONNECT-UDP request".as_slice()
        } else {
            b"bad CONNECT request".as_slice()
        };
        reject_bad_request!(message).await?;
        return Ok(None);
    }

    let base_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), None)
        .ok_or_else(|| anyhow!("listener plan not found"))?;
    let effective_policy = base_plan.policy_context.clone();
    let mut sanitized_headers = headers;
    sanitize_headers_for_policy(
        &state,
        &effective_policy,
        conn.remote_addr.ip(),
        &mut sanitized_headers,
    )?;
    let mut identity = resolve_identity(
        &state,
        &effective_policy,
        conn.remote_addr.ip(),
        Some(&sanitized_headers),
        conn.peer_certificates
            .as_deref()
            .map(|certs| certs.as_slice()),
    )?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(host.as_str()),
            ip: host.parse().ok(),
            sni: Some(host.as_str()),
            scheme: if is_connect_udp {
                req_head.uri().scheme_str()
            } else {
                Some("https")
            },
            port: Some(port),
            alpn: Some("h3"),
            ..Default::default()
        },
        base_plan.destination_resolution.as_ref(),
    );
    let audit_path = req_head
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string());
    macro_rules! send_policy {
        ($response:expr, $outcome:expr, $matched_rule:expr, $ext_authz_policy_id:expr, $log_context:expr) => {
            send_h3_policy_response(
                req_stream,
                $response,
                H3PolicyResponseContext {
                    request_method: &http::Method::CONNECT,
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: $outcome,
                    matched_rule: $matched_rule,
                    ext_authz_policy_id: $ext_authz_policy_id,
                    log_context: $log_context,
                },
            )
        };
    }
    macro_rules! respond_with_policy {
        ($response:expr, $outcome:expr, $matched_rule:expr, $ext_authz_policy_id:expr, $log_context:expr) => {{
            send_policy!(
                $response,
                $outcome,
                $matched_rule,
                $ext_authz_policy_id,
                $log_context
            )
            .await?;
            return Ok(None);
        }};
    }
    #[cfg(feature = "auth-basic")]
    macro_rules! respond_with_unmatched_policy {
        ($response:expr, $outcome:expr, $log_context:expr) => {{ respond_with_policy!($response, $outcome, None, None, $log_context) }};
    }
    macro_rules! rate_limited_response {
        ($retry_after:expr) => {
            finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                too_many_requests(Some($retry_after)),
                false,
            )
        };
    }
    let ctx = build_dispatch_connect_rule_context(DispatchConnectRuleContextInput {
        remote_ip: conn.remote_addr.ip(),
        port,
        host: host.as_str(),
        path: audit_path.as_deref(),
        authority: req_authority.as_str(),
        http_version: http_version_label(http::Version::HTTP_3),
        alpn: Some("h3"),
        destination: &destination,
        headers: &sanitized_headers,
        identity: &identity,
    });

    let (mut action, matched_rule) = match crate::forward::evaluate_forward_policy(
        &handler.runtime,
        handler.listener_name.as_ref(),
        ctx,
        &sanitized_headers,
        "CONNECT",
        auth_uri.as_str(),
    )
    .await
    {
        Ok(crate::forward::ForwardPolicyDecision::Allow(allowed)) => {
            identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (
                allowed.action,
                allowed.matched_rule.map(|rule| rule.to_string()),
            )
        }
        #[cfg(feature = "auth-basic")]
        Ok(crate::forward::ForwardPolicyDecision::Challenge(challenge)) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                proxy_auth_required(challenge, state.messages.proxy_auth_required.as_str()),
                false,
            );
            respond_with_unmatched_policy!(response, DispatchOutcome::Challenge, &log_context);
        }
        #[cfg(feature = "auth-basic")]
        Ok(crate::forward::ForwardPolicyDecision::Forbidden) => {
            let log_context = identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            );
            respond_with_unmatched_policy!(response, DispatchOutcome::Forbidden, &log_context);
        }
        Err(err) => {
            if is_connect_udp {
                warn!(
                    error = ?err,
                    "forward HTTP/3 CONNECT-UDP policy evaluation failed"
                );
            } else {
                warn!(error = ?err, "forward HTTP/3 CONNECT policy evaluation failed");
            }
            send_h3_static_response(
                req_stream,
                ::http::StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                proxy_name,
                max_h3_response_body_bytes,
            )
            .await?;
            return Ok(None);
        }
    };
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled HTTP/3 CONNECT listener execution plan not found"))?;
    let matched_rule_name = matched_rule.as_deref();

    let request_limit_ctx =
        RateLimitContext::from_identity(conn.remote_addr.ip(), &identity, matched_rule_name, None);
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
        let log_context = identity.to_log_context(matched_rule_name, None, None);
        let response = rate_limited_response!(retry_after);
        respond_with_policy!(
            response,
            DispatchOutcome::RateLimited,
            matched_rule_name,
            None,
            &log_context
        );
    }

    let ext_authz = enforce_ext_authz(
        &state,
        &effective_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name,
            scope_name: handler.listener_name.as_ref(),
            remote_ip: conn.remote_addr.ip(),
            dst_port: Some(port),
            host: Some(host.as_str()),
            sni: Some(host.as_str()),
            method: Some("CONNECT"),
            path: audit_path.as_deref(),
            uri: Some(auth_uri.as_str()),
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
    let (response_headers, timeout_override, rate_limit_profile) = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            let allow =
                prepare_ext_authz_allow_controls(allow, ExtAuthzMode::ForwardConnect, None)?;
            let rate_limit_profile = allow.rate_limit_profile.clone();
            if let Some(retry_after) = request_limits.merge_profile_and_check(
                &state.policy.rate_limiters,
                rate_limit_profile.as_deref(),
                TransportScope::Connect,
                &request_limit_ctx,
                1,
            )? {
                let response = rate_limited_response!(retry_after);
                respond_with_policy!(
                    response,
                    DispatchOutcome::RateLimited,
                    matched_rule_name,
                    ext_authz_policy_id.as_deref(),
                    &log_context
                );
            }
            allow.apply_action_overrides(&mut action);
            (allow.headers, allow.timeout_override, rate_limit_profile)
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let response = if let Some(local) = deny.local_response.as_ref() {
                finalized_local_response(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    local,
                    deny.headers.as_deref(),
                )?
            } else {
                finalize_response_with_headers(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    forbidden(state.messages.forbidden.as_str()),
                    deny.headers.as_deref(),
                    false,
                )
            };
            respond_with_policy!(
                response,
                if deny.local_response.is_some() {
                    DispatchOutcome::ExtAuthzLocalResponse
                } else {
                    DispatchOutcome::ExtAuthzDeny
                },
                matched_rule_name,
                ext_authz_policy_id.as_deref(),
                &log_context
            );
        }
    };

    match action.kind {
        ActionKind::Block => {
            let response = finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                blocked(state.messages.blocked.as_str()),
                response_headers.as_deref(),
                false,
            );
            respond_with_policy!(
                response,
                DispatchOutcome::Block,
                matched_rule_name,
                ext_authz_policy_id.as_deref(),
                &log_context
            );
        }
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            let response = finalized_local_response(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                local,
                response_headers.as_deref(),
            )?;
            respond_with_policy!(
                response,
                DispatchOutcome::Respond,
                matched_rule_name,
                ext_authz_policy_id.as_deref(),
                &log_context
            );
        }
        ActionKind::Inspect => {}
        ActionKind::Tunnel | ActionKind::Direct | ActionKind::Proxy => {}
    }

    Ok(Some(Box::new(PreparedH3Connect {
        authority: format_authority(&host, port),
        host,
        port,
        action,
        response_headers,
        log_context,
        matched_rule,
        ext_authz_policy_id,
        audit_path,
        timeout_override,
        rate_limit_profile,
        rate_limit_context: request_limit_ctx,
        sanitized_headers,
        identity,
    })))
}
