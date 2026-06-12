use super::{
    ConnectPolicyContext, EvaluatedConnectPolicy, PrepareQpxConnectInput, PreparedQpxConnect,
};
use crate::forward::policy::{ForwardPolicyDecision, evaluate_forward_policy};
#[cfg(feature = "auth-basic")]
use crate::forward::request::proxy_auth_required;
use crate::http::dispatch::{DispatchConnectRuleContextInput, build_dispatch_connect_rule_context};
use crate::http::local_response::finalized_local_response;
use crate::http::protocol::common::{
    blocked_response as blocked, forbidden_response as forbidden, http_version_label,
    too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::{finalize_response_for_request, finalize_response_with_headers};
use crate::policy_context::{
    ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, enforce_ext_authz,
    prepare_ext_authz_allow_controls,
};
use crate::rate_limit::{RateLimitContext, TransportScope};
use anyhow::{Result, anyhow};
use hyper::StatusCode;
use qpx_core::config::ActionKind;
use std::sync::Arc;
use tracing::warn;

use super::super::super::response::{
    QpxPolicyResponseContext, send_qpx_policy_response, send_qpx_static_response,
};

pub(super) async fn evaluate_connect_policy(
    input: &mut PrepareQpxConnectInput<'_>,
    mut context: ConnectPolicyContext,
) -> Result<Option<EvaluatedConnectPolicy>> {
    let req_stream = &mut *input.req_stream;
    let handler = input.handler;
    let conn = input.conn;
    let state = handler.runtime.state();
    #[cfg(feature = "auth-basic")]
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let ctx = build_dispatch_connect_rule_context(DispatchConnectRuleContextInput {
        remote_ip: conn.remote_addr.ip(),
        port: context.port,
        host: context.host.as_str(),
        path: context.audit_path.as_deref(),
        authority: context.req_authority.as_str(),
        http_version: http_version_label(http::Version::HTTP_3),
        alpn: Some("h3"),
        destination: &context.destination,
        headers: &context.sanitized_headers,
        identity: &context.identity,
    });
    let (action, matched_rule) = match evaluate_forward_policy(
        &handler.runtime,
        handler.listener_name.as_ref(),
        ctx,
        &context.sanitized_headers,
        "CONNECT",
        context.auth_uri.as_str(),
    )
    .await
    {
        Ok(ForwardPolicyDecision::Allow(allowed)) => {
            context
                .identity
                .supplement_builtin_auth(allowed.authenticated_user.as_ref());
            (
                allowed.action,
                allowed.matched_rule.map(|rule| rule.to_string()),
            )
        }
        #[cfg(feature = "auth-basic")]
        Ok(ForwardPolicyDecision::Challenge(challenge)) => {
            let log_context = context.identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                proxy_auth_required(challenge, state.messages.proxy_auth_required.as_str()),
                false,
            );
            send_qpx_policy_response(
                req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: context.host.as_str(),
                    path: context.audit_path.as_deref(),
                    outcome: crate::http::dispatch::DispatchOutcome::Challenge,
                    matched_rule: None,
                    ext_authz_policy_id: None,
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(None);
        }
        #[cfg(feature = "auth-basic")]
        Ok(ForwardPolicyDecision::Forbidden) => {
            let log_context = context.identity.to_log_context(None, None, None);
            let response = finalize_response_for_request(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                forbidden(state.messages.forbidden.as_str()),
                false,
            );
            send_qpx_policy_response(
                req_stream,
                response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: context.host.as_str(),
                    path: context.audit_path.as_deref(),
                    outcome: crate::http::dispatch::DispatchOutcome::Forbidden,
                    matched_rule: None,
                    ext_authz_policy_id: None,
                    log_context: &log_context,
                },
            )
            .await?;
            return Ok(None);
        }
        Err(err) => {
            warn!(error = ?err, "forward HTTP/3 qpx-h3 CONNECT policy evaluation failed");
            send_qpx_static_response(
                req_stream,
                StatusCode::BAD_GATEWAY,
                state.messages.proxy_error.as_bytes(),
                &http::Method::CONNECT,
                state.plan.identity.proxy_name.as_ref(),
            )
            .await?;
            return Ok(None);
        }
    };
    Ok(Some(EvaluatedConnectPolicy {
        context,
        action,
        matched_rule,
    }))
}

pub(super) async fn apply_connect_rate_limits(
    input: &mut PrepareQpxConnectInput<'_>,
    evaluated: EvaluatedConnectPolicy,
) -> Result<Option<PreparedQpxConnect>> {
    let req_stream = &mut *input.req_stream;
    let handler = input.handler;
    let conn = input.conn;
    let state = handler.runtime.state();
    let proxy_name = state.plan.identity.proxy_name.as_ref();
    let EvaluatedConnectPolicy {
        context,
        mut action,
        matched_rule,
    } = evaluated;
    let ConnectPolicyContext {
        host,
        port,
        auth_uri,
        sanitized_headers,
        identity,
        effective_policy,
        audit_path,
        ..
    } = context;
    let selected_plan = state
        .plan
        .ingress_edge_execution_plan(handler.listener_name.as_ref(), matched_rule.as_deref())
        .ok_or_else(|| anyhow!("compiled qpx-h3 CONNECT listener execution plan not found"))?;
    let matched_rule_name = matched_rule.as_deref();
    macro_rules! send_policy_response {
        ($response:expr, $outcome:expr, $ext_authz_policy_id:expr, $log_context:expr) => {
            send_qpx_policy_response(
                req_stream,
                $response,
                QpxPolicyResponseContext {
                    state: &state,
                    listener_name: handler.listener_name.as_ref(),
                    conn,
                    host: host.as_str(),
                    path: audit_path.as_deref(),
                    outcome: $outcome,
                    matched_rule: matched_rule_name,
                    ext_authz_policy_id: $ext_authz_policy_id,
                    log_context: $log_context,
                },
            )
            .await?
        };
    }
    macro_rules! send_rate_limited {
        ($retry_after:expr, $ext_authz_policy_id:expr, $log_context:expr) => {
            send_policy_response!(
                finalize_response_for_request(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    too_many_requests(Some($retry_after)),
                    false,
                ),
                crate::http::dispatch::DispatchOutcome::RateLimited,
                $ext_authz_policy_id,
                $log_context
            )
        };
    }

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
        send_rate_limited!(retry_after, None, &log_context);
        return Ok(None);
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
                send_rate_limited!(retry_after, ext_authz_policy_id.as_deref(), &log_context);
                return Ok(None);
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
            send_policy_response!(
                response,
                if deny.local_response.is_some() {
                    crate::http::dispatch::DispatchOutcome::ExtAuthzLocalResponse
                } else {
                    crate::http::dispatch::DispatchOutcome::ExtAuthzDeny
                },
                ext_authz_policy_id.as_deref(),
                &log_context
            );
            return Ok(None);
        }
    };

    if send_connect_local_action(SendConnectLocalActionInput {
        req_stream,
        state: &state,
        handler,
        conn,
        proxy_name,
        host: host.as_str(),
        audit_path: audit_path.as_deref(),
        matched_rule: matched_rule_name,
        ext_authz_policy_id: ext_authz_policy_id.as_deref(),
        log_context: &log_context,
        response_headers: response_headers.as_deref(),
        action: &action,
    })
    .await?
    {
        return Ok(None);
    }

    Ok(Some(PreparedQpxConnect {
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
    }))
}

struct SendConnectLocalActionInput<'a> {
    req_stream: &'a mut qpx_h3::RequestStream,
    state: &'a Arc<crate::runtime::RuntimeState>,
    handler: &'a super::super::super::ForwardQpxHandler,
    conn: &'a qpx_h3::ConnectionInfo,
    proxy_name: &'a str,
    host: &'a str,
    audit_path: Option<&'a str>,
    matched_rule: Option<&'a str>,
    ext_authz_policy_id: Option<&'a str>,
    log_context: &'a qpx_observability::access_log::RequestLogContext,
    response_headers: Option<&'a qpx_core::rules::CompiledHeaderControl>,
    action: &'a qpx_core::config::ActionConfig,
}

async fn send_connect_local_action(input: SendConnectLocalActionInput<'_>) -> Result<bool> {
    let SendConnectLocalActionInput {
        req_stream,
        state,
        handler,
        conn,
        proxy_name,
        host,
        audit_path,
        matched_rule,
        ext_authz_policy_id,
        log_context,
        response_headers,
        action,
    } = input;
    let (response, outcome) = match action.kind {
        ActionKind::Block => (
            finalize_response_with_headers(
                &http::Method::CONNECT,
                http::Version::HTTP_3,
                proxy_name,
                blocked(state.messages.blocked.as_str()),
                response_headers,
                false,
            ),
            crate::http::dispatch::DispatchOutcome::Block,
        ),
        ActionKind::Respond => {
            let local = action
                .local_response
                .as_ref()
                .ok_or_else(|| anyhow!("respond action requires local_response"))?;
            (
                finalized_local_response(
                    &http::Method::CONNECT,
                    http::Version::HTTP_3,
                    proxy_name,
                    local,
                    response_headers,
                )?,
                crate::http::dispatch::DispatchOutcome::Respond,
            )
        }
        _ => return Ok(false),
    };
    send_qpx_policy_response(
        req_stream,
        response,
        QpxPolicyResponseContext {
            state,
            listener_name: handler.listener_name.as_ref(),
            conn,
            host,
            path: audit_path,
            outcome,
            matched_rule,
            ext_authz_policy_id,
            log_context,
        },
    )
    .await?;
    Ok(true)
}
