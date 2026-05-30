#[cfg(feature = "auth-basic")]
use super::super::proxy_auth_required;
use super::types::{
    ForwardAllowedPolicy, ForwardPolicyOutcome, ForwardPolicyOutcomeInput,
    ForwardPolicyResponseInput,
};
use crate::forward::policy::{
    ForwardPolicyDecision, ForwardPolicyEvaluation, evaluate_forward_policy,
    evaluate_forward_policy_staged,
};
#[cfg(feature = "auth-basic")]
use crate::http::body::Body;
use crate::http::dispatch::{DispatchAuditContext, DispatchError};
use crate::http::policy::rule_context::attach_destination_trace;
#[cfg(feature = "auth-basic")]
use crate::http::protocol::common::forbidden_response as forbidden;
#[cfg(feature = "auth-basic")]
use crate::http::protocol::l7::finalize_response_for_request;
#[cfg(feature = "auth-basic")]
use crate::policy_context::{AuditRecord, attach_log_context, emit_audit_log};
use hyper::Method;
#[cfg(feature = "auth-basic")]
use hyper::Response;
use std::sync::Arc;

pub(super) async fn evaluate_forward_policy_outcome(
    input: ForwardPolicyOutcomeInput<'_>,
) -> std::result::Result<ForwardPolicyOutcome, DispatchError> {
    let ForwardPolicyOutcomeInput {
        runtime,
        listener_name,
        ctx,
        sanitized_headers,
        response: response_input,
        auth_method,
        auth_uri,
        stage_observation,
    } = input;
    let policy = if stage_observation {
        evaluate_forward_policy_staged(
            runtime,
            listener_name,
            ctx,
            sanitized_headers,
            auth_method,
            auth_uri,
        )
        .await?
    } else {
        ForwardPolicyEvaluation::Decision(
            evaluate_forward_policy(
                runtime,
                listener_name,
                ctx,
                sanitized_headers,
                auth_method,
                auth_uri,
            )
            .await?,
        )
    };
    match policy {
        ForwardPolicyEvaluation::Observe(requirements) => {
            Ok(ForwardPolicyOutcome::Observe(requirements))
        }
        ForwardPolicyEvaluation::Decision(policy) => match policy {
            ForwardPolicyDecision::Allow(allowed) => {
                let mut identity = response_input.identity.clone();
                identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
                Ok(ForwardPolicyOutcome::Allow(Box::new(
                    ForwardAllowedPolicy {
                        action: allowed.action,
                        headers: allowed.headers,
                        matched_rule: allowed.matched_rule.map(|rule| rule.to_string()),
                        identity,
                    },
                )))
            }
            #[cfg(feature = "auth-basic")]
            ForwardPolicyDecision::Challenge(chal) => {
                let mut response = proxy_auth_required(
                    chal,
                    response_input.state.messages.proxy_auth_required.as_str(),
                );
                response = finalize_forward_policy_response(
                    response_input,
                    response,
                    crate::http::dispatch::DispatchOutcome::Challenge,
                );
                Ok(ForwardPolicyOutcome::Rejected(
                    DispatchError::AuthRequired {
                        method: "proxy".to_string(),
                        response: Box::new(response),
                    },
                ))
            }
            #[cfg(feature = "auth-basic")]
            ForwardPolicyDecision::Forbidden => {
                let response = finalize_forward_policy_response(
                    response_input,
                    forbidden(response_input.state.messages.forbidden.as_str()),
                    crate::http::dispatch::DispatchOutcome::Forbidden,
                );
                Ok(ForwardPolicyOutcome::Rejected(
                    DispatchError::PolicyDenied {
                        reason: "authentication denied".to_string(),
                        response: Box::new(response),
                    },
                ))
            }
        },
    }
}

#[cfg(feature = "auth-basic")]
pub(super) fn finalize_forward_policy_response(
    input: ForwardPolicyResponseInput<'_>,
    response: Response<Body>,
    outcome: crate::http::dispatch::DispatchOutcome,
) -> Response<Body> {
    let mut log_context = input.identity.to_log_context(None, None, None);
    attach_destination_trace(&mut log_context, input.destination);
    let mut response = finalize_response_for_request(
        input.request_method,
        input.request_version,
        input.proxy_name,
        response,
        false,
    );
    attach_log_context(&mut response, &log_context);
    emit_audit_log(
        input.state,
        AuditRecord {
            kind: crate::http::dispatch::ProxyKind::Forward,
            name: input.listener_name,
            remote_ip: input.remote_addr.ip(),
            host: Some(input.host),
            sni: None,
            method: Some(input.request_method.as_str()),
            path: input.path,
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule: None,
            matched_route: None,
            ext_authz_policy_id: None,
        },
        &log_context,
    );
    response
}

pub(super) fn build_forward_rate_limit_audit_context(
    state: Arc<crate::runtime::RuntimeState>,
    policy: ForwardPolicyResponseInput<'_>,
    request_method: &Method,
    matched_rule: Option<&str>,
) -> DispatchAuditContext {
    let mut log_context = policy.identity.to_log_context(matched_rule, None, None);
    attach_destination_trace(&mut log_context, policy.destination);
    DispatchAuditContext::new(
        state,
        crate::http::dispatch::ProxyKind::Forward,
        policy.listener_name,
        policy.remote_addr,
        request_method.clone(),
        policy.path.map(str::to_string),
        log_context,
    )
    .with_host(Some(policy.host.to_string()))
    .with_matched_rule(matched_rule.map(str::to_string))
}
