#[cfg(feature = "auth-basic")]
use super::super::proxy_auth_required;
use super::types::{
    ForwardAllowedPolicy, ForwardPolicyOutcome, ForwardPolicyOutcomeInput,
    ForwardPolicyResponseInput,
};
use crate::forward::policy::{
    ForwardPolicyDecision, evaluate_forward_policy, evaluate_forward_policy_staged,
};
#[cfg(feature = "auth-basic")]
use crate::http::dispatch::DispatchOutcome;
use crate::http::dispatch::{
    DispatchAuditContext, DispatchAuditInput, DispatchError, ProxyKind,
    build_dispatch_audit_context,
};
use crate::http::pipeline::PolicyStage;
#[cfg(feature = "auth-basic")]
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
#[cfg(feature = "auth-basic")]
use qpx_http::body::Body;
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
        PolicyStage::Decision(
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
        PolicyStage::Observe(requirements) => Ok(PolicyStage::Observe(requirements)),
        PolicyStage::Decision(policy) => match policy {
            ForwardPolicyDecision::Allow(allowed) => {
                let mut identity = response_input.identity.clone();
                identity.supplement_builtin_auth(allowed.authenticated_user.as_ref());
                Ok(PolicyStage::Decision(Box::new(ForwardAllowedPolicy {
                    action: allowed.action,
                    headers: allowed.headers,
                    matched_rule: allowed.matched_rule.map(|rule| rule.to_string()),
                    identity,
                })))
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
                    DispatchOutcome::Challenge,
                );
                Err(DispatchError::AuthRequired {
                    method: "proxy".to_string(),
                    response: Box::new(response),
                })
            }
            #[cfg(feature = "auth-basic")]
            ForwardPolicyDecision::Forbidden => {
                let response = finalize_forward_policy_response(
                    response_input,
                    forbidden(response_input.state.messages.forbidden.as_str()),
                    DispatchOutcome::Forbidden,
                );
                Err(DispatchError::PolicyDenied {
                    reason: "authentication denied".to_string(),
                    response: Box::new(response),
                })
            }
        },
    }
}

#[cfg(feature = "auth-basic")]
pub(super) fn finalize_forward_policy_response(
    input: ForwardPolicyResponseInput<'_>,
    response: Response<Body>,
    outcome: DispatchOutcome,
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
            kind: ProxyKind::Forward,
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
    build_dispatch_audit_context(DispatchAuditInput {
        state,
        kind: ProxyKind::Forward,
        scope_name: policy.listener_name,
        remote_addr: policy.remote_addr,
        host: Some(policy.host.to_string()),
        sni: None,
        request_method: request_method.clone(),
        path: policy.path.map(str::to_string),
        matched_rule: matched_rule.map(str::to_string),
        matched_route: None,
        identity: policy.identity,
        destination: policy.destination,
        ext_authz: None,
    })
}
