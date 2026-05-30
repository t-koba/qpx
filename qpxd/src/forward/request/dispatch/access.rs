use super::super::HostPort;
use super::types::{ForwardAccess, ForwardAccessOutcome};
use crate::http::dispatch::{
    DispatchAuditContext, DispatchError, ExtAuthzDenyResponseInput, annotate_dispatch_response,
    ext_authz_deny_response,
};
use crate::http::policy::rule_context::attach_destination_trace;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::protocol::common::{
    forbidden_response as forbidden, too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::finalize_response_for_request;
use crate::policy_context::{
    ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode, apply_ext_authz_action_overrides,
    enforce_ext_authz, merge_header_controls, validate_ext_authz_allow_mode,
};
use crate::rate_limit::RateLimitContext;
use hyper::Method;
use std::sync::Arc;

pub(super) struct ForwardAccessInput<'a> {
    pub(super) state: Arc<crate::runtime::RuntimeState>,
    pub(super) effective_policy: &'a crate::policy_context::EffectivePolicyContext,
    pub(super) proxy_name: &'a str,
    pub(super) listener_name: &'a str,
    pub(super) remote_addr: std::net::SocketAddr,
    pub(super) host: &'a HostPort,
    pub(super) base: &'a BaseRequestFields,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) sanitized_headers: &'a http::HeaderMap,
    pub(super) request_method: Method,
    pub(super) request_version: http::Version,
    pub(super) action: qpx_core::config::ActionConfig,
    pub(super) headers: Option<Arc<qpx_core::rules::CompiledHeaderControl>>,
    pub(super) matched_rule: Option<String>,
    pub(super) cache_policy: Option<qpx_core::config::CachePolicyConfig>,
    pub(super) request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    pub(super) request_limit_ctx: &'a RateLimitContext,
}

pub(super) async fn enforce_forward_access_control(
    input: ForwardAccessInput<'_>,
) -> std::result::Result<ForwardAccessOutcome, DispatchError> {
    let ext_authz = enforce_ext_authz(
        &input.state,
        input.effective_policy,
        ExtAuthzInput {
            proxy_kind: crate::http::dispatch::ProxyKind::Forward,
            proxy_name: input.proxy_name,
            scope_name: input.listener_name,
            remote_ip: input.remote_addr.ip(),
            dst_port: input.host.port,
            host: Some(input.host.host.as_str()),
            sni: None,
            method: Some(input.request_method.as_str()),
            path: input.base.path.as_deref(),
            uri: Some(input.base.request_uri.as_str()),
            matched_rule: input.matched_rule.as_deref(),
            matched_route: None,
            action: Some(&input.action),
            headers: Some(input.sanitized_headers),
            identity: input.identity,
        },
    )
    .await?;
    let audit = build_forward_audit_context(&input, &ext_authz);
    let mut action = input.action;
    let mut headers = input.headers;
    let mut cache_policy = input.cache_policy;
    match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => {
            validate_ext_authz_allow_mode(&allow, ExtAuthzMode::ForwardHttp)?;
            headers = merge_header_controls(headers, allow.headers.clone());
            if allow.cache_bypass {
                cache_policy = None;
            }
            if let Some(retry_after) = input.request_limits.merge_profile_and_check(
                &input.state.policy.rate_limiters,
                allow.rate_limit_profile.as_deref(),
                crate::rate_limit::TransportScope::Request,
                input.request_limit_ctx,
                1,
            )? {
                let mut response = finalize_response_for_request(
                    &input.request_method,
                    input.request_version,
                    input.proxy_name,
                    too_many_requests(Some(retry_after)),
                    false,
                );
                annotate_dispatch_response(
                    &mut response,
                    &audit,
                    crate::http::dispatch::DispatchOutcome::RateLimited,
                    &[],
                );
                return Err(DispatchError::RateLimited {
                    response: Box::new(response),
                });
            }
            apply_ext_authz_action_overrides(&mut action, &allow);
            Ok(ForwardAccessOutcome::Continue(Box::new(ForwardAccess {
                action,
                headers,
                cache_policy,
                timeout_override: allow.timeout_override,
                audit,
            })))
        }
        ExtAuthzEnforcement::Deny(deny) => {
            let response = ext_authz_deny_response(ExtAuthzDenyResponseInput {
                ext_authz: ExtAuthzEnforcement::Deny(deny),
                base_headers: headers,
                request_method: &input.request_method,
                request_version: input.request_version,
                proxy_name: input.proxy_name,
                default_response: forbidden(input.state.messages.forbidden.as_str()),
                audit: &audit,
            })?;
            Err(DispatchError::ExtAuthzDenied {
                response: Box::new(response),
            })
        }
    }
}

pub(super) fn build_forward_audit_context(
    input: &ForwardAccessInput<'_>,
    ext_authz: &ExtAuthzEnforcement,
) -> DispatchAuditContext {
    let ext_authz_policy_id = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    };
    let ext_authz_policy_tags = match ext_authz {
        ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
        ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
    };
    let mut log_context = input.identity.to_log_context(
        input.matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    attach_destination_trace(&mut log_context, input.destination);
    log_context.policy_tags = ext_authz_policy_tags;
    DispatchAuditContext::new(
        input.state.clone(),
        crate::http::dispatch::ProxyKind::Forward,
        input.listener_name,
        input.remote_addr,
        input.request_method.clone(),
        input.base.path.clone(),
        log_context,
    )
    .with_host(Some(input.host.host.clone()))
    .with_matched_rule(input.matched_rule.clone())
    .with_ext_authz_policy_id(ext_authz_policy_id)
}
