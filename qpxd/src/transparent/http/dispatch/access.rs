use super::super::ConnectTarget;
use super::types::{TransparentAccess, TransparentAccessOutcome};
use crate::http::body::Body;
use crate::http::dispatch::{
    DispatchAuditContext, ExtAuthzDenyResponseInput, annotate_dispatch_response,
    ext_authz_deny_response,
};
use crate::http::policy::EvaluatedAction;
use crate::http::policy::rule_context::attach_destination_trace;
use crate::http::protocol::common::{
    forbidden_response as forbidden, too_many_requests_response as too_many_requests,
};
use crate::http::protocol::l7::finalize_response_for_request;
use crate::policy_context::{ext_authz_facade, identity_facade};
use crate::rate_limit::RateLimitContext;
use anyhow::{Result, anyhow};
use std::net::SocketAddr;
use std::sync::Arc;

pub(super) struct TransparentPrepareAuditInput<'a> {
    pub(super) state: &'a Arc<crate::runtime::RuntimeState>,
    pub(super) identity: &'a identity_facade::ResolvedIdentity,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) listener_name: &'a str,
    pub(super) remote_addr: SocketAddr,
    pub(super) host: Option<String>,
    pub(super) request_method: &'a hyper::Method,
    pub(super) path: Option<&'a str>,
    pub(super) matched_rule: Option<&'a str>,
}

pub(super) fn build_transparent_prepare_audit_context(
    input: TransparentPrepareAuditInput<'_>,
) -> DispatchAuditContext {
    let mut log_context = input
        .identity
        .to_log_context(input.matched_rule, None, None);
    attach_destination_trace(&mut log_context, input.destination);
    DispatchAuditContext::new(
        input.state.clone(),
        crate::http::dispatch::ProxyKind::Transparent,
        input.listener_name,
        input.remote_addr,
        input.request_method.clone(),
        input.path.map(str::to_string),
        log_context,
    )
    .with_host(input.host)
    .with_matched_rule(input.matched_rule.map(str::to_string))
}

pub(super) struct TransparentAccessInput<'a> {
    pub(super) state: Arc<crate::runtime::RuntimeState>,
    pub(super) proxy_name: &'a str,
    pub(super) listener_name: &'a str,
    pub(super) remote_addr: SocketAddr,
    pub(super) connect_target: &'a ConnectTarget,
    pub(super) host_for_match: &'a Option<String>,
    pub(super) base: &'a crate::http::protocol::base_fields::BaseRequestFields,
    pub(super) effective_policy: &'a identity_facade::EffectivePolicyContext,
    pub(super) destination: &'a crate::destination::DestinationMetadata,
    pub(super) identity: &'a identity_facade::ResolvedIdentity,
    pub(super) sanitized_headers: &'a http::HeaderMap,
    pub(super) request_method: hyper::Method,
    pub(super) request_version: hyper::Version,
    pub(super) request_uri: String,
    pub(super) policy: Option<Box<EvaluatedAction>>,
    pub(super) early_response: Option<Box<hyper::Response<Body>>>,
    pub(super) matched_rule: Option<String>,
    pub(super) request_limits: &'a mut crate::rate_limit::AppliedRateLimits,
    pub(super) request_limit_ctx: &'a RateLimitContext,
}

pub(super) async fn enforce_transparent_access_control(
    input: TransparentAccessInput<'_>,
) -> Result<TransparentAccessOutcome> {
    let ext_authz = if let Some(policy) = input.policy.as_ref() {
        Some(
            ext_authz_facade::enforce_ext_authz(
                &input.state,
                input.effective_policy,
                ext_authz_facade::ExtAuthzInput {
                    proxy_kind: crate::http::dispatch::ProxyKind::Transparent,
                    proxy_name: input.proxy_name,
                    scope_name: input.listener_name,
                    remote_ip: input.remote_addr.ip(),
                    dst_port: Some(input.connect_target.port()),
                    host: input.host_for_match.as_deref(),
                    sni: None,
                    method: Some(input.request_method.as_str()),
                    path: input.base.path.as_deref(),
                    uri: Some(input.request_uri.as_str()),
                    matched_rule: input.matched_rule.as_deref(),
                    matched_route: None,
                    action: Some(&policy.action),
                    headers: Some(input.sanitized_headers),
                    identity: input.identity,
                },
            )
            .await?,
        )
    } else {
        None
    };
    let audit = build_transparent_audit_context(&input, ext_authz.as_ref());
    if let Some(mut response) = input.early_response {
        annotate_dispatch_response(
            &mut response,
            &audit,
            crate::http::dispatch::DispatchOutcome::EarlyResponse,
            &[],
        );
        return Ok(TransparentAccessOutcome::Response(response));
    }
    let Some(mut policy) = input.policy else {
        return Err(anyhow!(
            "transparent policy missing after early response handling"
        ));
    };
    if let Some(ext_authz) = ext_authz {
        match ext_authz {
            ext_authz_facade::ExtAuthzEnforcement::Continue(allow) => {
                ext_authz_facade::validate_ext_authz_allow_mode(
                    &allow,
                    ext_authz_facade::ExtAuthzMode::TransparentHttp,
                )?;
                policy.headers =
                    ext_authz_facade::merge_header_controls(policy.headers, allow.headers.clone());
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
                    return Ok(TransparentAccessOutcome::Response(Box::new(response)));
                }
                ext_authz_facade::apply_ext_authz_action_overrides(&mut policy.action, &allow);
                return Ok(TransparentAccessOutcome::Continue(Box::new(
                    TransparentAccess {
                        policy,
                        timeout_override: allow.timeout_override,
                        audit,
                    },
                )));
            }
            ext_authz_facade::ExtAuthzEnforcement::Deny(deny) => {
                let response = ext_authz_deny_response(ExtAuthzDenyResponseInput {
                    ext_authz: ext_authz_facade::ExtAuthzEnforcement::Deny(deny),
                    base_headers: policy.headers.clone(),
                    request_method: &input.request_method,
                    request_version: input.request_version,
                    proxy_name: input.proxy_name,
                    default_response: forbidden(input.state.messages.forbidden.as_str()),
                    audit: &audit,
                })?;
                return Ok(TransparentAccessOutcome::Response(Box::new(response)));
            }
        }
    }
    Ok(TransparentAccessOutcome::Continue(Box::new(
        TransparentAccess {
            policy,
            timeout_override: None,
            audit,
        },
    )))
}

pub(super) fn build_transparent_audit_context(
    input: &TransparentAccessInput<'_>,
    ext_authz: Option<&ext_authz_facade::ExtAuthzEnforcement>,
) -> DispatchAuditContext {
    let ext_authz_policy_id = ext_authz.and_then(|decision| match decision {
        ext_authz_facade::ExtAuthzEnforcement::Continue(allow) => allow.policy_id.clone(),
        ext_authz_facade::ExtAuthzEnforcement::Deny(deny) => deny.policy_id.clone(),
    });
    let ext_authz_policy_tags = ext_authz
        .map(|decision| match decision {
            ext_authz_facade::ExtAuthzEnforcement::Continue(allow) => allow.policy_tags.clone(),
            ext_authz_facade::ExtAuthzEnforcement::Deny(deny) => deny.policy_tags.clone(),
        })
        .unwrap_or_default();
    let mut log_context = input.identity.to_log_context(
        input.matched_rule.as_deref(),
        None,
        ext_authz_policy_id.as_deref(),
    );
    attach_destination_trace(&mut log_context, input.destination);
    log_context.policy_tags = ext_authz_policy_tags;
    DispatchAuditContext::new(
        input.state.clone(),
        crate::http::dispatch::ProxyKind::Transparent,
        input.listener_name,
        input.remote_addr,
        input.request_method.clone(),
        input.base.path.clone(),
        log_context,
    )
    .with_host(input.host_for_match.clone())
    .with_matched_rule(input.matched_rule.clone())
    .with_ext_authz_policy_id(ext_authz_policy_id)
}
