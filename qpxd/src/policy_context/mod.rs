mod audit;
mod crypto;
mod decision_service;
mod identity;
mod metrics;
mod signed_assertion;
mod util;

pub(crate) use audit::{AuditRecord, emit_audit_log};
pub(crate) use decision_service::{
    CompiledDecisionService, DecisionServiceAllow, DecisionServiceDeny, DecisionServiceEnforcement,
    DecisionServiceInput, DecisionServiceMode, enforce_decision_service, merge_header_controls,
    prepare_decision_service_allow,
};
pub(crate) use identity::{
    CompiledIdentitySource, EffectivePolicyContext, ResolvedIdentity, resolve_identity,
    sanitize_headers_for_policy, strip_untrusted_identity_headers,
};

pub(crate) fn attach_log_context(
    state: &crate::runtime::RuntimeState,
    response: &mut hyper::Response<qpx_http::body::Body>,
    log_context: &qpx_observability::access_log::RequestLogContext,
) {
    if state.resources.access_log.output.enabled || qpx_observability::otel_enabled() {
        response.extensions_mut().insert(log_context.clone());
    }
}

pub(crate) fn merge_policy_tags(into: &mut Vec<String>, extra: &[String]) {
    for tag in extra.iter().map(|tag| tag.trim()) {
        if !tag.is_empty() && !into.iter().any(|existing| existing == tag) {
            into.push(tag.to_string());
        }
    }
}
