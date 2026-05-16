mod audit;
mod crypto;
mod ext_authz;
mod identity;
mod signed_assertion;
mod util;

pub(crate) use audit::{AuditRecord, emit_audit_log};
pub(crate) use ext_authz::{
    CompiledExtAuthz, ExtAuthzEnforcement, ExtAuthzInput, ExtAuthzMode,
    apply_ext_authz_action_overrides, enforce_ext_authz, merge_header_controls,
    validate_ext_authz_allow_mode,
};
pub(crate) use identity::{
    CompiledIdentitySource, EffectivePolicyContext, ResolvedIdentity, resolve_identity,
    sanitize_headers_for_policy, strip_untrusted_identity_headers,
};

pub(crate) fn attach_log_context(
    response: &mut hyper::Response<crate::http::body::Body>,
    log_context: &qpx_observability::access_log::RequestLogContext,
) {
    response.extensions_mut().insert(log_context.clone());
}

pub(crate) fn merge_policy_tags(into: &mut Vec<String>, extra: &[String]) {
    for tag in extra {
        let tag = tag.trim();
        if !tag.is_empty() && !into.iter().any(|existing| existing == tag) {
            into.push(tag.to_string());
        }
    }
}
