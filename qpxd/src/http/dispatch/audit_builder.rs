use super::{DispatchAuditContext, ProxyKind};
use crate::destination::DestinationMetadata;
use crate::http::policy::rule_context::attach_destination_trace;
use crate::policy_context::{ExtAuthzEnforcement, ResolvedIdentity};
use crate::runtime::RuntimeState;
use http::Method;
use std::net::SocketAddr;
use std::sync::Arc;

pub(crate) struct DispatchAuditInput<'a> {
    pub(crate) state: Arc<RuntimeState>,
    pub(crate) kind: ProxyKind,
    pub(crate) scope_name: &'a str,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) host: Option<String>,
    pub(crate) sni: Option<String>,
    pub(crate) request_method: Method,
    pub(crate) path: Option<String>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) matched_route: Option<String>,
    pub(crate) identity: &'a ResolvedIdentity,
    pub(crate) destination: &'a DestinationMetadata,
    pub(crate) ext_authz: Option<&'a ExtAuthzEnforcement>,
}

pub(crate) fn build_dispatch_audit_context(input: DispatchAuditInput<'_>) -> DispatchAuditContext {
    let ext_authz_policy_id = input
        .ext_authz
        .and_then(|decision| decision.policy_id().map(str::to_owned));
    let ext_authz_policy_tags = input
        .ext_authz
        .map(|decision| decision.policy_tags().to_vec())
        .unwrap_or_default();
    let mut log_context = input.identity.to_log_context(
        input.matched_rule.as_deref(),
        input.matched_route.as_deref(),
        ext_authz_policy_id.as_deref(),
    );
    attach_destination_trace(&mut log_context, input.destination);
    log_context.policy_tags = ext_authz_policy_tags;
    DispatchAuditContext::new(
        input.state,
        input.kind,
        input.scope_name,
        input.remote_addr,
        input.request_method,
        input.path,
        log_context,
    )
    .with_host(input.host)
    .with_sni(input.sni)
    .with_matched_rule(input.matched_rule)
    .with_matched_route(input.matched_route)
    .with_ext_authz_policy_id(ext_authz_policy_id)
}
