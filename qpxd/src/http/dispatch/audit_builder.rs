use super::{DispatchAuditContext, ProxyKind};
use crate::destination::DestinationMetadata;
use crate::http::policy::rule_context::attach_destination_trace;
use crate::policy_context::{DecisionServiceEnforcement, ResolvedIdentity};
use crate::runtime::RuntimeState;
use http::Method;
use std::net::SocketAddr;
use std::sync::Arc;

pub(crate) struct DispatchAuditInput<'a> {
    pub(crate) state: Arc<RuntimeState>,
    pub(crate) kind: ProxyKind,
    pub(crate) scope_name: &'a str,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) host: Option<&'a str>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) request_method: Method,
    pub(crate) path: Option<&'a str>,
    pub(crate) matched_rule: Option<&'a str>,
    pub(crate) matched_route: Option<&'a str>,
    pub(crate) identity: &'a ResolvedIdentity,
    pub(crate) destination: &'a DestinationMetadata,
    pub(crate) decision_service: Option<&'a DecisionServiceEnforcement>,
}

pub(crate) fn build_dispatch_audit_context(input: DispatchAuditInput<'_>) -> DispatchAuditContext {
    let observability_enabled = input.state.resources.access_log.output.enabled
        || input.state.resources.audit_log.output.enabled
        || qpx_observability::otel_enabled();
    let owned = |value: Option<&str>| value.filter(|_| observability_enabled).map(str::to_owned);
    let decision_service_policy_id = input
        .decision_service
        .filter(|_| observability_enabled)
        .and_then(|decision| decision.policy_id().map(str::to_owned));
    let mut log_context = if observability_enabled {
        input.identity.to_log_context(
            input.matched_rule,
            input.matched_route,
            decision_service_policy_id.as_deref(),
        )
    } else {
        Default::default()
    };
    if observability_enabled {
        attach_destination_trace(&mut log_context, input.destination);
        log_context.policy_tags = input
            .decision_service
            .map(|decision| decision.policy_tags().to_vec())
            .unwrap_or_default();
    }
    DispatchAuditContext::new(
        input.state,
        input.kind,
        input.scope_name,
        input.remote_addr,
        input.request_method,
        owned(input.path),
        log_context,
    )
    .with_host(owned(input.host))
    .with_sni(owned(input.sni))
    .with_matched_rule(owned(input.matched_rule))
    .with_matched_route(owned(input.matched_route))
    .with_decision_service_policy_id(decision_service_policy_id)
}
