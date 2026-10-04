use super::audit::DispatchObservabilityContext;
use super::{DispatchAuditContext, ProxyKind};
use crate::destination::DestinationMetadata;
use crate::http::policy::rule_context::attach_destination_trace;
use crate::policy_context::{DecisionServiceEnforcement, ResolvedIdentity};
use crate::runtime::RuntimeState;
use http::Method;
use std::net::SocketAddr;
use std::sync::Arc;

pub(crate) struct DispatchAuditInput<'a> {
    pub(crate) state: &'a Arc<RuntimeState>,
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
    let observability_enabled =
        input.state.plan.response_observability_required || qpx_observability::otel_enabled();
    let observability = observability_enabled.then(|| {
        let decision_service_policy_id = input
            .decision_service
            .and_then(|decision| decision.policy_id().map(str::to_owned));
        let mut log_context = input.identity.to_log_context(
            input.matched_rule,
            input.matched_route,
            decision_service_policy_id.as_deref(),
        );
        attach_destination_trace(&mut log_context, input.destination);
        log_context.policy_tags = input
            .decision_service
            .map(|decision| decision.policy_tags().to_vec())
            .unwrap_or_default();
        Box::new(DispatchObservabilityContext {
            state: input.state.clone(),
            scope_name: Arc::<str>::from(input.scope_name),
            path: input.path.map(str::to_owned),
            log_context,
            host: input.host.map(str::to_owned),
            sni: input.sni.map(str::to_owned),
            matched_rule: input.matched_rule.map(str::to_owned),
            matched_route: input.matched_route.map(str::to_owned),
            decision_service_policy_id,
        })
    });
    DispatchAuditContext {
        kind: input.kind,
        remote_addr: input.remote_addr,
        request_method: input.request_method,
        observability,
    }
}
