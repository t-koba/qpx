use crate::policy_context::{AuditRecord, attach_log_context, emit_audit_log, merge_policy_tags};
use crate::runtime::RuntimeState;
use http::Method;
use hyper::Response;
use qpx_http::body::Body;
use qpx_observability::access_log::RequestLogContext;
use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use super::metrics::record_dispatch_outcome;
use super::{DispatchOutcome, ProxyKind};

#[derive(Clone)]
pub(crate) struct DispatchAuditContext {
    pub(crate) kind: ProxyKind,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) request_method: Method,
    pub(super) observability: Option<Box<DispatchObservabilityContext>>,
}

#[derive(Clone)]
pub(super) struct DispatchObservabilityContext {
    pub(super) state: Arc<RuntimeState>,
    pub(super) scope_name: Arc<str>,
    pub(crate) host: Option<String>,
    pub(crate) sni: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) matched_route: Option<String>,
    pub(crate) decision_service_policy_id: Option<String>,
    pub(crate) log_context: RequestLogContext,
}

impl DispatchAuditContext {
    pub(crate) fn attach_destination_trace(
        &mut self,
        destination: &crate::destination::DestinationMetadata,
    ) {
        if let Some(context) = self.observability.as_mut() {
            crate::http::policy::rule_context::attach_destination_trace(
                &mut context.log_context,
                destination,
            );
        }
    }
}

pub(crate) fn annotate_dispatch_response(
    response: &mut Response<Body>,
    ctx: &DispatchAuditContext,
    outcome: DispatchOutcome,
    extra_policy_tags: &[String],
) {
    record_dispatch_outcome(ctx.kind, outcome);
    let Some(observability) = ctx.observability.as_deref() else {
        return;
    };
    let annotated_context = if extra_policy_tags.is_empty() {
        Cow::Borrowed(&observability.log_context)
    } else {
        let mut annotated_context = observability.log_context.clone();
        merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
        Cow::Owned(annotated_context)
    };
    let state = observability.state.as_ref();
    attach_log_context(state, response, &annotated_context);
    emit_audit_log(
        state,
        AuditRecord {
            kind: ctx.kind,
            name: observability.scope_name.as_ref(),
            remote_ip: ctx.remote_addr.ip(),
            host: observability.host.as_deref(),
            sni: observability.sni.as_deref(),
            method: Some(ctx.request_method.as_str()),
            path: observability.path.as_deref(),
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule: observability.matched_rule.as_deref(),
            matched_route: observability.matched_route.as_deref(),
            decision_service_policy_id: observability.decision_service_policy_id.as_deref(),
        },
        &annotated_context,
    );
}
