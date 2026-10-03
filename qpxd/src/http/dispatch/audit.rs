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
    pub(super) state: Option<Arc<RuntimeState>>,
    pub(crate) kind: ProxyKind,
    pub(crate) scope_name: Option<Arc<str>>,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) host: Option<String>,
    pub(crate) sni: Option<String>,
    pub(crate) request_method: Method,
    pub(crate) path: Option<String>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) matched_route: Option<String>,
    pub(crate) decision_service_policy_id: Option<String>,
    pub(crate) log_context: RequestLogContext,
}

pub(crate) fn annotate_dispatch_response(
    response: &mut Response<Body>,
    ctx: &DispatchAuditContext,
    outcome: DispatchOutcome,
    extra_policy_tags: &[String],
) {
    record_dispatch_outcome(ctx.kind, outcome);
    let annotated_context = if extra_policy_tags.is_empty() {
        Cow::Borrowed(&ctx.log_context)
    } else {
        let mut annotated_context = ctx.log_context.clone();
        merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
        Cow::Owned(annotated_context)
    };
    let Some(state) = ctx.state.as_deref() else {
        return;
    };
    attach_log_context(state, response, &annotated_context);
    emit_audit_log(
        state,
        AuditRecord {
            kind: ctx.kind,
            name: ctx.scope_name.as_deref().unwrap_or(""),
            remote_ip: ctx.remote_addr.ip(),
            host: ctx.host.as_deref(),
            sni: ctx.sni.as_deref(),
            method: Some(ctx.request_method.as_str()),
            path: ctx.path.as_deref(),
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule: ctx.matched_rule.as_deref(),
            matched_route: ctx.matched_route.as_deref(),
            decision_service_policy_id: ctx.decision_service_policy_id.as_deref(),
        },
        &annotated_context,
    );
}
