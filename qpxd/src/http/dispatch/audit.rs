use crate::policy_context::{AuditRecord, attach_log_context, emit_audit_log, merge_policy_tags};
use crate::runtime::RuntimeState;
use http::Method;
use hyper::Response;
use qpx_http::body::Body;
use qpx_observability::access_log::RequestLogContext;
use std::net::SocketAddr;
use std::sync::Arc;

use super::metrics::record_dispatch_outcome;
use super::{DispatchOutcome, ProxyKind};

#[derive(Clone)]
pub(crate) struct DispatchAuditContext {
    pub(crate) state: Arc<RuntimeState>,
    pub(crate) kind: ProxyKind,
    pub(crate) scope_name: String,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) host: Option<String>,
    pub(crate) sni: Option<String>,
    pub(crate) request_method: Method,
    pub(crate) path: Option<String>,
    pub(crate) matched_rule: Option<String>,
    pub(crate) matched_route: Option<String>,
    pub(crate) ext_authz_policy_id: Option<String>,
    pub(crate) log_context: RequestLogContext,
}

impl DispatchAuditContext {
    pub(crate) fn new(
        state: Arc<RuntimeState>,
        kind: ProxyKind,
        scope_name: impl Into<String>,
        remote_addr: SocketAddr,
        request_method: Method,
        path: Option<String>,
        log_context: RequestLogContext,
    ) -> Self {
        Self {
            state,
            kind,
            scope_name: scope_name.into(),
            remote_addr,
            host: None,
            sni: None,
            request_method,
            path,
            matched_rule: None,
            matched_route: None,
            ext_authz_policy_id: None,
            log_context,
        }
    }

    pub(crate) fn with_host(mut self, host: Option<String>) -> Self {
        self.host = host;
        self
    }

    pub(crate) fn with_sni(mut self, sni: Option<String>) -> Self {
        self.sni = sni;
        self
    }

    pub(crate) fn with_matched_rule(mut self, matched_rule: Option<String>) -> Self {
        self.matched_rule = matched_rule;
        self
    }

    pub(crate) fn with_matched_route(mut self, matched_route: Option<String>) -> Self {
        self.matched_route = matched_route;
        self
    }

    pub(crate) fn with_ext_authz_policy_id(mut self, ext_authz_policy_id: Option<String>) -> Self {
        self.ext_authz_policy_id = ext_authz_policy_id;
        self
    }
}

pub(crate) fn annotate_dispatch_response(
    response: &mut Response<Body>,
    ctx: &DispatchAuditContext,
    outcome: DispatchOutcome,
    extra_policy_tags: &[String],
) {
    record_dispatch_outcome(ctx.kind, outcome);
    let mut annotated_context = ctx.log_context.clone();
    merge_policy_tags(&mut annotated_context.policy_tags, extra_policy_tags);
    attach_log_context(response, &annotated_context);
    emit_audit_log(
        &ctx.state,
        AuditRecord {
            kind: ctx.kind,
            name: ctx.scope_name.as_str(),
            remote_ip: ctx.remote_addr.ip(),
            host: ctx.host.as_deref(),
            sni: ctx.sni.as_deref(),
            method: Some(ctx.request_method.as_str()),
            path: ctx.path.as_deref(),
            outcome,
            status: Some(response.status().as_u16()),
            matched_rule: ctx.matched_rule.as_deref(),
            matched_route: ctx.matched_route.as_deref(),
            ext_authz_policy_id: ctx.ext_authz_policy_id.as_deref(),
        },
        &annotated_context,
    );
}
