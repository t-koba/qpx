use crate::http::dispatch::{DispatchOutcome, ProxyKind};
use crate::policy_context::{AuditRecord, attach_log_context, emit_audit_log};
use hyper::Response;
use qpx_http::body::Body;
use qpx_observability::access_log::RequestLogContext;
use std::net::IpAddr;

pub(super) struct ConnectAuditContext<'a> {
    pub(super) state: &'a crate::runtime::RuntimeState,
    pub(super) listener_name: &'a str,
    pub(super) remote_ip: IpAddr,
    pub(super) audit_host: &'a str,
    pub(super) path: Option<&'a str>,
    pub(super) matched_rule: Option<&'a str>,
    pub(super) ext_authz_policy_id: Option<&'a str>,
    pub(super) log_context: &'a RequestLogContext,
}

impl ConnectAuditContext<'_> {
    pub(super) fn annotate(&self, response: &mut Response<Body>, outcome: DispatchOutcome) {
        attach_log_context(response, self.log_context);
        emit_audit_log(
            self.state,
            AuditRecord {
                kind: ProxyKind::Forward,
                name: self.listener_name,
                remote_ip: self.remote_ip,
                host: Some(self.audit_host),
                sni: Some(self.audit_host),
                method: Some("CONNECT"),
                path: self.path,
                outcome,
                status: Some(response.status().as_u16()),
                matched_rule: self.matched_rule,
                matched_route: None,
                ext_authz_policy_id: self.ext_authz_policy_id,
            },
            self.log_context,
        );
    }
}
