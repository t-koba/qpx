use crate::runtime::RuntimeState;
use qpx_core::config::AuditIncludeField;
use qpx_observability::access_log::RequestLogContext;
use std::net::IpAddr;
use tracing::Level;

pub(crate) struct AuditRecord<'a> {
    pub(crate) kind: &'static str,
    pub(crate) name: &'a str,
    pub(crate) remote_ip: IpAddr,
    pub(crate) host: Option<&'a str>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) method: Option<&'a str>,
    pub(crate) path: Option<&'a str>,
    pub(crate) outcome: &'a str,
    pub(crate) status: Option<u16>,
    pub(crate) matched_rule: Option<&'a str>,
    pub(crate) matched_route: Option<&'a str>,
    pub(crate) ext_authz_policy_id: Option<&'a str>,
}

pub(crate) fn emit_audit_log(
    state: &RuntimeState,
    record: AuditRecord<'_>,
    context: &RequestLogContext,
) {
    if !state
        .resources
        .operational
        .telemetry
        .audit_log
        .output
        .enabled
        || !tracing::enabled!(target: "audit_log", Level::INFO)
    {
        return;
    }
    let include = |field: AuditIncludeField| {
        state
            .resources
            .operational
            .telemetry
            .audit_log
            .include
            .contains(&field)
    };
    tracing::info!(
        target: "audit_log",
        event = "policy",
        kind = record.kind,
        name = record.name,
        remote = %record.remote_ip,
        host = record.host.unwrap_or(""),
        sni = record.sni.unwrap_or(""),
        method = record.method.unwrap_or(""),
        path = record.path.unwrap_or(""),
        outcome = record.outcome,
        status = record.status.unwrap_or(0),
        subject = if include(AuditIncludeField::Subject) {
            context.subject.as_deref().unwrap_or("")
        } else {
            ""
        },
        groups = if include(AuditIncludeField::Groups) {
            context.groups.join(",")
        } else {
            String::new()
        },
        device_id = if include(AuditIncludeField::DeviceId) {
            context.device_id.as_deref().unwrap_or("")
        } else {
            ""
        },
        posture = if include(AuditIncludeField::Posture) {
            context.posture.join(",")
        } else {
            String::new()
        },
        tenant = if include(AuditIncludeField::Tenant) {
            context.tenant.as_deref().unwrap_or("")
        } else {
            ""
        },
        auth_strength = if include(AuditIncludeField::AuthStrength) {
            context.auth_strength.as_deref().unwrap_or("")
        } else {
            ""
        },
        idp = if include(AuditIncludeField::Idp) {
            context.idp.as_deref().unwrap_or("")
        } else {
            ""
        },
        identity_source = if include(AuditIncludeField::IdentitySource) {
            context.identity_source.as_deref().unwrap_or("")
        } else {
            ""
        },
        policy_tags = if include(AuditIncludeField::PolicyTags) {
            context.policy_tags.join(",")
        } else {
            String::new()
        },
        ext_authz_policy_id = if include(AuditIncludeField::ExtAuthzPolicyId) {
            record
                .ext_authz_policy_id
                .or(context.ext_authz_policy_id.as_deref())
                .unwrap_or("")
        } else {
            ""
        },
        matched_rule = if include(AuditIncludeField::MatchedRule) {
            record
                .matched_rule
                .or(context.matched_rule.as_deref())
                .unwrap_or("")
        } else {
            ""
        },
        matched_route = if include(AuditIncludeField::MatchedRoute) {
            record
                .matched_route
                .or(context.matched_route.as_deref())
                .unwrap_or("")
        } else {
            ""
        },
        destination_trace = context.destination_trace.as_deref().unwrap_or(""),
    );
}
