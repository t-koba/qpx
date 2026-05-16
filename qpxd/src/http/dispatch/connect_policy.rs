use qpx_core::rules::RuleMatchContext;
use std::net::IpAddr;

pub(crate) struct DispatchConnectRuleContextInput<'a> {
    pub(crate) remote_ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) host: &'a str,
    pub(crate) path: Option<&'a str>,
    pub(crate) authority: &'a str,
    pub(crate) http_version: &'a str,
    pub(crate) alpn: Option<&'a str>,
    pub(crate) destination: &'a crate::destination::DestinationMetadata,
    pub(crate) headers: &'a http::HeaderMap,
    pub(crate) identity: &'a crate::policy_context::ResolvedIdentity,
}

pub(crate) fn build_dispatch_connect_rule_context<'a>(
    input: DispatchConnectRuleContextInput<'a>,
) -> RuleMatchContext<'a> {
    let DispatchConnectRuleContextInput {
        remote_ip,
        port,
        host,
        path,
        authority,
        http_version,
        alpn,
        destination,
        headers,
        identity,
    } = input;
    RuleMatchContext {
        src_ip: Some(remote_ip),
        dst_port: Some(port),
        host: Some(host),
        sni: Some(host),
        method: Some("CONNECT"),
        path,
        authority: Some(authority),
        http_version: Some(http_version),
        alpn,
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        headers: Some(headers),
        user: identity.user.as_deref(),
        user_groups: &identity.groups,
        device_id: identity.device_id.as_deref(),
        posture: &identity.posture,
        tenant: identity.tenant.as_deref(),
        auth_strength: identity.auth_strength.as_deref(),
        idp: identity.idp.as_deref(),
        ..Default::default()
    }
}
