use qpx_core::rules::RuleMatchContext;
use std::net::IpAddr;

pub(crate) struct DispatchConnectRuleContextInput<'a> {
    pub(crate) remote_ip: IpAddr,
    pub(crate) port: u16,
    pub(crate) host: &'a str,
    pub(crate) path: Option<&'a str>,
    pub(crate) authority: &'a str,
    pub(crate) http_version: http::Version,
    pub(crate) alpn: Option<&'a str>,
    pub(crate) destination: &'a crate::destination::DestinationMetadata,
    pub(crate) headers: &'a qpx_core::http_message::Headers,
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
    let mut ctx = RuleMatchContext {
        src_ip: Some(remote_ip),
        dst_port: Some(port),
        host: Some(host),
        sni: Some(host),
        method: Some("CONNECT"),
        path,
        authority: Some(authority),
        http_version: Some(crate::http::protocol::common::http_version_label(
            http_version,
        )),
        alpn,
        owned_headers: Some(headers.request_policy_view(http_version)),
        ..Default::default()
    };
    crate::http::policy::rule_context::apply_identity(&mut ctx, identity);
    destination.apply_to_rule_context(&mut ctx);
    ctx
}
