use crate::destination::DestinationMetadata;
use crate::http::protocol::base_fields::BaseRequestFields;
use crate::http::rpc::RpcMatchContext;
use crate::policy_context::ResolvedIdentity;
use http::HeaderMap;
use qpx_core::rules::RuleMatchContext;
use qpx_core::tls::UpstreamCertificateInfo;
use qpx_observability::access_log::RequestLogContext;

pub(crate) struct RequestRuleContextInput<'a> {
    pub(crate) base: &'a BaseRequestFields,
    pub(crate) headers: &'a qpx_core::http_message::Headers,
    pub(crate) destination: &'a DestinationMetadata,
    pub(crate) identity: &'a ResolvedIdentity,
    pub(crate) request_size: Option<u64>,
    pub(crate) rpc: Option<&'a RpcMatchContext>,
    pub(crate) client_cert: Option<&'a UpstreamCertificateInfo>,
    pub(crate) upstream_cert: Option<&'a UpstreamCertificateInfo>,
}

pub(crate) struct ResponseRuleContextInput<'a> {
    pub(crate) base: &'a BaseRequestFields,
    pub(crate) headers: Option<&'a HeaderMap>,
    pub(crate) destination: &'a DestinationMetadata,
    pub(crate) identity: &'a ResolvedIdentity,
    pub(crate) response_status: u16,
    pub(crate) response_size: Option<u64>,
    pub(crate) rpc: Option<&'a RpcMatchContext>,
    pub(crate) client_cert: Option<&'a UpstreamCertificateInfo>,
    pub(crate) upstream_cert: Option<&'a UpstreamCertificateInfo>,
}

pub(crate) fn build_request_rule_match_context(
    input: RequestRuleContextInput<'_>,
) -> RuleMatchContext<'_> {
    let RequestRuleContextInput {
        base,
        headers,
        destination,
        identity,
        request_size,
        rpc,
        client_cert,
        upstream_cert,
    } = input;
    let mut ctx = base.rule_match_context();
    ctx.headers = None;
    ctx.owned_headers = Some(headers.request_policy_view(base.version));
    ctx.request_size = request_size;
    destination.apply_to_rule_context(&mut ctx);
    apply_identity(&mut ctx, identity);
    apply_client_cert(&mut ctx, client_cert);
    apply_upstream_cert(&mut ctx, upstream_cert);
    if let Some(rpc) = rpc {
        apply_rpc(&mut ctx, rpc);
    }
    ctx
}

pub(crate) fn build_response_rule_match_context(
    input: ResponseRuleContextInput<'_>,
) -> RuleMatchContext<'_> {
    let ResponseRuleContextInput {
        base,
        headers,
        destination,
        identity,
        response_status,
        response_size,
        rpc,
        client_cert,
        upstream_cert,
    } = input;
    let mut ctx = base.rule_match_context();
    ctx.headers = headers.map(qpx_core::http_content_length::HeaderView::new);
    ctx.response_status = Some(response_status);
    ctx.response_size = response_size;
    destination.apply_to_rule_context(&mut ctx);
    apply_identity(&mut ctx, identity);
    apply_client_cert(&mut ctx, client_cert);
    apply_upstream_cert(&mut ctx, upstream_cert);
    if let Some(rpc) = rpc {
        apply_rpc(&mut ctx, rpc);
    }
    ctx
}

pub(crate) fn attach_destination_trace(
    log_context: &mut RequestLogContext,
    destination: &DestinationMetadata,
) {
    log_context.destination_trace = destination.decision_trace();
}

pub(crate) fn apply_identity<'a>(ctx: &mut RuleMatchContext<'a>, identity: &'a ResolvedIdentity) {
    ctx.user = identity.user.as_deref();
    ctx.user_groups = &identity.groups;
    ctx.device_id = identity.device_id.as_deref();
    ctx.posture = &identity.posture;
    ctx.tenant = identity.tenant.as_deref();
    ctx.auth_strength = identity.auth_strength.as_deref();
    ctx.idp = identity.idp.as_deref();
}

fn apply_client_cert<'a>(
    ctx: &mut RuleMatchContext<'a>,
    client_cert: Option<&'a UpstreamCertificateInfo>,
) {
    ctx.client_cert_present = client_cert.map(|cert| cert.present);
    ctx.client_cert_subject = client_cert.and_then(|cert| cert.subject.as_deref());
    ctx.client_cert_issuer = client_cert.and_then(|cert| cert.issuer.as_deref());
    ctx.client_cert_san_dns = client_cert
        .map(|cert| cert.san_dns.as_slice())
        .unwrap_or(&[]);
    ctx.client_cert_san_uri = client_cert
        .map(|cert| cert.san_uri.as_slice())
        .unwrap_or(&[]);
    ctx.client_cert_fingerprint_sha256 =
        client_cert.and_then(|cert| cert.fingerprint_sha256.as_deref());
}

fn apply_upstream_cert<'a>(
    ctx: &mut RuleMatchContext<'a>,
    upstream_cert: Option<&'a UpstreamCertificateInfo>,
) {
    ctx.upstream_cert_present = upstream_cert.map(|cert| cert.present);
    ctx.upstream_cert_subject = upstream_cert.and_then(|cert| cert.subject.as_deref());
    ctx.upstream_cert_issuer = upstream_cert.and_then(|cert| cert.issuer.as_deref());
    ctx.upstream_cert_san_dns = upstream_cert
        .map(|cert| cert.san_dns.as_slice())
        .unwrap_or(&[]);
    ctx.upstream_cert_san_uri = upstream_cert
        .map(|cert| cert.san_uri.as_slice())
        .unwrap_or(&[]);
    ctx.upstream_cert_fingerprint_sha256 =
        upstream_cert.and_then(|cert| cert.fingerprint_sha256.as_deref());
}

fn apply_rpc<'a>(ctx: &mut RuleMatchContext<'a>, rpc: &'a RpcMatchContext) {
    ctx.rpc_protocol = rpc.protocol.as_deref();
    ctx.rpc_service = rpc.service.as_deref();
    ctx.rpc_method = rpc.method.as_deref();
    ctx.rpc_streaming = rpc.streaming.as_deref();
    ctx.rpc_status = rpc.status.as_deref();
    ctx.rpc_message_size = rpc.message_size;
    ctx.rpc_message = rpc.message.as_deref();
    ctx.rpc_trailers = rpc
        .trailers
        .as_ref()
        .map(qpx_core::http_content_length::HeaderView::new);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie_engine(value: Option<&str>, regex: Option<&str>) -> qpx_core::rules::RuleEngine {
        use qpx_core::config::{ActionConfig, ActionKind, HeaderMatch, MatchConfig, RuleConfig};
        let rule = RuleConfig {
            name: "cookie".into(),
            r#match: Some(MatchConfig {
                headers: vec![HeaderMatch {
                    name: "cookie".into(),
                    value: value.map(str::to_owned),
                    regex: regex.map(str::to_owned),
                }],
                ..Default::default()
            }),
            auth: None,
            action: None,
            headers: None,
            rate_limit: None,
        };
        qpx_core::rules::RuleEngine::new(
            vec![rule],
            ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
        )
        .expect("compile rule")
    }

    #[test]
    fn request_cookie_rules_use_decoded_protocol_without_mutating_headers() {
        use crate::http::protocol::base_fields::{BaseRequestContext, extract_base_request_fields};
        use http::{HeaderValue, Version};
        use qpx_core::http_message::{OrdinaryHeaderName, Request};

        let exact = cookie_engine(Some("a=1; b=2"), None);
        let regex = cookie_engine(None, Some("^a=1; b=2$"));
        let fragment = cookie_engine(Some("a=1"), None);
        let present = cookie_engine(None, None);
        let name = OrdinaryHeaderName::try_from(http::header::COOKIE).unwrap();
        let destination = DestinationMetadata::default();
        let identity = ResolvedIdentity::default();
        for version in [Version::HTTP_11, Version::HTTP_2, Version::HTTP_3] {
            for fields in [
                [b"a=1".as_slice(), b"b=2".as_slice()],
                [b"".as_slice(), b"".as_slice()],
                [b"a=1".as_slice(), b"\xff".as_slice()],
            ] {
                let mut raw = http::Request::builder()
                    .version(version)
                    .uri("/")
                    .body(())
                    .unwrap();
                for (index, field) in fields.iter().enumerate() {
                    let mut value = HeaderValue::from_bytes(field).unwrap();
                    value.set_sensitive(index == 0);
                    raw.headers_mut().append(http::header::COOKIE, value);
                }
                let req = Request::from_http(raw);
                let original: Vec<_> = req
                    .headers()
                    .get_all(&name)
                    .map(|v| (v.as_bytes().to_vec(), v.is_sensitive()))
                    .collect();
                let base = extract_base_request_fields(&req, BaseRequestContext::default());
                let ctx = build_request_rule_match_context(RequestRuleContextInput {
                    base: &base,
                    headers: req.headers(),
                    destination: &destination,
                    identity: &identity,
                    request_size: None,
                    rpc: None,
                    client_cert: None,
                    upstream_cert: None,
                });
                let matches = |engine: &qpx_core::rules::RuleEngine| {
                    engine.evaluate_ref(&ctx).matched_rule.is_some()
                };
                let joined = fields[1] == b"b=2" && version != Version::HTTP_11;
                assert_eq!(matches(&exact), joined, "{version:?} {fields:?}");
                assert_eq!(matches(&regex), joined, "{version:?} {fields:?}");
                assert_eq!(
                    matches(&fragment),
                    version == Version::HTTP_11 && fields[0] == b"a=1",
                    "{version:?} {fields:?}"
                );
                let expected_present = if version == Version::HTTP_11 {
                    true
                } else {
                    fields[1] == b"b=2" || (version == Version::HTTP_3 && fields[0].is_empty())
                };
                assert_eq!(
                    matches(&present),
                    expected_present,
                    "{version:?} {fields:?}"
                );
                let after: Vec<_> = req
                    .headers()
                    .get_all(&name)
                    .map(|v| (v.as_bytes().to_vec(), v.is_sensitive()))
                    .collect();
                assert_eq!(after, original);
            }
        }
    }

    #[test]
    fn apply_identity_maps_all_seven_fields() {
        let identity = ResolvedIdentity {
            user: Some("alice".to_string()),
            groups: vec!["eng".to_string(), "ops".to_string()],
            device_id: Some("device-1".to_string()),
            posture: vec!["healthy".to_string()],
            tenant: Some("tenant-a".to_string()),
            auth_strength: Some("mfa".to_string()),
            idp: Some("example-idp".to_string()),
            ..ResolvedIdentity::default()
        };
        let mut ctx = RuleMatchContext::default();
        apply_identity(&mut ctx, &identity);
        assert_eq!(ctx.user, Some("alice"));
        assert_eq!(ctx.user_groups, &["eng".to_string(), "ops".to_string()]);
        assert_eq!(ctx.device_id, Some("device-1"));
        assert_eq!(ctx.posture, &["healthy".to_string()]);
        assert_eq!(ctx.tenant, Some("tenant-a"));
        assert_eq!(ctx.auth_strength, Some("mfa"));
        assert_eq!(ctx.idp, Some("example-idp"));
    }
}
