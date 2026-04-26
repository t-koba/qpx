use crate::destination::DestinationMetadata;
use crate::http::base_fields::BaseRequestFields;
use crate::http::rpc::RpcMatchContext;
use crate::policy_context::ResolvedIdentity;
use crate::tls::UpstreamCertificateInfo;
use http::HeaderMap;
use qpx_core::rules::RuleMatchContext;
use qpx_observability::access_log::RequestLogContext;

pub(crate) struct RequestRuleContextInput<'a> {
    pub(crate) base: &'a BaseRequestFields,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) destination: &'a DestinationMetadata,
    pub(crate) identity: &'a ResolvedIdentity,
    pub(crate) request_size: Option<u64>,
    pub(crate) rpc: Option<&'a RpcMatchContext>,
    pub(crate) client_cert: Option<&'a UpstreamCertificateInfo>,
    pub(crate) upstream_cert: Option<&'a UpstreamCertificateInfo>,
}

pub(crate) struct ResponseRuleContextInput<'a> {
    pub(crate) base: &'a BaseRequestFields,
    pub(crate) headers: &'a HeaderMap,
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
    ctx.headers = Some(headers);
    ctx.request_size = request_size;
    apply_destination(&mut ctx, destination);
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
    ctx.headers = Some(headers);
    ctx.response_status = Some(response_status);
    ctx.response_size = response_size;
    apply_destination(&mut ctx, destination);
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

fn apply_destination<'a>(ctx: &mut RuleMatchContext<'a>, destination: &'a DestinationMetadata) {
    ctx.destination_category = destination.category.as_deref();
    ctx.destination_category_source = destination.category_source.as_deref();
    ctx.destination_category_confidence = destination.category_confidence.map(u64::from);
    ctx.destination_reputation = destination.reputation.as_deref();
    ctx.destination_reputation_source = destination.reputation_source.as_deref();
    ctx.destination_reputation_confidence = destination.reputation_confidence.map(u64::from);
    ctx.destination_application = destination.application.as_deref();
    ctx.destination_application_source = destination.application_source.as_deref();
    ctx.destination_application_confidence = destination.application_confidence.map(u64::from);
}

fn apply_identity<'a>(ctx: &mut RuleMatchContext<'a>, identity: &'a ResolvedIdentity) {
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
    ctx.rpc_trailers = rpc.trailers.as_ref();
}
