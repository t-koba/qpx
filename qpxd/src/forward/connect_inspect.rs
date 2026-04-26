use super::*;

pub(in crate::forward) struct ConnectPolicyInput<'a> {
    pub runtime: &'a Runtime,
    pub listener_name: &'a str,
    pub remote_addr: SocketAddr,
    pub host: &'a str,
    pub port: u16,
    pub authority: &'a str,
    pub sanitized_headers: &'a HeaderMap,
    pub identity: &'a crate::policy_context::ResolvedIdentity,
    pub client_hello: &'a TlsClientHelloInfo,
    pub upstream_cert: Option<&'a UpstreamCertificateInfo>,
}

pub(in crate::forward) async fn decide_connect_action_from_client_hello(
    input: ConnectPolicyInput<'_>,
) -> Result<ActionConfig> {
    decide_connect_action_from_tls_metadata(ConnectPolicyInput {
        upstream_cert: None,
        ..input
    })
    .await
}

pub(in crate::forward) async fn decide_connect_action_from_tls_metadata(
    input: ConnectPolicyInput<'_>,
) -> Result<ActionConfig> {
    let state = input.runtime.state();
    let resolution_override = state
        .listener_config(input.listener_name)
        .and_then(|cfg| cfg.destination_resolution.as_ref());
    let destination = state.classify_destination(
        &DestinationInputs {
            host: Some(input.host),
            ip: input.host.parse().ok(),
            sni: input.client_hello.sni.as_deref().or(Some(input.host)),
            scheme: Some("https"),
            port: Some(input.port),
            alpn: input.client_hello.alpn.as_deref(),
            ja3: input.client_hello.ja3.as_deref(),
            ja4: input.client_hello.ja4.as_deref(),
            cert_subject: input.upstream_cert.and_then(|cert| cert.subject.as_deref()),
            cert_issuer: input.upstream_cert.and_then(|cert| cert.issuer.as_deref()),
            cert_san_dns: input
                .upstream_cert
                .map(|cert| cert.san_dns.as_slice())
                .unwrap_or(&[]),
            cert_san_uri: input
                .upstream_cert
                .map(|cert| cert.san_uri.as_slice())
                .unwrap_or(&[]),
            cert_fingerprint_sha256: input
                .upstream_cert
                .and_then(|cert| cert.fingerprint_sha256.as_deref()),
        },
        resolution_override,
    );
    let ctx = RuleMatchContext {
        src_ip: Some(input.remote_addr.ip()),
        dst_port: Some(input.port),
        host: Some(input.host),
        sni: Some(input.client_hello.sni.as_deref().unwrap_or(input.host)),
        method: Some("CONNECT"),
        authority: Some(input.authority),
        scheme: Some("https"),
        alpn: input.client_hello.alpn.as_deref(),
        tls_version: input.client_hello.tls_version.as_deref(),
        destination_category: destination.category.as_deref(),
        destination_category_source: destination.category_source.as_deref(),
        destination_category_confidence: destination.category_confidence.map(u64::from),
        destination_reputation: destination.reputation.as_deref(),
        destination_reputation_source: destination.reputation_source.as_deref(),
        destination_reputation_confidence: destination.reputation_confidence.map(u64::from),
        destination_application: destination.application.as_deref(),
        destination_application_source: destination.application_source.as_deref(),
        destination_application_confidence: destination.application_confidence.map(u64::from),
        ja3: input.client_hello.ja3.as_deref(),
        ja4: input.client_hello.ja4.as_deref(),
        headers: Some(input.sanitized_headers),
        user: input.identity.user.as_deref(),
        user_groups: &input.identity.groups,
        device_id: input.identity.device_id.as_deref(),
        posture: &input.identity.posture,
        tenant: input.identity.tenant.as_deref(),
        auth_strength: input.identity.auth_strength.as_deref(),
        idp: input.identity.idp.as_deref(),
        upstream_cert_present: input.upstream_cert.map(|cert| cert.present),
        upstream_cert_subject: input.upstream_cert.and_then(|cert| cert.subject.as_deref()),
        upstream_cert_issuer: input.upstream_cert.and_then(|cert| cert.issuer.as_deref()),
        upstream_cert_san_dns: input
            .upstream_cert
            .map(|cert| cert.san_dns.as_slice())
            .unwrap_or(&[]),
        upstream_cert_san_uri: input
            .upstream_cert
            .map(|cert| cert.san_uri.as_slice())
            .unwrap_or(&[]),
        upstream_cert_fingerprint_sha256: input
            .upstream_cert
            .and_then(|cert| cert.fingerprint_sha256.as_deref()),
        ..Default::default()
    };
    match evaluate_forward_policy(
        input.runtime,
        input.listener_name,
        ctx,
        input.sanitized_headers,
        "CONNECT",
        input.authority,
    )
    .await?
    {
        ForwardPolicyDecision::Allow(allowed) => Ok(match allowed.action.kind {
            ActionKind::Respond => ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            },
            _ => allowed.action,
        }),
        ForwardPolicyDecision::Challenge(_) | ForwardPolicyDecision::Forbidden => {
            Ok(ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            })
        }
    }
}

pub(in crate::forward) fn listener_uses_upstream_cert_match(listener_cfg: &ListenerConfig) -> bool {
    listener_cfg.rules.iter().any(|rule| {
        rule.r#match
            .as_ref()
            .and_then(|m| m.upstream_cert.as_ref())
            .is_some()
    })
}

pub(in crate::forward) fn listener_upstream_trust(
    listener_cfg: &ListenerConfig,
) -> Result<Option<std::sync::Arc<CompiledUpstreamTlsTrust>>> {
    CompiledUpstreamTlsTrust::from_config(
        listener_cfg
            .tls_inspection
            .as_ref()
            .and_then(|cfg| cfg.upstream_trust.as_ref()),
    )
}

pub(in crate::forward) fn listener_requires_upstream_cert_preview(
    listener_cfg: &ListenerConfig,
) -> bool {
    listener_uses_upstream_cert_match(listener_cfg)
        || listener_cfg
            .tls_inspection
            .as_ref()
            .and_then(|cfg| cfg.upstream_trust.as_ref())
            .is_some()
}
