use crate::destination::DestinationInputs;
use crate::forward::policy::{ForwardPolicyDecision, evaluate_forward_policy};
use crate::runtime::Runtime;
use crate::tls::TlsClientHelloInfo;
use anyhow::{Result, anyhow};
use qpx_core::config::{ActionConfig, ActionKind};
use qpx_core::http_message::Headers;
use qpx_core::rules::RuleMatchContext;
#[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
use qpx_core::tls::CompiledUpstreamTlsTrust;
use qpx_core::tls::UpstreamCertificateInfo;
use std::net::SocketAddr;

pub(in crate::forward) struct ConnectPolicyInput<'a> {
    pub runtime: &'a Runtime,
    pub listener_name: &'a str,
    pub remote_addr: SocketAddr,
    pub host: &'a str,
    pub port: u16,
    pub authority: &'a str,
    pub request_version: http::Version,
    pub sanitized_headers: &'a Headers,
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
    let base_plan = state
        .plan
        .ingress_edge_execution_plan(input.listener_name, None)
        .ok_or_else(|| anyhow!("listener plan not found"))?;
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
        base_plan.destination_resolution.as_ref(),
    );
    let mut ctx = RuleMatchContext {
        src_ip: Some(input.remote_addr.ip()),
        dst_port: Some(input.port),
        host: Some(input.host),
        sni: Some(input.client_hello.sni.as_deref().unwrap_or(input.host)),
        method: Some("CONNECT"),
        authority: Some(input.authority),
        scheme: Some("https"),
        alpn: input.client_hello.alpn.as_deref(),
        tls_version: input.client_hello.tls_version.as_deref(),
        ja3: input.client_hello.ja3.as_deref(),
        ja4: input.client_hello.ja4.as_deref(),
        owned_headers: Some(
            input
                .sanitized_headers
                .request_policy_view(input.request_version),
        ),
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
    crate::http::policy::rule_context::apply_identity(&mut ctx, input.identity);
    destination.apply_to_rule_context(&mut ctx);
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
        #[cfg(feature = "auth-basic")]
        ForwardPolicyDecision::Challenge(_) | ForwardPolicyDecision::Forbidden => {
            Ok(ActionConfig {
                kind: ActionKind::Block,
                upstream: None,
                local_response: None,
            })
        }
    }
}

#[cfg(all(feature = "http3", feature = "http3-backend-qpx"))]
pub(in crate::forward) fn listener_upstream_tls_settings(
    state: &crate::runtime::RuntimeState,
    listener_name: &str,
    host: &str,
) -> Result<(bool, Option<std::sync::Arc<CompiledUpstreamTlsTrust>>)> {
    let listener_cfg = state
        .ingress_edge_settings(listener_name)
        .ok_or_else(|| anyhow!("listener not found"))?;
    let trust = listener_cfg.upstream_tls_trust();
    let verify_upstream = state.tls_verify_upstream(Some(listener_cfg), listener_name, host);
    Ok((verify_upstream, trust))
}
