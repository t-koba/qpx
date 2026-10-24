use super::super::destination::ConnectTarget;
use crate::destination::DestinationInputs;
use crate::runtime::Runtime;
use crate::tls::TlsClientHelloInfo;
use anyhow::{Result, anyhow};
use qpx_core::config::ActionConfig;
use qpx_core::rules::RuleMatchContext;
use qpx_core::tls::UpstreamCertificateInfo;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub(super) struct TransparentTlsDecision {
    pub(super) action: ActionConfig,
    pub(super) matched_rule: Option<String>,
    pub(super) auth_required: bool,
}

pub(super) struct TransparentTlsPolicyInput<'a> {
    pub(super) runtime: &'a Runtime,
    pub(super) listener_name: &'a str,
    pub(super) remote_addr: SocketAddr,
    pub(super) connect_target: &'a ConnectTarget,
    pub(super) host_for_match: Option<&'a str>,
    pub(super) sni_for_match: Option<&'a str>,
    pub(super) client_hello: Option<&'a TlsClientHelloInfo>,
    pub(super) identity: &'a crate::policy_context::ResolvedIdentity,
    pub(super) upstream_cert: Option<&'a UpstreamCertificateInfo>,
}

pub(super) fn evaluate_tls_policy_decision(
    input: TransparentTlsPolicyInput<'_>,
) -> Result<TransparentTlsDecision> {
    let TransparentTlsPolicyInput {
        runtime,
        listener_name,
        remote_addr,
        connect_target,
        host_for_match,
        sni_for_match,
        client_hello,
        identity,
        upstream_cert,
    } = input;
    let state = runtime.state();
    let engine = state.policy.rule_engine_for_listener(listener_name)?;
    let base_plan = state
        .plan
        .ingress_edge_execution_plan(listener_name, None)
        .ok_or_else(|| anyhow!("listener plan not found"))?;
    let destination = state.classify_destination(
        &DestinationInputs {
            host: host_for_match,
            ip: host_for_match.and_then(|value| value.parse().ok()),
            sni: sni_for_match,
            scheme: Some("https"),
            port: Some(connect_target.port()),
            alpn: client_hello.and_then(|hello| hello.alpn.as_deref()),
            ja3: client_hello.and_then(|hello| hello.ja3.as_deref()),
            ja4: client_hello.and_then(|hello| hello.ja4.as_deref()),
            cert_subject: upstream_cert.and_then(|cert| cert.subject.as_deref()),
            cert_issuer: upstream_cert.and_then(|cert| cert.issuer.as_deref()),
            cert_san_dns: upstream_cert
                .map(|cert| cert.san_dns.as_slice())
                .unwrap_or(&[]),
            cert_san_uri: upstream_cert
                .map(|cert| cert.san_uri.as_slice())
                .unwrap_or(&[]),
            cert_fingerprint_sha256: upstream_cert
                .and_then(|cert| cert.fingerprint_sha256.as_deref()),
        },
        base_plan.destination_resolution.as_ref(),
    );
    let mut ctx = RuleMatchContext {
        src_ip: Some(remote_addr.ip()),
        dst_port: Some(connect_target.port()),
        host: host_for_match,
        sni: sni_for_match,
        method: None,
        path: None,
        alpn: client_hello.and_then(|hello| hello.alpn.as_deref()),
        tls_version: client_hello.and_then(|hello| hello.tls_version.as_deref()),
        ja3: client_hello.and_then(|hello| hello.ja3.as_deref()),
        ja4: client_hello.and_then(|hello| hello.ja4.as_deref()),
        headers: None,
        upstream_cert_present: upstream_cert.map(|cert| cert.present),
        upstream_cert_subject: upstream_cert.and_then(|cert| cert.subject.as_deref()),
        upstream_cert_issuer: upstream_cert.and_then(|cert| cert.issuer.as_deref()),
        upstream_cert_san_dns: upstream_cert
            .map(|cert| cert.san_dns.as_slice())
            .unwrap_or(&[]),
        upstream_cert_san_uri: upstream_cert
            .map(|cert| cert.san_uri.as_slice())
            .unwrap_or(&[]),
        upstream_cert_fingerprint_sha256: upstream_cert
            .and_then(|cert| cert.fingerprint_sha256.as_deref()),
        ..Default::default()
    };
    crate::http::policy::rule_context::apply_identity(&mut ctx, identity);
    destination.apply_to_rule_context(&mut ctx);
    let outcome = engine.evaluate_ref(&ctx);
    Ok(TransparentTlsDecision {
        action: outcome.action.clone(),
        matched_rule: outcome.matched_rule.map(str::to_string),
        auth_required: outcome
            .auth
            .map(|auth| !auth.require.is_empty())
            .unwrap_or(false),
    })
}
