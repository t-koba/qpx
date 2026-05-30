use super::policy::{TransparentTlsPolicyInput, evaluate_tls_policy_decision};
use super::*;
use qpx_core::config::{
    AccessLogConfig, AuditLogConfig, AuthConfig, CertificateMatchConfig, Config, IdentityConfig,
    IngressEdgeConfig, IngressEdgeMode, MatchConfig, MessagesConfig, RuleConfig, RuntimeConfig,
    SystemLogConfig, TlsInspectionConfig,
};

fn tls_runtime(rules: Vec<RuleConfig>) -> Runtime {
    #[cfg(feature = "tls-rustls")]
    qpx_core::tls::init_rustls_crypto_provider();

    Runtime::new(Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig::default(),
        telemetry: qpx_core::config::TelemetryConfig {
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: qpx_core::config::SecurityConfig {
            auth: AuthConfig::default(),
            identity_sources: Vec::new(),
            decisions: qpx_core::config::DecisionConfig {
                ext_authz: Vec::new(),
            },
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
        traffic: qpx_core::config::TrafficConfig::default(),
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
            name: "transparent".to_string(),
            mode: IngressEdgeMode::Transparent,
            listen: "127.0.0.1:18443".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Tunnel,
                upstream: None,
                local_response: None,
            },
            original_dst: None,
            tls_inspection: Some(TlsInspectionConfig {
                enabled: true,
                ca: None,
                verify_upstream: false,
                verify_exceptions: Vec::new(),
                upstream_trust_profile: None,
                upstream_trust: None,
            }),
            rules,
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: None,
            upstream_proxy: None,
            http3: None,
            ftp: qpx_core::config::FtpConfig::default(),
            xdp: None,
            cache: None,
            capture: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime")
}

#[test]
fn upstream_cert_match_can_force_block_before_mitm() {
    let runtime = tls_runtime(vec![RuleConfig {
        name: "block-bad-issuer".to_string(),
        r#match: Some(MatchConfig {
            upstream_cert: Some(CertificateMatchConfig {
                issuer: vec!["Bad Issuer".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        auth: None,
        action: Some(ActionConfig {
            kind: ActionKind::Block,
            upstream: None,
            local_response: None,
        }),
        headers: None,
        rate_limit: None,
    }]);
    let client_hello = TlsClientHelloInfo {
        sni: Some("example.com".to_string()),
        alpn: Some("h2".to_string()),
        tls_version: Some("TLS1.3".to_string()),
        ja3: Some("ja3".to_string()),
        ja4: Some("ja4".to_string()),
    };
    let identity = crate::policy_context::ResolvedIdentity::default();
    let upstream_cert = UpstreamCertificateInfo {
        present: true,
        issuer: Some("Bad Issuer".to_string()),
        ..Default::default()
    };
    let target = ConnectTarget::HostPort("example.com".to_string(), 443);
    let decision = evaluate_tls_policy_decision(TransparentTlsPolicyInput {
        runtime: &runtime,
        listener_name: "transparent",
        remote_addr: "127.0.0.1:44321".parse().expect("remote"),
        connect_target: &target,
        host_for_match: Some("example.com"),
        sni_for_match: Some("example.com"),
        client_hello: Some(&client_hello),
        identity: &identity,
        upstream_cert: Some(&upstream_cert),
    })
    .expect("decision");
    assert_eq!(decision.action.kind, ActionKind::Block);
    assert_eq!(decision.matched_rule.as_deref(), Some("block-bad-issuer"));
}

#[test]
fn resolve_tls_connect_target_uses_sni_when_original_target_is_missing() {
    let (target, sni) = resolve_tls_connect_target(
        None,
        Some(&TlsClientHelloInfo {
            sni: Some("example.com".to_string()),
            alpn: Some("h2".to_string()),
            tls_version: Some("TLS1.3".to_string()),
            ja3: None,
            ja4: None,
        }),
    )
    .expect("target");
    assert!(matches!(target, ConnectTarget::HostPort(ref host, 443) if host == "example.com"));
    assert_eq!(sni.as_deref(), Some("example.com"));
}

#[test]
fn resolve_tls_connect_target_prefers_original_target_over_sni() {
    let (target, sni) = resolve_tls_connect_target(
        Some(ConnectTarget::Socket(
            "127.0.0.1:18443".parse().expect("socket"),
        )),
        Some(&TlsClientHelloInfo {
            sni: Some("example.com".to_string()),
            alpn: None,
            tls_version: None,
            ja3: None,
            ja4: None,
        }),
    )
    .expect("target");
    assert!(matches!(target, ConnectTarget::Socket(addr) if addr.port() == 18443));
    assert_eq!(sni.as_deref(), Some("example.com"));
}
