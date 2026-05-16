mod compile;
mod resolve;

pub(crate) use compile::DestinationClassifier;
pub(crate) use resolve::CompiledDestinationResolutionPolicy;

use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationMetadata {
    pub(crate) category: Option<String>,
    pub(crate) category_source: Option<String>,
    pub(crate) category_confidence: Option<u8>,
    pub(crate) reputation: Option<String>,
    pub(crate) reputation_source: Option<String>,
    pub(crate) reputation_confidence: Option<u8>,
    pub(crate) application: Option<String>,
    pub(crate) application_source: Option<String>,
    pub(crate) application_confidence: Option<u8>,
    pub(crate) category_trace: Option<String>,
    pub(crate) reputation_trace: Option<String>,
    pub(crate) application_trace: Option<String>,
}

impl DestinationMetadata {
    pub(crate) fn decision_trace(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(trace) = self.category_trace.as_deref() {
            parts.push(trace.to_string());
        }
        if let Some(trace) = self.reputation_trace.as_deref() {
            parts.push(trace.to_string());
        }
        if let Some(trace) = self.application_trace.as_deref() {
            parts.push(trace.to_string());
        }
        (!parts.is_empty()).then(|| parts.join(" | "))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationInputs<'a> {
    pub(crate) host: Option<&'a str>,
    pub(crate) ip: Option<IpAddr>,
    pub(crate) sni: Option<&'a str>,
    pub(crate) scheme: Option<&'a str>,
    pub(crate) port: Option<u16>,
    pub(crate) alpn: Option<&'a str>,
    pub(crate) ja3: Option<&'a str>,
    pub(crate) ja4: Option<&'a str>,
    pub(crate) cert_subject: Option<&'a str>,
    pub(crate) cert_issuer: Option<&'a str>,
    pub(crate) cert_san_dns: &'a [String],
    pub(crate) cert_san_uri: &'a [String],
    pub(crate) cert_fingerprint_sha256: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use qpx_core::config::{Config, NamedSetConfig, NamedSetKind};
    use std::net::{IpAddr, Ipv4Addr};

    fn base_config() -> Config {
        Config {
            state_dir: None,
            identity: Default::default(),
            messages: Default::default(),
            runtime: Default::default(),
            telemetry: qpx_core::config::TelemetryConfig {
                system_log: Default::default(),
                access_log: Default::default(),
                audit_log: Default::default(),
                metrics: None,
                otel: None,
                exporter: None,
            },
            security: qpx_core::config::SecurityConfig {
                auth: Default::default(),
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
            edges: Vec::new(),
            upstreams: Vec::new(),
            caches: Vec::new(),
        }
    }

    #[test]
    fn classifier_uses_prefixed_named_sets_and_application_heuristics() {
        let mut config = base_config();
        config.security.named_sets = vec![
            NamedSetConfig {
                name: "category:ai".to_string(),
                kind: NamedSetKind::Domain,
                values: vec!["*.openai.com".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "reputation/high".to_string(),
                kind: NamedSetKind::Regex,
                values: vec![r"(^|\.)malware\.example$".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "application:slack".to_string(),
                kind: NamedSetKind::String,
                values: vec!["*.slack.com".to_string()],
                file: None,
            },
        ];

        let classifier = DestinationClassifier::from_config(&config).expect("classifier");
        let policy = CompiledDestinationResolutionPolicy::default();
        let openai = classifier.classify(
            &DestinationInputs {
                host: Some("api.openai.com"),
                scheme: Some("https"),
                port: Some(443),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(openai.category.as_deref(), Some("ai"));
        assert_eq!(openai.category_source.as_deref(), Some("host"));
        assert_eq!(openai.category_confidence, Some(100));
        assert_eq!(openai.application.as_deref(), Some("https"));
        assert_eq!(openai.application_source.as_deref(), Some("heuristic"));
        assert_eq!(openai.application_confidence, Some(40));

        let malware = classifier.classify(
            &DestinationInputs {
                host: Some("malware.example"),
                port: Some(443),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(malware.reputation.as_deref(), Some("high"));
        assert_eq!(malware.reputation_source.as_deref(), Some("host"));
        assert_eq!(malware.reputation_confidence, Some(100));

        let slack = classifier.classify(
            &DestinationInputs {
                host: Some("app.slack.com"),
                port: Some(443),
                alpn: Some("h2"),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(slack.application.as_deref(), Some("slack"));
        assert_eq!(slack.application_source.as_deref(), Some("host"));
        assert_eq!(slack.application_confidence, Some(92));

        let dns = classifier.classify(
            &DestinationInputs {
                port: Some(853),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(dns.application.as_deref(), Some("dns"));
        assert_eq!(dns.application_source.as_deref(), Some("heuristic"));
        assert_eq!(dns.application_confidence, Some(40));
    }

    #[test]
    fn classifier_uses_ip_sni_cert_and_fingerprint_precedence() {
        let mut config = base_config();
        config.security.named_sets = vec![
            NamedSetConfig {
                name: "category:corp".to_string(),
                kind: NamedSetKind::String,
                values: vec!["corp issuer".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "category:web".to_string(),
                kind: NamedSetKind::Domain,
                values: vec!["api.example.com".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "reputation:suspicious".to_string(),
                kind: NamedSetKind::Cidr,
                values: vec!["203.0.113.0/24".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "application:chrome".to_string(),
                kind: NamedSetKind::String,
                values: vec!["ja4-chrome".to_string()],
                file: None,
            },
        ];
        let classifier = DestinationClassifier::from_config(&config).expect("classifier");
        let policy = CompiledDestinationResolutionPolicy::default();
        let cert_san_dns = vec!["download.example.com".to_string()];
        let destination = classifier.classify(
            &DestinationInputs {
                host: Some("api.example.com"),
                ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
                sni: Some("download.example.com"),
                ja4: Some("ja4-chrome"),
                cert_issuer: Some("Corp Issuer"),
                cert_san_dns: cert_san_dns.as_slice(),
                ..Default::default()
            },
            &policy,
        );
        assert_eq!(destination.category.as_deref(), Some("web"));
        assert_eq!(destination.category_source.as_deref(), Some("host"));
        assert_eq!(destination.category_confidence, Some(100));
        assert_eq!(destination.reputation.as_deref(), Some("suspicious"));
        assert_eq!(destination.reputation_source.as_deref(), Some("ip"));
        assert_eq!(destination.reputation_confidence, Some(94));
        assert_eq!(destination.application.as_deref(), Some("chrome"));
        assert_eq!(destination.application_source.as_deref(), Some("ja4"));
        assert_eq!(destination.application_confidence, Some(100));
    }

    #[test]
    fn resolution_override_can_prefer_certificate_evidence() {
        let mut config = base_config();
        config.security.named_sets = vec![
            NamedSetConfig {
                name: "category:host".to_string(),
                kind: NamedSetKind::Domain,
                values: vec!["api.example.com".to_string()],
                file: None,
            },
            NamedSetConfig {
                name: "category:cert".to_string(),
                kind: NamedSetKind::String,
                values: vec!["corp issuer".to_string()],
                file: None,
            },
        ];
        let classifier = DestinationClassifier::from_config(&config).expect("classifier");
        let override_policy = CompiledDestinationResolutionPolicy::default().with_override(Some(
            &qpx_core::config::DestinationResolutionOverrideConfig {
                precedence: Some(vec![
                    qpx_core::config::DestinationEvidenceSourceKind::Cert,
                    qpx_core::config::DestinationEvidenceSourceKind::Host,
                ]),
                conflict_mode: Some(qpx_core::config::DestinationConflictMode::PreferPrecedence),
                merge_mode: None,
                min_confidence: None,
            },
        ));
        let destination = classifier.classify(
            &DestinationInputs {
                host: Some("api.example.com"),
                cert_issuer: Some("Corp Issuer"),
                ..Default::default()
            },
            &override_policy,
        );
        assert_eq!(destination.category.as_deref(), Some("cert"));
        assert_eq!(destination.category_source.as_deref(), Some("cert_issuer"));
    }
}
