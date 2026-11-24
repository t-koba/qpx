use super::*;
use qpx_core::config::{Config, DestinationResolutionPolicyConfig, NamedSetConfig, NamedSetKind};
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
                services: Vec::new(),
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
        true,
    );
    assert_eq!(openai.category.as_deref(), Some("ai"));
    assert_eq!(openai.category_source, Some("host"));
    assert_eq!(openai.category_confidence, Some(100));
    assert_eq!(openai.application.as_deref(), Some("https"));
    assert_eq!(openai.application_source, Some("heuristic"));
    assert_eq!(openai.application_confidence, Some(40));
    assert_eq!(
        openai.category_trace.as_deref(),
        Some("category(selected=ai@host:100; candidates=ai@host:100)")
    );
    assert_eq!(
        openai.application_trace.as_deref(),
        Some("application(selected=https@heuristic:40; candidates=https@heuristic:40)")
    );

    let malware = classifier.classify(
        &DestinationInputs {
            host: Some("malware.example"),
            port: Some(443),
            ..Default::default()
        },
        &policy,
        true,
    );
    assert_eq!(malware.reputation.as_deref(), Some("high"));
    assert_eq!(malware.reputation_source, Some("host"));
    assert_eq!(malware.reputation_confidence, Some(100));

    let slack = classifier.classify(
        &DestinationInputs {
            host: Some("app.slack.com"),
            port: Some(443),
            alpn: Some("h2"),
            ..Default::default()
        },
        &policy,
        true,
    );
    assert_eq!(slack.application.as_deref(), Some("slack"));
    assert_eq!(slack.application_source, Some("host"));
    assert_eq!(slack.application_confidence, Some(92));

    let dns = classifier.classify(
        &DestinationInputs {
            port: Some(853),
            ..Default::default()
        },
        &policy,
        true,
    );
    assert_eq!(dns.application.as_deref(), Some("dns"));
    assert_eq!(dns.application_source, Some("heuristic"));
    assert_eq!(dns.application_confidence, Some(40));

    let untraced = classifier.classify(
        &DestinationInputs {
            port: Some(443),
            ..Default::default()
        },
        &policy,
        false,
    );
    assert_eq!(untraced.application.as_deref(), Some("https"));
    assert!(untraced.category_trace.is_none());
    assert!(untraced.reputation_trace.is_none());
    assert!(untraced.application_trace.is_none());
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
        true,
    );
    assert_eq!(destination.category.as_deref(), Some("web"));
    assert_eq!(destination.category_source, Some("host"));
    assert_eq!(destination.category_confidence, Some(100));
    assert_eq!(destination.reputation.as_deref(), Some("suspicious"));
    assert_eq!(destination.reputation_source, Some("ip"));
    assert_eq!(destination.reputation_confidence, Some(94));
    assert_eq!(destination.application.as_deref(), Some("chrome"));
    assert_eq!(destination.application_source, Some("ja4"));
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
    let default_policy = CompiledDestinationResolutionPolicy::default();
    let override_policy = default_policy.with_override(Some(
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
        true,
    );
    assert_eq!(destination.category.as_deref(), Some("cert"));
    assert_eq!(destination.category_source, Some("cert_issuer"));
}

#[test]
fn destination_metadata_apply_to_rule_context_maps_nine_fields() {
    let metadata = DestinationMetadata {
        category: Some("web".to_string()),
        category_source: Some("host"),
        category_confidence: Some(100),
        reputation: Some("suspicious".to_string()),
        reputation_source: Some("ip"),
        reputation_confidence: Some(94),
        application: Some(Arc::from("chrome")),
        application_source: Some("ja4"),
        application_confidence: Some(77),
        ..Default::default()
    };
    let mut ctx = qpx_core::rules::RuleMatchContext {
        host: Some("example.com"),
        ..Default::default()
    };
    metadata.apply_to_rule_context(&mut ctx);
    assert_eq!(ctx.destination_category, Some("web"));
    assert_eq!(ctx.destination_category_source, Some("host"));
    assert_eq!(ctx.destination_category_confidence, Some(100u64));
    assert_eq!(ctx.destination_reputation, Some("suspicious"));
    assert_eq!(ctx.destination_reputation_source, Some("ip"));
    assert_eq!(ctx.destination_reputation_confidence, Some(94u64));
    assert_eq!(ctx.destination_application, Some("chrome"));
    assert_eq!(ctx.destination_application_source, Some("ja4"));
    assert_eq!(ctx.destination_application_confidence, Some(77u64));
    assert_eq!(ctx.host, Some("example.com"));
}

#[test]
fn destination_metadata_apply_to_rule_context_leaves_defaults_for_empty() {
    let metadata = DestinationMetadata::default();
    let mut ctx = qpx_core::rules::RuleMatchContext::default();
    metadata.apply_to_rule_context(&mut ctx);
    assert_eq!(ctx.destination_category, None);
    assert_eq!(ctx.destination_category_source, None);
    assert_eq!(ctx.destination_category_confidence, None);
    assert_eq!(ctx.destination_reputation, None);
    assert_eq!(ctx.destination_reputation_source, None);
    assert_eq!(ctx.destination_reputation_confidence, None);
    assert_eq!(ctx.destination_application, None);
    assert_eq!(ctx.destination_application_source, None);
    assert_eq!(ctx.destination_application_confidence, None);
}

#[test]
fn inferred_application_respects_min_confidence_without_named_sets() {
    let mut config = DestinationResolutionPolicyConfig::default();
    config.min_confidence.application = Some(41);
    let policy = CompiledDestinationResolutionPolicy::from_config(&config);
    let inputs = DestinationInputs {
        port: Some(443),
        ..Default::default()
    };

    let result = DestinationClassifier::default().classify(&inputs, &policy, false);
    assert_eq!(result.application, None);
    assert_eq!(result.application_confidence, None);
}

#[test]
fn classifier_matches_cidr_set_for_bracketed_ipv6_host() {
    let mut config = base_config();
    config.security.named_sets = vec![NamedSetConfig {
        name: "category:doc_ipv6".to_string(),
        kind: NamedSetKind::Cidr,
        values: vec!["2001:db8::/32".to_string()],
        file: None,
    }];
    let classifier = DestinationClassifier::from_config(&config).expect("classifier");
    let policy = CompiledDestinationResolutionPolicy::default();

    let destination = classifier.classify(
        &DestinationInputs {
            host: Some("[2001:db8::1]"),
            ip: None,
            port: Some(80),
            ..Default::default()
        },
        &policy,
        true,
    );
    assert_eq!(destination.category.as_deref(), Some("doc_ipv6"));
    assert_eq!(destination.category_source, Some("ip"));
}

#[test]
fn destination_ip_accepts_bracketed_ipv6_host_and_sni() {
    use super::resolve::destination_ip;

    let host = DestinationInputs {
        host: Some("[2001:db8::1]"),
        ip: None,
        ..Default::default()
    };
    assert_eq!(
        destination_ip(&host),
        Some("2001:db8::1".parse::<IpAddr>().expect("ip"))
    );

    let sni = DestinationInputs {
        sni: Some("[2001:db8::2]"),
        ..Default::default()
    };
    assert_eq!(
        destination_ip(&sni),
        Some("2001:db8::2".parse::<IpAddr>().expect("ip"))
    );

    let explicit = DestinationInputs {
        host: Some("[2001:db8::1]"),
        ip: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
        ..Default::default()
    };
    assert_eq!(
        destination_ip(&explicit),
        Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
    );

    let bracketed_name = DestinationInputs {
        host: Some("[example.com]"),
        ..Default::default()
    };
    assert_eq!(destination_ip(&bracketed_name), None);
}

#[test]
fn domain_named_set_compiles_explicit_regex_pattern() {
    let mut config = base_config();
    config.security.named_sets = vec![NamedSetConfig {
        name: "category:explicit-domain-regex".to_string(),
        kind: NamedSetKind::Domain,
        values: vec![r"re:^www\.example\.test$".to_string()],
        file: None,
    }];

    let classifier = DestinationClassifier::from_config(&config).expect("classifier");
    let patterns = &classifier.category[0].patterns;
    assert!(patterns.matches_text("www.example.test"));
}

#[test]
fn domain_named_set_regex_classifies_raw_host() {
    for prefix in ["re:", "RE:"] {
        let mut config = base_config();
        config.security.named_sets = vec![NamedSetConfig {
            name: "category:domain-non-digit".to_string(),
            kind: NamedSetKind::Domain,
            values: vec![format!("{}{}", prefix, r"^api\D+\.example\.test$")],
            file: None,
        }];

        let classifier = DestinationClassifier::from_config(&config).expect("classifier");
        let policy = CompiledDestinationResolutionPolicy::default();
        let matched = classifier.classify(
            &DestinationInputs {
                host: Some("apixyz.example.test"),
                ..Default::default()
            },
            &policy,
            false,
        );
        assert_eq!(
            matched.category.as_deref(),
            Some("domain-non-digit"),
            "prefix {prefix} must classify a non-digit suffix"
        );
        assert_eq!(matched.category_source, Some("host"), "prefix {prefix}");
        assert_eq!(matched.category_confidence, Some(100), "prefix {prefix}");

        let rejected = classifier.classify(
            &DestinationInputs {
                host: Some("api123.example.test"),
                ..Default::default()
            },
            &policy,
            false,
        );
        assert_eq!(
            rejected.category, None,
            "a digit suffix must not be classified by the \\D class with prefix {prefix}"
        );
    }
}

#[test]
fn string_named_set_regex_classifies_raw_string_evidence() {
    for prefix in ["re:", "REGEX:"] {
        let mut config = base_config();
        config.security.named_sets = vec![NamedSetConfig {
            name: "application:upper-token".to_string(),
            kind: NamedSetKind::String,
            values: vec![format!("{}{}", prefix, r"^[A-Z]{3}-\d{4}$")],
            file: None,
        }];

        let classifier = DestinationClassifier::from_config(&config).expect("classifier");
        let policy = CompiledDestinationResolutionPolicy::default();
        let matched = classifier.classify(
            &DestinationInputs {
                cert_issuer: Some("ABC-1234"),
                ..Default::default()
            },
            &policy,
            false,
        );
        assert_eq!(
            matched.application.as_deref(),
            Some("upper-token"),
            "prefix {prefix} must classify lowercased [A-Z] evidence"
        );
        assert_eq!(
            matched.application_source,
            Some("cert_issuer"),
            "prefix {prefix}"
        );
        assert_eq!(matched.application_confidence, Some(76), "prefix {prefix}");

        let rejected = classifier.classify(
            &DestinationInputs {
                cert_issuer: Some("AB1-1234"),
                ..Default::default()
            },
            &policy,
            false,
        );
        assert_eq!(
            rejected.application, None,
            "a digit in the token prefix must not match [A-Z]{{3}} with prefix {prefix}"
        );
    }
}
