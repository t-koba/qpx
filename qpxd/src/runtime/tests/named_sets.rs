use super::*;

#[test]
fn expand_named_sets_in_listener_rules() {
    let mut config = base_config();
    config.security.named_sets = vec![
        NamedSetConfig {
            name: "corp_domains".to_string(),
            kind: NamedSetKind::Domain,
            values: vec!["*.corp.example".to_string(), "api.internal".to_string()],
            file: None,
        },
        NamedSetConfig {
            name: "internal_paths".to_string(),
            kind: NamedSetKind::Regex,
            values: vec!["^/internal/.*$".to_string()],
            file: None,
        },
    ];
    push_ingress(
        &mut config,
        IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:18080".to_string(),
            default_action: allow_action(),
            original_dst: None,
            tls_inspection: None,
            rules: vec![RuleConfig {
                name: "allow corp".to_string(),
                r#match: Some(MatchConfig {
                    host: vec!["@corp_domains".to_string()],
                    path: vec!["set:internal_paths".to_string()],
                    ..Default::default()
                }),
                auth: None,
                action: Some(allow_action()),
                headers: None,
                rate_limit: None,
            }],
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            capture: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        },
    );

    expand_named_sets_in_config(&mut config).expect("expand named sets");

    let rule_match = ingress(&config, 0).rules[0]
        .r#match
        .as_ref()
        .expect("match");
    assert_eq!(
        rule_match.host,
        vec!["*.corp.example".to_string(), "api.internal".to_string()]
    );
    assert_eq!(rule_match.path, vec!["re:^/internal/.*$".to_string()]);
}

#[test]
fn expand_named_sets_from_external_feed_files() {
    let cidr_file = temp_named_set_file("cidr", "10.0.0.0/8\n# comment\n192.168.0.0/16\n");
    let sni_file = temp_named_set_file("sni", "example.com\n*.corp.example\n");
    let mut config = base_config();
    config.security.named_sets = vec![
        NamedSetConfig {
            name: "office_cidrs".to_string(),
            kind: NamedSetKind::Cidr,
            values: Vec::new(),
            file: Some(cidr_file.display().to_string()),
        },
        NamedSetConfig {
            name: "tls_sni".to_string(),
            kind: NamedSetKind::Domain,
            values: Vec::new(),
            file: Some(sni_file.display().to_string()),
        },
    ];
    config
        .edges
        .push(qpx_core::config::EdgeConfig::Reverse(ReverseEdgeConfig {
            name: "rev".to_string(),
            listen: "127.0.0.1:19090".to_string(),
            tls: None,
            http3: None,
            xdp: None,
            enforce_sni_host_match: false,
            sni_host_exceptions: Vec::new(),
            policy_context: None,
            destination_resolution: None,
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            routes: vec![ReverseRouteConfig {
                name: Some("http".to_string()),
                r#match: MatchConfig {
                    src_ip: vec!["@office_cidrs".to_string()],
                    ..Default::default()
                },
                target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
                    upstreams: vec!["http://127.0.0.1:8080".to_string()],
                    lb: "round_robin".to_string(),
                },
                mirrors: Vec::new(),
                headers: None,
                timeout_ms: None,
                health_check: None,
                cache: None,
                capture: None,
                rate_limit: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                affinity: None,
                policy_context: None,
                http: Some(HttpPolicyConfig {
                    response_rules: Vec::new(),
                }),
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
                streaming: None,
                grpc: None,
                sse: None,
                streaming_requirement: Some(StreamingRequirement::Preferred),
            }],
            tls_passthrough_routes: vec![ReverseTlsPassthroughRouteConfig {
                r#match: TlsPassthroughMatchConfig {
                    src_ip: Vec::new(),
                    dst_port: vec![443],
                    sni: vec!["@tls_sni".to_string()],
                },
                upstreams: vec!["127.0.0.1:8443".to_string()],
                lb: "round_robin".to_string(),
                timeout_ms: None,
                health_check: None,
                lifecycle: None,
                affinity: None,
                resilience: None,
            }],
        }));

    expand_named_sets_in_config(&mut config).expect("expand named sets");

    assert_eq!(
        config.reverse_edge_configs()[0].routes[0].r#match.src_ip,
        vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
    );
    assert_eq!(
        config.reverse_edge_configs()[0].tls_passthrough_routes[0]
            .r#match
            .sni,
        vec!["example.com".to_string(), "*.corp.example".to_string()]
    );

    let _ = fs::remove_file(cidr_file);
    let _ = fs::remove_file(sni_file);
}

#[test]
fn expand_upstream_trust_profiles_merges_inline_overrides() {
    let mut config = base_config();
    config.security.upstream_trust_profiles = vec![UpstreamTlsTrustProfileConfig {
        name: "corp".to_string(),
        trust: UpstreamTlsTrustConfig {
            pin_sha256: vec!["aa".repeat(32)],
            issuer: vec!["Corp Issuer".to_string()],
            san_dns: vec!["*.corp.example".to_string()],
            san_uri: Vec::new(),
            client_cert: Some("/tmp/profile.crt".to_string()),
            client_key: Some("/tmp/profile.key".to_string()),
        },
    }];
    push_ingress(
        &mut config,
        IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:18080".to_string(),
            default_action: allow_action(),
            original_dst: None,
            tls_inspection: Some(TlsInspectionConfig {
                enabled: true,
                ca: None,
                verify_upstream: true,
                verify_exceptions: Vec::new(),
                upstream_trust_profile: Some("corp".to_string()),
                upstream_trust: Some(UpstreamTlsTrustConfig {
                    pin_sha256: vec!["bb".repeat(32)],
                    issuer: vec!["Inline Issuer".to_string()],
                    san_dns: Vec::new(),
                    san_uri: vec!["spiffe://inline".to_string()],
                    client_cert: Some("/tmp/inline.crt".to_string()),
                    client_key: Some("/tmp/inline.key".to_string()),
                }),
            }),
            rules: Vec::new(),
            connection_filter: Vec::new(),
            streaming: None,
            grpc: None,
            sse: None,
            streaming_requirement: Some(StreamingRequirement::Preferred),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            capture: None,
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        },
    );

    expand_upstream_trust_profiles_in_config(&mut config).expect("expand trust profiles");
    let tls = ingress(&config, 0)
        .tls_inspection
        .as_ref()
        .expect("tls inspection");
    let trust = tls.upstream_trust.as_ref().expect("merged trust");
    assert_eq!(trust.pin_sha256.len(), 2);
    assert_eq!(
        trust.issuer,
        vec!["Corp Issuer".to_string(), "Inline Issuer".to_string()]
    );
    assert_eq!(trust.san_dns, vec!["*.corp.example".to_string()]);
    assert_eq!(trust.san_uri, vec!["spiffe://inline".to_string()]);
    assert_eq!(trust.client_cert.as_deref(), Some("/tmp/inline.crt"));
    assert_eq!(trust.client_key.as_deref(), Some("/tmp/inline.key"));
}
