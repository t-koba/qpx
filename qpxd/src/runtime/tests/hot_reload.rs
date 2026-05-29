use super::*;

#[test]
fn hot_reload_allows_rule_updates_without_topology_change() {
    let mut old = base_config();
    push_ingress(
        &mut old,
        IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:18080".to_string(),
            default_action: allow_action(),
            original_dst: None,
            tls_inspection: None,
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

    let mut new = old.clone();
    ingress_mut(&mut new, 0).rules.push(RuleConfig {
        name: "allow-example".to_string(),
        r#match: Some(MatchConfig {
            host: vec!["example.com".to_string()],
            ..Default::default()
        }),
        auth: None,
        action: Some(allow_action()),
        headers: None,
        rate_limit: None,
    });

    ensure_hot_reload_compatible(&old, &new).expect("rule update should be reload-safe");
}

#[test]
fn hot_reload_requires_server_restart_for_listener_topology_change() {
    let mut old = base_config();
    push_ingress(
        &mut old,
        IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:18080".to_string(),
            default_action: allow_action(),
            original_dst: None,
            tls_inspection: None,
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

    let mut new = old.clone();
    ingress_mut(&mut new, 0).listen = "127.0.0.1:18081".to_string();
    ensure_hot_reload_compatible(&old, &new)
        .expect("listener topology change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}

#[test]
fn hot_reload_requires_server_restart_for_reverse_http3_startup_change() {
    let mut old = base_config();
    push_reverse(
        &mut old,
        ReverseEdgeConfig {
            name: "reverse_edges".to_string(),
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
                name: Some("default".to_string()),
                r#match: MatchConfig::default(),
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
            tls_passthrough_routes: Vec::new(),
        },
    );

    let mut new = old.clone();
    reverse_mut(&mut new, 0).http3 = Some(qpx_core::config::ReverseHttp3Config {
        enabled: true,
        listen: Some("127.0.0.1:19443".to_string()),
        passthrough_upstreams: Vec::new(),
        passthrough_max_sessions: 1024,
        passthrough_idle_timeout_secs: 30,
        passthrough_max_new_sessions_per_sec: 100,
        passthrough_min_client_bytes: 1024,
        passthrough_max_amplification: 3,
    });

    ensure_hot_reload_compatible(&old, &new)
        .expect("reverse_edges HTTP/3 startup change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}
