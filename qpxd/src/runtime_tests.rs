use super::*;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CacheConfig,
    HttpPolicyConfig, ListenerConfig, ListenerMode, MatchConfig, NamedSetConfig, NamedSetKind,
    ReverseConfig, ReverseRouteConfig, ReverseTlsPassthroughRouteConfig, RuleConfig,
    SystemLogConfig, TlsInspectionConfig, TlsPassthroughMatchConfig, UpstreamTlsTrustConfig,
    UpstreamTlsTrustProfileConfig, XdpConfig,
};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn base_config() -> Config {
    Config {
        state_dir: None,
        identity: Default::default(),
        messages: Default::default(),
        runtime: Default::default(),
        system_log: SystemLogConfig::default(),
        access_log: AccessLogConfig::default(),
        audit_log: AuditLogConfig::default(),
        metrics: None,
        otel: None,
        acme: None,
        exporter: None,
        auth: AuthConfig {
            users: Vec::new(),
            ldap: None,
        },
        identity_sources: Vec::new(),
        ext_authz: Vec::new(),
        named_sets: Vec::new(),
        http_guard_profiles: Vec::new(),
        rate_limit_profiles: Vec::new(),
        upstream_trust_profiles: Vec::new(),
        destination_resolution: Default::default(),
        listeners: Vec::new(),
        reverse: Vec::new(),
        upstreams: Vec::new(),
        cache: CacheConfig::default(),
    }
}

fn allow_action() -> ActionConfig {
    ActionConfig {
        kind: ActionKind::Direct,
        upstream: None,
        local_response: None,
    }
}

fn temp_named_set_file(name: &str, contents: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("qpx-{name}-{unique}.txt"));
    fs::write(&path, contents).expect("write named set file");
    path
}

#[test]
fn runtime_rejects_unregistered_custom_http_modules() {
    let mut config = base_config();
    config.listeners.push(ListenerConfig {
        name: "forward".to_string(),
        mode: ListenerMode::Forward,
        listen: "127.0.0.1:18080".to_string(),
        default_action: allow_action(),
        tls_inspection: None,
        rules: Vec::new(),
        connection_filter: Vec::new(),
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: vec![serde_yaml::from_str(
            r#"type: custom_filter
id: inject
header_name: x-custom
header_value: yes"#,
        )
        .expect("http module config")],
    });

    let err = Runtime::new(config)
        .err()
        .expect("runtime should reject unknown module");
    assert!(err
        .to_string()
        .contains("unknown http module type custom_filter"));
}

#[test]
fn expand_named_sets_in_listener_rules() {
    let mut config = base_config();
    config.named_sets = vec![
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
    config.listeners.push(ListenerConfig {
        name: "forward".to_string(),
        mode: ListenerMode::Forward,
        listen: "127.0.0.1:18080".to_string(),
        default_action: allow_action(),
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
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: Vec::new(),
    });

    expand_named_sets_in_config(&mut config).expect("expand named sets");

    let rule_match = config.listeners[0].rules[0]
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
    config.named_sets = vec![
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
    config.reverse.push(ReverseConfig {
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
        routes: vec![ReverseRouteConfig {
            name: Some("http".to_string()),
            r#match: MatchConfig {
                src_ip: vec!["@office_cidrs".to_string()],
                ..Default::default()
            },
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: None,
            http: Some(HttpPolicyConfig {
                response_rules: Vec::new(),
            }),
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
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
    });

    expand_named_sets_in_config(&mut config).expect("expand named sets");

    assert_eq!(
        config.reverse[0].routes[0].r#match.src_ip,
        vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
    );
    assert_eq!(
        config.reverse[0].tls_passthrough_routes[0].r#match.sni,
        vec!["example.com".to_string(), "*.corp.example".to_string()]
    );

    let _ = fs::remove_file(cidr_file);
    let _ = fs::remove_file(sni_file);
}

#[test]
fn expand_upstream_trust_profiles_merges_inline_overrides() {
    let mut config = base_config();
    config.upstream_trust_profiles = vec![UpstreamTlsTrustProfileConfig {
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
    config.listeners.push(ListenerConfig {
        name: "forward".to_string(),
        mode: ListenerMode::Forward,
        listen: "127.0.0.1:18080".to_string(),
        default_action: allow_action(),
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
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: Vec::new(),
    });

    expand_upstream_trust_profiles_in_config(&mut config).expect("expand trust profiles");
    let tls = config.listeners[0]
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

#[test]
fn hot_reload_allows_rule_updates_without_topology_change() {
    let mut old = base_config();
    old.listeners.push(ListenerConfig {
        name: "forward".to_string(),
        mode: ListenerMode::Forward,
        listen: "127.0.0.1:18080".to_string(),
        default_action: allow_action(),
        tls_inspection: None,
        rules: Vec::new(),
        connection_filter: Vec::new(),
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: Vec::new(),
    });

    let mut new = old.clone();
    new.listeners[0].rules.push(RuleConfig {
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
    old.listeners.push(ListenerConfig {
        name: "forward".to_string(),
        mode: ListenerMode::Forward,
        listen: "127.0.0.1:18080".to_string(),
        default_action: allow_action(),
        tls_inspection: None,
        rules: Vec::new(),
        connection_filter: Vec::new(),
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: Vec::new(),
    });

    let mut new = old.clone();
    new.listeners[0].listen = "127.0.0.1:18081".to_string();
    ensure_hot_reload_compatible(&old, &new)
        .expect("listener topology change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}

#[test]
fn hot_reload_requires_server_restart_for_reverse_http3_startup_change() {
    let mut old = base_config();
    old.reverse.push(ReverseConfig {
        name: "reverse".to_string(),
        listen: "127.0.0.1:19090".to_string(),
        tls: None,
        http3: None,
        xdp: None,
        enforce_sni_host_match: false,
        sni_host_exceptions: Vec::new(),
        policy_context: None,
        destination_resolution: None,
        connection_filter: Vec::new(),
        routes: vec![ReverseRouteConfig {
            name: Some("default".to_string()),
            r#match: MatchConfig::default(),
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            backends: Vec::new(),
            mirrors: Vec::new(),
            local_response: None,
            headers: None,
            lb: "round_robin".to_string(),
            timeout_ms: None,
            health_check: None,
            cache: None,
            rate_limit: None,
            path_rewrite: None,
            upstream_trust_profile: None,
            upstream_trust: None,
            lifecycle: None,
            ipc: None,
            affinity: None,
            policy_context: None,
            http: Some(HttpPolicyConfig {
                response_rules: Vec::new(),
            }),
            http_guard_profile: None,
            destination_resolution: None,
            resilience: None,
            http_modules: Vec::new(),
        }],
        tls_passthrough_routes: Vec::new(),
    });

    let mut new = old.clone();
    new.reverse[0].http3 = Some(qpx_core::config::ReverseHttp3Config {
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
        .expect("reverse HTTP/3 startup change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}

#[test]
fn hot_reload_requires_server_restart_for_acceptor_tuning_change() {
    let mut old = base_config();
    old.runtime.acceptor_tasks_per_listener = Some(1);
    old.listeners.push(ListenerConfig {
        name: "forward".to_string(),
        mode: ListenerMode::Forward,
        listen: "127.0.0.1:18080".to_string(),
        default_action: allow_action(),
        tls_inspection: None,
        rules: Vec::new(),
        connection_filter: Vec::new(),
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: Vec::new(),
    });

    let mut new = old.clone();
    new.runtime.acceptor_tasks_per_listener = Some(4);

    ensure_hot_reload_compatible(&old, &new)
        .expect("acceptor tuning change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}

#[test]
fn hot_reload_requires_server_restart_for_xdp_startup_change() {
    let mut old = base_config();
    old.listeners.push(ListenerConfig {
        name: "forward".to_string(),
        mode: ListenerMode::Forward,
        listen: "127.0.0.1:18080".to_string(),
        default_action: allow_action(),
        tls_inspection: None,
        rules: Vec::new(),
        connection_filter: Vec::new(),
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: Vec::new(),
    });

    let mut new = old.clone();
    new.listeners[0].xdp = Some(XdpConfig {
        enabled: true,
        metadata_mode: "proxy-v2".to_string(),
        require_metadata: true,
        trusted_peers: vec!["127.0.0.0/8".to_string()],
    });

    ensure_hot_reload_compatible(&old, &new)
        .expect("xdp startup change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}

#[test]
fn hot_reload_rejects_worker_thread_change() {
    let mut old = base_config();
    old.runtime.worker_threads = Some(2);
    old.listeners.push(ListenerConfig {
        name: "forward".to_string(),
        mode: ListenerMode::Forward,
        listen: "127.0.0.1:18080".to_string(),
        default_action: allow_action(),
        tls_inspection: None,
        rules: Vec::new(),
        connection_filter: Vec::new(),
        upstream_proxy: None,
        http3: None,
        ftp: Default::default(),
        xdp: None,
        cache: None,
        rate_limit: None,
        policy_context: None,
        http: None,
        http_guard_profile: None,
        destination_resolution: None,
        http_modules: Vec::new(),
    });

    let mut new = old.clone();
    new.runtime.worker_threads = Some(8);

    let err = ensure_hot_reload_compatible(&old, &new)
        .expect_err("worker thread change must still require process restart");
    assert!(err.to_string().contains("runtime startup tuning changed"));
}
