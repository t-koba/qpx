use super::plan::CompiledEdge;
use super::*;
use qpx_core::config::{
    AccessLogConfig, ActionConfig, ActionKind, AuditLogConfig, AuthConfig, CachePolicyConfig,
    CapturePlaintextPolicyConfig, CapturePolicyConfig, ExporterCaptureConfig, ExporterConfig,
    HttpModuleConfig, HttpPolicyConfig, IngressEdgeConfig, IngressEdgeMode, IpcMode,
    IpcUpstreamConfig, MatchConfig, NamedSetConfig, NamedSetKind, PolicyContextConfig,
    RateLimitApplyTo, RateLimitConfig, RateLimitRequestsConfig, ReverseEdgeConfig,
    ReverseRouteConfig, ReverseRouteTargetConfig, ReverseTlsPassthroughRouteConfig, RuleConfig,
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
        telemetry: qpx_core::config::TelemetryConfig {
            system_log: SystemLogConfig::default(),
            access_log: AccessLogConfig::default(),
            audit_log: AuditLogConfig::default(),
            metrics: None,
            otel: None,
            exporter: None,
        },
        security: qpx_core::config::SecurityConfig {
            auth: AuthConfig {
                users: Vec::new(),
                ldap: None,
            },
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

fn push_ingress(config: &mut Config, edge: IngressEdgeConfig) {
    config
        .edges
        .push(qpx_core::config::EdgeConfig::Forward(edge));
}

fn push_reverse(config: &mut Config, edge: ReverseEdgeConfig) {
    config
        .edges
        .push(qpx_core::config::EdgeConfig::Reverse(edge));
}

fn ingress_mut(config: &mut Config, idx: usize) -> &mut IngressEdgeConfig {
    config.ingress_edges_mut().nth(idx).expect("ingress edge")
}

fn ingress(config: &Config, idx: usize) -> &IngressEdgeConfig {
    config.ingress_edges().nth(idx).expect("ingress edge")
}

fn reverse_mut(config: &mut Config, idx: usize) -> &mut ReverseEdgeConfig {
    config.reverse_edges_mut().nth(idx).expect("reverse edge")
}

fn allow_action() -> ActionConfig {
    ActionConfig {
        kind: ActionKind::Direct,
        upstream: None,
        local_response: None,
    }
}

fn reverse_route(name: &str) -> ReverseRouteConfig {
    ReverseRouteConfig {
        name: Some(name.to_string()),
        r#match: MatchConfig::default(),
        target: ReverseRouteTargetConfig::Upstream {
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
    }
}

fn reverse_edge(route: ReverseRouteConfig) -> ReverseEdgeConfig {
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
        routes: vec![route],
        tls_passthrough_routes: Vec::new(),
    }
}

fn single_reverse_route_flags(config: Config) -> PlanFlags {
    let runtime = Runtime::new(config).expect("runtime");
    let state = runtime.state();
    match state.plan.edges.as_ref() {
        [CompiledEdge::Reverse(edge)] => edge.routes[0].plan.flags,
        edges => panic!("expected one reverse_edges edge, got {}", edges.len()),
    }
}

fn single_reverse_route_plan(config: Config) -> ExecutionPlan {
    let runtime = Runtime::new(config).expect("runtime");
    let state = runtime.state();
    match state.plan.edges.as_ref() {
        [CompiledEdge::Reverse(edge)] => edge.routes[0].plan.clone(),
        edges => panic!("expected one reverse_edges edge, got {}", edges.len()),
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
    config
        .edges
        .push(qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:18080".to_string(),
            default_action: allow_action(),
            original_dst: None,
            tls_inspection: None,
            rules: Vec::new(),
            connection_filter: Vec::new(),
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
            http_modules: vec![serde_yaml::from_str(
                r#"type: custom_filter
id: inject
header_name: x-custom
header_value: yes"#,
            )
            .expect("http module config")],
        }));

    let err = Runtime::new(config)
        .err()
        .expect("runtime should reject unknown module");
    assert!(err
        .to_string()
        .contains("unknown http module type custom_filter"));
}

#[test]
fn runtime_plan_keeps_minimal_reverse_route_empty() {
    let mut config = base_config();
    push_reverse(&mut config, reverse_edge(reverse_route("default")));

    let flags = single_reverse_route_flags(config);

    assert_eq!(flags.bits(), 0);
}

#[test]
fn runtime_plan_marks_policy_context_features() {
    let mut route = reverse_route("default");
    route.policy_context = Some(PolicyContextConfig {
        identity_sources: vec!["trusted_headers".to_string()],
        ext_authz: Some("opa".to_string()),
    });
    let mut config = base_config();
    push_reverse(&mut config, reverse_edge(route));

    let flags = single_reverse_route_flags(config);

    assert!(flags.contains(PlanFlags::IDENTITY_SOURCES));
    assert!(flags.contains(PlanFlags::EXT_AUTHZ));
}

#[test]
fn runtime_plan_marks_cache_lookup_and_store() {
    let mut route = reverse_route("default");
    route.cache = Some(CachePolicyConfig {
        enabled: true,
        backend: "default".to_string(),
        namespace: None,
        default_ttl_secs: Some(60),
        max_object_bytes: 1024,
        allow_set_cookie_store: false,
    });
    let mut config = base_config();
    push_reverse(&mut config, reverse_edge(route));

    let plan = single_reverse_route_plan(config);

    assert!(plan.flags.contains(PlanFlags::CACHE_LOOKUP));
    assert!(plan.flags.contains(PlanFlags::CACHE_STORE));
    assert!(plan.cache.is_some());
}

#[test]
fn runtime_plan_compiles_route_rate_limits() {
    let mut route = reverse_route("limited");
    route.rate_limit = Some(RateLimitConfig {
        enabled: true,
        apply_to: vec![RateLimitApplyTo::Request],
        key: "src_ip".to_string(),
        requests: Some(RateLimitRequestsConfig {
            rps: Some(1),
            burst: Some(1),
            quota: None,
        }),
        traffic: None,
        sessions: None,
    });
    let mut config = base_config();
    push_reverse(&mut config, reverse_edge(route));

    let plan = single_reverse_route_plan(config);

    assert!(!plan
        .rate_limits
        .is_empty_for_scope(crate::rate_limit::TransportScope::Request));
}

#[test]
fn runtime_plan_classifies_http_modules_by_phase() {
    let cases = [
        (
            serde_yaml::from_str::<HttpModuleConfig>("type: response_compression")
                .expect("compression module"),
            PlanFlags::RESPONSE_MODULES,
            PlanFlags::REQUEST_MODULES,
        ),
        (
            serde_yaml::from_str::<HttpModuleConfig>(
                r#"type: subrequest
settings:
  name: enrich
  phase: request_headers
  url: http://127.0.0.1:18081/enrich
  max_response_bytes: 65536
  allowed_schemes: [http]
  allowed_hosts: [127.0.0.1]"#,
            )
            .expect("request subrequest module"),
            PlanFlags::REQUEST_MODULES,
            PlanFlags::RESPONSE_MODULES,
        ),
        (
            serde_yaml::from_str::<HttpModuleConfig>(
                r#"type: subrequest
settings:
  name: observe
  phase: response_headers
  url: http://127.0.0.1:18081/observe
  max_response_bytes: 65536
  allowed_schemes: [http]
  allowed_hosts: [127.0.0.1]"#,
            )
            .expect("response subrequest module"),
            PlanFlags::RESPONSE_MODULES,
            PlanFlags::REQUEST_MODULES,
        ),
    ];

    for (module, expected, unexpected) in cases {
        let mut route = reverse_route("default");
        route.http_modules = vec![module];
        let mut config = base_config();
        push_reverse(&mut config, reverse_edge(route));

        let flags = single_reverse_route_flags(config);

        assert!(flags.contains(expected));
        assert!(!flags.contains(unexpected));
    }
}

#[test]
fn runtime_plan_marks_ipc_reverse_routes() {
    let mut route = reverse_route("ipc");
    route.target = ReverseRouteTargetConfig::Ipc {
        config: IpcUpstreamConfig {
            mode: IpcMode::Shm,
            address: "qpx-ipc.sock".to_string(),
            timeout_ms: 500,
            body: Default::default(),
        },
    };
    let mut config = base_config();
    push_reverse(&mut config, reverse_edge(route));

    let flags = single_reverse_route_flags(config);

    assert!(flags.contains(PlanFlags::IPC));
}

#[tokio::test]
async fn runtime_plan_exporter_only_does_not_enable_plaintext_body_capture() {
    let mut config = base_config();
    config.telemetry.exporter = Some(ExporterConfig {
        enabled: true,
        shm_path: String::new(),
        shm_size_mb: 16,
        lossy: true,
        max_queue_events: 128,
        capture: ExporterCaptureConfig {
            plaintext: true,
            encrypted: true,
            max_chunk_bytes: 4096,
            redact: Default::default(),
        },
    });
    push_reverse(&mut config, reverse_edge(reverse_route("default")));

    let flags = single_reverse_route_flags(config);

    assert!(flags.contains(PlanFlags::CAPTURE_ENCRYPTED));
    assert!(!flags.contains(PlanFlags::CAPTURE_PLAINTEXT));
    assert!(!flags.contains(PlanFlags::CAPTURE_BODY));
    assert!(!flags.contains(PlanFlags::REQUEST_BODY_OBSERVE));
    assert!(!flags.contains(PlanFlags::RESPONSE_BODY_OBSERVE));
}

#[test]
fn export_session_for_plan_is_absent_without_capture_flags() {
    let config = base_config();
    let state = RuntimeState::build(config).expect("state");
    let plan = ExecutionPlan {
        flags: PlanFlags::empty(),
        capture: Default::default(),
        modules: std::sync::Arc::new(crate::http::modules::CompiledHttpModuleChain::default()),
        cache: None,
        response_rules: None,
        guard: None,
        destination_resolution: None,
        policy_context: Default::default(),
        rate_limits: Default::default(),
    };

    assert!(state
        .export_session_for_plan(&plan, "127.0.0.1:1", "example.com:443")
        .is_none());
}

#[test]
fn runtime_plan_marks_route_level_plaintext_body_capture() {
    let mut route = reverse_route("capture");
    route.capture = Some(CapturePolicyConfig {
        encrypted: false,
        plaintext: CapturePlaintextPolicyConfig {
            enabled: true,
            headers: true,
            body: true,
            sample_percent: Some(10),
            max_body_bytes: Some(16_384),
            redact: Default::default(),
        },
    });
    let mut config = base_config();
    push_reverse(&mut config, reverse_edge(route));

    let plan = single_reverse_route_plan(config);
    let flags = plan.flags;

    assert!(flags.contains(PlanFlags::CAPTURE_PLAINTEXT));
    assert!(flags.contains(PlanFlags::CAPTURE_BODY));
    assert!(flags.contains(PlanFlags::REQUEST_BODY_OBSERVE));
    assert!(flags.contains(PlanFlags::RESPONSE_BODY_OBSERVE));
    let capture = plan.capture.plaintext.expect("plaintext capture");
    assert!(capture.headers);
    assert!(capture.body);
    assert_eq!(capture.sample_percent, Some(10));
    assert_eq!(capture.max_body_bytes, Some(16_384));
}

#[test]
fn runtime_plan_plaintext_headers_only_does_not_observe_body() {
    let mut route = reverse_route("capture-headers");
    route.capture = Some(CapturePolicyConfig {
        encrypted: false,
        plaintext: CapturePlaintextPolicyConfig {
            enabled: true,
            headers: true,
            body: false,
            sample_percent: None,
            max_body_bytes: None,
            redact: Default::default(),
        },
    });
    let mut config = base_config();
    push_reverse(&mut config, reverse_edge(route));

    let flags = single_reverse_route_flags(config);

    assert!(flags.contains(PlanFlags::CAPTURE_PLAINTEXT));
    assert!(!flags.contains(PlanFlags::CAPTURE_BODY));
    assert!(!flags.contains(PlanFlags::REQUEST_BODY_OBSERVE));
    assert!(!flags.contains(PlanFlags::RESPONSE_BODY_OBSERVE));
}

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

#[test]
fn hot_reload_requires_server_restart_for_acceptor_tuning_change() {
    let mut old = base_config();
    old.runtime.acceptor_tasks_per_listener = Some(1);
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
    new.runtime.acceptor_tasks_per_listener = Some(4);

    ensure_hot_reload_compatible(&old, &new)
        .expect("acceptor tuning change should be reload-safe with server restart");
    assert!(requires_server_restart(&old, &new));
}

#[test]
fn hot_reload_requires_server_restart_for_xdp_startup_change() {
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
    ingress_mut(&mut new, 0).xdp = Some(XdpConfig {
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
    new.runtime.worker_threads = Some(8);

    let err = ensure_hot_reload_compatible(&old, &new)
        .expect_err("worker thread change must still require process restart");
    assert!(err.to_string().contains("runtime startup tuning changed"));
}
