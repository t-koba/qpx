use super::*;

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
            http_modules: vec![
                serde_yaml::from_str(
                    r#"type: custom_filter
id: inject
settings:
  header_name: x-custom
  header_value: yes"#,
                )
                .expect("http module config"),
            ],
        }));

    let err = Runtime::new(config)
        .err()
        .expect("runtime should reject unknown module");
    assert!(
        err.to_string()
            .contains("unknown http module type custom_filter")
    );
}

#[test]
fn runtime_unifies_observability_query_redaction_keys() {
    let mut config = base_config();
    config.telemetry.access_log.redact.query_keys = vec!["code".to_string()];
    config.telemetry.otel = Some(OtelConfig {
        enabled: false,
        endpoint: None,
        protocol: "grpc".to_string(),
        level: "info".to_string(),
        sample_percent: 100,
        headers: Default::default(),
        service_name: None,
        redact: CaptureRedactionConfig {
            query_keys: vec!["trace_token".to_string()],
            ..Default::default()
        },
    });

    let mut route = reverse_route("default");
    route.capture = Some(CapturePolicyConfig {
        plaintext: CapturePlaintextPolicyConfig {
            redact: CaptureRedactionConfig {
                query_keys: vec!["api_key".to_string()],
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    });
    push_reverse(&mut config, reverse_edge(route));

    let runtime = Runtime::new(config).expect("runtime");
    let state = runtime.state();
    let keys = &state.resources.access_log.redact.query_keys;

    assert!(keys.iter().any(|key| key == "code"));
    assert!(keys.iter().any(|key| key == "trace_token"));
    assert!(keys.iter().any(|key| key == "api_key"));
    assert!(keys.iter().any(|key| key == "access_token"));
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

    assert!(
        !plan
            .rate_limits
            .is_empty_for_scope(crate::rate_limit::TransportScope::Request)
    );
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
#[cfg(unix)]
async fn runtime_plan_exporter_only_does_not_enable_plaintext_body_capture() {
    let mut config = base_config();
    config.telemetry.exporter = Some(qpx_core::config::ExporterConfig {
        enabled: true,
        shm_path: temp_exporter_shm_path("runtime-exporter-only"),
        shm_size_mb: 16,
        lossy: true,
        max_queue_events: 128,
        capture: qpx_core::config::ExporterCaptureConfig {
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
        streaming: crate::runtime::ResolvedStreamingLimits::from(state.plan.limits),
        buffering_reasons: Vec::new(),
        capture: Default::default(),
        local_response: None,
        modules: std::sync::Arc::new(crate::http::modules::CompiledHttpModuleChain::default()),
        cache: None,
        response_rules: None,
        guard: None,
        destination_resolution: None,
        policy_context: Default::default(),
        rate_limits: Default::default(),
    };

    assert!(
        state
            .export_session_for_plan(&plan, "127.0.0.1:1", "example.com:443")
            .is_none()
    );
}

#[test]
fn runtime_plan_marks_route_level_plaintext_body_capture() {
    let mut route = reverse_route("capture");
    route.capture = Some(CapturePolicyConfig {
        encrypted: false,
        plaintext: CapturePlaintextPolicyConfig {
            enabled: true,
            headers: true,
            body: CaptureBodyMode::Full,
            body_sample_bytes: None,
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
    assert!(!flags.contains(PlanFlags::REQUEST_BODY_OBSERVE));
    assert!(!flags.contains(PlanFlags::RESPONSE_BODY_OBSERVE));
    let capture = plan.capture.plaintext.expect("plaintext capture");
    assert!(capture.headers);
    assert_eq!(capture.body, CaptureBodyMode::Full);
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
            body: CaptureBodyMode::Disabled,
            body_sample_bytes: None,
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
fn forward_streaming_required_allows_streaming_full_body_capture() {
    let mut config = base_config();
    push_ingress(
        &mut config,
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
            streaming_requirement: Some(StreamingRequirement::Required),
            upstream_proxy: None,
            http3: None,
            ftp: Default::default(),
            xdp: None,
            cache: None,
            capture: Some(CapturePolicyConfig {
                encrypted: false,
                plaintext: CapturePlaintextPolicyConfig {
                    enabled: true,
                    headers: true,
                    body: CaptureBodyMode::Full,
                    body_sample_bytes: None,
                    sample_percent: None,
                    max_body_bytes: Some(4096),
                    redact: Default::default(),
                },
            }),
            rate_limit: None,
            policy_context: None,
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        },
    );

    Runtime::new(config).expect("streaming full body capture should not require buffering opt-in");
}

#[test]
fn unknown_length_exact_size_requires_runtime_buffer_opt_in() {
    let mut route = reverse_route("size");
    route.streaming_requirement = Some(StreamingRequirement::Preferred);
    route.r#match.request_size = vec![">1m".to_string()];
    let mut config = base_config();
    push_reverse(&mut config, reverse_edge(route.clone()));

    let err = match Runtime::new(config) {
        Ok(_) => panic!("default exact-size policy should reject buffering"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("runtime.unknown_length_exact_size: buffer"),
        "unexpected error: {err}"
    );

    let mut config = base_config();
    config.runtime.unknown_length_exact_size = UnknownLengthExactSizePolicy::Buffer;
    push_reverse(&mut config, reverse_edge(route));
    Runtime::new(config).expect("explicit buffer policy should allow exact unknown-size matcher");
}
