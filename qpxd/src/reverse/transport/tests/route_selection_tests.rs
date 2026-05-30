use super::*;

#[tokio::test]
async fn route_match_uses_actual_chunked_request_size() {
    let reverse_cfg = ReverseEdgeConfig {
        name: "test".to_string(),
        listen: "127.0.0.1:0".to_string(),
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
        routes: vec![
            ReverseRouteConfig {
                name: Some("sized".to_string()),
                r#match: MatchConfig {
                    request_size: vec!["4".to_string()],
                    ..Default::default()
                },
                target: qpx_core::config::ReverseRouteTargetConfig::LocalResponse {
                    response: Box::new(LocalResponseConfig {
                        status: 204,
                        body: String::new(),
                        content_type: None,
                        headers: HashMap::new(),
                        rpc: None,
                    }),
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
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
                streaming: None,
                grpc: None,
                sse: None,
                streaming_requirement: Some(StreamingRequirement::Preferred),
            },
            ReverseRouteConfig {
                name: Some("fallback".to_string()),
                r#match: MatchConfig::default(),
                target: qpx_core::config::ReverseRouteTargetConfig::LocalResponse {
                    response: Box::new(LocalResponseConfig {
                        status: 409,
                        body: "fallback".to_string(),
                        content_type: Some("text/plain".to_string()),
                        headers: HashMap::new(),
                        rpc: None,
                    }),
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
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
                streaming: None,
                grpc: None,
                sse: None,
                streaming_requirement: Some(StreamingRequirement::Preferred),
            },
        ],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
        state_dir: None,
        identity: IdentityConfig::default(),
        messages: MessagesConfig::default(),
        runtime: RuntimeConfig {
            unknown_length_exact_size: UnknownLengthExactSizePolicy::Buffer,
            ..RuntimeConfig::default()
        },
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
        edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
        upstreams: vec![UpstreamConfig {
            name: "upstream".to_string(),
            url: "http://127.0.0.1:8080".to_string(),
            tls_trust_profile: None,
            tls_trust: None,
            discovery: None,
            resilience: None,
        }],
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = crate::reverse::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");
    let (mut sender, body) = Body::channel();
    tokio::spawn(async move {
        sender
            .send_data(bytes::Bytes::from_static(b"ab"))
            .await
            .expect("send first chunk");
        sender
            .send_data(bytes::Bytes::from_static(b"cd"))
            .await
            .expect("send second chunk");
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/upload")
        .header("host", "reverse.test")
        .version(http::Version::HTTP_11)
        .body(body)
        .expect("request");

    let (_, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn route_match_uses_destination_category() {
    let reverse_cfg = ReverseEdgeConfig {
        name: "test".to_string(),
        listen: "127.0.0.1:0".to_string(),
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
        routes: vec![
            ReverseRouteConfig {
                name: Some("ai".to_string()),
                r#match: MatchConfig {
                    destination: Some(DestinationMatchConfig {
                        category: Some(DestinationDimensionMatchConfig {
                            value: vec!["ai".to_string()],
                            source: Vec::new(),
                            confidence: Vec::new(),
                        }),
                        reputation: None,
                        application: None,
                    }),
                    ..Default::default()
                },
                target: qpx_core::config::ReverseRouteTargetConfig::LocalResponse {
                    response: Box::new(LocalResponseConfig {
                        status: 204,
                        body: String::new(),
                        content_type: None,
                        headers: HashMap::new(),
                        rpc: None,
                    }),
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
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
                streaming: None,
                grpc: None,
                sse: None,
                streaming_requirement: Some(StreamingRequirement::Preferred),
            },
            ReverseRouteConfig {
                name: Some("fallback".to_string()),
                r#match: MatchConfig::default(),
                target: qpx_core::config::ReverseRouteTargetConfig::LocalResponse {
                    response: Box::new(LocalResponseConfig {
                        status: 409,
                        body: "fallback".to_string(),
                        content_type: Some("text/plain".to_string()),
                        headers: HashMap::new(),
                        rpc: None,
                    }),
                },
                mirrors: Vec::new(),
                headers: None,
                timeout_ms: None,
                health_check: None,
                rate_limit: None,
                cache: None,
                capture: None,
                path_rewrite: None,
                upstream_trust_profile: None,
                upstream_trust: None,
                lifecycle: None,
                affinity: None,
                policy_context: None,
                http: None,
                http_guard_profile: None,
                destination_resolution: None,
                resilience: None,
                http_modules: Vec::new(),
                streaming: None,
                grpc: None,
                sse: None,
                streaming_requirement: Some(StreamingRequirement::Preferred),
            },
        ],
        tls_passthrough_routes: Vec::new(),
    };
    let config = Config {
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
            named_sets: vec![NamedSetConfig {
                name: "category:ai".to_string(),
                kind: NamedSetKind::Domain,
                values: vec!["*.openai.com".to_string()],
                file: None,
            }],
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
        traffic: qpx_core::config::TrafficConfig::default(),
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
        upstreams: Vec::new(),
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = crate::reverse::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_destination_category"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header("host", "api.openai.com")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let (_, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443),
    )
    .await
    .expect("response");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
