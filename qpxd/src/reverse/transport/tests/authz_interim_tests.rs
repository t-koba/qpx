use super::*;

#[tokio::test]
async fn reverse_ext_authz_rate_limit_profile_is_enforced() {
    let authz_addr = spawn_ext_authz_server(
        r#"{"decision":"allow","rate_limit_profile":"reverse-profile"}"#.to_string(),
        2,
    )
    .await;
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
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
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
            policy_context: Some(PolicyContextConfig {
                identity_sources: Vec::new(),
                ext_authz: Some("authz".to_string()),
            }),
            http: None,
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
                ext_authz: vec![ExtAuthzConfig {
                    name: "authz".to_string(),
                    kind: Default::default(),
                    endpoint: format!("http://{}", authz_addr),
                    timeout_ms: 1_000,
                    max_response_bytes: 1024 * 1024,
                    send: ExtAuthzSendConfig::default(),
                    on_error: Default::default(),
                }],
            },
            destination: Default::default(),
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
        traffic: qpx_core::config::TrafficConfig {
            rate_limit_profiles: vec![RateLimitProfileConfig {
                name: "reverse-profile".to_string(),
                limit: RateLimitConfig {
                    enabled: true,
                    apply_to: vec![qpx_core::config::RateLimitApplyTo::Request],
                    key: "global".to_string(),
                    requests: Some(qpx_core::config::RateLimitRequestsConfig {
                        rps: Some(1),
                        burst: Some(1),
                        quota: None,
                    }),
                    traffic: None,
                    sessions: None,
                },
            }],
        },
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
        upstreams: Vec::new(),
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = crate::reverse::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");

    let request = || {
        Request::builder()
            .method(Method::GET)
            .uri("/asset")
            .header("host", "reverse.test")
            .version(http::Version::HTTP_11)
            .body(Body::empty())
            .expect("request")
    };
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80);

    let (_, first) = handle_request_with_interim(request(), reverse.clone(), conn.clone())
        .await
        .expect("first response");
    assert_eq!(first.status(), StatusCode::NO_CONTENT);

    let (_, second) = handle_request_with_interim(request(), reverse, conn)
        .await
        .expect("second response");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn handle_request_with_interim_returns_early_hints_for_h3_downstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let upstream_addr = listener.local_addr().expect("upstream addr");
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.expect("read request");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        stream
            .write_all(
                b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            )
            .await
            .expect("write response");
    });

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
        routes: vec![ReverseRouteConfig {
            name: Some("route".to_string()),
            r#match: MatchConfig::default(),
            target: qpx_core::config::ReverseRouteTargetConfig::Upstream {
                upstreams: vec!["upstream".to_string()],
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
            http: None,
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
    };
    let upstream_cfg = UpstreamConfig {
        name: "upstream".to_string(),
        url: format!("http://{}", upstream_addr),
        tls_trust_profile: None,
        tls_trust: None,
        discovery: None,
        resilience: None,
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
            named_sets: Vec::new(),
            upstream_trust_profiles: Vec::new(),
        },
        http: qpx_core::config::HttpGlobalConfig::default(),
        traffic: qpx_core::config::TrafficConfig::default(),
        acme: None,
        edges: vec![qpx_core::config::EdgeConfig::Reverse(reverse_cfg.clone())],
        upstreams: vec![upstream_cfg],
        caches: Vec::new(),
    };
    let runtime = Runtime::new(config).expect("runtime");
    let reverse = crate::reverse::ReloadableReverse::new(
        reverse_cfg,
        runtime,
        StdArc::<str>::from("reverse_upstreams_unhealthy"),
    )
    .expect("reloadable reverse");
    let request = Request::builder()
        .method(Method::GET)
        .uri("/asset")
        .header("host", "reverse.test")
        .version(http::Version::HTTP_3)
        .body(Body::empty())
        .expect("request");

    let (interim, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443),
    )
    .await
    .expect("response");

    assert_eq!(interim.len(), 1);
    assert_eq!(interim[0].status, StatusCode::from_u16(103).unwrap());
    assert_eq!(
        interim[0]
            .headers
            .get("link")
            .and_then(|value| value.to_str().ok()),
        Some("</style.css>; rel=preload; as=style")
    );
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body()).await.expect("body bytes"),
        bytes::Bytes::from_static(b"OK")
    );
}
