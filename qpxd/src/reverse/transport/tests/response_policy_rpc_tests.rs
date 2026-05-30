use super::*;

#[tokio::test]
async fn response_rule_can_force_local_response_and_merge_headers() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "resp-local".to_string(),
        r#match: Some(MatchConfig {
            response_status: vec!["500-599".to_string()],
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            local_response: Some(LocalResponseConfig {
                status: 418,
                body: "blocked upstream".to_string(),
                content_type: Some("text/plain".to_string()),
                headers: HashMap::new(),
                rpc: None,
            }),
            headers: Some(HeaderControl {
                request_set: HashMap::new(),
                request_add: HashMap::new(),
                request_remove: Vec::new(),
                request_regex_replace: Vec::new(),
                response_set: HashMap::from([("x-rule".to_string(), "local".to_string())]),
                response_add: HashMap::new(),
                response_remove: Vec::new(),
                response_regex_replace: Vec::new(),
            }),
            ..Default::default()
        },
    }]);
    let route = router.route_at(0).expect("route");
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443);
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = DestinationMetadata::default();
    let response = Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Body::empty())
        .unwrap();
    let request_rpc = crate::http::rpc::RpcMatchContext::default();
    let base = make_base_request_fields("GET", "example.com", "/", None);

    let decision = apply_response_rules(ResponseRuleInput {
        route,
        base: &base,
        conn: &conn,
        destination: &destination,
        upstream_cert: None,
        identity: &identity,
        request_rpc: Some(&request_rpc),
        route_headers: Some(compile_headers("x-base", "route")),
        response,
        max_observed_response_body_bytes: usize::MAX,
        response_body_read_timeout: std::time::Duration::from_secs(1),
        force_response_body_observation: false,
    })
    .await
    .expect("apply");

    match decision {
        ResponseRuleDecision::LocalResponse {
            response,
            route_headers,
            ..
        } => {
            assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
            let headers = route_headers.expect("merged headers");
            assert!(
                headers
                    .response_set()
                    .iter()
                    .any(|(name, value)| name == "x-base" && value == "route")
            );
            assert!(
                headers
                    .response_set()
                    .iter()
                    .any(|(name, value)| name == "x-rule" && value == "local")
            );
        }
        ResponseRuleDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[tokio::test]
async fn response_rule_matches_request_derived_rpc_fields() {
    let router = build_router(vec![HttpResponseRuleConfig {
        name: "resp-rpc".to_string(),
        r#match: Some(MatchConfig {
            rpc: Some(RpcMatchConfig {
                protocol: vec!["grpc".to_string()],
                service: vec!["demo.Echo".to_string()],
                method: vec!["Say".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }),
        effects: HttpResponseEffectsConfig {
            local_response: Some(LocalResponseConfig {
                status: 204,
                body: String::new(),
                content_type: None,
                headers: HashMap::new(),
                rpc: None,
            }),
            ..Default::default()
        },
    }]);
    let route = router.route_at(0).expect("route");
    let candidates = route.response_rule_candidate_profile(MatchPrefilterContext {
        method: Some("POST"),
        dst_port: Some(443),
        src_ip: None,
        host: Some("example.com"),
        sni: None,
        path: Some("/demo.Echo/Say"),
    });
    assert!(candidates.requires_request_rpc_context);
    let conn = ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 443);
    let identity = crate::policy_context::ResolvedIdentity::default();
    let destination = DestinationMetadata::default();
    let response = Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap();
    let request_rpc = crate::http::rpc::RpcMatchContext {
        protocol: Some("grpc".to_string()),
        service: Some("demo.Echo".to_string()),
        method: Some("Say".to_string()),
        ..Default::default()
    };
    let base = make_base_request_fields("POST", "example.com", "/demo.Echo/Say", None);

    let decision = apply_response_rules(ResponseRuleInput {
        route,
        base: &base,
        conn: &conn,
        destination: &destination,
        upstream_cert: None,
        identity: &identity,
        request_rpc: Some(&request_rpc),
        route_headers: None,
        response,
        max_observed_response_body_bytes: usize::MAX,
        response_body_read_timeout: std::time::Duration::from_secs(1),
        force_response_body_observation: false,
    })
    .await
    .expect("apply");

    match decision {
        ResponseRuleDecision::LocalResponse { response, .. } => {
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        }
        ResponseRuleDecision::Continue { .. } => panic!("expected local response"),
    }
}

#[tokio::test]
async fn reverse_response_rule_matches_client_streaming_rpc() {
    let mut request_body = grpc_test_frame(b"one");
    request_body.extend_from_slice(&grpc_test_frame(b"two"));
    assert_reverse_response_rule_matches_streaming("client", 210, Vec::new(), request_body).await;
}

#[tokio::test]
async fn reverse_response_rule_matches_bidi_streaming_rpc() {
    let mut request_body = grpc_test_frame(b"one");
    request_body.extend_from_slice(&grpc_test_frame(b"two"));
    let mut response_body = grpc_test_frame(b"alpha");
    response_body.extend_from_slice(&grpc_test_frame(b"beta"));
    assert_reverse_response_rule_matches_streaming("bidi", 211, response_body, request_body).await;
}

async fn assert_reverse_response_rule_matches_streaming(
    streaming: &str,
    status: u16,
    upstream_body: Vec<u8>,
    request_body: Vec<u8>,
) {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "application/grpc".to_string())],
        String::from_utf8(upstream_body).expect("test gRPC frame bytes are UTF-8 control bytes"),
        1,
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
            name: Some("grpc".to_string()),
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
            http: Some(HttpPolicyConfig {
                response_rules: vec![HttpResponseRuleConfig {
                    name: "rpc-streaming".to_string(),
                    r#match: Some(MatchConfig {
                        rpc: Some(RpcMatchConfig {
                            streaming: vec![streaming.to_string()],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    effects: HttpResponseEffectsConfig {
                        local_response: Some(LocalResponseConfig {
                            status,
                            body: "reverse streaming matched".to_string(),
                            content_type: Some("text/plain".to_string()),
                            headers: HashMap::new(),
                            rpc: None,
                        }),
                        ..Default::default()
                    },
                }],
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
            url: format!("http://{upstream_addr}"),
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
    let request = Request::builder()
        .method(Method::POST)
        .uri("/demo.Echo/Say")
        .header("host", "reverse.test")
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::CONTENT_LENGTH, request_body.len().to_string())
        .version(http::Version::HTTP_11)
        .body(Body::from(request_body))
        .expect("request");

    let (_, response) = handle_request_with_interim(
        request,
        reverse,
        ReverseConnInfo::plain(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345), 80),
    )
    .await
    .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::from_u16(status).expect("custom status")
    );
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(body.as_ref(), b"reverse streaming matched");
}

fn grpc_test_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
