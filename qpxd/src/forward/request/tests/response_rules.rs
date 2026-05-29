use super::*;

#[tokio::test]
async fn forward_response_rule_matches_request_derived_rpc_fields() {
    let upstream_addr = spawn_static_http_server(
        "200 OK",
        vec![("Content-Type", "application/grpc".to_string())],
        String::new(),
        1,
    )
    .await;
    let runtime = Runtime::new(Config {
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
        edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
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
            http: Some(HttpPolicyConfig {
                response_rules: vec![HttpResponseRuleConfig {
                    name: "rpc-response".to_string(),
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
                            status: 209,
                            body: "rpc matched".to_string(),
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{upstream_addr}/demo.Echo/Say"))
        .header("host", upstream_addr.to_string())
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let response = handle_request_inner(
        request,
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::from_u16(209).expect("custom status")
    );
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(body.as_ref(), b"rpc matched");
}

#[tokio::test]
async fn forward_response_rule_matches_client_streaming_rpc() {
    let mut request_body = grpc_test_frame(b"one");
    request_body.extend_from_slice(&grpc_test_frame(b"two"));
    assert_forward_response_rule_matches_streaming("client", 210, Vec::new(), request_body).await;
}

#[tokio::test]
async fn forward_response_rule_matches_bidi_streaming_rpc() {
    let mut request_body = grpc_test_frame(b"one");
    request_body.extend_from_slice(&grpc_test_frame(b"two"));
    let mut response_body = grpc_test_frame(b"alpha");
    response_body.extend_from_slice(&grpc_test_frame(b"beta"));
    assert_forward_response_rule_matches_streaming("bidi", 211, response_body, request_body).await;
}

async fn assert_forward_response_rule_matches_streaming(
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
    let runtime = Runtime::new(Config {
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
        edges: vec![qpx_core::config::EdgeConfig::Forward(IngressEdgeConfig {
            name: "forward".to_string(),
            mode: IngressEdgeMode::Forward,
            listen: "127.0.0.1:0".to_string(),
            default_action: ActionConfig {
                kind: ActionKind::Direct,
                upstream: None,
                local_response: None,
            },
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
            http: Some(HttpPolicyConfig {
                response_rules: vec![HttpResponseRuleConfig {
                    name: "rpc-client-streaming".to_string(),
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
                            body: "streaming matched".to_string(),
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
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{upstream_addr}/demo.Echo/Say"))
        .header("host", upstream_addr.to_string())
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::CONTENT_LENGTH, request_body.len().to_string())
        .version(http::Version::HTTP_11)
        .body(Body::from(request_body))
        .expect("request");

    let response = handle_request_inner(
        request,
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::from_u16(status).expect("custom status")
    );
    let body = to_bytes(response.into_body()).await.expect("body");
    assert_eq!(body.as_ref(), b"streaming matched");
}

fn grpc_test_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
