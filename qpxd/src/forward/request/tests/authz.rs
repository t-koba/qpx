use super::*;

async fn spawn_ext_authz_server(response_body: &str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind authz");
    let addr = listener.local_addr().expect("authz addr");
    let response_body = response_body.to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("authz accept");
        let mut raw = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await.expect("authz read");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..n]);
            if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("authz write");
    });
    addr
}

#[tokio::test]
async fn ext_authz_unknown_rate_limit_profile_fails_closed() {
    let authz_addr =
        spawn_ext_authz_server(r#"{"decision":"allow","rate_limit_profile":"missing"}"#).await;
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
                ext_authz: vec![ExtAuthzConfig {
                    name: "authz".to_string(),
                    kind: Default::default(),
                    endpoint: format!("http://{authz_addr}"),
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
            policy_context: Some(PolicyContextConfig {
                identity_sources: Vec::new(),
                ext_authz: Some("authz".to_string()),
            }),
            http: None,
            http_guard_profile: None,
            destination_resolution: None,
            http_modules: Vec::new(),
        })],
        upstreams: Vec::new(),
        caches: Vec::new(),
    })
    .expect("runtime");
    let request = Request::builder()
        .method(Method::GET)
        .uri("http://example.com/")
        .header("host", "example.com")
        .version(http::Version::HTTP_11)
        .body(Body::empty())
        .expect("request");

    let err = handle_request_inner(
        request,
        runtime,
        "forward",
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
    )
    .await
    .expect_err("unknown ext_authz profile should fail closed");
    assert!(err.to_string().contains("unknown rate limit profile"));
}
